//go:build ignore
//
// nvme_uring_cmd_monitor.bpf.c — decode NVMe commands issued via io_uring
// IORING_OP_URING_CMD passthrough (Phase 3 + P2 completions). Fentry on the
// NVMe namespace char-device uring_cmd handlers; reads the nvme_uring_cmd the
// application embedded in the SQE and exports the raw command fields.
// SLBA/NLB -> bytes decoding is done in userspace with the namespace LBA size
// (plan: keep the BPF small, do geometry in userspace).
//
// P2 completions: fentry on nvme_uring_cmd_end_io — the DEVICE completion
// callback (req->end_io), which fires regardless of io_uring CQ state.  The
// io_uring_complete tracepoint is deliberately NOT used: it sits after
// io_get_cqe() succeeds, so completions that hit a full CQ (the overflow
// wedge this tracer exists to catch) never reach it.  Submissions and
// completions are paired IN KERNEL via a hash map keyed on the io_uring_cmd
// pointer: inserted at submit (BPF_ANY, so an -EAGAIN re-issue of the same
// SQE simply refreshes the entry), lookup+delete at completion, and a cmp
// event is emitted only on a hit — foreign io_uring traffic never floods the
// ring buffer, and the pid filter applies transitively (completions run in
// IRQ context where current is meaningless; only tracked submissions match).
//
// Optional: fentry on the CQ-overflow path (io_cqring_event_overflow on 6.8,
// io_cqe_overflow on newer kernels) so overflowed completions appear as
// their own events; userspace probes vmlinux BTF and autoloads whichever
// symbol exists.
//
// Grounded in live BTF (kernel 6.8, nvme_core module BTF):
//   struct io_uring_cmd { struct file *file; const struct io_uring_sqe *sqe;
//                         ...; u32 cmd_op; ... }
//   io_uring_sqe.cmd[] is at offset 48 (verified via pahole).
//   nvme_uring_cmd_end_io(struct request *req, blk_status_t err)
//     (FUNC_PROTO vlen=2 'req','err'; static but address-taken as
//      req->end_io, so present in BTF and fentry-attachable)
//   struct nvme_uring_cmd is uapi (not in vmlinux BTF) -> defined locally.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define SQE_CMD_OFF 48   /* io_uring_sqe.cmd[] offset */

#define EV_CMD 0
#define EV_CMP 1
#define EV_OVF 2

/* uapi struct nvme_uring_cmd (72 bytes) — not in vmlinux BTF */
struct nvme_uring_cmd_u {
	__u8  opcode;
	__u8  flags;
	__u16 rsvd1;
	__u32 nsid;
	__u32 cdw2;
	__u32 cdw3;
	__u64 metadata;
	__u64 addr;
	__u32 metadata_len;
	__u32 data_len;
	__u32 cdw10;
	__u32 cdw11;
	__u32 cdw12;
	__u32 cdw13;
	__u32 cdw14;
	__u32 cdw15;
	__u32 timeout_ms;
	__u32 rsvd2;
};

struct nvme_cmd_event {
	__u32 ev_type;      /* EV_CMD */
	__u32 pid;
	__u64 ts;
	__u32 tid;
	__u32 rdev;         /* char-dev i_rdev — identifies WHICH /dev/ngXnY */
	__u64 user_data;    /* SQE user_data — the KV-object join key (if LMCache tags it) */
	__u64 cmd_op;       /* ioucmd->cmd_op (NVME_URING_CMD_IO/_VEC) */
	__u8  nvme_opcode;  /* 0x02 read, 0x01 write, ... */
	__u8  multipath;    /* 1 if via *_head_chr handler */
	__u8  _pad[2];
	__u32 nsid;
	__u32 data_len;     /* bytes the command declares */
	__u64 slba;         /* cdw10 | cdw11<<32 (NVM read/write) */
	__u32 nlb_zero;     /* cdw12 & 0xffff (zero-based) */
	__u32 cdw12;
	char  comm[16];
};

struct nvme_cmp_event {
	__u32 ev_type;      /* EV_CMP */
	__u32 err;          /* blk_status_t (0 = OK) */
	__u64 ts;           /* completion time (device end_io) */
	__u64 user_data;    /* from the paired submission */
	__u64 lat_ns;       /* ts - submission ts, computed in kernel */
	__u32 hwq;          /* req->mq_hctx->queue_num (hw queue index) */
	__s32 cid;          /* req->tag (NVMe command id) */
};

struct ovf_event {
	__u32 ev_type;      /* EV_OVF */
	__s32 res;
	__u64 ts;
	__u64 user_data;
};

struct inflight_val {
	__u64 ts;
	__u64 user_data;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);           /* io_uring_cmd pointer */
	__type(value, struct inflight_val);
} inflight SEC(".maps");

volatile const __u32 targ_pid = 0;
__u64 dropped;                    /* ringbuf reserve failures (all types) */

static __always_inline int handle(struct io_uring_cmd *ioucmd, __u8 multipath)
{
	if (!ioucmd)
		return 0;
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (targ_pid && tgid != targ_pid)
		return 0;

	const struct io_uring_sqe *sqe = BPF_CORE_READ(ioucmd, sqe);
	if (!sqe)
		return 0;

	struct nvme_uring_cmd_u c = {};
	if (bpf_probe_read_kernel(&c, sizeof(c), (const void *)sqe + SQE_CMD_OFF))
		return 0;

	__u64 now = bpf_ktime_get_ns();
	__u64 user_data = BPF_CORE_READ(sqe, user_data);

	/* Track for completion pairing FIRST so a dropped cmd event still
	 * yields a correct cmp event.  BPF_ANY: an -EAGAIN nonblock attempt
	 * re-issued via io-wq refreshes the entry rather than duplicating. */
	struct inflight_val v = { .ts = now, .user_data = user_data };
	__u64 key = (__u64)(unsigned long)ioucmd;
	bpf_map_update_elem(&inflight, &key, &v, BPF_ANY);

	struct nvme_cmd_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		__sync_fetch_and_add(&dropped, 1);
		return 0;
	}
	__u64 id = bpf_get_current_pid_tgid();
	e->ev_type = EV_CMD;
	e->ts = now;
	e->pid = id >> 32;
	e->tid = (__u32)id;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	/* SQE user_data: the join key tying this NVMe command to a KV object, IF the
	 * application (LMCache) encodes a trace_id there. user_data is at a fixed
	 * offset in the SQE; the kernel carries it through untouched. */
	e->user_data = user_data;
	e->cmd_op = BPF_CORE_READ(ioucmd, cmd_op);
	e->rdev = BPF_CORE_READ(ioucmd, file, f_inode, i_rdev);
	e->nvme_opcode = c.opcode;
	e->multipath = multipath;
	e->nsid = c.nsid;
	e->data_len = c.data_len;
	e->slba = (__u64)c.cdw10 | ((__u64)c.cdw11 << 32);
	e->nlb_zero = c.cdw12 & 0xffff;
	e->cdw12 = c.cdw12;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/nvme_ns_chr_uring_cmd")
int BPF_PROG(ns_chr, struct io_uring_cmd *ioucmd, unsigned int issue_flags)
{ return handle(ioucmd, 0); }

SEC("fentry/nvme_ns_head_chr_uring_cmd")
int BPF_PROG(ns_head_chr, struct io_uring_cmd *ioucmd, unsigned int issue_flags)
{ return handle(ioucmd, 1); }

/* Device completion: req->end_io for every NVMe passthrough command, invoked
 * before any io_uring CQE handling — immune to CQ overflow.  The io_uring_cmd
 * is recoverable as req->end_io_data (set at submission in
 * nvme_uring_cmd_io()), which is exactly our inflight key. */
SEC("fentry/nvme_uring_cmd_end_io")
int BPF_PROG(uring_cmd_end_io, struct request *req, unsigned int err)
{
	struct io_uring_cmd *ioucmd = BPF_CORE_READ(req, end_io_data);
	__u64 key = (__u64)(unsigned long)ioucmd;
	struct inflight_val *v = bpf_map_lookup_elem(&inflight, &key);
	if (!v)
		return 0;   /* not a tracked submission (foreign / pid-filtered) */
	__u64 now = bpf_ktime_get_ns();

	struct nvme_cmp_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		__sync_fetch_and_add(&dropped, 1);
		bpf_map_delete_elem(&inflight, &key);
		return 0;
	}
	e->ev_type = EV_CMP;
	e->err = err;
	e->ts = now;
	e->user_data = v->user_data;
	e->lat_ns = now - v->ts;
	e->hwq = BPF_CORE_READ(req, mq_hctx, queue_num);
	e->cid = BPF_CORE_READ(req, tag);
	bpf_ringbuf_submit(e, 0);
	bpf_map_delete_elem(&inflight, &key);
	return 0;
}

/* CQ-overflow visibility (optional; userspace enables the variant whose
 * symbol exists in this kernel's BTF, or neither).  These fire for any ring
 * on the host — overflow is pathological and rare, so no filtering. */
static __always_inline int emit_ovf(__u64 user_data, __s32 res)
{
	struct ovf_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		__sync_fetch_and_add(&dropped, 1);
		return 0;
	}
	e->ev_type = EV_OVF;
	e->res = res;
	e->ts = bpf_ktime_get_ns();
	e->user_data = user_data;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/io_cqring_event_overflow")   /* 6.8 */
int BPF_PROG(cq_ovf_68, struct io_ring_ctx *ring_ctx, __u64 user_data, __s32 res)
{ return emit_ovf(user_data, res); }

SEC("fentry/io_cqe_overflow")            /* 6.16+ (ctx, struct io_uring_cqe *) */
int BPF_PROG(cq_ovf_616, struct io_ring_ctx *ring_ctx, struct io_uring_cqe *cqe)
{
	__u64 ud = 0;
	__s32 res = 0;
	if (cqe) {
		bpf_probe_read_kernel(&ud, sizeof(ud), &cqe->user_data);
		bpf_probe_read_kernel(&res, sizeof(res), &cqe->res);
	}
	return emit_ovf(ud, res);
}

char _license[] SEC("license") = "GPL";
