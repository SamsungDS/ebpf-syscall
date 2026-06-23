//go:build ignore
//
// nvme_uring_cmd_monitor.bpf.c — decode NVMe commands issued via io_uring
// IORING_OP_URING_CMD passthrough (Phase 3). Fentry on the NVMe namespace
// char-device uring_cmd handlers; reads the nvme_uring_cmd the application
// embedded in the SQE and exports the raw command fields. SLBA/NLB -> bytes
// decoding is done in userspace with the namespace LBA size (plan: keep the BPF
// small, do geometry in userspace).
//
// Grounded in live BTF (kernel 6.8):
//   struct io_uring_cmd { struct file *file; const struct io_uring_sqe *sqe;
//                         ...; u32 cmd_op; ... }
//   io_uring_sqe.cmd[] is at offset 48 (verified via pahole).
//   struct nvme_uring_cmd is uapi (not in vmlinux BTF) -> defined locally.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define SQE_CMD_OFF 48   /* io_uring_sqe.cmd[] offset */

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
	__u64 ts;
	__u32 pid;
	__u32 tid;
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

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024);
} events SEC(".maps");

volatile const __u32 targ_pid = 0;

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

	struct nvme_cmd_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__u64 id = bpf_get_current_pid_tgid();
	e->ts = bpf_ktime_get_ns();
	e->pid = id >> 32;
	e->tid = (__u32)id;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->cmd_op = BPF_CORE_READ(ioucmd, cmd_op);
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

char _license[] SEC("license") = "GPL";
