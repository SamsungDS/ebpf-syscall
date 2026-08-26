//go:build ignore
//
// nvme_tp_monitor.bpf.c — driver-level NVMe command capture via the nvme
// tracepoints (tp_btf/nvme_setup_cmd + tp_btf/nvme_complete_rq).
//
// Why this exists alongside nvme_uring_cmd_monitor: the tracepoints fire for
// EVERY nvme request regardless of submission path — io_uring_cmd
// passthrough, GDS/nvidia-fs, POSIX file IO, block IO — so transports with no
// io_uring user_data channel (NIXL/GDS, POSIX backends) become traceable with
// the same JSONL dialect. The cost: no user_data, so no in-band trace_id —
// object attribution happens offline by LBA-range join against the semantic
// trace (kvio2perfetto --join-by-offset). It also double-covers the
// passthrough path, cross-validating the uring monitor's completion latencies
// from an independent hook.
//
// Pairing: hash map keyed on the struct request pointer — inserted at setup,
// lookup+delete at complete, latency computed in kernel (same pattern as the
// uring monitor's ioucmd map).
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EV_CMD 0
#define EV_CMP 1

/* nvme driver types live in the nvme_core MODULE BTF, not vmlinux.h — declare
 * minimal local mirrors with preserve_access_index: CO-RE relocates every
 * field access by NAME against the module BTF at load time, so the local
 * layout (and any omitted members) is irrelevant. */
struct nvme_common_command {
	__u8  opcode;
	__u8  flags;
	__u16 command_id;
	__u32 nsid;
} __attribute__((preserve_access_index));

struct nvme_rw_command {
	__u8  opcode;
	__u64 slba;
	__u16 length;
} __attribute__((preserve_access_index));

struct nvme_command {
	union {
		struct nvme_common_command common;
		struct nvme_rw_command rw;
	};
} __attribute__((preserve_access_index));

struct nvme_request {
	struct nvme_command *cmd;
	__u16 status;
} __attribute__((preserve_access_index));

struct tp_cmd_event {
	__u32 ev_type;      /* EV_CMD */
	__u32 nsid;
	__u64 ts;
	__u64 slba;         /* rw.slba (0 for non-rw commands) */
	__u32 nlb_zero;     /* rw.length (zero-based) */
	__u32 hwq;          /* req->mq_hctx->queue_num */
	__s32 cid;          /* req->tag */
	__u8  nvme_opcode;
	__u8  _pad[3];
	char  disk[16];     /* req->q->disk->disk_name, e.g. nvme1n1 */
};

struct tp_cmp_event {
	__u32 ev_type;      /* EV_CMP */
	__u32 status;       /* nvme_request status (0 = success) */
	__u64 ts;
	__u64 lat_ns;
	__u32 hwq;
	__s32 cid;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 8 * 1024 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);           /* struct request pointer */
	__type(value, __u64);         /* setup timestamp */
} inflight SEC(".maps");

__u64 dropped;
volatile const char targ_disk[16];   /* empty = capture all disks */

SEC("tp_btf/nvme_setup_cmd")
int BPF_PROG(nvme_setup, struct request *req, struct nvme_command *cmd)
{
	if (!req || !cmd)
		return 0;   /* tp_btf args are _or_null — verifier requires the check */

	char disk[16] = {};
	struct gendisk *d = BPF_CORE_READ(req, q, disk);
	if (d)
		bpf_probe_read_kernel_str(disk, sizeof(disk), d->disk_name);
	/* in-kernel disk filter: a request that never enters the inflight map
	 * emits neither cmd nor cmp — foreign disks (the OS drive) cannot leak
	 * into either stream or pollute latency distributions. */
	if (targ_disk[0]) {
		for (int i = 0; i < 16; i++) {
			if (targ_disk[i] != disk[i])
				return 0;
			if (!targ_disk[i])
				break;
		}
	}

	__u64 now = bpf_ktime_get_ns();
	__u64 key = (__u64)(unsigned long)req;
	bpf_map_update_elem(&inflight, &key, &now, BPF_ANY);

	struct tp_cmd_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		__sync_fetch_and_add(&dropped, 1);
		return 0;
	}
	e->ev_type = EV_CMD;
	e->ts = now;
	e->nvme_opcode = BPF_CORE_READ(cmd, common.opcode);
	e->nsid = BPF_CORE_READ(cmd, common.nsid);
	e->slba = BPF_CORE_READ(cmd, rw.slba);
	e->nlb_zero = BPF_CORE_READ(cmd, rw.length);
	e->hwq = BPF_CORE_READ(req, mq_hctx, queue_num);
	e->cid = BPF_CORE_READ(req, tag);
	__builtin_memcpy(e->disk, disk, sizeof(e->disk));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp_btf/nvme_complete_rq")
int BPF_PROG(nvme_complete, struct request *req)
{
	if (!req)
		return 0;
	__u64 key = (__u64)(unsigned long)req;
	__u64 *ts0 = bpf_map_lookup_elem(&inflight, &key);
	if (!ts0)
		return 0;
	__u64 now = bpf_ktime_get_ns();

	struct tp_cmp_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		__sync_fetch_and_add(&dropped, 1);
		bpf_map_delete_elem(&inflight, &key);
		return 0;
	}
	e->ev_type = EV_CMP;
	e->ts = now;
	e->lat_ns = now - *ts0;
	e->hwq = BPF_CORE_READ(req, mq_hctx, queue_num);
	e->cid = BPF_CORE_READ(req, tag);
	/* struct nvme_request is the driver pdu directly after the request;
	 * go via a scalar address (trusted-ptr arithmetic is prohibited) with a
	 * CO-RE-relocated struct size. */
	__u64 pdu = (__u64)(unsigned long)req + bpf_core_type_size(struct request);
	e->status = BPF_CORE_READ((struct nvme_request *)pdu, status);
	bpf_ringbuf_submit(e, 0);
	bpf_map_delete_elem(&inflight, &key);
	return 0;
}

char _license[] SEC("license") = "GPL";
