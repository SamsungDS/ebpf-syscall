//go:build ignore
//
// iouring_monitor.bpf.c — io_uring application-intent tracer (Phase 2).
//
// Goal: capture *application-requested logical bytes* for I/O submitted through
// io_uring, separately from what completes, with no kernel or application
// change. Mirrors the focused fentry/fexit + ringbuf style of mmap_readamp.bpf.c.
//
// Probe strategy (see docs/io_uring_evaluation.md, grounded in live BTF):
//   * intent: fexit on io_prep_read/write/readv/writev/{read,write}_fixed.
//     The SQE arg carries raw intent (fd, off, len, user_data) and is valid at
//     prep time; we emit one intent event per ACCEPTED prep (ret == 0).
//       - scalar/fixed: requested_bytes = sqe->len  (exact).
//       - vectored:     sqe->len is the iovec COUNT, never bytes. We sum the
//         user iovec array (bounded by MAX_IOV) -> exact when iovcnt<=MAX_IOV,
//         else a lower bound with requested_bytes_valid=0. The user read is
//         only valid in the submitter's address space, so it is skipped under
//         SQPOLL (degraded, honestly flagged) rather than reading the poller's.
//   * completion: tracepoint io_uring/io_uring_complete, correlated by the
//     io_kiocb req pointer (NOT user_data, which apps may reuse).
//
// Requested vs completed bytes are kept in distinct event types and never
// collapsed.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_IOV 32
#define IORING_SETUP_SQPOLL 2u   /* (1U << 1) */

enum iou_etype { IOU_INTENT = 0, IOU_COMPLETION = 1 };

/* local iovec mirror so we don't depend on a vmlinux struct name */
struct iovec_u { unsigned long iov_base; unsigned long iov_len; };

struct iou_event {
	__u64 ts;
	__u32 etype;
	__u32 pid;            /* tgid */
	__u32 tid;
	__u32 opcode;
	__u8  ddir;           /* 0 read, 1 write */
	__u8  sqpoll;
	__u8  req_bytes_valid;
	__u8  _pad;
	__u32 iovcnt;
	__s32 cqe_res;        /* completion only */
	__u64 user_data;
	__u64 req;            /* io_kiocb ptr (correlation/debug) */
	__u64 ctx;            /* ring ptr (SQPOLL owner/debug) */
	__u64 offset;
	__u64 requested_bytes;
	__u64 requested_bytes_lower;
	__u64 latency_ns;     /* completion only */
	__u64 cgroup_id;
	char  comm[16];
};

/* inflight state keyed by io_kiocb req pointer, for completion correlation */
struct iou_inflight {
	__u64 user_data;
	__u64 submit_ns;
	__u64 requested;
	__u64 lower;
	__u64 offset;
	__u32 tgid;
	__u32 iovcnt;
	__u32 opcode;
	__u8  ddir;
	__u8  valid;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 8 * 1024 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);            /* req pointer */
	__type(value, struct iou_inflight);
} inflight SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} dropcnt SEC(".maps");

volatile const __u32 targ_pid = 0;   /* 0 = all pids */

static __always_inline void bump_drop(void)
{
	__u32 k = 0;
	__u64 *v = bpf_map_lookup_elem(&dropcnt, &k);
	if (v)
		__sync_fetch_and_add(v, 1);
}

static __always_inline int handle_intent(struct io_kiocb *req,
					 const struct io_uring_sqe *sqe,
					 long ret, __u8 ddir, bool vectored)
{
	if (ret != 0 || !sqe || !req)
		return 0;

	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;
	if (targ_pid && tgid != targ_pid)
		return 0;

	__u8  opcode = BPF_CORE_READ(sqe, opcode);
	__u64 off    = BPF_CORE_READ(sqe, off);
	__u32 len    = BPF_CORE_READ(sqe, len);
	__u64 udata  = BPF_CORE_READ(sqe, user_data);
	__u64 addr   = BPF_CORE_READ(sqe, addr);

	/* SQPOLL? read ring ctx flags (best-effort) */
	struct io_ring_ctx *rctx = BPF_CORE_READ(req, ctx);
	__u32 rflags = rctx ? BPF_CORE_READ(rctx, flags) : 0;
	__u8  sqpoll = (rflags & IORING_SETUP_SQPOLL) ? 1 : 0;

	__u64 requested = 0, lower = 0;
	__u32 iovcnt = 1;
	__u8  valid = 1;

	if (!vectored) {
		requested = len;          /* scalar/fixed: len is bytes */
	} else {
		iovcnt = len;             /* vectored: len is iovec count */
		if (sqpoll) {
			/* cannot safely read app iovecs from poller ctx */
			valid = 0;
			requested = 0;
		} else {
			__u64 sum = 0;
			__u32 n = iovcnt;
			valid = (n <= MAX_IOV) ? 1 : 0;
#pragma clang loop unroll(full)
			for (int i = 0; i < MAX_IOV; i++) {
				if ((__u32)i >= n)
					break;
				struct iovec_u iov = {};
				if (bpf_probe_read_user(&iov, sizeof(iov),
				    (void *)(addr + (__u64)i * sizeof(iov)))) {
					valid = 0;
					break;
				}
				sum += iov.iov_len;
			}
			requested = sum;
			if (!valid)
				lower = sum;
		}
	}

	__u64 ts = bpf_ktime_get_ns();
	__u64 reqp = (__u64)(unsigned long)req;

	struct iou_inflight fl = {};
	fl.user_data = udata;
	fl.submit_ns = ts;
	fl.requested = requested;
	fl.lower     = lower;
	fl.offset    = off;
	fl.tgid      = tgid;
	fl.iovcnt    = iovcnt;
	fl.opcode    = opcode;
	fl.ddir      = ddir;
	fl.valid     = valid;
	bpf_map_update_elem(&inflight, &reqp, &fl, BPF_ANY);

	struct iou_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		bump_drop();
		return 0;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->ts = ts;
	e->etype = IOU_INTENT;
	e->pid = tgid;
	e->tid = (__u32)id;
	e->opcode = opcode;
	e->ddir = ddir;
	e->sqpoll = sqpoll;
	e->req_bytes_valid = valid;
	e->iovcnt = iovcnt;
	e->user_data = udata;
	e->req = reqp;
	e->ctx = (__u64)(unsigned long)rctx;
	e->offset = off;
	e->requested_bytes = requested;
	e->requested_bytes_lower = lower;
	e->cgroup_id = bpf_get_current_cgroup_id();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ---- intent probes: fexit gives (args..., long ret) ---- */
SEC("fexit/io_prep_read")
int BPF_PROG(prep_read, struct io_kiocb *req, const struct io_uring_sqe *sqe, long ret)
{ return handle_intent(req, sqe, ret, 0, false); }

SEC("fexit/io_prep_write")
int BPF_PROG(prep_write, struct io_kiocb *req, const struct io_uring_sqe *sqe, long ret)
{ return handle_intent(req, sqe, ret, 1, false); }

SEC("fexit/io_prep_readv")
int BPF_PROG(prep_readv, struct io_kiocb *req, const struct io_uring_sqe *sqe, long ret)
{ return handle_intent(req, sqe, ret, 0, true); }

SEC("fexit/io_prep_writev")
int BPF_PROG(prep_writev, struct io_kiocb *req, const struct io_uring_sqe *sqe, long ret)
{ return handle_intent(req, sqe, ret, 1, true); }

SEC("fexit/io_prep_read_fixed")
int BPF_PROG(prep_read_fixed, struct io_kiocb *req, const struct io_uring_sqe *sqe, long ret)
{ return handle_intent(req, sqe, ret, 0, false); }

SEC("fexit/io_prep_write_fixed")
int BPF_PROG(prep_write_fixed, struct io_kiocb *req, const struct io_uring_sqe *sqe, long ret)
{ return handle_intent(req, sqe, ret, 1, false); }

/* ---- completion: correlate by req pointer ---- */
SEC("tp/io_uring/io_uring_complete")
int on_complete(struct trace_event_raw_io_uring_complete *ctx)
{
	__u64 reqp = (__u64)(unsigned long)BPF_CORE_READ(ctx, req);
	struct iou_inflight *fl = bpf_map_lookup_elem(&inflight, &reqp);
	if (!fl)
		return 0;   /* only report completions for intents we tracked */

	int res = BPF_CORE_READ(ctx, res);
	__u64 ts = bpf_ktime_get_ns();

	struct iou_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		bump_drop();
		bpf_map_delete_elem(&inflight, &reqp);
		return 0;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->ts = ts;
	e->etype = IOU_COMPLETION;
	e->pid = fl->tgid;
	e->opcode = fl->opcode;
	e->ddir = fl->ddir;
	e->req_bytes_valid = fl->valid;
	e->iovcnt = fl->iovcnt;
	e->cqe_res = res;
	e->user_data = fl->user_data;
	e->req = reqp;
	e->offset = fl->offset;
	e->requested_bytes = fl->requested;
	e->requested_bytes_lower = fl->lower;
	e->latency_ns = ts - fl->submit_ns;
	bpf_ringbuf_submit(e, 0);

	bpf_map_delete_elem(&inflight, &reqp);
	return 0;
}

char _license[] SEC("license") = "GPL";
