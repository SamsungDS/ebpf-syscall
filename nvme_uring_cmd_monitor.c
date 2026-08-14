// nvme_uring_cmd_monitor.c — userspace loader for the NVMe uring_cmd decoder
// (Phase 3 + P2 completions). Streams decoded NVMe passthrough commands as
// JSON Lines. SLBA/NLB -> bytes is computed here with the namespace LBA size
// (--lba-size).
//
// P2 event stream additions (all JSONL, one object per line):
//   {"event_type":"nvme_cmd",...}    submission (now also carries "rdev")
//   {"event_type":"nvme_cmp",...}    device completion (nvme_uring_cmd_end_io):
//                                    user_data, lat_ns (kernel-computed),
//                                    err (blk_status_t), hwq, cid, ts
//   {"event_type":"cq_overflow",...} a CQE hit a full CQ (optional probe)
//   {"event_type":"clock_anchor",...} monotonic_ns + realtime_ns, at start and
//                                    every 10s — lets consumers align this
//                                    trace with wall-clock logs
//   {"event_type":"drops","dropped":N,...} final line: producer drops,
//                                    consumer drain, and optional quiescence
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include "nvme_uring_cmd_monitor.skel.h"

#define EV_CMD 0
#define EV_CMP 1
#define EV_OVF 2

/* must match the structs in the BPF object */
struct nvme_cmd_event {
	unsigned int ev_type;
	unsigned int pid;
	unsigned long long ts;
	unsigned int tid;
	unsigned int rdev;
	unsigned long long user_data;
	unsigned long long cmd_op;
	unsigned char nvme_opcode;
	unsigned char multipath;
	unsigned char _pad[2];
	unsigned int nsid;
	unsigned int data_len;
	unsigned long long slba;
	unsigned int nlb_zero;
	unsigned int cdw12;
	unsigned int cdw2;      /* KV key bytes 0-3 */
	unsigned int cdw3;      /* KV key bytes 4-7 */
	unsigned int cdw14;     /* KV key bytes 8-11 */
	unsigned int cdw15;     /* KV key bytes 12-15 */
	char comm[16];
};

struct nvme_cmp_event {
	unsigned int ev_type;
	unsigned int err;
	unsigned long long ts;
	unsigned long long user_data;
	unsigned long long lat_ns;
	unsigned int hwq;
	int cid;
};

struct ovf_event {
	unsigned int ev_type;
	int res;
	unsigned long long ts;
	unsigned long long user_data;
};

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }
static FILE *out;
static unsigned lba_size = 512;
static int kv_mode;             /* --kv: decode the KV command set instead */

static const char *nvme_op(unsigned char op)
{
	switch (op) {
	case 0x01: return "write";
	case 0x02: return "read";
	case 0x00: return "flush";
	default:   return "other";
	}
}

/* KV command set (Key Value Command Set Spec 1.0c).  Opcodes COLLIDE with
 * the NVM set (Store 0x01 = Write, Retrieve 0x02 = Read), which is why KV
 * decode is an explicit mode: the namespace's command set is a property of
 * the device, not the command. */
static const char *kv_op(unsigned char op)
{
	switch (op) {
	case 0x01: return "store";
	case 0x02: return "retrieve";
	case 0x06: return "list";
	case 0x10: return "delete";
	case 0x14: return "exist";
	default:   return "other";
	}
}

/* The key travels in the SQE itself: bytes 0-7 memcpy'd into cdw2-3,
 * bytes 8-15 into cdw14-15 (little-endian dwords in memory order), key
 * length in cdw11 bits 0-7.  Reassemble the original bytes and hex them —
 * this is the canonical join form the semantic side must match. */
static void kv_key_hex(const struct nvme_cmd_event *e, char *hex, size_t cap)
{
	unsigned char kb[16];
	unsigned kl = e->slba >> 32 & 0xff;      /* cdw11 low byte */
	memcpy(kb + 0,  &e->cdw2,  4);
	memcpy(kb + 4,  &e->cdw3,  4);
	memcpy(kb + 8,  &e->cdw14, 4);
	memcpy(kb + 12, &e->cdw15, 4);
	if (kl > 16) kl = 16;
	size_t n = 0;
	for (unsigned i = 0; i < kl && n + 3 <= cap; i++)
		n += snprintf(hex + n, cap - n, "%02x", kb[i]);
	hex[n] = '\0';
}

static int handle_event(void *ctx, void *data, size_t sz)
{
	(void)ctx;
	if (sz < sizeof(unsigned int))
		return 0;
	unsigned int ev_type = *(const unsigned int *)data;

	if (ev_type == EV_CMD && sz >= sizeof(struct nvme_cmd_event)) {
		const struct nvme_cmd_event *e = data;
		if (kv_mode) {
			char hex[36];
			kv_key_hex(e, hex, sizeof(hex));
			fprintf(out,
				"{\"event_type\":\"nvme_cmd\",\"pid\":%u,\"tid\":%u,\"user_data\":%llu,"
				"\"nvme_opcode\":%u,\"op_name\":\"%s\",\"nsid\":%u,"
				"\"key_hex\":\"%s\",\"key_len\":%u,\"value_len\":%llu,"
				"\"data_len\":%u,\"multipath\":%u,\"cmd_op\":\"0x%llx\","
				"\"rdev\":%u,\"comm\":\"%s\",\"ts\":%llu}\n",
				e->pid, e->tid, e->user_data, e->nvme_opcode,
				kv_op(e->nvme_opcode), e->nsid, hex,
				(unsigned)(e->slba >> 32 & 0xff),
				e->slba & 0xffffffffULL,
				e->data_len, e->multipath, e->cmd_op,
				e->rdev, e->comm, e->ts);
			return 0;
		}
		unsigned long long nlb = (unsigned long long)e->nlb_zero + 1;
		unsigned long long bytes = nlb * lba_size;
		fprintf(out,
			"{\"event_type\":\"nvme_cmd\",\"pid\":%u,\"tid\":%u,\"user_data\":%llu,"
			"\"nvme_opcode\":%u,\"op_name\":\"%s\",\"nsid\":%u,\"slba\":%llu,\"nlb\":%llu,"
			"\"bytes\":%llu,\"data_len\":%u,\"multipath\":%u,\"cmd_op\":\"0x%llx\","
			"\"rdev\":%u,\"comm\":\"%s\",\"ts\":%llu}\n",
			e->pid, e->tid, e->user_data, e->nvme_opcode, nvme_op(e->nvme_opcode),
			e->nsid, e->slba, nlb, bytes, e->data_len, e->multipath, e->cmd_op,
			e->rdev, e->comm, e->ts);
	} else if (ev_type == EV_CMP && sz >= sizeof(struct nvme_cmp_event)) {
		const struct nvme_cmp_event *e = data;
		fprintf(out,
			"{\"event_type\":\"nvme_cmp\",\"user_data\":%llu,\"err\":%u,"
			"\"lat_ns\":%llu,\"hwq\":%u,\"cid\":%d,\"ts\":%llu}\n",
			e->user_data, e->err, e->lat_ns, e->hwq, e->cid, e->ts);
	} else if (ev_type == EV_OVF && sz >= sizeof(struct ovf_event)) {
		const struct ovf_event *e = data;
		fprintf(out,
			"{\"event_type\":\"cq_overflow\",\"user_data\":%llu,\"res\":%d,"
			"\"ts\":%llu}\n",
			e->user_data, e->res, e->ts);
	}
	return 0;
}

static int emit_anchor(void)
{
	struct timespec mono, real;
	int ret;

	if (clock_gettime(CLOCK_MONOTONIC, &mono) ||
	    clock_gettime(CLOCK_REALTIME, &real))
		return -errno;
	ret = fprintf(out,
		"{\"event_type\":\"clock_anchor\",\"monotonic_ns\":%llu,"
		"\"realtime_ns\":%llu}\n",
		(unsigned long long)mono.tv_sec * 1000000000ULL + mono.tv_nsec,
		(unsigned long long)real.tv_sec * 1000000000ULL + real.tv_nsec);
	if (ret < 0 || fflush(out))
		return errno ? -errno : -EIO;
	return 0;
}

static int vmlinux_has_func(const char *name)
{
	struct btf *vb = btf__load_vmlinux_btf();
	int found = 0;
	if (vb) {
		found = btf__find_by_name_kind(vb, name, BTF_KIND_FUNC) > 0;
		btf__free(vb);
	}
	return found;
}

/* graceful-degradation ladder: each step disables one more optional probe.
 * step 0: everything (minus overflow variants the BTF pre-probe ruled out)
 * step 1: - multipath head handler (absent on some configs)
 * step 2: - CQ-overflow probes (signature drift safety net)
 * step 3: - device completion probe (legacy submission-only behavior) */
static struct nvme_uring_cmd_monitor_bpf *
open_load_attach(unsigned int pid, int step, int have68, int have616,
		 int have_locked, int have_alloc, int trace_overflow)
{
	struct nvme_uring_cmd_monitor_bpf *skel = nvme_uring_cmd_monitor_bpf__open();
	int use_legacy = trace_overflow && have68;
	int use_alloc = trace_overflow && !have68 && have_alloc;
	int use_modern = trace_overflow && !have68 && !have_alloc &&
			 have616 && have_locked;

	if (!skel)
		return NULL;
	skel->rodata->targ_pid = pid;
	bpf_program__set_autoload(skel->progs.cq_ovf_68,
				  step < 2 && use_legacy);
	bpf_program__set_autoload(skel->progs.cq_ovf_616,
				  step < 2 && use_modern);
	bpf_program__set_autoload(skel->progs.cq_ovf_locked,
				  step < 2 && use_modern);
	bpf_program__set_autoload(skel->progs.cq_ovf_alloc,
				  step < 2 && use_alloc);
	if (step >= 1)
		bpf_program__set_autoload(skel->progs.ns_head_chr, false);
	if (step >= 3)
		bpf_program__set_autoload(skel->progs.uring_cmd_end_io, false);
	if (nvme_uring_cmd_monitor_bpf__load(skel) ||
	    nvme_uring_cmd_monitor_bpf__attach(skel)) {
		nvme_uring_cmd_monitor_bpf__destroy(skel);
		return NULL;
	}
	return skel;
}

int main(int argc, char **argv)
{
	unsigned int pid = 0;
	int dur = 0;
	const char *jsonl = NULL;
	unsigned long long drained = 0;
	int poll_error = 0;
	int drain_error = 0;
	int exit_code = 0;
	int quiesced = 0;
	int trace_overflow = 1;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--pid") && i+1 < argc) pid = (unsigned)atoi(argv[++i]);
		else if (!strcmp(argv[i], "--dur") && i+1 < argc) dur = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--jsonl") && i+1 < argc) jsonl = argv[++i];
		else if (!strcmp(argv[i], "--lba-size") && i+1 < argc) lba_size = (unsigned)atoi(argv[++i]);
		else if (!strcmp(argv[i], "--kv")) kv_mode = 1;
		else if (!strcmp(argv[i], "--quiesced")) quiesced = 1;
		else if (!strcmp(argv[i], "--no-cq-overflow")) trace_overflow = 0;
		else if (!strcmp(argv[i], "--help")) {
			fprintf(stderr, "usage: %s [--pid P] [--dur S] [--jsonl PATH] "
				"[--lba-size N] [--kv] [--quiesced --no-cq-overflow]\n"
				"  --kv  target is an NVMe Key-Value namespace: decode "
				"store/retrieve/delete/exist\n"
				"        + the 16-byte object key from the SQE "
				"(key_hex) instead of slba/nlb\n"
				"  --quiesced  assert PID-scoped producers are stopped "
				"before signaling the monitor\n"
				"  --no-cq-overflow  disable system-wide overflow probes\n",
				argv[0]);
			return 0;
		} else { fprintf(stderr, "unknown arg %s\n", argv[i]); return 2; }
	}
	if (quiesced && (!pid || dur || trace_overflow)) {
		fprintf(stderr,
			"--quiesced requires --pid, no --dur, and "
			"--no-cq-overflow\n");
		return 2;
	}

	out = stdout;
	if (jsonl) { out = fopen(jsonl, "w"); if (!out) { perror("fopen"); return 1; } }

	int have68 = vmlinux_has_func("io_cqring_event_overflow");
	int have616 = vmlinux_has_func("io_cqe_overflow");
	int have_locked = vmlinux_has_func("io_cqe_overflow_locked");
	int have_alloc = vmlinux_has_func("io_alloc_ocqe");
	int use_legacy = trace_overflow && have68;
	int use_alloc = trace_overflow && !have68 && have_alloc;
	int use_modern = trace_overflow && !have68 && !have_alloc &&
			 have616 && have_locked;

	if (trace_overflow && !use_legacy && !use_alloc && !use_modern)
		fprintf(stderr,
			"note: no complete CQ-overflow probe set in vmlinux "
			"BTF; overflow probes off\n");

	struct nvme_uring_cmd_monitor_bpf *skel = NULL;
	int step;
	for (step = 0; step <= 3 && !skel; step++) {
		skel = open_load_attach(pid, step, have68, have616,
					have_locked, have_alloc, trace_overflow);
		if (!skel && step < 3)
			fprintf(stderr, "attach step %d failed; degrading (%s)\n", step,
				step == 0 ? "dropping multipath head probe" :
				step == 1 ? "dropping CQ-overflow probe" :
					    "dropping completion probe");
	}
	if (!skel) { fprintf(stderr, "attach failed (need root + nvme_core BTF)\n"); return 1; }
	step--;

	struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) { fprintf(stderr, "ringbuf failed\n"); nvme_uring_cmd_monitor_bpf__destroy(skel); return 1; }

	signal(SIGINT, on_sig); signal(SIGTERM, on_sig);
	fprintf(stderr, "nvme_uring_cmd_monitor: attached (pid=%u, lba=%u, "
		"completions=%s, cq_overflow=%s, cq_overflow_locked=%s, "
		"cq_overflow_alloc=%s, "
		"cq_overflow_complete=%s, quiesced=%s)\n", pid, lba_size,
		step < 3 ? "on" : "OFF",
		(step < 2 && (use_legacy || use_modern || use_alloc)) ? "on" : "off",
		(step < 2 && use_modern) ? "on" : "off",
		(step < 2 && use_alloc) ? "on" : "off",
		(step < 2 && (use_modern || use_alloc)) ? "yes" : "no",
		quiesced ? "yes" : "no");
	fprintf(out,
		"{\"event_type\":\"capabilities\",\"completions\":%s,"
		"\"cq_overflow_legacy\":%s,\"cq_overflow_unlocked\":%s,"
		"\"cq_overflow_locked\":%s,"
		"\"cq_overflow_alloc\":%s,\"cq_overflow_complete\":%s,"
		"\"quiesced_contract\":%s}\n",
		step < 3 ? "true" : "false",
		(step < 2 && use_legacy) ? "true" : "false",
		(step < 2 && use_modern) ? "true" : "false",
		(step < 2 && use_modern) ? "true" : "false",
		(step < 2 && use_alloc) ? "true" : "false",
		(step < 2 && (use_modern || use_alloc)) ? "true" : "false",
		quiesced ? "true" : "false");

	poll_error = emit_anchor();
	if (poll_error)
		fprintf(stderr, "initial clock anchor failed: %s\n",
			strerror(-poll_error));
	time_t t0 = time(NULL), last_anchor = t0;
	while (!stop && !poll_error) {
		int n = ring_buffer__poll(rb, 200);
		if (n < 0 && n != -EINTR) {
			poll_error = n;
			fprintf(stderr, "ring buffer poll failed: %s\n",
				strerror(-n));
			break;
		}
		time_t now = time(NULL);
		if (difftime(now, last_anchor) >= 10) {
			poll_error = emit_anchor();
			if (poll_error) {
				fprintf(stderr, "clock anchor failed: %s\n",
					strerror(-poll_error));
				break;
			}
			last_anchor = now;
		}
		if (dur && difftime(now, t0) >= dur) break;
	}

	/* Detach the producers before draining the userspace consumer.  In the
	 * quiesced mode the controller also holds the target at its done/F
	 * barrier, so its PID-scoped command stream has already stopped. */
	nvme_uring_cmd_monitor_bpf__detach(skel);
	for (;;) {
		int n = ring_buffer__consume(rb);

		if (n > 0) {
			drained += (unsigned int)n;
			continue;
		}
		if (n < 0) {
			drain_error = n;
			fprintf(stderr, "ring buffer drain failed: %s\n",
				strerror(-n));
		}
		break;
	}
	if (poll_error || drain_error)
		exit_code = 1;
	{
		int anchor_error = emit_anchor();

		if (anchor_error) {
			fprintf(stderr, "final clock anchor failed: %s\n",
				strerror(-anchor_error));
			exit_code = 1;
		}
	}
	if (fprintf(out,
		"{\"event_type\":\"drops\",\"dropped\":%llu,"
		"\"drained_after_detach\":%llu,\"consumer_drained\":%s,"
		"\"quiesced_contract\":%s,\"consumer_complete\":%s}\n",
		(unsigned long long)skel->bss->dropped, drained,
		exit_code ? "false" : "true",
		quiesced ? "true" : "false",
		(quiesced && !exit_code) ? "true" : "false") < 0 ||
	    fflush(out)) {
		perror("flush trace output");
		exit_code = 1;
	}
	ring_buffer__free(rb);
	nvme_uring_cmd_monitor_bpf__destroy(skel);
	if (jsonl && fclose(out)) {
		perror("close trace output");
		exit_code = 1;
	}
	fprintf(stderr,
		"nvme_uring_cmd_monitor: done (drained_after_detach=%llu, "
		"consumer_drained=%s, consumer_complete=%s)\n",
		drained, exit_code ? "no" : "yes",
		(quiesced && !exit_code) ? "yes" : "no");
	return exit_code;
}
