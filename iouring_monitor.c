// iouring_monitor.c — userspace loader for the io_uring intent tracer (Phase 2).
// Attaches the fexit io_prep_* programs + the io_uring_complete tracepoint,
// streams ring-buffer events as JSON Lines (so examples/io_uring/verify_iouring.py
// can correlate them against application ground truth), and reports ringbuf
// drops at exit. Mirrors the structure of mmap_readamp.c.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "iouring_monitor.skel.h"

enum iou_etype { IOU_INTENT = 0, IOU_COMPLETION = 1 };

/* must match struct iou_event in iouring_monitor.bpf.c */
struct iou_event {
	unsigned long long ts;
	unsigned int etype;
	unsigned int pid;
	unsigned int tid;
	unsigned int opcode;
	unsigned char ddir;
	unsigned char sqpoll;
	unsigned char req_bytes_valid;
	unsigned char _pad;
	unsigned int iovcnt;
	int cqe_res;
	unsigned long long user_data;
	unsigned long long req;
	unsigned long long ctx;
	unsigned long long offset;
	unsigned long long requested_bytes;
	unsigned long long requested_bytes_lower;
	unsigned long long latency_ns;
	unsigned long long cgroup_id;
	char comm[16];
};

static volatile sig_atomic_t stop;
static void on_sigint(int s) { (void)s; stop = 1; }
static FILE *out;

static const char *opname(unsigned int op)
{
	switch (op) {
	case 1:  return "READV";
	case 2:  return "WRITEV";
	case 4:  return "READ_FIXED";
	case 5:  return "WRITE_FIXED";
	case 22: return "READ";
	case 23: return "WRITE";
	default: return "OTHER";
	}
}

static int handle_event(void *ctx, void *data, size_t sz)
{
	(void)ctx;
	if (sz < sizeof(struct iou_event))
		return 0;
	const struct iou_event *e = data;

	if (e->etype == IOU_INTENT) {
		fprintf(out,
			"{\"event_type\":\"intent\",\"user_data\":%llu,\"pid\":%u,\"tid\":%u,"
			"\"opcode\":%u,\"op_name\":\"%s\",\"ddir\":\"%s\",\"offset\":%llu,"
			"\"requested_bytes\":%llu,\"requested_bytes_valid\":%s,"
			"\"requested_bytes_lower\":%llu,\"iovcnt\":%u,\"sqpoll\":%s,"
			"\"req\":\"0x%llx\",\"ctx\":\"0x%llx\",\"cgroup_id\":%llu,"
			"\"comm\":\"%s\",\"ts\":%llu}\n",
			e->user_data, e->pid, e->tid, e->opcode, opname(e->opcode),
			e->ddir ? "write" : "read", e->offset,
			e->requested_bytes, e->req_bytes_valid ? "true" : "false",
			e->requested_bytes_lower, e->iovcnt, e->sqpoll ? "true" : "false",
			e->req, e->ctx, e->cgroup_id, e->comm, e->ts);
	} else {
		fprintf(out,
			"{\"event_type\":\"completion\",\"user_data\":%llu,\"pid\":%u,"
			"\"opcode\":%u,\"op_name\":\"%s\",\"ddir\":\"%s\",\"offset\":%llu,"
			"\"requested_bytes\":%llu,\"cqe_res\":%d,\"latency_ns\":%llu,"
			"\"req\":\"0x%llx\",\"ts\":%llu}\n",
			e->user_data, e->pid, e->opcode, opname(e->opcode),
			e->ddir ? "write" : "read", e->offset, e->requested_bytes,
			e->cqe_res, e->latency_ns, e->req, e->ts);
	}
	return 0;
}

int main(int argc, char **argv)
{
	unsigned int pid = 0;
	int dur = 0;
	const char *jsonl = NULL;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--pid") && i+1 < argc) pid = (unsigned)atoi(argv[++i]);
		else if (!strcmp(argv[i], "--dur") && i+1 < argc) dur = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--jsonl") && i+1 < argc) jsonl = argv[++i];
		else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
			fprintf(stderr, "usage: %s [--pid PID] [--dur SECONDS] [--jsonl PATH]\n", argv[0]);
			return 0;
		} else { fprintf(stderr, "unknown arg %s\n", argv[i]); return 2; }
	}

	out = stdout;
	if (jsonl) { out = fopen(jsonl, "w"); if (!out) { perror("fopen jsonl"); return 1; } }

	struct iouring_monitor_bpf *skel = iouring_monitor_bpf__open();
	if (!skel) { fprintf(stderr, "open failed\n"); return 1; }
	skel->rodata->targ_pid = pid;

	if (iouring_monitor_bpf__load(skel)) {
		fprintf(stderr, "load failed (io_prep_* fexit / io_uring_complete tp). "
				"Need root + BTF + io_uring kernel.\n");
		iouring_monitor_bpf__destroy(skel);
		return 1;
	}
	if (iouring_monitor_bpf__attach(skel)) {
		fprintf(stderr, "attach failed\n");
		iouring_monitor_bpf__destroy(skel);
		return 1;
	}

	struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) { fprintf(stderr, "ringbuf new failed\n"); iouring_monitor_bpf__destroy(skel); return 1; }

	signal(SIGINT, on_sigint);
	signal(SIGTERM, on_sigint);
	fprintf(stderr, "iouring_monitor: attached (pid filter=%u). %s\n",
		pid, dur ? "" : "Ctrl-C to stop.");

	time_t start = time(NULL);
	while (!stop) {
		int n = ring_buffer__poll(rb, 200 /* ms */);
		if (n < 0 && n != -EINTR) { fprintf(stderr, "poll err %d\n", n); break; }
		if (dur && difftime(time(NULL), start) >= dur) break;
	}

	/* report drops */
	unsigned long long drops = 0, v;
	int ncpu = libbpf_num_possible_cpus();
	unsigned long long *vals = calloc(ncpu, sizeof(*vals));
	unsigned int key = 0;
	if (vals && bpf_map__lookup_elem(skel->maps.dropcnt, &key, sizeof(key), vals,
					 (size_t)ncpu * sizeof(*vals), 0) == 0) {
		for (int c = 0; c < ncpu; c++) drops += vals[c];
	}
	(void)v;
	fprintf(out, "{\"dropped\":%llu}\n", drops);
	free(vals);

	ring_buffer__free(rb);
	iouring_monitor_bpf__destroy(skel);
	if (jsonl) fclose(out);
	fprintf(stderr, "iouring_monitor: done, ringbuf drops=%llu\n", drops);
	return 0;
}
