// nvme_uring_cmd_monitor.c — userspace loader for the NVMe uring_cmd decoder
// (Phase 3). Streams decoded NVMe passthrough commands as JSON Lines. SLBA/NLB
// -> bytes is computed here with the namespace LBA size (--lba-size).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "nvme_uring_cmd_monitor.skel.h"

/* must match struct nvme_cmd_event in the BPF object */
struct nvme_cmd_event {
	unsigned long long ts;
	unsigned int pid;
	unsigned int tid;
	unsigned long long cmd_op;
	unsigned char nvme_opcode;
	unsigned char multipath;
	unsigned char _pad[2];
	unsigned int nsid;
	unsigned int data_len;
	unsigned long long slba;
	unsigned int nlb_zero;
	unsigned int cdw12;
	char comm[16];
};

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }
static FILE *out;
static unsigned lba_size = 512;

static const char *nvme_op(unsigned char op)
{
	switch (op) {
	case 0x01: return "write";
	case 0x02: return "read";
	case 0x00: return "flush";
	default:   return "other";
	}
}

static int handle_event(void *ctx, void *data, size_t sz)
{
	(void)ctx;
	if (sz < sizeof(struct nvme_cmd_event))
		return 0;
	const struct nvme_cmd_event *e = data;
	unsigned long long nlb = (unsigned long long)e->nlb_zero + 1;
	unsigned long long bytes = nlb * lba_size;
	fprintf(out,
		"{\"event_type\":\"nvme_cmd\",\"pid\":%u,\"tid\":%u,\"nvme_opcode\":%u,"
		"\"op_name\":\"%s\",\"nsid\":%u,\"slba\":%llu,\"nlb\":%llu,"
		"\"bytes\":%llu,\"data_len\":%u,\"multipath\":%u,\"cmd_op\":\"0x%llx\","
		"\"comm\":\"%s\",\"ts\":%llu}\n",
		e->pid, e->tid, e->nvme_opcode, nvme_op(e->nvme_opcode), e->nsid,
		e->slba, nlb, bytes, e->data_len, e->multipath, e->cmd_op, e->comm, e->ts);
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
		else if (!strcmp(argv[i], "--lba-size") && i+1 < argc) lba_size = (unsigned)atoi(argv[++i]);
		else if (!strcmp(argv[i], "--help")) {
			fprintf(stderr, "usage: %s [--pid P] [--dur S] [--jsonl PATH] [--lba-size N]\n", argv[0]);
			return 0;
		} else { fprintf(stderr, "unknown arg %s\n", argv[i]); return 2; }
	}

	out = stdout;
	if (jsonl) { out = fopen(jsonl, "w"); if (!out) { perror("fopen"); return 1; } }

	struct nvme_uring_cmd_monitor_bpf *skel = nvme_uring_cmd_monitor_bpf__open();
	if (!skel) { fprintf(stderr, "open failed\n"); return 1; }
	skel->rodata->targ_pid = pid;

	if (nvme_uring_cmd_monitor_bpf__load(skel)) {
		fprintf(stderr, "load failed (need root + nvme_core BTF)\n");
		nvme_uring_cmd_monitor_bpf__destroy(skel);
		return 1;
	}
	/* attach; tolerate the multipath-head probe being absent on some configs */
	if (nvme_uring_cmd_monitor_bpf__attach(skel)) {
		fprintf(stderr, "full attach failed; retrying without ns_head_chr\n");
		bpf_program__set_autoload(skel->progs.ns_head_chr, false);
		nvme_uring_cmd_monitor_bpf__destroy(skel);
		skel = nvme_uring_cmd_monitor_bpf__open();
		skel->rodata->targ_pid = pid;
		bpf_program__set_autoload(skel->progs.ns_head_chr, false);
		if (nvme_uring_cmd_monitor_bpf__load(skel) || nvme_uring_cmd_monitor_bpf__attach(skel)) {
			fprintf(stderr, "attach failed\n");
			nvme_uring_cmd_monitor_bpf__destroy(skel);
			return 1;
		}
	}

	struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) { fprintf(stderr, "ringbuf failed\n"); nvme_uring_cmd_monitor_bpf__destroy(skel); return 1; }

	signal(SIGINT, on_sig); signal(SIGTERM, on_sig);
	fprintf(stderr, "nvme_uring_cmd_monitor: attached (pid=%u, lba=%u)\n", pid, lba_size);

	time_t t0 = time(NULL);
	while (!stop) {
		int n = ring_buffer__poll(rb, 200);
		if (n < 0 && n != -EINTR) break;
		if (dur && difftime(time(NULL), t0) >= dur) break;
	}
	ring_buffer__free(rb);
	nvme_uring_cmd_monitor_bpf__destroy(skel);
	if (jsonl) fclose(out);
	fprintf(stderr, "nvme_uring_cmd_monitor: done\n");
	return 0;
}
