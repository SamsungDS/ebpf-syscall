// nvme_tp_monitor.c — userspace loader for the nvme-tracepoint capture.
// Streams driver-level NVMe commands as JSON Lines in the same dialect as
// nvme_uring_cmd_monitor (nvme_cmd / nvme_cmp / clock_anchor / drops), for
// transports that never touch io_uring_cmd (NIXL/GDS, POSIX file IO) and as
// an independent cross-check of the uring monitor's latencies.
//
// Differences from the uring monitor's output: no user_data (attribute
// offline by LBA-range join), a "disk" field (e.g. nvme1n1) for device
// identity, and pairing metadata cid/hwq on both records. --disk NAME drops
// everything not on that disk (OS-disk noise).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "nvme_tp_monitor.skel.h"

#define EV_CMD 0
#define EV_CMP 1

struct tp_cmd_event {
	unsigned int ev_type;
	unsigned int nsid;
	unsigned long long ts;
	unsigned long long slba;
	unsigned int nlb_zero;
	unsigned int hwq;
	int cid;
	unsigned char nvme_opcode;
	unsigned char _pad[3];
	char disk[16];
};

struct tp_cmp_event {
	unsigned int ev_type;
	unsigned int status;
	unsigned long long ts;
	unsigned long long lat_ns;
	unsigned int hwq;
	int cid;
};

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }
static FILE *out;
static unsigned lba_size = 512;
static const char *disk_filter;

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
	if (sz < sizeof(unsigned int))
		return 0;
	unsigned int ev_type = *(const unsigned int *)data;

	if (ev_type == EV_CMD && sz >= sizeof(struct tp_cmd_event)) {
		const struct tp_cmd_event *e = data;
		if (disk_filter && strncmp(e->disk, disk_filter, sizeof(e->disk)))
			return 0;
		unsigned long long nlb = (unsigned long long)e->nlb_zero + 1;
		fprintf(out,
			"{\"event_type\":\"nvme_cmd\",\"disk\":\"%s\",\"nsid\":%u,"
			"\"nvme_opcode\":%u,\"op_name\":\"%s\",\"slba\":%llu,\"nlb\":%llu,"
			"\"bytes\":%llu,\"data_len\":%llu,\"hwq\":%u,\"cid\":%d,\"ts\":%llu}\n",
			e->disk, e->nsid, e->nvme_opcode, nvme_op(e->nvme_opcode),
			e->slba, nlb, nlb * lba_size, nlb * lba_size, e->hwq, e->cid,
			e->ts);
	} else if (ev_type == EV_CMP && sz >= sizeof(struct tp_cmp_event)) {
		const struct tp_cmp_event *e = data;
		/* cmp events carry no disk; consumers pair by (hwq, cid, ts order)
		 * or simply use lat_ns distributions. */
		fprintf(out,
			"{\"event_type\":\"nvme_cmp\",\"status\":%u,\"lat_ns\":%llu,"
			"\"hwq\":%u,\"cid\":%d,\"ts\":%llu}\n",
			e->status, e->lat_ns, e->hwq, e->cid, e->ts);
	}
	return 0;
}

static void emit_anchor(void)
{
	struct timespec mono, real;
	clock_gettime(CLOCK_MONOTONIC, &mono);
	clock_gettime(CLOCK_REALTIME, &real);
	fprintf(out,
		"{\"event_type\":\"clock_anchor\",\"monotonic_ns\":%llu,"
		"\"realtime_ns\":%llu}\n",
		(unsigned long long)mono.tv_sec * 1000000000ULL + mono.tv_nsec,
		(unsigned long long)real.tv_sec * 1000000000ULL + real.tv_nsec);
	fflush(out);
}

int main(int argc, char **argv)
{
	int dur = 0;
	const char *jsonl = NULL;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--dur") && i+1 < argc) dur = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--jsonl") && i+1 < argc) jsonl = argv[++i];
		else if (!strcmp(argv[i], "--lba-size") && i+1 < argc) lba_size = (unsigned)atoi(argv[++i]);
		else if (!strcmp(argv[i], "--disk") && i+1 < argc) disk_filter = argv[++i];
		else if (!strcmp(argv[i], "--help")) {
			fprintf(stderr, "usage: %s [--dur S] [--jsonl PATH] [--lba-size N] [--disk nvme1n1]\n", argv[0]);
			return 0;
		} else { fprintf(stderr, "unknown arg %s\n", argv[i]); return 2; }
	}

	out = stdout;
	if (jsonl) { out = fopen(jsonl, "w"); if (!out) { perror("fopen"); return 1; } }

	struct nvme_tp_monitor_bpf *skel = nvme_tp_monitor_bpf__open();
	if (!skel) { fprintf(stderr, "open failed\n"); return 1; }
	if (disk_filter) {
		strncpy((char *)skel->rodata->targ_disk, disk_filter,
			sizeof(skel->rodata->targ_disk) - 1);
	}
	if (nvme_tp_monitor_bpf__load(skel) || nvme_tp_monitor_bpf__attach(skel)) {
		fprintf(stderr, "load/attach failed (need root + nvme tracepoints in BTF)\n");
		nvme_tp_monitor_bpf__destroy(skel);
		return 1;
	}

	struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) { fprintf(stderr, "ringbuf failed\n"); nvme_tp_monitor_bpf__destroy(skel); return 1; }

	signal(SIGINT, on_sig); signal(SIGTERM, on_sig);
	fprintf(stderr, "nvme_tp_monitor: attached (lba=%u, disk=%s)\n",
		lba_size, disk_filter ? disk_filter : "all");

	emit_anchor();
	time_t t0 = time(NULL), last_anchor = t0;
	while (!stop) {
		int n = ring_buffer__poll(rb, 200);
		if (n < 0 && n != -EINTR) break;
		time_t now = time(NULL);
		if (difftime(now, last_anchor) >= 10) { emit_anchor(); last_anchor = now; }
		if (dur && difftime(now, t0) >= dur) break;
	}
	ring_buffer__free(rb);
	fprintf(out, "{\"event_type\":\"drops\",\"dropped\":%llu}\n",
		(unsigned long long)skel->bss->dropped);
	nvme_tp_monitor_bpf__destroy(skel);
	if (jsonl) fclose(out);
	fprintf(stderr, "nvme_tp_monitor: done\n");
	return 0;
}
