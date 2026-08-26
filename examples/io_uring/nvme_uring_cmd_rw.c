// nvme_uring_cmd_rw — issue NVMe read/write commands via io_uring
// IORING_OP_URING_CMD passthrough against an NVMe namespace char device
// (/dev/ngXnY), emitting JSON-Lines ground truth so the eBPF decoder
// (nvme_uring_cmd_monitor) can be verified against application intent (Phase 3).
//
// Safety: reads are always allowed. WRITES modify the device and are refused
// unless --i-know-disposable is passed AND the device path matches /dev/ng*.
// Only ever point --write at a throwaway namespace (e.g. a QEMU file-backed
// NVMe), never a device backing a real filesystem.
//
// A single NVMe command cannot exceed the controller MDTS; this tool issues
// per-command transfers and reports each, so a large logical transfer is
// visibly the sum of several <=MDTS commands.
#define _GNU_SOURCE
#include <liburing.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#ifndef IORING_OP_URING_CMD
#define IORING_OP_URING_CMD 46
#endif

/* uapi struct nvme_uring_cmd + ioctl op, defined locally to avoid header deps */
struct nvme_uring_cmd {
	uint8_t  opcode; uint8_t flags; uint16_t rsvd1; uint32_t nsid;
	uint32_t cdw2; uint32_t cdw3; uint64_t metadata; uint64_t addr;
	uint32_t metadata_len; uint32_t data_len;
	uint32_t cdw10, cdw11, cdw12, cdw13, cdw14, cdw15;
	uint32_t timeout_ms; uint32_t rsvd2;
};
#define NVME_URING_CMD_IO  0xC0484E80u   /* _IOWR('N', 0x80, struct nvme_uring_cmd) */
#define NVME_OPC_WRITE 0x01
#define NVME_OPC_READ  0x02
#define SQE_CMD_OFF 48

static void die(const char *m) { perror(m); exit(1); }

int main(int argc, char **argv)
{
	const char *dev = "/dev/ng0n1";
	const char *jsonl = NULL;
	int is_write = 0, allow_disposable = 0;
	uint64_t slba = 0;
	uint32_t nlb = 8;        /* nlb logical blocks per command */
	int count = 4;           /* number of commands */
	uint32_t lba = 512, nsid = 1;
	int qd = 8;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--dev") && i+1<argc) dev = argv[++i];
		else if (!strcmp(argv[i], "--read")) is_write = 0;
		else if (!strcmp(argv[i], "--write")) is_write = 1;
		else if (!strcmp(argv[i], "--slba") && i+1<argc) slba = strtoull(argv[++i],0,0);
		else if (!strcmp(argv[i], "--nlb") && i+1<argc) nlb = strtoul(argv[++i],0,0);
		else if (!strcmp(argv[i], "--count") && i+1<argc) count = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--lba-size") && i+1<argc) lba = strtoul(argv[++i],0,0);
		else if (!strcmp(argv[i], "--nsid") && i+1<argc) nsid = strtoul(argv[++i],0,0);
		else if (!strcmp(argv[i], "--qd") && i+1<argc) qd = atoi(argv[++i]);
		else if (!strcmp(argv[i], "--jsonl") && i+1<argc) jsonl = argv[++i];
		else if (!strcmp(argv[i], "--i-know-disposable")) allow_disposable = 1;
		else { fprintf(stderr, "unknown arg %s\n", argv[i]); return 2; }
	}

	if (is_write) {
		if (!allow_disposable) { fprintf(stderr, "refusing --write without --i-know-disposable\n"); return 2; }
		if (strncmp(dev, "/dev/ng", 7)) { fprintf(stderr, "refusing --write to non-/dev/ng device\n"); return 2; }
	}

	FILE *out = stdout;
	if (jsonl) { out = fopen(jsonl, "w"); if (!out) die("fopen jsonl"); }

	int fd = open(dev, O_RDWR);
	if (fd < 0) die("open dev");

	struct io_uring ring;
	struct io_uring_params p; memset(&p, 0, sizeof(p));
	p.flags = IORING_SETUP_SQE128 | IORING_SETUP_CQE32;
	if (io_uring_queue_init_params(qd, &ring, &p) < 0) die("queue_init (SQE128/CQE32)");

	size_t bytes = (size_t)nlb * lba;
	int fail = 0;
	for (int done = 0; done < count; ) {
		int batch = (count - done) < qd ? (count - done) : qd;
		void **bufs = calloc(batch, sizeof(void*));
		uint64_t *uds = calloc(batch, sizeof(uint64_t));
		uint64_t *lbas = calloc(batch, sizeof(uint64_t));
		for (int b = 0; b < batch; b++) {
			int idx = done + b;
			uint64_t cur_slba = slba + (uint64_t)idx * nlb;
			void *buf; if (posix_memalign(&buf, 4096, bytes)) die("memalign");
			memset(buf, is_write ? (0x40 + (idx & 0x3f)) : 0, bytes);
			bufs[b] = buf; uds[b] = idx + 1; lbas[b] = cur_slba;

			struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
			if (!sqe) die("get_sqe");
			memset(sqe, 0, 128);
			sqe->opcode = IORING_OP_URING_CMD;
			sqe->fd = fd;
			sqe->cmd_op = NVME_URING_CMD_IO;
			struct nvme_uring_cmd *c = (struct nvme_uring_cmd *)((char *)sqe + SQE_CMD_OFF);
			c->opcode = is_write ? NVME_OPC_WRITE : NVME_OPC_READ;
			c->nsid = nsid;
			c->addr = (uint64_t)(uintptr_t)buf;
			c->data_len = bytes;
			c->cdw10 = (uint32_t)(cur_slba & 0xffffffff);
			c->cdw11 = (uint32_t)(cur_slba >> 32);
			c->cdw12 = (nlb - 1) & 0xffff;
			io_uring_sqe_set_data64(sqe, uds[b]);
		}
		int sub = io_uring_submit(&ring);
		if (sub < 0) { errno = -sub; die("submit"); }

		for (int c = 0; c < batch; c++) {
			struct io_uring_cqe *cqe;
			int r = io_uring_wait_cqe(&ring, &cqe);
			if (r < 0) { errno = -r; die("wait_cqe"); }
			uint64_t ud = io_uring_cqe_get_data64(cqe);
			int res = cqe->res;
			io_uring_cqe_seen(&ring, cqe);
			uint64_t this_slba = 0;
			for (int b = 0; b < batch; b++) if (uds[b] == ud) this_slba = lbas[b];
			if (res != 0) { fprintf(stderr, "cmd ud=%lu FAILED res=%d (%s)\n",
				(unsigned long)ud, res, strerror(res < 0 ? -res : res)); fail++; }
			fprintf(out,
				"{\"seq\":%lu,\"user_data\":%lu,\"op_name\":\"%s\",\"nsid\":%u,"
				"\"slba\":%lu,\"nlb\":%u,\"bytes\":%zu,\"cqe_res\":%d}\n",
				(unsigned long)ud, (unsigned long)ud, is_write ? "write" : "read",
				nsid, (unsigned long)this_slba, nlb, bytes, res);
		}
		for (int b = 0; b < batch; b++) free(bufs[b]);
		free(bufs); free(uds); free(lbas);
		done += batch;
	}

	io_uring_queue_exit(&ring);
	if (jsonl) fclose(out);
	close(fd);
	fprintf(stderr, "nvme_uring_cmd_rw: dev=%s op=%s nlb=%u (%zu B/cmd) count=%d fail=%d\n",
		dev, is_write ? "write" : "read", nlb, bytes, count, fail);
	return fail ? 1 : 0;
}
