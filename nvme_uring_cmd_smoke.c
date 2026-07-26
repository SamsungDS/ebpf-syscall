// nvme_uring_cmd_smoke.c — minimal NVMe passthrough workload generator for
// exercising nvme_uring_cmd_monitor. Issues tagged READ commands (opcode 0x02,
// non-destructive) to an NVMe char device (/dev/ngXnY) via io_uring
// IORING_OP_URING_CMD at a configurable queue depth, with kvio-style
// user_data tagging: trace_id in the high 32 bits (one trace_id per group of
// --cmds-per-obj commands), sequence in the low 32.
//
// This is the firing test for the tracer's submission+completion probes on a
// machine with no LMCache stack: run the monitor, run this, and every
// nvme_cmd line must gain a matching nvme_cmp line.
//
//   sudo ./nvme_uring_cmd_smoke --dev /dev/ng0n1 --count 512 --qd 16
//
// Needs liburing (build: make nvme_uring_cmd_smoke).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <liburing.h>

/* uapi bits defined locally so old headers don't matter */
struct nvme_uring_cmd {
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
#define NVME_URING_CMD_IO	_IOWR('N', 0x80, struct nvme_uring_cmd)
#define NVME_IOCTL_ID		_IO('N', 0x40)
#define SQE_CMD_OFF 48		/* io_uring_sqe.cmd[] — matches the BPF side */

int main(int argc, char **argv)
{
	const char *dev = "/dev/ng0n1";
	unsigned count = 256, qd = 8, len = 4096, lba = 512;
	unsigned cmds_per_obj = 8;
	unsigned long long trace_base = 7000;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--dev") && i+1 < argc) dev = argv[++i];
		else if (!strcmp(argv[i], "--count") && i+1 < argc) count = (unsigned)atoi(argv[++i]);
		else if (!strcmp(argv[i], "--qd") && i+1 < argc) qd = (unsigned)atoi(argv[++i]);
		else if (!strcmp(argv[i], "--len") && i+1 < argc) len = (unsigned)atoi(argv[++i]);
		else if (!strcmp(argv[i], "--lba-size") && i+1 < argc) lba = (unsigned)atoi(argv[++i]);
		else if (!strcmp(argv[i], "--cmds-per-obj") && i+1 < argc) cmds_per_obj = (unsigned)atoi(argv[++i]);
		else if (!strcmp(argv[i], "--trace-base") && i+1 < argc) trace_base = strtoull(argv[++i], NULL, 0);
		else {
			fprintf(stderr, "usage: %s [--dev D] [--count N] [--qd Q] "
				"[--len B] [--lba-size N] [--cmds-per-obj N] [--trace-base T]\n",
				argv[0]);
			return 2;
		}
	}
	if (!cmds_per_obj) cmds_per_obj = 1;

	int fd = open(dev, O_RDONLY);
	if (fd < 0) { perror(dev); return 1; }
	int nsid = ioctl(fd, NVME_IOCTL_ID);
	if (nsid < 0) { perror("NVME_IOCTL_ID (is this a /dev/ng char dev?)"); return 1; }

	struct io_uring_params p = {};
	p.flags = IORING_SETUP_SQE128 | IORING_SETUP_CQE32;
	struct io_uring ring;
	if (io_uring_queue_init_params(qd, &ring, &p)) { perror("ring init"); return 1; }

	void *bufs[qd];
	for (unsigned i = 0; i < qd; i++)
		if (posix_memalign(&bufs[i], 4096, len)) { perror("memalign"); return 1; }

	unsigned submitted = 0, completed = 0, errors = 0;
	unsigned nlb_zero = len / lba - 1;
	while (completed < count) {
		while (submitted < count && submitted - completed < qd) {
			struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
			if (!sqe) break;
			memset(sqe, 0, 128);           /* full big-SQE */
			sqe->opcode = IORING_OP_URING_CMD;
			sqe->fd = fd;
			sqe->cmd_op = NVME_URING_CMD_IO;
			unsigned long long tid = trace_base + submitted / cmds_per_obj;
			sqe->user_data = (tid << 32) | (submitted & 0xffffffff);
			struct nvme_uring_cmd *c =
				(struct nvme_uring_cmd *)((char *)sqe + SQE_CMD_OFF);
			c->opcode = 0x02;              /* NVM read — non-destructive */
			c->nsid = (unsigned)nsid;
			c->addr = (unsigned long long)(uintptr_t)bufs[submitted % qd];
			c->data_len = len;
			unsigned long long slba =
				(unsigned long long)submitted * (len / lba);
			c->cdw10 = (unsigned)slba;
			c->cdw11 = (unsigned)(slba >> 32);
			c->cdw12 = nlb_zero;
			submitted++;
		}
		if (io_uring_submit_and_wait(&ring, 1) < 0) { perror("submit"); return 1; }
		struct io_uring_cqe *cqe;
		while (!io_uring_peek_cqe(&ring, &cqe)) {
			if (cqe->res != 0) errors++;
			io_uring_cqe_seen(&ring, cqe);
			completed++;
		}
	}
	io_uring_queue_exit(&ring);
	close(fd);
	fprintf(stderr, "nvme_uring_cmd_smoke: dev=%s nsid=%d count=%u qd=%u "
		"len=%u trace_ids=%llu..%llu errors=%u\n",
		dev, nsid, count, qd, len, trace_base,
		trace_base + (count - 1) / cmds_per_obj, errors);
	return errors ? 1 : 0;
}
