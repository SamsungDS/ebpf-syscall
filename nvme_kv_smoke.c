// nvme_kv_smoke.c — minimal NVMe Key-Value workload generator for exercising
// nvme_uring_cmd_monitor --kv and the key-join.  Issues Store then Retrieve
// for --count distinct keys against a KV namespace char device (/dev/ngXnY,
// e.g. an SPDK kvmalloc target attached via nvme-tcp) using raw io_uring
// IORING_OP_URING_CMD — the same passthrough path xNVMe and the NIXL
// XNVME_KV plugin use, with no xNVMe build dependency.
//
// KV command layout (Key Value Command Set Spec 1.0c, matching xNVMe's
// kvs_cmd_set_key): key bytes 0-7 memcpy'd into cdw2-3, bytes 8-15 into
// cdw14-15, key length in cdw11 bits 0-7, value size in cdw10.
//
// With --sem PATH it also emits a kvio semantic JSONL (one record per op:
// op, key, key_hex, bytes, ts_start/ts in CLOCK_MONOTONIC seconds) — the
// producer side of the converter's --join-by-key, so a monitor capture plus
// this file demonstrates full object attribution with zero instrumentation
// in the initiator library.
//
//   sudo ./nvme_kv_smoke --dev /dev/ng1n1 --count 16 --len 4096
//        [--sem /tmp/kv.sem.jsonl]
//
// Needs liburing (build: make nvme_kv_smoke).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/ioctl.h>
#include <liburing.h>

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
#define SQE_CMD_OFF 48

#define KV_STORE    0x01
#define KV_RETRIEVE 0x02

static double mono_s(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static void set_key(struct nvme_uring_cmd *c, const unsigned char *key,
		    unsigned kl)
{
	unsigned char kb[16] = {0};
	memcpy(kb, key, kl > 16 ? 16 : kl);
	memcpy(&c->cdw2,  kb + 0,  4);
	memcpy(&c->cdw3,  kb + 4,  4);
	memcpy(&c->cdw14, kb + 8,  4);
	memcpy(&c->cdw15, kb + 12, 4);
	c->cdw11 = kl & 0xff;
}

static void hex_of(const unsigned char *b, unsigned n, char *hex)
{
	for (unsigned i = 0; i < n; i++)
		sprintf(hex + 2 * i, "%02x", b[i]);
	hex[2 * n] = '\0';
}

/* one synchronous KV op through the ring; returns cqe->res */
static int kv_op(struct io_uring *ring, int fd, int nsid, __u8 opcode,
		 const unsigned char *key, unsigned kl, void *buf,
		 unsigned len, unsigned long long user_data)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
	if (!sqe) return -ENOSPC;
	memset(sqe, 0, 128);
	sqe->opcode = IORING_OP_URING_CMD;
	sqe->fd = fd;
	sqe->cmd_op = NVME_URING_CMD_IO;
	sqe->user_data = user_data;
	struct nvme_uring_cmd *c =
		(struct nvme_uring_cmd *)((char *)sqe + SQE_CMD_OFF);
	c->opcode = opcode;
	c->nsid = (unsigned)nsid;
	c->addr = (unsigned long long)(uintptr_t)buf;
	c->data_len = len;
	c->cdw10 = len;                 /* value size */
	set_key(c, key, kl);
	if (io_uring_submit_and_wait(ring, 1) < 0)
		return -errno;
	struct io_uring_cqe *cqe;
	if (io_uring_peek_cqe(ring, &cqe))
		return -EIO;
	int res = cqe->res;
	io_uring_cqe_seen(ring, cqe);
	return res;
}

int main(int argc, char **argv)
{
	const char *dev = "/dev/ng0n1";
	const char *sem_path = NULL;
	unsigned count = 16, len = 4096;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--dev") && i+1 < argc) dev = argv[++i];
		else if (!strcmp(argv[i], "--count") && i+1 < argc) count = (unsigned)atoi(argv[++i]);
		else if (!strcmp(argv[i], "--len") && i+1 < argc) len = (unsigned)atoi(argv[++i]);
		else if (!strcmp(argv[i], "--sem") && i+1 < argc) sem_path = argv[++i];
		else {
			fprintf(stderr, "usage: %s [--dev D] [--count N] "
				"[--len B] [--sem PATH]\n", argv[0]);
			return 2;
		}
	}

	/* NVMe controller numbering is NOT stable across boots, so a saved
	 * /dev/ngXnY name can silently point at a different namespace after
	 * a reboot.  A KV namespace never gets a block node (the kernel
	 * skips it: "block device for nsid N not supported (csi 1)"), so a
	 * sibling /dev/nvmeXnY existing means this is a BLOCK namespace --
	 * where our KV Store would be interpreted as an NVM write.  Refuse.
	 * Select KV devices by subsystem NQN, not by remembered name. */
	const char *ng = strrchr(dev, '/');
	ng = ng ? ng + 1 : dev;
	if (ng[0] == 'n' && ng[1] == 'g') {
		char blk[64];
		snprintf(blk, sizeof(blk), "/dev/nvme%s", ng + 2);
		if (access(blk, F_OK) == 0) {
			fprintf(stderr, "%s: sibling block device %s exists -- "
				"this is a block namespace, not KV; refusing "
				"(KV namespaces have no block node)\n", dev, blk);
			return 1;
		}
	}

	int fd = open(dev, O_RDWR);
	if (fd < 0) { perror(dev); return 1; }
	int nsid = ioctl(fd, NVME_IOCTL_ID);
	if (nsid < 0) { perror("NVME_IOCTL_ID (is this a /dev/ng char dev?)"); return 1; }

	FILE *sem = NULL;
	if (sem_path) {
		sem = fopen(sem_path, "w");
		if (!sem) { perror(sem_path); return 1; }
		fprintf(sem, "{\"event_type\":\"kvio_meta\",\"kvio_schema\":2,"
			"\"pid\":%d,\"instance\":\"kvsmoke\",\"device_path\":\"%s\","
			"\"io_engine\":\"kv_smoke\",\"use_uring_cmd\":true,"
			"\"ts_monotonic\":%.9f,\"ts_realtime\":%ld}\n",
			getpid(), dev, mono_s(), (long)time(NULL));
	}

	struct io_uring_params p = {};
	p.flags = IORING_SETUP_SQE128 | IORING_SETUP_CQE32;
	struct io_uring ring;
	if (io_uring_queue_init_params(8, &ring, &p)) { perror("ring init"); return 1; }

	void *buf;
	if (posix_memalign(&buf, 4096, len)) { perror("memalign"); return 1; }

	unsigned errors = 0;
	for (int phase = 0; phase < 2; phase++) {
		__u8 opc = phase == 0 ? KV_STORE : KV_RETRIEVE;
		const char *opn = phase == 0 ? "store" : "load";
		for (unsigned i = 0; i < count; i++) {
			unsigned char key[16];
			unsigned kl = (unsigned)snprintf((char *)key, sizeof(key),
							 "kvsmoke%04u", i);
			char khex[33];
			hex_of(key, kl, khex);
			memset(buf, 'A' + (i % 26), len);
			double t0 = mono_s();
			int res = kv_op(&ring, fd, nsid, opc, key, kl, buf, len,
					((unsigned long long)(i + 1) << 32) | phase);
			double t1 = mono_s();
			if (res != 0) {
				errors++;
				fprintf(stderr, "%s %s -> res=%d\n", opn, key, res);
			}
			if (sem)
				fprintf(sem, "{\"trace_id\":%u,\"op\":\"%s\","
					"\"key\":\"%s\",\"key_hex\":\"%s\","
					"\"object_id\":\"%s\",\"part\":\"kv\","
					"\"bytes\":%u,\"ts_start\":%.9f,"
					"\"ts\":%.9f,\"pid\":%d,"
					"\"instance\":\"kvsmoke\"%s}\n",
					i + 1, opn, key, khex, key, len, t0, t1,
					getpid(),
					res ? ",\"error\":\"nvme status\"" : "");
		}
	}
	if (sem) fclose(sem);
	io_uring_queue_exit(&ring);
	close(fd);
	fprintf(stderr, "nvme_kv_smoke: dev=%s nsid=%d keys=%u len=%u "
		"ops=%u errors=%u\n", dev, nsid, count, len, count * 2, errors);
	return errors ? 1 : 0;
}
