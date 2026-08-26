// io_uring_demo — controlled liburing workload that emits JSON-Lines ground
// truth, for verifying the ebpf-syscall io_uring intent tracer (Phase 1).
//
// Each accepted submission gets a unique, monotonic user_data (== seq), so the
// tracer side can correlate exactly. We deliberately use REGULAR temp files and
// deterministic offsets/patterns so the verifier can detect missing/duplicate/
// misdecoded events without any hardware.
//
// Modes:
//   scalar   : io_uring_prep_read / io_uring_prep_write        (len = bytes)
//   vectored : io_uring_prep_readv / io_uring_prep_writev      (len = iovcnt)
//   fixed    : io_uring_prep_read_fixed / write_fixed          (registered buf)
//
// Op direction:
//   write : write deterministic buffers at increasing offsets
//   read  : read them back and verify the pattern
//   rw    : write pass, then read-verify pass (default)
//
// Ground-truth JSONL fields (one object per accepted SQE):
//   seq,user_data,pid,tid,opcode,op_name,ddir,file,fd,offset,
//   requested_bytes,iovcnt,iov_sizes,submit_ns,complete_ns,cqe_res,
//   ring_flags,sqpoll
//
// Build: see examples/io_uring/Makefile  (needs liburing-dev).
#define _GNU_SOURCE
#include <liburing.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/types.h>

enum mode { M_SCALAR, M_VECTORED, M_FIXED };
enum opdir { OP_WRITE, OP_READ, OP_RW };

static const char *opcode_name(int op)
{
	switch (op) {
	case IORING_OP_READ:        return "READ";
	case IORING_OP_WRITE:       return "WRITE";
	case IORING_OP_READV:       return "READV";
	case IORING_OP_WRITEV:      return "WRITEV";
	case IORING_OP_READ_FIXED:  return "READ_FIXED";
	case IORING_OP_WRITE_FIXED: return "WRITE_FIXED";
	default:                    return "OTHER";
	}
}

static uint64_t now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

static pid_t gettid_(void) { return (pid_t)syscall(SYS_gettid); }

// Per-op bookkeeping, indexed by seq, so completions can be matched and timed.
struct op_rec {
	uint64_t user_data;
	int      opcode;
	int      ddir;        // 0 read, 1 write
	uint64_t offset;
	uint64_t requested;   // logical bytes the app asked for
	int      iovcnt;
	uint64_t submit_ns;
	uint64_t complete_ns;
	long     res;
	void    *buf;         // owning buffer for this op (page aligned)
	struct iovec *iov;    // vectored only
	int      bufidx;      // registered-buffer index (fixed mode), else -1
};

static void die(const char *m) { perror(m); exit(1); }

// Deterministic byte pattern keyed by (offset) so reads can verify writes.
static void fill_pattern(unsigned char *b, size_t n, uint64_t off)
{
	for (size_t i = 0; i < n; i++)
		b[i] = (unsigned char)((off + i) * 1103515245u >> 16);
}
static int check_pattern(const unsigned char *b, size_t n, uint64_t off)
{
	for (size_t i = 0; i < n; i++)
		if (b[i] != (unsigned char)((off + i) * 1103515245u >> 16))
			return 0;
	return 1;
}

int main(int argc, char **argv)
{
	enum mode mode = M_SCALAR;
	enum opdir opdir = OP_RW;
	size_t size = 128 * 1024;     // per-op logical bytes
	int    count = 16;            // ops per pass
	int    qd = 8;                // ring/queue depth
	int    iovs = 4;              // iovecs per op (vectored)
	int    sqpoll = 0;
	int    odirect = 0;
	const char *path = "/tmp/io_uring_demo.dat";
	const char *jsonl = NULL;     // ground-truth output (default stdout)

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--mode") && i+1 < argc) {
			const char *m = argv[++i];
			if (!strcmp(m, "scalar")) mode = M_SCALAR;
			else if (!strcmp(m, "vectored")) mode = M_VECTORED;
			else if (!strcmp(m, "fixed")) mode = M_FIXED;
			else { fprintf(stderr, "bad --mode %s\n", m); return 2; }
		} else if (!strcmp(argv[i], "--op") && i+1 < argc) {
			const char *o = argv[++i];
			if (!strcmp(o, "read")) opdir = OP_READ;
			else if (!strcmp(o, "write")) opdir = OP_WRITE;
			else if (!strcmp(o, "rw")) opdir = OP_RW;
			else { fprintf(stderr, "bad --op %s\n", o); return 2; }
		} else if (!strcmp(argv[i], "--size") && i+1 < argc) {
			size = strtoull(argv[++i], NULL, 0);
		} else if (!strcmp(argv[i], "--count") && i+1 < argc) {
			count = atoi(argv[++i]);
		} else if (!strcmp(argv[i], "--qd") && i+1 < argc) {
			qd = atoi(argv[++i]);
		} else if (!strcmp(argv[i], "--iovs") && i+1 < argc) {
			iovs = atoi(argv[++i]);
		} else if (!strcmp(argv[i], "--sqpoll")) {
			sqpoll = 1;
		} else if (!strcmp(argv[i], "--direct")) {
			odirect = 1;
		} else if (!strcmp(argv[i], "--file") && i+1 < argc) {
			path = argv[++i];
		} else if (!strcmp(argv[i], "--jsonl") && i+1 < argc) {
			jsonl = argv[++i];
		} else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
			fprintf(stderr,
"usage: %s [--mode scalar|vectored|fixed] [--op read|write|rw]\n"
"          [--size BYTES] [--count N] [--qd DEPTH] [--iovs N]\n"
"          [--sqpoll] [--direct] [--file PATH] [--jsonl PATH]\n", argv[0]);
			return 0;
		} else {
			fprintf(stderr, "unknown arg %s\n", argv[i]); return 2;
		}
	}

	if (mode == M_VECTORED && (size % iovs)) {
		fprintf(stderr, "size %zu not divisible by iovs %d\n", size, iovs);
		return 2;
	}
	// O_DIRECT alignment: keep size and offsets 4K-aligned.
	size_t align = odirect ? 4096 : 4096; // page-align always (simplifies fixed)
	if (odirect && (size % 512)) { fprintf(stderr, "O_DIRECT needs 512-aligned size\n"); return 2; }

	FILE *out = stdout;
	if (jsonl) { out = fopen(jsonl, "w"); if (!out) die("fopen jsonl"); }

	int oflags = O_RDWR | O_CREAT;
	if (odirect) oflags |= O_DIRECT;
	int fd = open(path, oflags, 0644);
	if (fd < 0) die("open data file");
	if (ftruncate(fd, (off_t)size * count) < 0) die("ftruncate");

	struct io_uring ring;
	struct io_uring_params p;
	memset(&p, 0, sizeof(p));
	if (sqpoll) { p.flags |= IORING_SETUP_SQPOLL; p.sq_thread_idle = 1000; }
	if (io_uring_queue_init_params(qd, &ring, &p) < 0) die("io_uring_queue_init_params");
	uint32_t ring_flags = p.flags;

	pid_t pid = getpid(), tid = gettid_();

	// Determine passes: write pass and/or read pass.
	int do_write = (opdir == OP_WRITE || opdir == OP_RW);
	int do_read  = (opdir == OP_READ  || opdir == OP_RW);

	uint64_t seq = 0;
	int verify_fail = 0;

	// For fixed mode we register one buffer per queue slot. To keep things
	// simple and correct, run with effective queue depth = min(qd, count) and
	// register exactly that many fixed buffers, reusing them across batches.
	int eff_qd = qd < count ? qd : count;
	struct iovec *regbufs = NULL;
	if (mode == M_FIXED) {
		regbufs = calloc(eff_qd, sizeof(*regbufs));
		for (int i = 0; i < eff_qd; i++) {
			if (posix_memalign(&regbufs[i].iov_base, align, size)) die("posix_memalign reg");
			regbufs[i].iov_len = size;
		}
		if (io_uring_register_buffers(&ring, regbufs, eff_qd) < 0)
			die("io_uring_register_buffers");
	}

	// One pass = submit `count` ops in batches of eff_qd, reap each batch.
	// pass_dir: 1 = write, 0 = read.
	for (int pass = 0; pass < 2; pass++) {
		int is_write = (pass == 0);
		if (is_write && !do_write) continue;
		if (!is_write && !do_read) continue;

		int done = 0;
		while (done < count) {
			int batch = (count - done) < eff_qd ? (count - done) : eff_qd;
			struct op_rec *recs = calloc(batch, sizeof(*recs));

			for (int b = 0; b < batch; b++) {
				int idx = done + b;
				uint64_t off = (uint64_t)idx * size;
				struct op_rec *r = &recs[b];
				r->user_data = ++seq;
				r->ddir = is_write ? 1 : 0;
				r->offset = off;
				r->requested = size;
				r->iovcnt = (mode == M_VECTORED) ? iovs : 1;
				r->bufidx = (mode == M_FIXED) ? b : -1;

				// buffer
				void *buf;
				if (mode == M_FIXED) buf = regbufs[b].iov_base;
				else { if (posix_memalign(&buf, align, size)) die("posix_memalign"); }
				r->buf = (mode == M_FIXED) ? NULL : buf; // fixed bufs freed at end
				if (is_write) fill_pattern(buf, size, off);

				struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
				if (!sqe) die("io_uring_get_sqe");

				if (mode == M_SCALAR) {
					if (is_write) { io_uring_prep_write(sqe, fd, buf, size, off); r->opcode = IORING_OP_WRITE; }
					else          { io_uring_prep_read(sqe, fd, buf, size, off);  r->opcode = IORING_OP_READ; }
				} else if (mode == M_VECTORED) {
					struct iovec *iov = calloc(iovs, sizeof(*iov));
					size_t chunk = size / iovs;
					for (int k = 0; k < iovs; k++) { iov[k].iov_base = (char*)buf + k*chunk; iov[k].iov_len = chunk; }
					r->iov = iov;
					if (is_write) { io_uring_prep_writev(sqe, fd, iov, iovs, off); r->opcode = IORING_OP_WRITEV; }
					else          { io_uring_prep_readv(sqe, fd, iov, iovs, off);  r->opcode = IORING_OP_READV; }
				} else { // M_FIXED
					if (is_write) { io_uring_prep_write_fixed(sqe, fd, buf, size, off, b); r->opcode = IORING_OP_WRITE_FIXED; }
					else          { io_uring_prep_read_fixed(sqe, fd, buf, size, off, b);  r->opcode = IORING_OP_READ_FIXED; }
				}
				io_uring_sqe_set_data64(sqe, r->user_data);
				r->submit_ns = now_ns();
			}

			int sub = io_uring_submit(&ring);
			if (sub < 0) { errno = -sub; die("io_uring_submit"); }

			// reap `batch` completions, match by user_data
			for (int c = 0; c < batch; c++) {
				struct io_uring_cqe *cqe;
				int ret = io_uring_wait_cqe(&ring, &cqe);
				if (ret < 0) { errno = -ret; die("io_uring_wait_cqe"); }
				uint64_t ud = io_uring_cqe_get_data64(cqe);
				long res = cqe->res;
				uint64_t cns = now_ns();
				io_uring_cqe_seen(&ring, cqe);

				// find rec
				struct op_rec *r = NULL;
				for (int b = 0; b < batch; b++) if (recs[b].user_data == ud) { r = &recs[b]; break; }
				if (!r) { fprintf(stderr, "unmatched cqe user_data=%lu\n", (unsigned long)ud); continue; }
				r->complete_ns = cns; r->res = res;

				if (res < 0) fprintf(stderr, "op ud=%lu FAILED res=%ld (%s)\n",
						      (unsigned long)ud, res, strerror((int)-res));
				else if ((size_t)res != size)
					fprintf(stderr, "op ud=%lu short res=%ld want=%zu\n",
						(unsigned long)ud, res, size);
				if (!is_write && res > 0) {
					void *vb = (mode == M_FIXED) ? regbufs[r->bufidx].iov_base : r->buf;
					if (!check_pattern(vb, size, r->offset)) { verify_fail++; }
				}
			}

			// emit ground truth for this batch (after completion, fields final)
			for (int b = 0; b < batch; b++) {
				struct op_rec *r = &recs[b];
				fprintf(out, "{\"seq\":%lu,\"user_data\":%lu,\"pid\":%d,\"tid\":%d,"
					"\"opcode\":%d,\"op_name\":\"%s\",\"ddir\":\"%s\",\"file\":\"%s\","
					"\"fd\":%d,\"offset\":%lu,\"requested_bytes\":%lu,\"iovcnt\":%d,"
					"\"iov_sizes\":[",
					(unsigned long)r->user_data, (unsigned long)r->user_data,
					pid, tid, r->opcode, opcode_name(r->opcode),
					r->ddir ? "write" : "read", path, fd,
					(unsigned long)r->offset, (unsigned long)r->requested, r->iovcnt);
				if (mode == M_VECTORED) {
					size_t chunk = size / iovs;
					for (int k = 0; k < iovs; k++) fprintf(out, "%s%zu", k?",":"", chunk);
				} else fprintf(out, "%zu", size);
				fprintf(out, "],\"submit_ns\":%lu,\"complete_ns\":%lu,\"cqe_res\":%ld,"
					"\"ring_flags\":%u,\"sqpoll\":%s}\n",
					(unsigned long)r->submit_ns, (unsigned long)r->complete_ns,
					r->res, ring_flags, sqpoll ? "true" : "false");

				if (r->buf && mode != M_FIXED) free(r->buf);
				if (r->iov) free(r->iov);
			}
			free(recs);
			done += batch;
		}
	}

	if (mode == M_FIXED) {
		io_uring_unregister_buffers(&ring);
		for (int i = 0; i < eff_qd; i++) free(regbufs[i].iov_base);
		free(regbufs);
	}
	io_uring_queue_exit(&ring);
	if (jsonl) fclose(out);
	close(fd);

	fprintf(stderr, "io_uring_demo: mode=%d op=%d size=%zu count=%d qd=%d "
		"emitted=%lu ops, verify_fail=%d\n",
		mode, opdir, size, count, qd, (unsigned long)seq, verify_fail);
	return verify_fail ? 1 : 0;
}
