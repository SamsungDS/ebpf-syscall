// nvme_uring_cmd_smoke.c — NVMe passthrough READ workload generator for
// exercising nvme_uring_cmd_monitor and comparing user, registered-fixed,
// hugetlb, and blk_iobuf premap DMA-mapping paths. Every command keeps the
// kvio-style user_data layout: trace_id in the high 32 bits and the command
// sequence in the low 32 bits.
//
// This is the firing test for the tracer's submission+completion probes on a
// machine with no LMCache stack: run the monitor, run this, and every
// nvme_cmd line must gain a matching nvme_cmp line.
//
//   sudo ./nvme_uring_cmd_smoke --dev /dev/ng0n1 --count 512 --qd 16 --fixed
//       --len 131072 --buffer-len 2097152
//
// Needs liburing (build: make nvme_uring_cmd_smoke).
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>
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

/* premapped-pool op (uapi <linux/blkdev.h>): allocate one blk_iobuf_pool
 * buffer into a sparse io_uring buffer-table slot, then issue the NVMe
 * command with IORING_URING_CMD_FIXED against that slot. When the requested
 * premap succeeds, the kernel maps the pool folio once (dma_iova); best-effort
 * allocation may instead fall back, so hardware runs also need queue stats. */
#ifndef BLOCK_URING_CMD_ALLOC_IOBUF
#define BLOCK_URING_CMD_ALLOC_IOBUF	_IO(0x12, 1)
#endif
#ifndef BLOCK_URING_CMD_ALLOC_IOBUF_F_STRICT_PGSIZE
#define BLOCK_URING_CMD_ALLOC_IOBUF_F_STRICT_PGSIZE	(1U << 0)
#endif
#ifndef IORING_URING_CMD_FIXED
#define IORING_URING_CMD_FIXED		(1U << 0)
#endif

#define DEFAULT_DEV		"/dev/ng0n1"
#define DEFAULT_COUNT		256U
#define DEFAULT_QD		8U
#define DEFAULT_IO_LEN		4096U
#define DEFAULT_LBA_SIZE	512U
#define DEFAULT_CMDS_PER_OBJ	8U
#define DEFAULT_TRACE_BASE	UINT64_C(7000)

/* One uint64_t timestamp/latency per command: 32 MiB at this ceiling. */
#define MAX_COMMANDS		(1U << 22)
#define LATENCY_DONE_BIT	(UINT64_C(1) << 63)

struct options {
	const char *dev;
	uint32_t count;
	uint32_t qd;
	uint32_t slots;
	uint32_t io_len;
	uint32_t buffer_len;
	uint32_t lba_size;
	uint32_t cmds_per_obj;
	uint64_t trace_base;
	int ready_fd;
	int start_fd;
	bool fixed;
	bool premap;
	bool strict_premap;
	bool hugepage;
};

struct geometry {
	uint32_t blocks_per_io;
	uint64_t allocated_bytes;
	uint64_t requested_bytes;
	uint64_t last_lba_exclusive;
	uint64_t trace_last;
};

struct hugepage_meminfo {
	bool valid;
	uint64_t total;
	uint64_t free;
	uint64_t reserved;
	uint64_t surplus;
	uint64_t page_size_kb;
};

struct smaps_proof {
	bool found;
	bool covers_mapping;
	bool vmflag_ht;
	bool vmflag_nh;
	uint64_t vma_start;
	uint64_t vma_end;
	uint64_t kernel_page_kb;
	uint64_t mmu_page_kb;
	uint64_t anon_huge_kb;
	uint64_t private_hugetlb_kb;
	uint64_t shared_hugetlb_kb;
};

struct backing_proof {
	uint64_t system_page_bytes;
	uint64_t required_alignment_bytes;
	uint64_t total_pages;
	uint64_t resident_pages;
	uint32_t aligned_slots;
	bool madv_nohugepage;
	struct smaps_proof smaps;
};

struct user_backing {
	void *base;
	size_t map_len;
	struct iovec *iovecs;
	struct backing_proof proof;
};

struct latency_stats {
	uint64_t samples;
	long double mean_ns;
	uint64_t p50_ns;
	uint64_t p95_ns;
	uint64_t p99_ns;
	uint64_t max_ns;
};

struct run_result {
	uint32_t submitted;
	uint32_t completed;
	uint32_t errors;
	int first_cqe_res;
	int fatal_error;
	const char *fatal_stage;
	uint64_t elapsed_ns;
	uint32_t touched_slots;
	uint32_t expected_touched_slots;
	unsigned char *touched_bitmap;
	size_t touched_bitmap_bytes;
	bool slot_validation_passed;
	uint32_t sq_dropped_start;
	uint32_t sq_dropped_end;
	uint32_t sq_dropped_delta;
	uint32_t cq_overflow_start;
	uint32_t cq_overflow_end;
	uint32_t cq_overflow_delta;
	struct latency_stats latency;
};

struct free_slot_queue {
	uint32_t *slots;
	uint32_t capacity;
	uint32_t head;
	uint32_t tail;
	uint32_t count;
};

struct barrier_state {
	bool enabled;
	bool ready_emitted;
	bool start_acknowledged;
	bool outcome_emitted;
	bool timed_loop_complete;
	bool finish_acknowledged;
};

static void usage(FILE *out, const char *program)
{
	fprintf(out,
		"usage: %s [OPTIONS]\n"
		"  --dev D               NVMe namespace character device (default %s)\n"
		"  --count N             READ command count (default %u, max %u)\n"
		"  --qd Q                ring and maximum outstanding depth (default %u)\n"
		"  --slots S             buffer slots (default: --qd; must be >= qd)\n"
		"  --len B               bytes read by each command (default %u)\n"
		"  --buffer-len B        bytes in each slot (default: --len)\n"
		"  --lba-size B          namespace LBA size (default %u)\n"
		"  --cmds-per-obj N      commands sharing one trace ID (default %u)\n"
		"  --trace-base T        first 32-bit trace ID (default %" PRIu64 ")\n"
		"  --fixed               register ordinary user slots with io_uring\n"
		"  --hugepage            back user slots with anonymous MAP_HUGETLB\n"
		"                         (legacy unregistered unless --fixed is added)\n"
		"  --premap              allocate registered blk_iobuf_pool slots\n"
		"  --strict-premap       also require pool-sized IOMMU leaves\n"
		"  --ready-fd FD         event fd for ready/done protocol\n"
		"  --start-fd FD         control fd for S/F protocol (must pair with\n"
		"                         --ready-fd)\n"
		"  --help                 show this help\n"
		"\n"
		"stdout is one JSON object for each completed run; diagnostics use stderr.\n"
		"With a barrier, setup/proof finishes before `ready\\n`; send byte S to\n"
		"start. After the timed final CQE the event fd receives `done\\n` (or\n"
		"`error\\n`); stop measurement and send byte F before teardown proceeds.\n",
		program, DEFAULT_DEV, DEFAULT_COUNT, MAX_COMMANDS, DEFAULT_QD,
		DEFAULT_IO_LEN, DEFAULT_LBA_SIZE, DEFAULT_CMDS_PER_OBJ,
		DEFAULT_TRACE_BASE);
}

static int parse_u64(const char *text, uint64_t max, uint64_t *value)
{
	char *end;
	unsigned long long parsed;

	errno = 0;
	parsed = strtoull(text, &end, 0);
	if (errno || !*text || *end || parsed > max)
		return -EINVAL;
	*value = parsed;
	return 0;
}

static int parse_u32_nonzero(const char *text, uint32_t *value)
{
	uint64_t parsed;
	int ret;

	ret = parse_u64(text, UINT32_MAX, &parsed);
	if (ret || !parsed)
		return -EINVAL;
	*value = (uint32_t)parsed;
	return 0;
}

static int parse_fd(const char *text, int *value)
{
	uint64_t parsed;
	int ret;

	ret = parse_u64(text, INT_MAX, &parsed);
	if (ret)
		return ret;
	*value = (int)parsed;
	return 0;
}

enum {
	OPT_DEV = 256,
	OPT_COUNT,
	OPT_QD,
	OPT_SLOTS,
	OPT_LEN,
	OPT_BUFFER_LEN,
	OPT_LBA_SIZE,
	OPT_CMDS_PER_OBJ,
	OPT_TRACE_BASE,
	OPT_FIXED,
	OPT_PREMAP,
	OPT_STRICT_PREMAP,
	OPT_HUGEPAGE,
	OPT_READY_FD,
	OPT_START_FD,
};

/* Returns 1 for --help, 0 for success, and -EINVAL for a CLI error. */
static int parse_options(int argc, char **argv, struct options *opts)
{
	static const struct option long_options[] = {
		{ "dev", required_argument, NULL, OPT_DEV },
		{ "count", required_argument, NULL, OPT_COUNT },
		{ "qd", required_argument, NULL, OPT_QD },
		{ "slots", required_argument, NULL, OPT_SLOTS },
		{ "len", required_argument, NULL, OPT_LEN },
		{ "buffer-len", required_argument, NULL, OPT_BUFFER_LEN },
		{ "lba-size", required_argument, NULL, OPT_LBA_SIZE },
		{ "cmds-per-obj", required_argument, NULL, OPT_CMDS_PER_OBJ },
		{ "trace-base", required_argument, NULL, OPT_TRACE_BASE },
		{ "fixed", no_argument, NULL, OPT_FIXED },
		{ "premap", no_argument, NULL, OPT_PREMAP },
		{ "strict-premap", no_argument, NULL, OPT_STRICT_PREMAP },
		{ "hugepage", no_argument, NULL, OPT_HUGEPAGE },
		{ "ready-fd", required_argument, NULL, OPT_READY_FD },
		{ "start-fd", required_argument, NULL, OPT_START_FD },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};
	bool buffer_len_set = false;
	bool slots_set = false;
	int option;

	opterr = 0;
	while ((option = getopt_long(argc, argv, "h", long_options, NULL)) != -1) {
		int ret = 0;

		switch (option) {
		case OPT_DEV:
			opts->dev = optarg;
			break;
		case OPT_COUNT:
			ret = parse_u32_nonzero(optarg, &opts->count);
			break;
		case OPT_QD:
			ret = parse_u32_nonzero(optarg, &opts->qd);
			break;
		case OPT_SLOTS:
			ret = parse_u32_nonzero(optarg, &opts->slots);
			slots_set = !ret;
			break;
		case OPT_LEN:
			ret = parse_u32_nonzero(optarg, &opts->io_len);
			break;
		case OPT_BUFFER_LEN:
			ret = parse_u32_nonzero(optarg, &opts->buffer_len);
			buffer_len_set = !ret;
			break;
		case OPT_LBA_SIZE:
			ret = parse_u32_nonzero(optarg, &opts->lba_size);
			break;
		case OPT_CMDS_PER_OBJ:
			{
				uint64_t parsed;

				ret = parse_u64(optarg, UINT32_MAX, &parsed);
				if (!ret)
					opts->cmds_per_obj = parsed ? (uint32_t)parsed : 1U;
			}
			break;
		case OPT_TRACE_BASE:
			ret = parse_u64(optarg, UINT32_MAX, &opts->trace_base);
			break;
		case OPT_FIXED:
			opts->fixed = true;
			break;
		case OPT_PREMAP:
			opts->premap = true;
			break;
		case OPT_STRICT_PREMAP:
			opts->premap = true;
			opts->strict_premap = true;
			break;
		case OPT_HUGEPAGE:
			opts->hugepage = true;
			break;
		case OPT_READY_FD:
			ret = parse_fd(optarg, &opts->ready_fd);
			break;
		case OPT_START_FD:
			ret = parse_fd(optarg, &opts->start_fd);
			break;
		case 'h':
			return 1;
		default:
			fprintf(stderr, "unknown or incomplete option: %s\n",
				optind > 0 ? argv[optind - 1] : "");
			return -EINVAL;
		}
		if (ret) {
			fprintf(stderr, "invalid numeric option value: %s\n", optarg);
			return ret;
		}
	}
	if (optind != argc) {
		fprintf(stderr, "unexpected positional argument: %s\n", argv[optind]);
		return -EINVAL;
	}
	if (!buffer_len_set)
		opts->buffer_len = opts->io_len;
	if (!slots_set)
		opts->slots = opts->qd;
	return 0;
}

static int multiply_u64(uint64_t left, uint64_t right, uint64_t *product)
{
	if (left && right > UINT64_MAX / left)
		return -EOVERFLOW;
	*product = left * right;
	return 0;
}

static int validate_options(const struct options *opts, struct geometry *geometry)
{
	long system_page = sysconf(_SC_PAGESIZE);
	uint64_t groups;
	int ret;

	if (opts->count > MAX_COMMANDS) {
		fprintf(stderr, "--count exceeds the %u-command latency bound\n",
			MAX_COMMANDS);
		return -E2BIG;
	}
	if (opts->qd > UINT16_MAX || opts->slots > UINT16_MAX) {
		fprintf(stderr, "--qd/--slots exceeds the 16-bit fixed-buffer index space\n");
		return -ERANGE;
	}
	if (opts->slots < opts->qd) {
		fprintf(stderr, "--slots must be greater than or equal to --qd\n");
		return -EINVAL;
	}
	if (opts->io_len > opts->buffer_len) {
		fprintf(stderr, "--len must not exceed --buffer-len\n");
		return -EINVAL;
	}
	if (system_page <= 0 || system_page > UINT32_MAX)
		return -EINVAL;
	if (!opts->premap && !opts->hugepage &&
	    opts->buffer_len % (uint32_t)system_page) {
		fprintf(stderr,
			"normal user --buffer-len must be a multiple of the %ld-byte "
			"system page size\n", system_page);
		return -EINVAL;
	}
	if (opts->io_len % opts->lba_size) {
		fprintf(stderr, "--len must be an exact multiple of --lba-size\n");
		return -EINVAL;
	}
	geometry->blocks_per_io = opts->io_len / opts->lba_size;
	if (!geometry->blocks_per_io || geometry->blocks_per_io > UINT16_MAX + 1U) {
		fprintf(stderr, "one command must contain 1..65536 logical blocks\n");
		return -ERANGE;
	}
	if (opts->fixed && opts->premap) {
		fprintf(stderr, "--fixed cannot be combined with a premap mode\n");
		return -EINVAL;
	}
	if (opts->hugepage && opts->premap) {
		fprintf(stderr, "--hugepage cannot be combined with a premap mode\n");
		return -EINVAL;
	}
	if ((opts->ready_fd < 0) != (opts->start_fd < 0)) {
		fprintf(stderr, "--ready-fd and --start-fd must be supplied together\n");
		return -EINVAL;
	}
	if (opts->ready_fd == STDOUT_FILENO || opts->start_fd == STDOUT_FILENO) {
		fprintf(stderr, "barrier fds must not use stdout (reserved for JSON)\n");
		return -EINVAL;
	}

	ret = multiply_u64(opts->slots, opts->buffer_len,
			   &geometry->allocated_bytes);
	if (ret || geometry->allocated_bytes > SIZE_MAX) {
		fprintf(stderr, "buffer allocation size overflows size_t\n");
		return -EOVERFLOW;
	}
	ret = multiply_u64(opts->count, opts->io_len,
			   &geometry->requested_bytes);
	if (ret)
		return ret;
	ret = multiply_u64(opts->count, geometry->blocks_per_io,
			   &geometry->last_lba_exclusive);
	if (ret) {
		fprintf(stderr, "sequential LBA range overflows 64 bits\n");
		return ret;
	}
	groups = (opts->count - 1U) / opts->cmds_per_obj;
	if (groups > UINT32_MAX - opts->trace_base) {
		fprintf(stderr, "trace ID range exceeds the high 32-bit field\n");
		return -ERANGE;
	}
	geometry->trace_last = opts->trace_base + groups;
	return 0;
}

static const char *mode_name(const struct options *opts)
{
	if (opts->strict_premap)
		return "strict-premap";
	if (opts->premap)
		return "premap";
	if (opts->fixed && opts->hugepage)
		return "fixed-hugetlb";
	if (opts->fixed)
		return "fixed";
	if (opts->hugepage)
		return "user-hugetlb";
	return "user";
}

static const char *fixed_addr_semantics(const struct options *opts)
{
	if (opts->premap)
		return "kbuf-offset-zero";
	if (opts->fixed)
		return "registered-user-va";
	return "user-va";
}

/*
 * Ordinary registered buffers retain their userspace base in imu->ubuf, so
 * io_import_fixed() requires that VA (plus any desired offset). blk_iobuf KBUF
 * slots deliberately use ubuf=0, making zero the offset to their first byte.
 */
static uint64_t command_buffer_addr(const struct options *opts, const void *buf)
{
	return opts->premap ? 0 : (uint64_t)(uintptr_t)buf;
}

static int read_hugepage_meminfo(struct hugepage_meminfo *info)
{
	bool saw_total = false, saw_free = false, saw_reserved = false;
	bool saw_surplus = false, saw_size = false;
	char *line = NULL;
	size_t capacity = 0;
	FILE *file;

	memset(info, 0, sizeof(*info));
	file = fopen("/proc/meminfo", "re");
	if (!file)
		return -errno;
	while (getline(&line, &capacity, file) >= 0) {
		unsigned long long value;

		if (sscanf(line, "HugePages_Total: %llu", &value) == 1) {
			info->total = value;
			saw_total = true;
		} else if (sscanf(line, "HugePages_Free: %llu", &value) == 1) {
			info->free = value;
			saw_free = true;
		} else if (sscanf(line, "HugePages_Rsvd: %llu", &value) == 1) {
			info->reserved = value;
			saw_reserved = true;
		} else if (sscanf(line, "HugePages_Surp: %llu", &value) == 1) {
			info->surplus = value;
			saw_surplus = true;
		} else if (sscanf(line, "Hugepagesize: %llu kB", &value) == 1) {
			info->page_size_kb = value;
			saw_size = true;
		}
	}
	free(line);
	if (ferror(file)) {
		int saved = errno ? errno : EIO;

		fclose(file);
		return -saved;
	}
	fclose(file);
	info->valid = saw_total && saw_free && saw_reserved && saw_surplus && saw_size;
	return info->valid ? 0 : -ENODATA;
}

static bool vmflag_present(const char *line, const char *wanted)
{
	const char *cursor = strchr(line, ':');
	size_t wanted_len = strlen(wanted);

	if (!cursor)
		return false;
	cursor++;
	while (*cursor) {
		size_t token_len;

		while (isspace((unsigned char)*cursor))
			cursor++;
		if (!*cursor)
			break;
		token_len = strcspn(cursor, " \t\r\n");
		if (token_len == wanted_len && !memcmp(cursor, wanted, token_len))
			return true;
		cursor += token_len;
	}
	return false;
}

static int read_smaps_proof(const void *base, size_t len,
			    struct smaps_proof *proof)
{
	const uint64_t target = (uint64_t)(uintptr_t)base;
	uint64_t target_end;
	char *line = NULL;
	size_t capacity = 0;
	bool inside = false;
	FILE *file;

	memset(proof, 0, sizeof(*proof));
	if (target > UINT64_MAX - len)
		return -EOVERFLOW;
	target_end = target + len;
	file = fopen("/proc/self/smaps", "re");
	if (!file)
		return -errno;
	while (getline(&line, &capacity, file) >= 0) {
		unsigned long start, end;
		char permissions[5];
		unsigned long long value;

		if (sscanf(line, "%lx-%lx %4s", &start, &end, permissions) == 3) {
			if (inside)
				break;
			if (target >= start && target < end) {
				inside = true;
				proof->found = true;
				proof->vma_start = start;
				proof->vma_end = end;
				proof->covers_mapping = target_end <= end;
			}
			continue;
		}
		if (!inside)
			continue;
		if (sscanf(line, "KernelPageSize: %llu kB", &value) == 1)
			proof->kernel_page_kb = value;
		else if (sscanf(line, "MMUPageSize: %llu kB", &value) == 1)
			proof->mmu_page_kb = value;
		else if (sscanf(line, "AnonHugePages: %llu kB", &value) == 1)
			proof->anon_huge_kb = value;
		else if (sscanf(line, "Private_Hugetlb: %llu kB", &value) == 1)
			proof->private_hugetlb_kb = value;
		else if (sscanf(line, "Shared_Hugetlb: %llu kB", &value) == 1)
			proof->shared_hugetlb_kb = value;
		else if (!strncmp(line, "VmFlags:", 8)) {
			proof->vmflag_ht = vmflag_present(line, "ht");
			proof->vmflag_nh = vmflag_present(line, "nh");
		}
	}
	free(line);
	if (ferror(file)) {
		int saved = errno ? errno : EIO;

		fclose(file);
		return -saved;
	}
	fclose(file);
	return proof->found ? 0 : -ENOENT;
}

static int allocate_user_backing(const struct options *opts,
				 const struct geometry *geometry,
				 const struct hugepage_meminfo *meminfo,
				 struct user_backing *backing)
{
	const long system_page = sysconf(_SC_PAGESIZE);
	int flags = MAP_PRIVATE | MAP_ANONYMOUS;
	volatile unsigned char *touch;
	uint64_t hugepage_bytes = 0;
	uint32_t slot;
	size_t page_size;
	size_t offset;

	memset(backing, 0, sizeof(*backing));
	if (system_page <= 0)
		return -EINVAL;
	page_size = (size_t)system_page;
	backing->map_len = (size_t)geometry->allocated_bytes;
	if (opts->hugepage) {
		if (meminfo->page_size_kb > UINT64_MAX / 1024)
			return -EOVERFLOW;
		hugepage_bytes = meminfo->page_size_kb * 1024;
		if (!hugepage_bytes || opts->buffer_len % hugepage_bytes) {
			fprintf(stderr,
				"hugetlb --buffer-len must be a multiple of the default "
				"hugepage size (%" PRIu64 " bytes)\n",
				hugepage_bytes);
			return -EINVAL;
		}
		flags |= MAP_HUGETLB;
	}
	backing->base = mmap(NULL, backing->map_len, PROT_READ | PROT_WRITE,
			     flags, -1, 0);
	if (backing->base == MAP_FAILED) {
		backing->base = NULL;
		return -errno;
	}
	if (!opts->hugepage &&
	    madvise(backing->base, backing->map_len, MADV_NOHUGEPAGE))
		return -errno;

	/* Fault every base page before registration, proof, and the ready event. */
	touch = backing->base;
	for (offset = 0; offset < backing->map_len; offset += page_size)
		touch[offset] = (unsigned char)(offset / page_size);

	backing->iovecs = calloc(opts->slots, sizeof(*backing->iovecs));
	if (!backing->iovecs)
		return -ENOMEM;
	for (slot = 0; slot < opts->slots; slot++) {
		backing->iovecs[slot].iov_base =
			(char *)backing->base + (size_t)slot * opts->buffer_len;
		backing->iovecs[slot].iov_len = opts->buffer_len;
	}
	return 0;
}

static int collect_backing_proof(const struct options *opts,
				 const struct hugepage_meminfo *meminfo,
				 struct user_backing *backing)
{
	long system_page = sysconf(_SC_PAGESIZE);
	uint64_t required_alignment;
	unsigned char *resident;
	uint64_t resident_pages = 0;
	uint64_t hugetlb_kb;
	size_t page_count;
	uint32_t slot;
	int ret;

	if (system_page <= 0)
		return -EINVAL;
	required_alignment = opts->hugepage ? meminfo->page_size_kb * 1024 :
		(uint64_t)system_page;
	page_count = backing->map_len / (size_t)system_page +
		!!(backing->map_len % (size_t)system_page);
	resident = calloc(page_count, 1);
	if (!resident)
		return -ENOMEM;
	if (mincore(backing->base, backing->map_len, resident)) {
		ret = -errno;
		free(resident);
		return ret;
	}
	for (size_t page = 0; page < page_count; page++)
		resident_pages += !!(resident[page] & 1);
	free(resident);

	backing->proof.system_page_bytes = (uint64_t)system_page;
	backing->proof.required_alignment_bytes = required_alignment;
	backing->proof.total_pages = page_count;
	backing->proof.resident_pages = resident_pages;
	backing->proof.madv_nohugepage = !opts->hugepage;
	for (slot = 0; slot < opts->slots; slot++) {
		uintptr_t address = (uintptr_t)backing->iovecs[slot].iov_base;

		if (!(address % required_alignment))
			backing->proof.aligned_slots++;
	}
	ret = read_smaps_proof(backing->base, backing->map_len,
			       &backing->proof.smaps);
	if (ret)
		return ret;
	if (resident_pages != page_count) {
		fprintf(stderr, "backing proof failed: only %" PRIu64
			"/%zu base pages resident\n", resident_pages, page_count);
		return -ENXIO;
	}
	if (backing->proof.aligned_slots != opts->slots) {
		fprintf(stderr, "backing proof failed: only %u/%u slots aligned to %"
			PRIu64 " bytes\n", backing->proof.aligned_slots, opts->slots,
			required_alignment);
		return -EADDRNOTAVAIL;
	}
	if (!backing->proof.smaps.covers_mapping) {
		fprintf(stderr, "backing proof failed: one smaps VMA does not cover "
			"the complete mapping\n");
		return -ERANGE;
	}
	if (backing->proof.smaps.kernel_page_kb != required_alignment / 1024 ||
	    backing->proof.smaps.mmu_page_kb != required_alignment / 1024) {
		fprintf(stderr,
			"backing proof failed: smaps KernelPageSize=%" PRIu64
			" kB MMUPageSize=%" PRIu64 " kB, expected %" PRIu64
			" kB\n", backing->proof.smaps.kernel_page_kb,
			backing->proof.smaps.mmu_page_kb,
			required_alignment / 1024);
		return -EPROTO;
	}
	if (opts->hugepage) {
		hugetlb_kb = backing->proof.smaps.private_hugetlb_kb +
			backing->proof.smaps.shared_hugetlb_kb;
		if (!backing->proof.smaps.vmflag_ht ||
		    hugetlb_kb < backing->map_len / 1024) {
			fprintf(stderr, "hugetlb proof failed: smaps ht=%d hugetlb=%"
				PRIu64 " kB mapping=%zu kB\n",
				backing->proof.smaps.vmflag_ht, hugetlb_kb,
				backing->map_len / 1024);
			return -EPROTO;
		}
	} else if (!backing->proof.smaps.vmflag_nh ||
		   backing->proof.smaps.anon_huge_kb) {
		fprintf(stderr, "normal-page proof failed: smaps nh=%d "
			"AnonHugePages=%" PRIu64 " kB\n",
			backing->proof.smaps.vmflag_nh,
			backing->proof.smaps.anon_huge_kb);
		return -EPROTO;
	}
	return 0;
}

static int write_all(int fd, const char *data, size_t length)
{
	while (length) {
		ssize_t written = write(fd, data, length);

		if (written < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (!written)
			return -EPIPE;
		data += written;
		length -= (size_t)written;
	}
	return 0;
}

static int read_control_byte(int fd, char expected)
{
	char byte;

	for (;;) {
		ssize_t count = read(fd, &byte, 1);

		if (count == 1)
			return byte == expected ? 0 : -EPROTO;
		if (!count)
			return -EPIPE;
		if (errno != EINTR)
			return -errno;
	}
}

static int measurement_begin(const struct options *opts,
			     struct barrier_state *state)
{
	int ret;

	state->enabled = opts->ready_fd >= 0;
	if (!state->enabled)
		return 0;
	ret = write_all(opts->ready_fd, "ready\n", sizeof("ready\n") - 1);
	if (ret)
		return ret;
	state->ready_emitted = true;
	ret = read_control_byte(opts->start_fd, 'S');
	if (!ret) {
		state->start_acknowledged = true;
		return 0;
	}
	/* Do not wait for F when S was invalid; make controller wakeup best effort. */
	if (!write_all(opts->ready_fd, "error\n", sizeof("error\n") - 1))
		state->outcome_emitted = true;
	return ret;
}

static int measurement_finish(const struct options *opts, bool complete,
			      struct barrier_state *state)
{
	const char *event = complete ? "done\n" : "error\n";
	int ret;

	state->timed_loop_complete = complete;
	if (!state->enabled)
		return 0;
	ret = write_all(opts->ready_fd, event, strlen(event));
	if (ret)
		return ret;
	state->outcome_emitted = true;
	ret = read_control_byte(opts->start_fd, 'F');
	if (!ret)
		state->finish_acknowledged = true;
	return ret;
}

static bool barrier_protocol_complete(const struct barrier_state *state)
{
	return !state->enabled ||
		(state->ready_emitted && state->start_acknowledged &&
		 state->outcome_emitted && state->finish_acknowledged);
}

static int monotonic_ns(uint64_t *value)
{
	struct timespec now;
	uint64_t seconds;

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return -errno;
	if (now.tv_sec < 0 || now.tv_nsec < 0)
		return -ERANGE;
	if (multiply_u64((uint64_t)now.tv_sec, UINT64_C(1000000000), &seconds) ||
	    seconds > UINT64_MAX - (uint64_t)now.tv_nsec)
		return -EOVERFLOW;
	*value = seconds + (uint64_t)now.tv_nsec;
	return 0;
}

/* Allocate a pool buffer of @len into buffer-table @slot (carried in plain SQE
 * fields so it works on the 128-byte NVMe ring). Returns the cqe res. */
static int alloc_iobuf(struct io_uring *ring, int fd, unsigned slot, unsigned len,
		       int strict)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
	struct io_uring_cqe *cqe;
	int res;

	if (!sqe)
		return -ENOSPC;
	memset(sqe, 0, 128);
	sqe->opcode = IORING_OP_URING_CMD;
	sqe->fd = fd;
	sqe->cmd_op = BLOCK_URING_CMD_ALLOC_IOBUF;
	sqe->addr = slot;			/* target slot */
	sqe->addr3 = len;			/* buffer length */
	sqe->len = strict ? BLOCK_URING_CMD_ALLOC_IOBUF_F_STRICT_PGSIZE : 0;
	res = io_uring_submit_and_wait(ring, 1);
	if (res < 0)
		return res;
	res = io_uring_wait_cqe(ring, &cqe);
	if (res < 0)
		return res;
	res = cqe->res;
	io_uring_cqe_seen(ring, cqe);
	return res > 0 ? -EPROTO : res;
}

static void set_fatal(struct run_result *result, const char *stage, int error)
{
	if (result->fatal_error)
		return;
	result->fatal_stage = stage;
	result->fatal_error = error < 0 ? error : -error;
}

static uint32_t load_ring_counter(const unsigned int *counter)
{
	return __atomic_load_n(counter, __ATOMIC_ACQUIRE);
}

static void free_slot_queue_init(struct free_slot_queue *queue,
				 uint32_t *storage, uint32_t capacity)
{
	queue->slots = storage;
	queue->capacity = capacity;
	queue->head = 0;
	queue->tail = 0;
	queue->count = capacity;
	for (uint32_t slot = 0; slot < capacity; slot++)
		storage[slot] = slot;
}

static int free_slot_queue_take(struct free_slot_queue *queue, uint32_t *slot)
{
	if (!queue->count)
		return -EAGAIN;
	*slot = queue->slots[queue->head];
	queue->head = (queue->head + 1U) % queue->capacity;
	queue->count--;
	return 0;
}

static int free_slot_queue_release(struct free_slot_queue *queue, uint32_t slot)
{
	if (slot >= queue->capacity || queue->count >= queue->capacity)
		return -EPROTO;
	queue->slots[queue->tail] = slot;
	queue->tail = (queue->tail + 1U) % queue->capacity;
	queue->count++;
	return 0;
}

static int run_workload(struct io_uring *ring, int fd, uint32_t nsid,
			const struct options *opts,
			const struct geometry *geometry,
			const struct user_backing *backing,
			uint64_t *command_times, uint16_t *command_slots,
			bool *slot_busy, struct free_slot_queue *free_slots,
			struct run_result *result)
{
	uint64_t window_start = 0, window_end = 0;
	int ret = 0;

	ret = monotonic_ns(&window_start);
	if (ret) {
		set_fatal(result, "window-start-clock", ret);
		goto timed_out;
	}
	while (result->completed < opts->count) {
		uint32_t batch_first = result->submitted;
		uint64_t batch_submit_ns;

		while (result->submitted < opts->count &&
		       result->submitted - result->completed < opts->qd) {
			uint32_t sequence = result->submitted;
			uint32_t slot;
			uint64_t trace_id;
			uint64_t slba;
			struct nvme_uring_cmd *command;
			struct io_uring_sqe *sqe;

			if (!free_slots->count)
				break;
			sqe = io_uring_get_sqe(ring);
			if (!sqe)
				break;
			ret = free_slot_queue_take(free_slots, &slot);
			if (ret || slot_busy[slot]) {
				set_fatal(result, "take-free-slot", ret ? ret : -EPROTO);
				goto timed_out;
			}
			memset(sqe, 0, 128);
			sqe->opcode = IORING_OP_URING_CMD;
			sqe->fd = fd;
			sqe->cmd_op = NVME_URING_CMD_IO;
			if (opts->fixed || opts->premap) {
				sqe->uring_cmd_flags = IORING_URING_CMD_FIXED;
				sqe->buf_index = (uint16_t)slot;
			}
			trace_id = opts->trace_base + sequence / opts->cmds_per_obj;
			sqe->user_data = (trace_id << 32) | sequence;
			command = (struct nvme_uring_cmd *)
				((char *)sqe + SQE_CMD_OFF);
			command->opcode = 0x02; /* NVM READ: no media modification. */
			command->nsid = nsid;
			command->addr = command_buffer_addr(opts,
				opts->premap ? NULL : backing->iovecs[slot].iov_base);
			command->data_len = opts->io_len;
			slba = (uint64_t)sequence * geometry->blocks_per_io;
			command->cdw10 = (uint32_t)slba;
			command->cdw11 = (uint32_t)(slba >> 32);
			command->cdw12 = geometry->blocks_per_io - 1U;

			slot_busy[slot] = true;
			command_slots[sequence] = (uint16_t)slot;
			if (!(result->touched_bitmap[slot / 8U] & (1U << (slot % 8U)))) {
				result->touched_bitmap[slot / 8U] |= 1U << (slot % 8U);
				result->touched_slots++;
			}
			result->submitted++;
		}
		if (batch_first == result->submitted &&
		    result->submitted == result->completed) {
			ret = -EDEADLK;
			set_fatal(result, "prepare-sqe", ret);
			goto timed_out;
		}
		if (batch_first != result->submitted) {
			ret = monotonic_ns(&batch_submit_ns);
			if (ret) {
				set_fatal(result, "command-submit-clock", ret);
				goto timed_out;
			}
			if (!batch_submit_ns)
				batch_submit_ns = 1;
			for (uint32_t sequence = batch_first;
			     sequence < result->submitted; sequence++)
				command_times[sequence] = batch_submit_ns;
		}

		ret = io_uring_submit_and_wait(ring, 1);
		if (ret < 0) {
			set_fatal(result, "submit-and-wait", ret);
			goto timed_out;
		}
		for (;;) {
			struct io_uring_cqe *cqe;
			uint32_t sequence, slot;
			uint64_t complete_ns, latency;

			ret = io_uring_peek_cqe(ring, &cqe);
			if (ret == -EAGAIN)
				break;
			if (ret < 0) {
				set_fatal(result, "peek-cqe", ret);
				goto timed_out;
			}
			sequence = (uint32_t)cqe->user_data;
			if (sequence >= opts->count || !command_times[sequence] ||
			    (command_times[sequence] & LATENCY_DONE_BIT)) {
				io_uring_cqe_seen(ring, cqe);
				ret = -EPROTO;
				set_fatal(result, "cqe-sequence", ret);
				goto timed_out;
			}
			slot = command_slots[sequence];
			if (!slot_busy[slot]) {
				io_uring_cqe_seen(ring, cqe);
				ret = -EPROTO;
				set_fatal(result, "cqe-slot-ownership", ret);
				goto timed_out;
			}
			ret = monotonic_ns(&complete_ns);
			if (ret) {
				io_uring_cqe_seen(ring, cqe);
				set_fatal(result, "command-complete-clock", ret);
				goto timed_out;
			}
			if (complete_ns < command_times[sequence]) {
				io_uring_cqe_seen(ring, cqe);
				ret = -ERANGE;
				set_fatal(result, "command-clock-order", ret);
				goto timed_out;
			}
			latency = complete_ns - command_times[sequence];
			if (latency & LATENCY_DONE_BIT) {
				io_uring_cqe_seen(ring, cqe);
				ret = -EOVERFLOW;
				set_fatal(result, "command-latency", ret);
				goto timed_out;
			}
			command_times[sequence] = latency | LATENCY_DONE_BIT;
			slot_busy[slot] = false;
			ret = free_slot_queue_release(free_slots, slot);
			if (ret) {
				io_uring_cqe_seen(ring, cqe);
				set_fatal(result, "release-free-slot", ret);
				goto timed_out;
			}
			if (cqe->res) {
				if (!result->errors)
					result->first_cqe_res = cqe->res;
				result->errors++;
			}
			io_uring_cqe_seen(ring, cqe);
			result->completed++;
		}
	}

timed_out:
	ret = monotonic_ns(&window_end);
	if (ret)
		set_fatal(result, "window-end-clock", ret);
	else if (window_end < window_start)
		set_fatal(result, "window-clock-order", -ERANGE);
	else
		result->elapsed_ns = window_end - window_start;
	result->sq_dropped_end = load_ring_counter(ring->sq.kdropped);
	result->cq_overflow_end = load_ring_counter(ring->cq.koverflow);
	if (result->sq_dropped_end < result->sq_dropped_start ||
	    result->cq_overflow_end < result->cq_overflow_start) {
		set_fatal(result, "ring-counter-wrap", -EOVERFLOW);
	} else {
		result->sq_dropped_delta = result->sq_dropped_end -
			result->sq_dropped_start;
		result->cq_overflow_delta = result->cq_overflow_end -
			result->cq_overflow_start;
		if (result->sq_dropped_end || result->cq_overflow_end)
			set_fatal(result, "ring-counter-nonzero", -EOVERFLOW);
	}
	if (!result->fatal_error && free_slots->count != opts->slots)
		set_fatal(result, "free-slot-accounting", -EBUSY);

	return result->fatal_error;
}

static void validate_slot_state(const struct options *opts,
				const bool *slot_busy,
				struct run_result *result)
{
	bool any_busy = false;

	for (uint32_t slot = 0; slot < opts->slots; slot++)
		any_busy |= slot_busy[slot];
	result->slot_validation_passed = !any_busy &&
		result->touched_slots == result->expected_touched_slots;
	if (any_busy)
		set_fatal(result, "slot-still-inflight", -EBUSY);
	else if (!result->slot_validation_passed)
		set_fatal(result, "touched-slot-validation", -EPROTO);
}

static int compare_u64(const void *left, const void *right)
{
	const uint64_t a = *(const uint64_t *)left;
	const uint64_t b = *(const uint64_t *)right;

	return (a > b) - (a < b);
}

static uint64_t latency_percentile(const uint64_t *samples, size_t count,
				   unsigned int percentile)
{
	size_t rank = (count * percentile + 99U) / 100U;

	return samples[rank ? rank - 1 : 0];
}

static int calculate_latency_stats(uint64_t *command_times, uint32_t count,
				   struct latency_stats *stats)
{
	long double sum = 0;

	memset(stats, 0, sizeof(*stats));
	for (uint32_t sequence = 0; sequence < count; sequence++) {
		if (!(command_times[sequence] & LATENCY_DONE_BIT))
			return -ENODATA;
		command_times[sequence] &= ~LATENCY_DONE_BIT;
		sum += command_times[sequence];
		if (command_times[sequence] > stats->max_ns)
			stats->max_ns = command_times[sequence];
	}
	qsort(command_times, count, sizeof(*command_times), compare_u64);
	stats->samples = count;
	stats->mean_ns = sum / count;
	stats->p50_ns = latency_percentile(command_times, count, 50);
	stats->p95_ns = latency_percentile(command_times, count, 95);
	stats->p99_ns = latency_percentile(command_times, count, 99);
	return 0;
}

static void json_string(FILE *out, const char *value)
{
	const unsigned char *cursor = (const unsigned char *)value;

	fputc('"', out);
	for (; *cursor; cursor++) {
		switch (*cursor) {
		case '"':
		case '\\':
			fputc('\\', out);
			fputc(*cursor, out);
			break;
		case '\b':
			fputs("\\b", out);
			break;
		case '\f':
			fputs("\\f", out);
			break;
		case '\n':
			fputs("\\n", out);
			break;
		case '\r':
			fputs("\\r", out);
			break;
		case '\t':
			fputs("\\t", out);
			break;
		default:
			if (*cursor < 0x20)
				fprintf(out, "\\u%04x", *cursor);
			else
				fputc(*cursor, out);
		}
	}
	fputc('"', out);
}

static void print_meminfo_json(FILE *out, const struct hugepage_meminfo *info)
{
	fprintf(out,
		"{\"valid\":%s,\"total\":%" PRIu64 ",\"free\":%" PRIu64
		",\"reserved\":%" PRIu64 ",\"surplus\":%" PRIu64
		",\"page_size_kb\":%" PRIu64 "}",
		info->valid ? "true" : "false", info->total, info->free,
		info->reserved, info->surplus, info->page_size_kb);
}

static void print_bitmap_json(FILE *out, const unsigned char *bitmap,
			      size_t bytes)
{
	fputc('"', out);
	for (size_t byte = 0; byte < bytes; byte++)
		fprintf(out, "%02x", bitmap[byte]);
	fputc('"', out);
}

static int print_run_json(FILE *out, const struct options *opts,
			  const struct geometry *geometry,
			  const struct user_backing *backing,
			  const struct hugepage_meminfo *before,
			  const struct hugepage_meminfo *after_setup,
			  const struct run_result *result,
			  const struct barrier_state *barrier, uint32_t nsid)
{
	const char *status = result->fatal_error ? "runtime-error" :
		(result->errors ? "io-error" : "ok");
	uint64_t successful = result->completed - result->errors;
	uint64_t successful_bytes = successful * opts->io_len;
	double seconds = (double)result->elapsed_ns / 1e9;
	double iops = seconds != 0.0 ? (double)successful / seconds : 0.0;
	double bytes_per_second = seconds != 0.0 ?
		(double)successful_bytes / seconds : 0.0;
	fputs("{\"schema\":\"nvme_uring_cmd_smoke/v1\",\"status\":", out);
	json_string(out, status);
	fputs(",\"mode\":", out);
	json_string(out, mode_name(opts));
	fputs(",\"device\":", out);
	json_string(out, opts->dev);
	fprintf(out,
		",\"nsid\":%u,\"count\":%u,\"qd\":%u,\"slots\":%u"
		",\"io_len\":%u,\"buffer_len\":%u,\"lba_size\":%u"
		",\"cmds_per_obj\":%u"
		",\"blocks_per_io\":%u,\"allocated_bytes\":%" PRIu64
		",\"requested_bytes\":%" PRIu64 ",\"last_lba_exclusive\":%"
		PRIu64 ",\"submitted\":%u,\"completed\":%u,\"errors\":%u"
		",\"successful_commands\":%" PRIu64
		",\"first_cqe_res\":%d,\"successful_bytes\":%" PRIu64
		",\"elapsed_ns\":%" PRIu64 ",\"iops\":%.6f"
		",\"bytes_per_second\":%.3f,\"trace_id_first\":%" PRIu64
		",\"trace_id_last\":%" PRIu64,
		nsid, opts->count, opts->qd, opts->slots, opts->io_len,
		opts->buffer_len, opts->lba_size, opts->cmds_per_obj,
		geometry->blocks_per_io,
		geometry->allocated_bytes, geometry->requested_bytes,
		geometry->last_lba_exclusive, result->submitted,
		result->completed, result->errors, successful, result->first_cqe_res,
		successful_bytes, result->elapsed_ns, iops, bytes_per_second,
		opts->trace_base, geometry->trace_last);
	fprintf(out,
		",\"fixed_registered\":%s,\"premap_requested\":%s"
		",\"strict_premap_requested\":%s,\"hugetlb\":%s"
		",\"dma_mapping_intent\":",
		(opts->fixed || opts->premap) ? "true" : "false",
		opts->premap ? "true" : "false",
		opts->strict_premap ? "true" : "false",
		opts->hugepage ? "true" : "false");
	json_string(out, opts->premap ? "retained-registration" : "per-command");
	fputs(",\"fixed_addr_semantics\":", out);
	json_string(out, fixed_addr_semantics(opts));
	fprintf(out,
		",\"barrier\":{\"enabled\":%s"
		",\"protocol\":\"ready-S-done-F-v1\""
		",\"ready_emitted\":%s,\"start_acknowledged\":%s"
		",\"outcome_emitted\":%s,\"timed_loop_outcome\":\"%s\""
		",\"finish_acknowledged\":%s,\"complete\":%s}"
		",\"latency_ns\":{\"samples\":%" PRIu64
		",\"mean\":%.3Lf,\"p50\":%" PRIu64 ",\"p95\":%" PRIu64
		",\"p99\":%" PRIu64 ",\"max\":%" PRIu64 "}"
		",\"slot_validation\":{\"reuse_guard\":true"
		",\"scheduler\":\"fifo-free-slot\",\"touched\":%u"
		",\"expected_touched\":%u,\"passed\":%s"
		",\"bitmap_encoding\":\"hex bytes; slot N is bit (N%%8) of byte N/8\""
		",\"touched_bitmap\":",
		barrier->enabled ? "true" : "false",
		barrier->ready_emitted ? "true" : "false",
		barrier->start_acknowledged ? "true" : "false",
		barrier->outcome_emitted ? "true" : "false",
		barrier->outcome_emitted ?
			(barrier->timed_loop_complete ? "done" : "error") : "none",
		barrier->finish_acknowledged ? "true" : "false",
		barrier_protocol_complete(barrier) ? "true" : "false",
		result->latency.samples,
		result->latency.mean_ns, result->latency.p50_ns,
		result->latency.p95_ns, result->latency.p99_ns,
		result->latency.max_ns, result->touched_slots,
		result->expected_touched_slots,
		result->slot_validation_passed ? "true" : "false");
	print_bitmap_json(out, result->touched_bitmap,
			  result->touched_bitmap_bytes);
	fprintf(out,
		"},\"ring_counters\":{\"sq_dropped_start\":%u"
		",\"sq_dropped_end\":%u,\"sq_dropped_delta\":%u"
		",\"cq_overflow_start\":%u,\"cq_overflow_end\":%u"
		",\"cq_overflow_delta\":%u,\"passed\":%s}"
		",\"backing_proof\":",
		result->sq_dropped_start, result->sq_dropped_end,
		result->sq_dropped_delta, result->cq_overflow_start,
		result->cq_overflow_end, result->cq_overflow_delta,
		(!result->sq_dropped_end && !result->cq_overflow_end) ?
			"true" : "false");
	if (opts->premap) {
		fputs("{\"kind\":\"blk-iobuf-kernel-pool-request\","
		      "\"allocation_cqes_ok\":true,"
		      "\"retained_dma_mapping_proven\":false}",
		      out);
	} else {
		const struct backing_proof *proof = &backing->proof;
		const struct smaps_proof *smaps = &proof->smaps;

		fprintf(out,
			"{\"kind\":\"%s\",\"mapping_bytes\":%zu"
			",\"system_page_bytes\":%" PRIu64
			",\"required_alignment_bytes\":%" PRIu64
			",\"aligned_slots\":%u,\"resident_pages\":%" PRIu64
			",\"total_pages\":%" PRIu64 ",\"madv_nohugepage\":%s"
			",\"smaps\":{\"found\":%s,\"covers_mapping\":%s"
			",\"vma_start\":%" PRIu64 ",\"vma_end\":%" PRIu64
			",\"kernel_page_kb\":%" PRIu64 ",\"mmu_page_kb\":%" PRIu64
			",\"anon_huge_kb\":%" PRIu64
			",\"private_hugetlb_kb\":%" PRIu64
			",\"shared_hugetlb_kb\":%" PRIu64
			",\"vmflag_ht\":%s,\"vmflag_nh\":%s}}",
			opts->hugepage ? "anonymous-hugetlb" : "anonymous-normal",
			backing->map_len, proof->system_page_bytes,
			proof->required_alignment_bytes, proof->aligned_slots,
			proof->resident_pages, proof->total_pages,
			proof->madv_nohugepage ? "true" : "false",
			smaps->found ? "true" : "false",
			smaps->covers_mapping ? "true" : "false",
			smaps->vma_start, smaps->vma_end, smaps->kernel_page_kb,
			smaps->mmu_page_kb, smaps->anon_huge_kb,
			smaps->private_hugetlb_kb, smaps->shared_hugetlb_kb,
			smaps->vmflag_ht ? "true" : "false",
			smaps->vmflag_nh ? "true" : "false");
	}
	fputs(",\"hugepages_before\":", out);
	print_meminfo_json(out, before);
	fputs(",\"hugepages_after_setup\":", out);
	print_meminfo_json(out, after_setup);
	fprintf(out, ",\"fatal_errno\":%d,\"fatal_stage\":",
		result->fatal_error ? -result->fatal_error : 0);
	if (result->fatal_stage)
		json_string(out, result->fatal_stage);
	else
		fputs("null", out);
	fputs("}\n", out);
	if (fflush(out) || ferror(out))
		return -EIO;
	return 0;
}

int main(int argc, char **argv)
{
	struct options opts = {
		.dev = DEFAULT_DEV,
		.count = DEFAULT_COUNT,
		.qd = DEFAULT_QD,
		.io_len = DEFAULT_IO_LEN,
		.lba_size = DEFAULT_LBA_SIZE,
		.cmds_per_obj = DEFAULT_CMDS_PER_OBJ,
		.trace_base = DEFAULT_TRACE_BASE,
		.ready_fd = -1,
		.start_fd = -1,
	};
	struct hugepage_meminfo hugepages_before = {};
	struct hugepage_meminfo hugepages_after_setup = {};
	struct io_uring_params params = {};
	struct user_backing backing = {};
	struct run_result result = {};
	struct geometry geometry = {};
	struct free_slot_queue free_slot_queue = {};
	struct barrier_state barrier = {};
	struct io_uring ring;
	uint64_t *command_times = NULL;
	uint32_t *free_slot_storage = NULL;
	uint16_t *command_slots = NULL;
	bool *slot_busy = NULL;
	bool buffers_registered = false;
	bool ring_ready = false;
	bool measurement_started = false;
	int exit_code = 1;
	int nsid = -1;
	int fd = -1;
	int ret;

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		fprintf(stderr, "ignore SIGPIPE: %s\n", strerror(errno));
		return 1;
	}
	ret = parse_options(argc, argv, &opts);
	if (ret > 0) {
		usage(stdout, argv[0]);
		return 0;
	}
	if (ret < 0) {
		usage(stderr, argv[0]);
		return 2;
	}
	ret = validate_options(&opts, &geometry);
	if (ret) {
		usage(stderr, argv[0]);
		return 2;
	}
	ret = read_hugepage_meminfo(&hugepages_before);
	if (ret) {
		fprintf(stderr, "read /proc/meminfo hugepage evidence: %s\n",
			strerror(-ret));
		goto cleanup;
	}

	fd = open(opts.dev, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "%s: %s\n", opts.dev, strerror(errno));
		goto cleanup;
	}
	nsid = ioctl(fd, NVME_IOCTL_ID);
	if (nsid <= 0) {
		int saved = nsid < 0 ? errno : ENODEV;

		fprintf(stderr,
			"NVME_IOCTL_ID failed: %s (is %s a /dev/ng namespace?)\n",
			strerror(saved), opts.dev);
		goto cleanup;
	}

	params.flags = IORING_SETUP_SQE128 | IORING_SETUP_CQE32;
	ret = io_uring_queue_init_params(opts.qd, &ring, &params);
	if (ret < 0) {
		fprintf(stderr, "io_uring_queue_init_params: %s\n", strerror(-ret));
		goto cleanup;
	}
	ring_ready = true;
	command_times = calloc(opts.count, sizeof(*command_times));
	command_slots = calloc(opts.count, sizeof(*command_slots));
	free_slot_storage = calloc(opts.slots, sizeof(*free_slot_storage));
	if (!command_times || !command_slots || !free_slot_storage) {
		fprintf(stderr, "allocate command/slot state: %s\n", strerror(errno));
		goto cleanup;
	}
	free_slot_queue_init(&free_slot_queue, free_slot_storage, opts.slots);
	slot_busy = calloc(opts.slots, sizeof(*slot_busy));
	result.touched_bitmap_bytes = (opts.slots + 7U) / 8U;
	result.expected_touched_slots = opts.count < opts.slots ?
		opts.count : opts.slots;
	result.touched_bitmap = calloc(result.touched_bitmap_bytes, 1);
	if (!slot_busy || !result.touched_bitmap) {
		fprintf(stderr, "allocate slot validation state: %s\n",
			strerror(errno));
		goto cleanup;
	}

	if (opts.premap) {
		ret = io_uring_register_buffers_sparse(&ring, opts.slots);
		if (ret < 0) {
			fprintf(stderr, "io_uring_register_buffers_sparse: %s\n",
				strerror(-ret));
			goto cleanup;
		}
		buffers_registered = true;
		for (uint32_t slot = 0; slot < opts.slots; slot++) {
			ret = alloc_iobuf(&ring, fd, slot, opts.buffer_len,
					   opts.strict_premap);
			if (ret < 0) {
				fprintf(stderr,
					"ALLOC_IOBUF slot %u: %s; provision "
					"nvme_core.iobuf_pool_folios/order and use a "
					"non-multipath-head /dev/ng path\n",
					slot, strerror(-ret));
				goto cleanup;
			}
		}
	} else {
		ret = allocate_user_backing(&opts, &geometry, &hugepages_before,
					    &backing);
		if (ret) {
			fprintf(stderr, "allocate %s backing: %s\n",
				opts.hugepage ? "hugetlb" : "normal-page",
				strerror(-ret));
			goto cleanup;
		}
		if (opts.fixed) {
			ret = io_uring_register_buffers(&ring, backing.iovecs,
						opts.slots);
			if (ret < 0) {
				fprintf(stderr,
					"io_uring_register_buffers (%" PRIu64
					" bytes; check RLIMIT_MEMLOCK): %s\n",
					geometry.allocated_bytes, strerror(-ret));
				goto cleanup;
			}
			buffers_registered = true;
		}
		ret = collect_backing_proof(&opts, &hugepages_before, &backing);
		if (ret) {
			fprintf(stderr, "collect backing proof: %s\n", strerror(-ret));
			goto cleanup;
		}
	}
	ret = read_hugepage_meminfo(&hugepages_after_setup);
	if (ret) {
		fprintf(stderr, "read post-setup /proc/meminfo: %s\n",
			strerror(-ret));
		goto cleanup;
	}
	result.sq_dropped_start = load_ring_counter(ring.sq.kdropped);
	result.cq_overflow_start = load_ring_counter(ring.cq.koverflow);
	if (result.sq_dropped_start || result.cq_overflow_start) {
		fprintf(stderr,
			"io_uring counters nonzero before measurement: "
			"sq_dropped=%u cq_overflow=%u\n",
			result.sq_dropped_start, result.cq_overflow_start);
		goto cleanup;
	}

	fprintf(stderr,
		"nvme_uring_cmd_smoke ready: mode=%s dev=%s nsid=%d qd=%u "
		"slots=%u io_len=%u buffer_len=%u allocated=%" PRIu64
		" required_lbas=%" PRIu64 "\n",
		mode_name(&opts), opts.dev, nsid, opts.qd, opts.slots,
		opts.io_len, opts.buffer_len, geometry.allocated_bytes,
		geometry.last_lba_exclusive);
	if (!opts.premap) {
		fprintf(stderr,
			"backing proof: aligned=%u/%u resident=%" PRIu64 "/%"
			PRIu64 " smaps_ht=%d smaps_nh=%d hugetlb_kB=%" PRIu64
			" AnonHugePages_kB=%" PRIu64 "\n",
			backing.proof.aligned_slots, opts.slots,
			backing.proof.resident_pages, backing.proof.total_pages,
			backing.proof.smaps.vmflag_ht,
			backing.proof.smaps.vmflag_nh,
			backing.proof.smaps.private_hugetlb_kb +
				backing.proof.smaps.shared_hugetlb_kb,
			backing.proof.smaps.anon_huge_kb);
	}

	ret = measurement_begin(&opts, &barrier);
	if (ret) {
		fprintf(stderr, "measurement start protocol failed: %s\n",
			strerror(-ret));
		goto cleanup;
	}
	measurement_started = true;
	ret = run_workload(&ring, fd, (uint32_t)nsid, &opts, &geometry, &backing,
			   command_times, command_slots, slot_busy,
			   &free_slot_queue, &result);
	{
		int barrier_ret = measurement_finish(&opts, !ret, &barrier);

		if (barrier_ret) {
			fprintf(stderr, "measurement finish protocol failed: %s\n",
				strerror(-barrier_ret));
			set_fatal(&result, "measurement-finish-protocol", barrier_ret);
		}
	}
	validate_slot_state(&opts, slot_busy, &result);
	if (!result.fatal_error) {
		ret = calculate_latency_stats(command_times, opts.count,
					      &result.latency);
		if (ret)
			set_fatal(&result, "latency-summary", ret);
	}

cleanup:
	/* When enabled, the F acknowledgement permits this teardown to begin. */
	if (buffers_registered && ring_ready) {
		ret = io_uring_unregister_buffers(&ring);
		if (ret < 0) {
			fprintf(stderr, "io_uring_unregister_buffers: %s\n",
				strerror(-ret));
			if (measurement_started)
				set_fatal(&result, "unregister-buffers", ret);
		}
	}
	if (ring_ready)
		io_uring_queue_exit(&ring);
	free(backing.iovecs);
	if (backing.base && munmap(backing.base, backing.map_len)) {
		ret = -errno;
		fprintf(stderr, "munmap backing: %s\n", strerror(-ret));
		if (measurement_started)
			set_fatal(&result, "munmap-backing", ret);
	}
	if (fd >= 0 && close(fd)) {
		ret = -errno;
		fprintf(stderr, "close device: %s\n", strerror(-ret));
		if (measurement_started)
			set_fatal(&result, "close-device", ret);
	}

	if (measurement_started) {
		ret = print_run_json(stdout, &opts, &geometry, &backing,
				     &hugepages_before, &hugepages_after_setup,
				     &result, &barrier, (uint32_t)nsid);
		if (ret)
			set_fatal(&result, "write-json", ret);
		fprintf(stderr,
			"nvme_uring_cmd_smoke: mode=%s submitted=%u completed=%u "
			"errors=%u elapsed_ns=%" PRIu64 " touched=%u/%u%s%s\n",
			mode_name(&opts), result.submitted, result.completed,
			result.errors, result.elapsed_ns, result.touched_slots,
			result.expected_touched_slots,
			result.fatal_stage ? " fatal_stage=" : "",
			result.fatal_stage ? result.fatal_stage : "");
		exit_code = result.fatal_error || result.errors ? 1 : 0;
	}
	free(result.touched_bitmap);
	free(slot_busy);
	free(free_slot_storage);
	free(command_slots);
	free(command_times);
	return exit_code;
}
