#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "cJSON.h"
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <time.h>
#include <limits.h>

static inline uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL
         + (uint64_t)ts.tv_nsec;
}

static inline int is_io_syscall(int nr)
{
    switch (nr) {
        case  0:  /* read      */
        case  1:  /* write     */
        case 17:  /* pread64   */
        case 18:  /* pwrite64  */
        case 19:  /* readv     */
        case 20:  /* writev    */
        case 74:  /* fsync     */
            return 1;
        default:
            return 0;
    }
}

#define MAX_PROCNAME 256
#define MAX_SYSCALLNAME 64
#define MAX_FILENAME 4096
#define MAX_IODIR 16
#define LINE_BUF (MAX_FILENAME + 512)
#define JSON_BUFFER_SIZE (MAX_FILENAME * 20)  // Large buffer for multi-line JSON objects
#define RING_BUF_SIZE  4096  /* number of ring buffer entries */
#define FD_MAP_BUCKETS 65536
#define MAX_FD  65536
#define MAX_TRACKED_PIDS 256   /* >= MAX_WORKERS; one fd_map per captured pid */

/* ------------------------------------------------------------------ *
 * Thread-aware replay
 * ------------------------------------------------------------------ *
 * The capture is produced by a multi-process / multi-threaded workload
 * (e.g. 8x VLLM::Worker_TP) where these processes submit I/O
 * concurrently.
 *
 * A single serial dispatcher replays every record one-at-a-time, hence
 * add multi threaded support by allocating each unique capture WID its
 * own dispatcher thread and ring buffer to allow concurrent issures on
 * replay. The fd_map / mmap tables ar keyed per-PID and all workers pace
 * against a single shared replay anchor
 * (CLOCK_MONOTONIC at t0) to preserve cross-processing order.
 * ------------------------------------------------------------------ */
#define MAX_WORKERS  256   /* max distinct captured pids replayed in parallel */

#ifndef IOV_MAX
#define IOV_MAX 1024   /* Linux kernel limit for iovec count */
#endif

/* enhance synchronization to handle workers exiting at different times.
 * flex_barrier solves this by tracking n_active (threads still alive)
 * separately from n_waiting (threads currently at the barrier).
 * When a thread exits it calls flex_barrier_unregister() which
 * decrements n_active and wakes any threads already waiting.
 * ─────────────────────────────────────────────────────────────── */
struct flex_barrier {
    pthread_mutex_t lock;
    pthread_cond_t  cond;
    int             n_total;     /* initial thread count              */
    int             n_active;    /* threads still alive               */
    int             n_waiting;   /* threads currently at barrier      */
    uint64_t        generation;  /* increments on each barrier release */
};

static void flex_barrier_init(struct flex_barrier *b, int n)
{
    memset(b, 0, sizeof(*b));
    pthread_mutex_init(&b->lock, NULL);
    pthread_cond_init (&b->cond, NULL);
    b->n_total   = n;
    b->n_active  = n;
    b->n_waiting = 0;
    b->generation = 0;
}

static void flex_barrier_destroy(struct flex_barrier *b)
{
    pthread_cond_destroy (&b->cond);
    pthread_mutex_destroy(&b->lock);
}

/* Call before each I/O syscall — blocks until all active workers arrive */
static void flex_barrier_wait(struct flex_barrier *b)
{
    pthread_mutex_lock(&b->lock);

    /* If only 1 worker left, no need to sync — just pass through */
    if (b->n_active <= 1) {
        pthread_mutex_unlock(&b->lock);
        return;
    }

    uint64_t my_gen = b->generation;
    b->n_waiting++;

    if (b->n_waiting >= b->n_active) {
        /* Last active thread to arrive — release everyone */
        b->n_waiting = 0;
        b->generation++;
        pthread_cond_broadcast(&b->cond);
    } else {
        /* Wait for either:
         *   a) all remaining active workers arrive (generation changes)
         *   b) another worker exits and n_active drops to n_waiting
         *      (unregister will broadcast)
         * Timeout of 10ms prevents permanent deadlock if something
         * goes wrong (e.g. a worker crashes without unregistering). */
        struct timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_nsec += 10000000LL;   /* +10ms */
        if (deadline.tv_nsec >= 1000000000LL) {
            deadline.tv_sec++;
            deadline.tv_nsec -= 1000000000LL;
        }
        while (b->generation == my_gen) {
            int rc = pthread_cond_timedwait(&b->cond, &b->lock, &deadline);
            if (rc == ETIMEDOUT) {
                /* Timeout: decrement waiting count and proceed.
                 * This handles the case where a worker exited without
                 * calling unregister (e.g. signal/crash).            */
                b->n_waiting--;
                pthread_mutex_unlock(&b->lock);
                return;
            }
        }
    }

    pthread_mutex_unlock(&b->lock);
}

/* Call once when a worker is done with ALL its records (before return) */
static void flex_barrier_unregister(struct flex_barrier *b)
{
    pthread_mutex_lock(&b->lock);
    b->n_active--;

    /* If the threads still waiting now equal all remaining active
     * threads, release them — they would wait forever otherwise.  */
    if (b->n_waiting > 0 && b->n_waiting >= b->n_active) {
        b->n_waiting = 0;
        b->generation++;
        pthread_cond_broadcast(&b->cond);
    }

    pthread_mutex_unlock(&b->lock);
}
/*
* define the syscall_opt struct
*/

typedef struct {
	uint64_t timestamp_ns;
	double timestamp_ms;
	int32_t pid;
	char process_name[MAX_PROCNAME];
	int32_t syscall_nr;
	char syscall_name[MAX_SYSCALLNAME];
	int32_t fd;
	int64_t size;
	int64_t offset;
	char filename[MAX_FILENAME];
	int32_t open_flags_hex;
	char open_flags_str[MAX_FILENAME];
	char io_direction[MAX_IODIR];
	int32_t ret;
	int32_t error_code;
} syscall_opt;

struct ring_buf{
        syscall_opt entries[RING_BUF_SIZE];
	uint32_t head;
	uint32_t tail;
	pthread_mutex_t lock;
	pthread_cond_t not_empty;
	pthread_cond_t not_full;
	volatile int shutdown;
};

int    ring_buf_init(struct ring_buf *rb);
void   ring_buf_destroy(struct ring_buf *rb);
uint32_t ring_buf_count(struct ring_buf *rb);
void    ring_buf_shutdown(struct ring_buf *rb);

int ring_buf_enqueue(struct ring_buf *rb, const syscall_opt *opt);
int ring_buf_dequeue(struct ring_buf *rb, syscall_opt *opt);

struct fd_map_entry {
	int32_t captured_fd;
	int32_t replayed_fds[64];  /* stack — handles concurrent threads
	                              opening same cap_fd simultaneously */
	int     stack_top;         /* index of top (-1 = empty)         */
	int     valid;
};

struct fd_map {
	struct fd_map_entry buckets[FD_MAP_BUCKETS];
	pthread_mutex_t lock;
};

typedef struct {
    uint32_t      pid;
    struct fd_map *map;
} pid_fdmap_entry_t;

static pid_fdmap_entry_t pid_fdmap_table[MAX_TRACKED_PIDS];


struct dispatcher_ctx {
	struct ring_buf *rb;
	struct fd_map *fdmap;
	struct mmap_map *mmap;
	int verify;
	int paced;
	/* shared replay timing anchor (set once, read by every worker) so
	 * all per-pid workers pace against the same wall-clock origin and
	 * cross-process ordering from the capture is preserved.            */
	uint64_t  capture_start_ns;   /* timestamp_ns of the very first record */
	uint64_t  replay_start_ns;    /* now_ns() captured at replay t0         */
	pthread_mutex_t *start_lock;  /* guards one-time init of the two fields */
	int      *start_done;         /* 0 until the anchor has been set        */
	uint32_t  worker_pid;         /* the captured pid this worker replays    */
	/* per-worker counters (summed by main at the end) */
	struct flex_barrier *write_barrier;
	uint64_t syscalls_total;
	uint64_t syscalls_replayed_ok;
	uint64_t syscalls_replayed_failed;
	uint64_t syscalls_skipped;
	uint64_t syscalls_failed_verification;
};

/* ── per-pid replay worker ──────────────────────────────────────────── */
struct replay_worker {
	uint32_t              pid;        /* captured pid (0 = free slot)        */
	struct ring_buf      *rb;         /* this worker's own queue             */
	pthread_t             tid;        /* the worker thread                   */
	struct dispatcher_ctx ctx;        /* per-worker dispatch context         */
	int                   started;    /* 1 once the thread is running        */
};

struct worker_pool {
	struct replay_worker workers[MAX_WORKERS];
	int                  count;
	/* shared, read-mostly state handed to every worker ctx */
	struct fd_map       *fdmap;
	struct mmap_map     *mmap;
	int                  verify;
	int                  paced;
	int                  serial;        /* 1 = legacy single-queue behaviour */
	uint64_t             capture_start_ns;
	uint64_t             replay_start_ns;
	pthread_mutex_t      start_lock;
	int                  start_done;
	struct flex_barrier write_barrier;   /* active when serial=0           */
        int                  barrier_inited;  /* 1 once barrier is ready to use */
};

/* define dispatcher */
void *dispatcher_thread(void *arg);
void fd_map_init(struct fd_map *fdmap);
int fd_map_get(struct fd_map *fdmap, int32_t captured_fd);
void fd_map_set(struct fd_map *fdmap, int32_t captured_fd, int32_t replayed_fd);
void fd_map_clear_fd(struct fd_map *fdmap, int32_t captured_fd, int32_t replayed_fd);
void fd_map_destroy(struct fd_map *fdmap);

/* ------------------------------------------------------------------ */
/* mmap address translation table                                      */
/*                                                                     */
/* mmap() returns a void* (8 bytes on x86-64) which does not fit in   */
/* syscall_opt.ret (int32_t).  The tracer encodes the captured return  */
/* address as a hex string in filename[]. On replay, each successful  */
/* mmap stores (captured_addr → replay_addr) here so that munmap can   */
/* later resolve the correct replay address to pass to munmap(2).      */
/* ------------------------------------------------------------------ */
#define MMAP_MAP_SIZE   1024    /* max concurrent mappings tracked */

struct mmap_entry {
    uint64_t    captured_addr;  /* key: address mmap returned at mmap original trace time */
    void       *replay_addr;    /* value: address mmap returned at replay time */
    size_t      length;         /* stored for sanity-check on munmap */
    int         valid;
};

struct mmap_map {
    struct mmap_entry   entries[MMAP_MAP_SIZE];
    pthread_mutex_t     lock;
};

/* ── pending map key: (pid, timestamp) uniquely identifies one mmap call ── */
typedef struct {
    uint32_t pid;
    uint32_t _pad;        // alignment
    uint64_t timestamp_ns;
} mmap_pending_key_t;


typedef struct {
    int    prot;
    int    map_flags;
    size_t mmap_len;
    int    resolved_fd;
    loff_t offset;
} mmap_pending_t;

/* ── internal hash map ─────────────────────────────────────────────────── */
/* simple open-addressing hash map; 1024 slots is enough for typical workloads */
#define MMAP_PENDING_MAX 1024

typedef struct {
    mmap_pending_key_t key;
    mmap_pending_t     val;
    bool               occupied;
} mmap_pending_slot_t;

static mmap_pending_slot_t mmap_pending_table[MMAP_PENDING_MAX];

/* The pending table is shared across worker threads.  Entry/exit for one
 * (pid,ts) are issued by the same worker in sequence, but different pids
 * run concurrently and share this open-addressed table, so guard the
 * structural operations with a lock. */
static pthread_mutex_t mmap_pending_lock = PTHREAD_MUTEX_INITIALIZER;

/* ── hash function ─────────────────────────────────────────────────────── */
static uint32_t mmap_pending_hash(uint32_t pid, uint64_t ts)
{
    uint64_t h = (uint64_t)pid * 2654435761ULL ^ ts;
    return (uint32_t)(h % MMAP_PENDING_MAX);
}


/* ── set ───────────────────────────────────────────────────────────────── */
static int mmap_pending_set(uint32_t pid, uint64_t timestamp_ns,
                            const mmap_pending_t *val)
{
    uint32_t idx = mmap_pending_hash(pid, timestamp_ns);

    pthread_mutex_lock(&mmap_pending_lock);
    /* linear probe for an empty or matching slot */
    for (uint32_t i = 0; i < MMAP_PENDING_MAX; i++) {
        mmap_pending_slot_t *s = &mmap_pending_table[(idx + i) % MMAP_PENDING_MAX];

        if (!s->occupied ||
            (s->key.pid == pid && s->key.timestamp_ns == timestamp_ns))
        {
            s->key.pid          = pid;
            s->key.timestamp_ns = timestamp_ns;
            s->key._pad         = 0;
            s->val              = *val;
            s->occupied         = true;
            pthread_mutex_unlock(&mmap_pending_lock);
            return 0;
        }

    }
    pthread_mutex_unlock(&mmap_pending_lock);

    fprintf(stderr, "[replayer] mmap_pending_set: table full\n");
    return -1;
}


/* ── get ───────────────────────────────────────────────────────────────── */
/* Copies the value into a thread-local buffer so the returned pointer is
 * never invalidated by a concurrent worker mutating the shared table. */
static __thread mmap_pending_t mmap_pending_tls;
static mmap_pending_t *mmap_pending_get(uint32_t pid, uint64_t timestamp_ns)
{
    uint32_t idx = mmap_pending_hash(pid, timestamp_ns);
    mmap_pending_t *result = NULL;

    pthread_mutex_lock(&mmap_pending_lock);
    for (uint32_t i = 0; i < MMAP_PENDING_MAX; i++) {
        mmap_pending_slot_t *s = &mmap_pending_table[(idx + i) % MMAP_PENDING_MAX];

        if (!s->occupied)
            break;   // empty slot = not found
        if (s->key.pid == pid && s->key.timestamp_ns == timestamp_ns) {
            mmap_pending_tls = s->val;
            result = &mmap_pending_tls;
            break;
        }
    }
    pthread_mutex_unlock(&mmap_pending_lock);
    return result;
}


/* ── clear ─────────────────────────────────────────────────────────────── */
static void mmap_pending_clear(uint32_t pid, uint64_t timestamp_ns)
{
    uint32_t idx = mmap_pending_hash(pid, timestamp_ns);

    pthread_mutex_lock(&mmap_pending_lock);
    for (uint32_t i = 0; i < MMAP_PENDING_MAX; i++) {
        mmap_pending_slot_t *s = &mmap_pending_table[(idx + i) % MMAP_PENDING_MAX];

        if (!s->occupied)
            break;   // not found

        if (s->key.pid == pid && s->key.timestamp_ns == timestamp_ns) {
            s->occupied = false;
            memset(&s->key, 0, sizeof(s->key));
            memset(&s->val, 0, sizeof(s->val));
            break;
        }
    }
    pthread_mutex_unlock(&mmap_pending_lock);
}


void  mmap_map_init(struct mmap_map *m);
void  mmap_map_destroy(struct mmap_map *m);
/* set/clear keyed by captured_addr */
int   mmap_map_set(struct mmap_map *m, uint64_t cap_addr,
                   void *replay_addr, size_t length);
void *mmap_map_get(struct mmap_map *m, uint64_t cap_addr);   /* NULL = not found */
void  mmap_map_clear(struct mmap_map *m, uint64_t cap_addr);


/* implements the parser */
#define REQUIRE_STR(key, dst, dstsz)     \
    do { \
	cJSON *_n = cJSON_GetObjectItemCaseSensitive(root, key); \
	if (!cJSON_IsString(_n) || _n->valuestring == NULL) { \
	    fprintf(stderr, "Error: Missing or invalid '%s' field\n", key); \
	    cJSON_Delete(json); \
	    return -1; \
	} \
	strncpy(dst, _n->valuestring, (dstsz) - 1); \
	dst[(dstsz) - 1] = '\0'; \
    } while (0)

#define REQUIRE_INT(key, dst, ctype)     \
    do { \
	cJSON *_n = cJSON_GetObjectItemCaseSensitive(root, key); \
	if (!cJSON_IsNumber(_n)) { \
	    fprintf(stderr, "Error: Missing or invalid '%s' field\n", key); \
	    cJSON_Delete(json); \
	    return -1; \
	} \
	/* Cast via uint32_t to correctly reinterpret eBPF u32 values     \
	 * (e.g. AT_FDCWD=4294967196 -> -100) before narrowing to ctype.  \
	 * Direct (int32_t)double cast for values > INT32_MAX is UB in C.  \
	 */ \
	uint64_t _raw = (uint64_t)(unsigned long long)_n->valuedouble; \
	if (sizeof(ctype) == 4) \
	    dst = (ctype)(int32_t)(uint32_t)_raw; \
	else \
	    dst = (ctype)(int64_t)_raw; \
    } while (0)

#define REQUIRE_DOUBLE(key, dst)     \
    do { \
	cJSON *_n = cJSON_GetObjectItemCaseSensitive(root, key); \
	if (!cJSON_IsNumber(_n)) { \
	    fprintf(stderr, "Error: Missing or invalid '%s' field\n", key); \
	    cJSON_Delete(json); \
	    return -1; \
	} \
	dst = _n->valuedouble; \
    } while (0)

#define OPTIONAL_STR(key, dst, dstsz, default_val)     \
    do { \
	cJSON *_n = cJSON_GetObjectItemCaseSensitive(root, key); \
	if (cJSON_IsString(_n) && _n->valuestring != NULL) { \
	    strncpy(dst, _n->valuestring, (dstsz) - 1); \
	    dst[(dstsz) - 1] = '\0'; \
	} else { \
	    strncpy(dst, default_val, (dstsz) - 1); \
	    dst[(dstsz) - 1] = '\0'; \
	} \
    } while (0)

/* Returns 0 on success , -1 on parse/validation error */
int callsys_from_json(const char *utf8_json, syscall_opt *opt)
{

   if (!utf8_json || !opt) return -1;

    cJSON *json = cJSON_Parse(utf8_json);
    if (!json) {
	const char *err = cJSON_GetErrorPtr();
	fprintf(stderr, "Error parsing JSON: %s\n", err ? err : "Unknown error");
	fprintf(stderr, "Failed input (first 200 chars): %.200s\n", utf8_json);
	return -1;
    }

    cJSON *root = json;

    /* Special handling for timestamp_ns - can be number or string */
    cJSON *ts = cJSON_GetObjectItemCaseSensitive(root, "timestamp_ns");

    if (cJSON_IsNumber(ts)) {
	opt->timestamp_ns = (uint64_t)ts->valuedouble;
    } else if (cJSON_IsString(ts)) {
	opt->timestamp_ns = strtoull(ts->valuestring, NULL, 10);
    } /*else if (ts == NULL) {
	fprintf(stderr, "Error: Missing or invalid 'timestamp_ns' field\n");
	cJSON_Delete(json);
	return -1;
    } */

    /* Parse all other required fields using standard macros */
    REQUIRE_DOUBLE("timestamp_ms", opt->timestamp_ms);
    REQUIRE_INT("pid", opt->pid, int32_t);
    REQUIRE_STR("process_name", opt->process_name, MAX_PROCNAME);
    REQUIRE_INT("syscall_nr", opt->syscall_nr, int32_t);
    REQUIRE_STR("syscall_name", opt->syscall_name, MAX_SYSCALLNAME);
    REQUIRE_INT("fd", opt->fd, int32_t);
    REQUIRE_INT("size", opt->size, int64_t);
    REQUIRE_INT("offset", opt->offset, int64_t);
    OPTIONAL_STR("filename", opt->filename, MAX_FILENAME, "");
    REQUIRE_STR("io_direction", opt->io_direction, MAX_IODIR);
    REQUIRE_INT("open_flags_hex", opt->open_flags_hex, int32_t);
    OPTIONAL_STR("open_flags_str", opt->open_flags_str, MAX_FILENAME, "");
    REQUIRE_INT("ret", opt->ret, int32_t);
    REQUIRE_INT("error_code", opt->error_code, int32_t);

    cJSON_Delete(json);
    return 0;
}

#undef REQUIRE_STR
#undef REQUIRE_INT
#undef REQUIRE_DOUBLE
#undef OPTIONAL_STR

int ring_buf_init(struct ring_buf *rb){
	memset(rb, 0, sizeof(struct ring_buf));
	pthread_mutex_init(&rb->lock, NULL);
	pthread_cond_init(&rb->not_empty, NULL);
	pthread_cond_init(&rb->not_full, NULL);
	return 0;
}

void ring_buf_destroy(struct ring_buf *rb){
	pthread_mutex_destroy(&rb->lock);
	pthread_cond_destroy(&rb->not_empty);
	pthread_cond_destroy(&rb->not_full);
}

uint32_t ring_buf_count(struct ring_buf *rb){
	pthread_mutex_lock(&rb->lock);
	uint32_t count = (rb->head - rb->tail) % RING_BUF_SIZE;
	pthread_mutex_unlock(&rb->lock);
	return count;
}

void ring_buf_shutdown(struct ring_buf *rb){
	pthread_mutex_lock(&rb->lock);
	rb->shutdown = 1;
	pthread_cond_broadcast(&rb->not_empty);
	pthread_cond_broadcast(&rb->not_full);
	pthread_mutex_unlock(&rb->lock);
}

int ring_buf_enqueue(struct ring_buf *rb, const syscall_opt *opt)
{
	pthread_mutex_lock(&rb->lock);
	while (((rb->head + 1) % RING_BUF_SIZE) == rb->tail && !rb->shutdown) {
		pthread_cond_wait(&rb->not_full, &rb->lock);
	}
	if (rb->shutdown) {
		pthread_mutex_unlock(&rb->lock);
		return -1;
	}
	rb->entries[rb->head] = *opt;
	rb->head = (rb->head + 1) % RING_BUF_SIZE;
	pthread_cond_signal(&rb->not_empty); /* wakes up at least one waiting consumer*/
	pthread_mutex_unlock(&rb->lock);
	return 0;
}

int ring_buf_dequeue(struct ring_buf *rb, syscall_opt *opt)
{
	pthread_mutex_lock(&rb->lock);
	while (rb->head == rb->tail && !rb->shutdown) {
		pthread_cond_wait(&rb->not_empty, &rb->lock);
	}
	/* If queue is empty (and shutdown set), signal exit; otherwise drain. */
	if (rb->head == rb->tail) {
		pthread_mutex_unlock(&rb->lock);
		return -1;
	}
	*opt = rb->entries[rb->tail];
	rb->tail = (rb->tail + 1) % RING_BUF_SIZE;
	pthread_cond_signal(&rb->not_full); /* wakes up at least one waiting producer*/
	pthread_mutex_unlock(&rb->lock);
	return 0;
}

/*implementation for fd_map functions */
/* fd_map - open-addressing hash map , linear probing */
static inline uint32_t _fd_hash(uint32_t key)
{
	return key & (FD_MAP_BUCKETS - 1); /* Simple hash: modulo bucket count */
}

void fd_map_init(struct fd_map *fdmap)
{
	if (!fdmap) return;
	memset(fdmap->buckets, 0, sizeof(fdmap->buckets));
	for (int i = 0; i < FD_MAP_BUCKETS; i++)
		fdmap->buckets[i].stack_top = -1;
	pthread_mutex_init(&fdmap->lock, NULL);
}

void fd_map_destroy(struct fd_map *fdmap)
{
	pthread_mutex_destroy(&fdmap->lock);
}

int fd_map_get(struct fd_map *fdmap, int32_t captured_fd)
{
	if (!fdmap) return -1;
	uint32_t slot = _fd_hash((uint32_t)captured_fd);
	int result    = -1;

	pthread_mutex_lock(&fdmap->lock);
	for (uint32_t i = 0; i < FD_MAP_BUCKETS; i++) {
		uint32_t idx = (slot + i) & (FD_MAP_BUCKETS - 1);
		struct fd_map_entry *entry = &fdmap->buckets[idx];
		if (!entry->valid)
			break;
		if (entry->captured_fd == captured_fd) {
			if (entry->stack_top >= 0)
				result = entry->replayed_fds[entry->stack_top];
			break;
		}
	}
	pthread_mutex_unlock(&fdmap->lock);
	return result;
}

void fd_map_set(struct fd_map *fdmap, int32_t captured_fd, int32_t replayed_fd)
{
	if (!fdmap) return;
	uint32_t slot = _fd_hash((uint32_t)captured_fd);

	pthread_mutex_lock(&fdmap->lock);
	for (uint32_t i = 0; i < FD_MAP_BUCKETS; i++) {
		uint32_t idx = (slot + i) & (FD_MAP_BUCKETS - 1);
		struct fd_map_entry *entry = &fdmap->buckets[idx];

		if (!entry->valid || entry->captured_fd == captured_fd) {
			entry->captured_fd = captured_fd;
			entry->valid       = 1;

			if (replayed_fd < 0) {
				/* close — pop top of stack */
				if (entry->stack_top >= 0)
					entry->stack_top--;
				if (entry->stack_top < 0)
					entry->valid = 0;
			} else {
				/* open — push onto stack */
				if (entry->stack_top < 63) {
					entry->stack_top++;
					entry->replayed_fds[entry->stack_top] = replayed_fd;
				} else {
					fprintf(stderr,
						"[replayer] fd_map stack full "
						"cap_fd=%d\n", captured_fd);
					entry->replayed_fds[entry->stack_top] = replayed_fd;
				}
			}
			break;
		}
	}
	pthread_mutex_unlock(&fdmap->lock);
}

/* Pop a specific replayed_fd from the stack on close.
 * Used instead of fd_map_set(fdmap, cap_fd, -1) so that
 * concurrent threads each closing their own replay_fd
 * only remove their own entry rather than blindly popping
 * the top regardless of which thread is closing. */
void fd_map_clear_fd(struct fd_map *fdmap, int32_t captured_fd,
                     int32_t replayed_fd)
{
	if (!fdmap) return;
	uint32_t slot = _fd_hash((uint32_t)captured_fd);

	pthread_mutex_lock(&fdmap->lock);
	for (uint32_t i = 0; i < FD_MAP_BUCKETS; i++) {
		uint32_t idx = (slot + i) & (FD_MAP_BUCKETS - 1);
		struct fd_map_entry *entry = &fdmap->buckets[idx];

		if (!entry->valid)
			break;

		if (entry->captured_fd == captured_fd) {
			/* find and remove the specific replayed_fd */
			for (int j = entry->stack_top; j >= 0; j--) {
				if (entry->replayed_fds[j] == replayed_fd) {
					/* shift remaining entries down */
					for (int k = j; k < entry->stack_top; k++)
						entry->replayed_fds[k] =
							entry->replayed_fds[k + 1];
					entry->stack_top--;
					if (entry->stack_top < 0)
						entry->valid = 0;
					break;
				}
			}
			break;
		}
	}
	pthread_mutex_unlock(&fdmap->lock);
}

/* ── per-pid fd_map lookup/create ─────────────────────────────────── */
/* Now called from multiple worker threads concurrently, so the shared
 * pid_fdmap_table must be guarded.  Each pid's fd_map is only mutated by
 * its own worker; this lock only protects table slot allocation/lookup. */
static pthread_mutex_t pid_fdmap_table_lock = PTHREAD_MUTEX_INITIALIZER;

static struct fd_map *get_fdmap_for_pid(uint32_t pid)
{
    pthread_mutex_lock(&pid_fdmap_table_lock);
    for (int i = 0; i < MAX_TRACKED_PIDS; i++) {
        if (pid_fdmap_table[i].pid == pid) {
            struct fd_map *m = pid_fdmap_table[i].map;
            pthread_mutex_unlock(&pid_fdmap_table_lock);
            return m;
        }
    }
    for (int i = 0; i < MAX_TRACKED_PIDS; i++) {
        if (pid_fdmap_table[i].pid == 0) {
            pid_fdmap_table[i].pid = pid;
            pid_fdmap_table[i].map = calloc(1, sizeof(struct fd_map));
            fd_map_init(pid_fdmap_table[i].map);
            fprintf(stderr,
                "[replayer] new fd_map for pid=%u (slot %d)\n", pid, i);
            struct fd_map *m = pid_fdmap_table[i].map;
            pthread_mutex_unlock(&pid_fdmap_table_lock);
            return m;
        }
    }
    pthread_mutex_unlock(&pid_fdmap_table_lock);
    fprintf(stderr, "[replayer] pid_fdmap_table full\n");
    return NULL;
}

static void free_all_pid_fdmaps(void)
{
    for (int i = 0; i < MAX_TRACKED_PIDS; i++) {
        if (pid_fdmap_table[i].pid != 0) {
            fd_map_destroy(pid_fdmap_table[i].map);
            free(pid_fdmap_table[i].map);
            pid_fdmap_table[i].pid = 0;
            pid_fdmap_table[i].map = NULL;
        }
    }
}

/* ================================================================== */
/* mmap address translation table                                      */
/* ================================================================== */

void mmap_map_init(struct mmap_map *m)
{
    memset(m->entries, 0, sizeof(m->entries));
    pthread_mutex_init(&m->lock, NULL);
}

void mmap_map_destroy(struct mmap_map *m)
{
    pthread_mutex_destroy(&m->lock);
}

int mmap_map_set(struct mmap_map *m, uint64_t cap_addr,
                 void *replay_addr, size_t length)
{
    pthread_mutex_lock(&m->lock);
    /* reuse existing slot for same captured addr (re-mmap after munmap) */
    for (int i = 0; i < MMAP_MAP_SIZE; i++) {
        if (m->entries[i].valid && m->entries[i].captured_addr == cap_addr) {
            m->entries[i].replay_addr = replay_addr;
            m->entries[i].length     = length;
            pthread_mutex_unlock(&m->lock);
            return 0;
        }
    }
    /* find a free slot */
    for (int i = 0; i < MMAP_MAP_SIZE; i++) {
        if (!m->entries[i].valid) {
            m->entries[i].captured_addr = cap_addr;
            m->entries[i].replay_addr   = replay_addr;
            m->entries[i].length        = length;
            m->entries[i].valid         = 1;
            pthread_mutex_unlock(&m->lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&m->lock);
    fprintf(stderr, "[replayer] mmap_map full (MMAP_MAP_SIZE=%d)\n",
            MMAP_MAP_SIZE);
    return -ENOMEM;
}

void *mmap_map_get(struct mmap_map *m, uint64_t cap_addr)
{
    pthread_mutex_lock(&m->lock);
    for (int i = 0; i < MMAP_MAP_SIZE; i++) {
        if (m->entries[i].valid && m->entries[i].captured_addr == cap_addr) {
            void *r = m->entries[i].replay_addr;
            pthread_mutex_unlock(&m->lock);
            return r;
        }
    }
    pthread_mutex_unlock(&m->lock);
    return NULL;
}

void mmap_map_clear(struct mmap_map *m, uint64_t cap_addr)
{
    pthread_mutex_lock(&m->lock);
    for (int i = 0; i < MMAP_MAP_SIZE; i++) {
        if (m->entries[i].valid && m->entries[i].captured_addr == cap_addr) {
            m->entries[i].valid = 0;
            break;
        }
    }
    pthread_mutex_unlock(&m->lock);
}

/*
 * Parse a captured mmap address stored as a hex string in filename[].
 * Accepts "0x7f..." or plain hex digits.  Returns 0 on parse failure.
 */
static uint64_t parse_hex_addr(const char *s)
{
    char *end;
    uint64_t v;

    if (!s || s[0] == '\0')
        return 0;

    errno = 0;
    v = strtoull(s, &end, 16);
    if (end == s || errno != 0)
        return 0;

    while (*end == ' ' || *end == '\t' || *end == '\n' ||
           *end == '\r' || *end == '\f' || *end == '\v') {
        end++;
    }

    if (*end != '\0')
        return 0;
    return v;
}

/*
 * parse_mmap_flags — split open_flags_str[] on '|' and accumulate
 * prot and MAP_* flag values.
 *
 * Recognised tokens (case-sensitive, as written by strace / eBPF tracers):
 *   prot  : PROT_READ  PROT_WRITE  PROT_EXEC  PROT_NONE
 *   flags : MAP_SHARED  MAP_PRIVATE  MAP_ANONYMOUS  MAP_ANON
 *           MAP_FIXED  MAP_POPULATE  MAP_LOCKED  MAP_HUGETLB
 *           MAP_NORESERVE  MAP_STACK  MAP_GROWSDOWN
 *
 * Unknown tokens are logged and skipped; the function always succeeds.
 */
static void parse_mmap_flags(const char *str, int *prot_out, int *flags_out)
{
    char buf[MAX_FILENAME];
    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    *prot_out  = 0;
    *flags_out = 0;

    if (!str || str[0] == '\0')
        return;

    /*
     * Hex format: "0xPPPPPPPP:0xFFFFFFFF"
     * Generated by BPF probe hex encoding.
     */
    unsigned int p = 0, f = 0;
    if (sscanf(str, "0x%x:0x%x", &p, &f) == 2) {
        *prot_out  = (int)p;
        *flags_out = (int)f;
        return;
    }

    char *saveptr = NULL;
    char *tok = strtok_r(buf, "|", &saveptr); /* used to separate the tokens in a continuous string with | as delimiter */
    while (tok) {
        /* trim leading/trailing spaces */
        while (*tok == ' ') tok++;
        char *e = tok + strlen(tok) - 1;
        while (e > tok && *e == ' ') *e-- = '\0';

        if      (!strcmp(tok, "PROT_READ"))     *prot_out  |= PROT_READ;
        else if (!strcmp(tok, "PROT_WRITE"))    *prot_out  |= PROT_WRITE;
        else if (!strcmp(tok, "PROT_EXEC"))     *prot_out  |= PROT_EXEC;
        else if (!strcmp(tok, "PROT_NONE"))     *prot_out  |= PROT_NONE;
        else if (!strcmp(tok, "MAP_SHARED"))    *flags_out |= MAP_SHARED;
        else if (!strcmp(tok, "MAP_PRIVATE"))   *flags_out |= MAP_PRIVATE;
        else if (!strcmp(tok, "MAP_ANONYMOUS") ||
                 !strcmp(tok, "MAP_ANON"))      *flags_out |= MAP_ANONYMOUS;
        else if (!strcmp(tok, "MAP_FIXED"))     *flags_out |= MAP_FIXED;
        else if (!strcmp(tok, "MAP_POPULATE"))  *flags_out |= MAP_POPULATE;
        else if (!strcmp(tok, "MAP_LOCKED"))    *flags_out |= MAP_LOCKED;
        else if (!strcmp(tok, "MAP_HUGETLB"))   *flags_out |= MAP_HUGETLB;
        else if (!strcmp(tok, "MAP_NORESERVE")) *flags_out |= MAP_NORESERVE;
        else if (!strcmp(tok, "MAP_STACK"))     *flags_out |= MAP_STACK;
        else if (!strcmp(tok, "MAP_GROWSDOWN")) *flags_out |= MAP_GROWSDOWN;
        else
            fprintf(stderr,
                    "[replayer] parse_mmap_flags: unknown token '%s'\n", tok);

        tok = strtok_r(NULL, "|", &saveptr);
    }
}

/* generates a replayed fd based on the fd of the captured syscall */
static int resolve_fd(struct fd_map *fdmap, const syscall_opt *opt)
{
    int replayed_fd = -1;
    if (opt->fd >=0 && opt->fd < MAX_FD)
        replayed_fd = fd_map_get(fdmap, opt->fd);

    return replayed_fd;

}
long dispatch_one(const syscall_opt *opt, struct mmap_map *m)
{
    long ret = -1;
    void *buf = NULL;

   /* ── get per-pid fd_map ── */
    struct fd_map *pidmap = get_fdmap_for_pid((uint32_t)opt->pid);
    if (!pidmap) return -2;

    int replayed_fd = resolve_fd(pidmap, opt);
    if (replayed_fd < 0 && opt->syscall_nr != 2 && opt->syscall_nr != 257 && opt->syscall_nr != 11
        && opt->syscall_nr != 9) {
	fprintf(stderr,
        "[replayer] SKIP-FDMAP ts=%lu pid=%u %-12s fd=%d\n",
        (unsigned long)opt->timestamp_ns,
        opt->pid, opt->syscall_name, opt->fd);
	return -2;  /* Skip: fd not mapped for this operation */
    }

    switch (opt->syscall_nr) {
	case 0: /* read */
	    if (replayed_fd >= 0) {
		buf = calloc(1, opt->size);
		if (!buf)
		    return -ENOMEM;
		ret = read(replayed_fd, buf, (size_t)opt->size);
		free(buf); buf = NULL;
	        }
	        break;
	case 1: /*write*/
	    if (replayed_fd >= 0) {
		buf = calloc(1, opt->size);
		if (!buf)
		    return -ENOMEM;
		ret = write(replayed_fd, buf, (size_t)opt->size);
		free(buf); buf = NULL;
	        }
	        break;
	case 2: /*open*/
		ret = open(opt->filename, opt->open_flags_hex, 0644);
		if (ret >= 0)
		    fd_map_set(pidmap, opt->ret, (int32_t) ret); /* map captured retval fd -> replayed fd */
	        break;
	case 3: /* close */
	        if (replayed_fd < 0)
			return -2;
		ret = close(replayed_fd);
		if (ret == 0)
			fd_map_clear_fd(pidmap, opt->fd, replayed_fd);
		break;
	case 8: /*lseek*/
	        if ((int)opt->fd == -1 && opt->size == 1) { /*skip lseek exit tracepoint */
                        return -2;
                }

                if (replayed_fd < 0) {
                        fprintf(stderr,
                        "[replayer] lseek ts=%lu: fd=%d not in fd_map, skipping\n",
                        (unsigned long)opt->timestamp_ns, opt->fd);
                        return -2;
               }

		int whence = (int)opt->open_flags_hex;
		off_t result = lseek(replayed_fd, (off_t)opt->offset, whence);
                if (result == (off_t)-1) {
                        ret = -1;
                        break;
                }

                ret = (long)result;
	        break;
	case 9: /* mmap*/
	        if (opt->filename[0] == '\0')
                        goto case_mmap_entry;
                else
                        goto case_mmap_exit;
	        break;
        case 11: { /* munmap */
	/*
         * filename[] carries the hex address of the mapping to unmap
         * (same encoding the tracer used for the paired mmap entry).
         */
                uint64_t cap_addr = parse_hex_addr(opt->filename);
                if (cap_addr == 0) {
                     fprintf(stderr,
                    "[replayer] munmap ts=%lu: no address in filename[], "
                    "skipping\n", (unsigned long)opt->timestamp_ns);
                     return -2;  /* skipped */
               }

               void *replay_addr = mmap_map_get(m, cap_addr);
               if (!replay_addr) {
                     fprintf(stderr,
                    "[replayer] munmap ts=%lu: cap=0x%016lx not in mmap_map "
                    "(mmap not seen?), skipping\n",
                    (unsigned long)opt->timestamp_ns,
                    (unsigned long)cap_addr);
                    return -2;  /* skipped */
              }

              ret = munmap(replay_addr, (size_t)opt->size);
              if (ret == 0) {
                      mmap_map_clear(m, cap_addr);
                      fprintf(stderr,
                    "[replayer] munmap cap=0x%016lx replay=%p  len=%ld  OK\n",
                    (unsigned long)cap_addr, replay_addr, (long)opt->size);
                }

	        break;
	}
	case 17: /*pread64 */
	        if (replayed_fd >= 0 ){
		        buf = calloc(1, opt->size);
		        if (!buf) {
		             return -ENOMEM;
		}
		ret = pread(replayed_fd, buf, (size_t)opt->size, (off_t)opt->offset);
		free(buf); buf = NULL;
	       }
	        break;
	case 18: /*pwrite64 */
	    if (replayed_fd >= 0 ) {
		buf = calloc(1, opt->size);
		if (!buf) {
		    return -ENOMEM;
		}
		ret = pwrite(replayed_fd, buf, (size_t)opt->size, (off_t)opt->offset);
		free(buf); buf = NULL;
	       }
	       break;
	case 19: /*readv*/
	case 20: /*writev*/
	        if (replayed_fd < 0) {
                        fprintf(stderr,
                        "[replayer] %s ts=%lu: fd=%d not in fd_map, skipping\n",
                         opt->syscall_name,
                        (unsigned long)opt->timestamp_ns, opt->fd);
                        return -2;
                }

                int iovcnt = (int)opt->size;
                if (iovcnt <= 0 || iovcnt > IOV_MAX) {
                        fprintf(stderr,
                        "[replayer] %s ts=%lu: invalid iovcnt=%d skipping\n",
                        opt->syscall_name,
                        (unsigned long)opt->timestamp_ns, iovcnt);
                        return -2;
                }

                /*
                * Entry-only probe — ret is always -1, cannot derive iov_len.
                * Use fixed 4096 per vector.
                */
                size_t iov_len = 4096;

                struct iovec *iov = calloc(iovcnt, sizeof(struct iovec));
                if (!iov)
                        return -1;

                int alloc_count = 0;
                for (int i = 0; i < iovcnt; i++) {
                        iov[i].iov_base = malloc(iov_len);
                        if (!iov[i].iov_base) {
                                for (int j = 0; j < alloc_count; j++)
                                free(iov[j].iov_base);
                                free(iov);
                                return -1;
                       }
                       iov[i].iov_len = iov_len;
                       alloc_count++;
                }
	        if (opt->syscall_nr == 19)
                        ret = readv(replayed_fd, iov, iovcnt);
                else
                        ret = writev(replayed_fd, iov, iovcnt);

                for (int i = 0; i < alloc_count; i++)
                        free(iov[i].iov_base);
                free(iov);

                ret =  (ret < 0) ? -1 : ret;
	        break;
	case 74: /*fsync */
	        if (replayed_fd >= 0) {
		        ret = fsync(replayed_fd);
	                }
	        break;
        case 257: /** openat  */
		{ /* openat */
                int dirfd;
	        int open_flags  = opt->open_flags_hex;
	        if (opt->filename[0] == '/') {
		        dirfd = AT_FDCWD;
		        printf("[replayer] openat ts=%lu: absolute path, dirfd is ignored\n", (unsigned long)opt->timestamp_ns);
		} else if (opt->fd == AT_FDCWD) {        /* -100, parsed correctly by JSON */
                        dirfd = AT_FDCWD;
                } else if (opt->fd >= 0) {
                        dirfd = fd_map_get(pidmap, opt->fd);
                        if (dirfd < 0) {
                                fprintf(stderr,
                                "[replayer] openat ts=%lu: dirfd=%d not in fd_map, "
                                "skipping\n",
                                (unsigned long)opt->timestamp_ns, opt->fd);
                                return -2;
                }
               } else {
                        fprintf(stderr,
                        "[replayer] openat ts=%lu: unexpected dirfd=%d, skipping\n",
                        (unsigned long)opt->timestamp_ns, opt->fd);
                        return -2;
                }
	       if (strncmp(opt->filename, "/sys/",  5) == 0 ||
                        strncmp(opt->filename, "/proc/", 6) == 0) {
                        open_flags  &= ~O_DIRECTORY;   // no-op if O_DIRECTORY not set — always safe
               }

                ret = openat(dirfd, opt->filename, open_flags, 0644);
                if (ret >= 0) {
                /*
                * opt->ret is the fd the kernel assigned during capture.
                * Map it to our replayed fd so subsequent syscalls using
                * this fd (read/write/mmap) can resolve it.
                * NOTE: opt->ret=0 is suspicious — stdin — but map it anyway
                * since the captured workload may have had stdin closed.
                */
                if (opt->ret >= 0) {
                        fd_map_set(pidmap, opt->ret, ret); /*was fdmap*/
                        fprintf(stderr,
                        "[replayer] openat '%s' cap_fd=%d → replay_fd=%ld\n",
                        opt->filename, opt->ret, ret);
                }
            } else {
               fprintf(stderr,
               "[replayer] openat '%s' failed: %s\n",
               opt->filename, strerror(errno));
               ret = -1;
        }
        break;
}
}
    goto mmap_done;  /* non-mmap syscalls skip the mmap handling below */

case_mmap_entry:
        int prot      = 0;
        int map_flags = 0;
        parse_mmap_flags(opt->open_flags_str, &prot, &map_flags);
        if (map_flags == 0) {
            if (opt->open_flags_str[0] != '\0') {
                fprintf(stderr,
                    "[replayer] mmap entry ts=%lu: no recognised mmap flags in '%s', "
                    "using defaults (PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS)\n",
                    (unsigned long)opt->timestamp_ns, opt->open_flags_str);
            }
            prot      = PROT_READ | PROT_WRITE;
            map_flags = MAP_PRIVATE | MAP_ANONYMOUS;
        }

       size_t mmap_len = (opt->size > 0) ? (size_t)opt->size : (size_t)1;
       printf(" replayer mmap entry mmap_len and opt->size %zu %zu\n", mmap_len, (size_t)opt->size);

       /* Resolve fd at entry time while fd_map is still valid */
        int resolved_fd = -1;
        if (!(map_flags & MAP_ANONYMOUS)) {
                if (opt->fd == -1 || opt->fd == 0) {
                map_flags |= MAP_ANONYMOUS;
                resolved_fd = -1;
        } else {
                resolved_fd = fd_map_get(pidmap, opt->fd);
                if (resolved_fd < 0) {
                fprintf(stderr,
                    "[replayer] mmap entry ts=%lu: fd=%d not in fd_map, "
                    "skipping\n",
                    (unsigned long)opt->timestamp_ns, opt->fd);
                return -2;
                }
           }
        }

        /*
        * filename[] is empty at entry — no return address yet.
        * Store parsed args in pending map keyed by (pid, timestamp)
        * for the exit record to consume.
        */
        mmap_pending_t pending = {
                .prot       = prot,
                .map_flags  = map_flags,
                .mmap_len   = mmap_len,
                .resolved_fd = resolved_fd,
                .offset     = opt->offset,
        };
        mmap_pending_set(opt->pid, opt->timestamp_ns, &pending);
	fprintf(stderr,
                "[replayer] mmap_pending_set: pid=%u ts=%lu\n",
                opt->pid, (unsigned long)opt->timestamp_ns);

        ret = 0;
	goto mmap_done;

case_mmap_exit:
        fprintf(stderr,
                "[replayer] mmap_pending_get: pid=%u ts=%lu\n",
                opt->pid, (unsigned long)opt->timestamp_ns);
	mmap_pending_t *p = mmap_pending_get(opt->pid, opt->timestamp_ns);
        if (!p) {
                fprintf(stderr,
                "[replayer] mmap exit ts=%lu: no matching entry record for "
                "pid=%u, skipping\n",
                (unsigned long)opt->timestamp_ns, opt->pid);
                 return -2;
        }
	/* guard — zero mmap_len means corrupted/skipped entry */
        if (p->mmap_len == 0) {
         fprintf(stderr,
                "[replayer] mmap exit ts=%lu: mmap_len=0, skipping\n",
                (unsigned long)opt->timestamp_ns);
        mmap_pending_clear(opt->pid, opt->timestamp_ns);
        return -2;
   }
        mmap_pending_t pending_p = *p;
	mmap_pending_clear(opt->pid, opt->timestamp_ns); /* clear early to avoid stale entry if replay fails */

	/*strip flags while debugging that cause operation not permitted*/
	pending_p.map_flags &= ~MAP_FIXED;   /* 0x10 */
        pending_p.map_flags &= ~0x0800;      /* MAP_DENYWRITE */

	/*
        * Validate resolved_fd — if invalid or closed force MAP_ANONYMOUS.
        * Handles stale fds from failed library openat (ENOENT).
        * fd=0 placeholder in exit records also caught here.
        */
        int fd_valid = 0;
        if (pending_p.resolved_fd >= 0) {
           struct stat st;
           if (fstat(pending_p.resolved_fd, &st) == 0)
                fd_valid = 1;
       }
        if (!fd_valid && !(pending_p.map_flags & MAP_ANONYMOUS)) {
              fprintf(stderr,
            "[replayer] mmap exit ts=%lu: resolved_fd=%d invalid "
             "— forcing MAP_ANONYMOUS\n", (unsigned long)opt->timestamp_ns,
        pending_p.resolved_fd);
        pending_p.map_flags   |=  MAP_ANONYMOUS;
        pending_p.map_flags   &= ~MAP_SHARED;
        pending_p.map_flags   |=  MAP_PRIVATE;
        pending_p.resolved_fd  =  -1;
        pending_p.offset       =  0;
    }

	fprintf(stderr,
		"[replayer] mmap_exit debug: pid=%u ts=%lu prot=0x%x flags=0x%x "
		"len=%zu fd=%d offset=%ld\n",
		opt->pid, (unsigned long)opt->timestamp_ns,
		pending_p.prot, pending_p.map_flags, pending_p.mmap_len,
		pending_p.resolved_fd, (long)pending_p.offset);

	/* cap_addr is the kernel-assigned address from the original run */
        uint64_t cap_addr = parse_hex_addr(opt->filename);

        /* replay the mmap */
        void *addr = mmap(NULL,
                      pending_p.mmap_len,
                      pending_p.prot,
                      pending_p.map_flags,
                      pending_p.resolved_fd,
                      (off_t)pending_p.offset);
        int mmap_errno = errno;

        if (addr == MAP_FAILED) {
                fprintf(stderr,
                "[replayer] mmap exit ts=%lu: mmap() failed: %s\n",
                (unsigned long)opt->timestamp_ns, strerror(mmap_errno));
                ret = -1;
		goto mmap_done;
        }

        if (cap_addr != 0) {
                if (mmap_map_set(m, cap_addr, addr, pending_p.mmap_len) < 0) {
                        munmap(addr, pending_p.mmap_len);
                        ret = -1;
                        goto mmap_done;
               }
               fprintf(stderr,
                        "[replayer] mmap  cap=0x%016lx → replay=%p  len=%zu\n",
                        (unsigned long)cap_addr, addr, pending_p.mmap_len);
        }

        ret = 0;
        goto mmap_done;

mmap_done:
    if (buf)
	free(buf);

    return ret;
}

/* ── worker pool: one dispatcher thread + queue per captured pid ─────── */

static void worker_pool_init(struct worker_pool *wp,
                             struct fd_map *fdmap, struct mmap_map *mmap,
                             int verify, int paced, int serial,
                             uint64_t capture_start_ns)
{
    memset(wp, 0, sizeof(*wp));
    wp->fdmap            = fdmap;
    wp->mmap             = mmap;
    wp->verify           = verify;
    wp->paced            = paced;
    wp->serial           = serial;
    wp->capture_start_ns = capture_start_ns;
    wp->replay_start_ns  = 0;
    wp->start_done       = 0;
    wp->barrier_inited   = 0;
    pthread_mutex_init(&wp->start_lock, NULL);
}

static void worker_pool_init_barrier(struct worker_pool *wp, int n_pids)
{
    /* Barrier only makes sense in thread-aware mode with ≥2 workers.
     * In serial mode (serial=1) everything runs on one thread so
     * a barrier would deadlock waiting for threads that never arrive. */
    if (wp->serial || n_pids < 2)
        return;
    flex_barrier_init(&wp->write_barrier, n_pids);
    wp->barrier_inited = 1;
    fprintf(stderr,
            "[replayer] I/O barrier enabled: %d workers will synchronise "
            "on read/write/fsync syscalls\n", n_pids);
}

/*
 * Return the worker that should replay records for captured `pid`,
 * creating + starting it on first sight.  In --serial mode every pid
 * collapses onto a single worker (slot 0), reproducing the legacy
 * single-threaded behaviour for A/B comparison.
 */
static struct replay_worker *worker_pool_get(struct worker_pool *wp, uint32_t pid)
{
    uint32_t key = wp->serial ? 0u : pid;

    for (int i = 0; i < wp->count; i++)
        if (wp->workers[i].pid == key)
            return &wp->workers[i];

    if (wp->count >= MAX_WORKERS) {
        /* Pool exhausted — fold onto slot 0 so we never drop records.   */
        fprintf(stderr,
                "[replayer] worker pool full (%d), folding pid=%u onto worker 0\n",
                MAX_WORKERS, pid);
        return &wp->workers[0];
    }

    struct replay_worker *w = &wp->workers[wp->count];
    w->pid = key;
    w->rb  = calloc(1, sizeof(struct ring_buf));
    if (!w->rb) {
        fprintf(stderr, "[replayer] OOM allocating ring buffer for pid=%u\n", pid);
        return NULL;
    }
    ring_buf_init(w->rb);

    w->ctx.rb               = w->rb;
    w->ctx.fdmap            = wp->fdmap;
    w->ctx.mmap             = wp->mmap;
    w->ctx.verify           = wp->verify;
    w->ctx.paced            = wp->paced;
    w->ctx.capture_start_ns = wp->capture_start_ns;
    w->ctx.replay_start_ns  = 0;
    w->ctx.start_lock       = &wp->start_lock;
    w->ctx.start_done       = &wp->start_done;
    w->ctx.worker_pid       = key;
    w->ctx.write_barrier    = wp->barrier_inited ? &wp->write_barrier : NULL;

    pthread_create(&w->tid, NULL, dispatcher_thread, &w->ctx);
    w->started = 1;
    wp->count++;
    return w;
}

/* Signal every worker queue to drain, join all threads, sum counters. */
static void worker_pool_finish(struct worker_pool *wp, struct dispatcher_ctx *totals)
{
    for (int i = 0; i < wp->count; i++)
        if (wp->workers[i].started)
            ring_buf_shutdown(wp->workers[i].rb);

    for (int i = 0; i < wp->count; i++) {
        if (!wp->workers[i].started)
            continue;
        pthread_join(wp->workers[i].tid, NULL);
        struct dispatcher_ctx *c = &wp->workers[i].ctx;
        totals->syscalls_total               += c->syscalls_total;
        totals->syscalls_replayed_ok         += c->syscalls_replayed_ok;
        totals->syscalls_replayed_failed     += c->syscalls_replayed_failed;
        totals->syscalls_skipped             += c->syscalls_skipped;
        totals->syscalls_failed_verification += c->syscalls_failed_verification;
    }
}

static void worker_pool_destroy(struct worker_pool *wp)
{
    for (int i = 0; i < wp->count; i++) {
        if (wp->workers[i].rb) {
            ring_buf_destroy(wp->workers[i].rb);
            free(wp->workers[i].rb);
            wp->workers[i].rb = NULL;
        }
    }
    if (wp->barrier_inited)
        flex_barrier_destroy(&wp->write_barrier);
    pthread_mutex_destroy(&wp->start_lock);
}

void *dispatcher_thread(void *arg)
{
    struct dispatcher_ctx *ctx = (struct dispatcher_ctx *)arg;
    struct ring_buf       *rb  = ctx->rb;
    syscall_opt            op;

    for (;;) {
        int rc = ring_buf_dequeue(rb, &op);
        if (rc == -1 && ring_buf_count(rb) == 0)
            break;  /* Shutdown and queue empty */
        if (rc != 0)
            continue;  /* Empty, waiting or error */

	/*
         * Pace against a SHARED replay anchor so that every per-pid
         * worker measures elapsed time from the same wall-clock origin
         * and the same capture origin.  This keeps cross-process
         * ordering intact: a record captured 5ms after t0 is issued
         * ~5ms after replay t0 regardless of which worker owns it,
         * so concurrent captured I/O stays concurrent on replay and
         * the block layer can plug/merge as it did originally.
        */
        if (ctx->paced) {
            /* one-time, race-free initialisation of the shared anchor */
            if (!*ctx->start_done) {
                pthread_mutex_lock(ctx->start_lock);
                if (!*ctx->start_done) {
                    ctx->replay_start_ns  = now_ns();
                    /* capture_start_ns is pre-seeded by main() to the
                     * global minimum timestamp across all records.    */
                    *ctx->start_done = 1;
                }
                pthread_mutex_unlock(ctx->start_lock);
            }

            uint64_t capture_elapsed_ns =
                (op.timestamp_ns > ctx->capture_start_ns)
                ? (op.timestamp_ns - ctx->capture_start_ns) : 0;

            uint64_t replay_elapsed_ns =
                now_ns() - ctx->replay_start_ns;

            /* If we are ahead of the original timeline: sleep.
             * If we are behind (slow disk / long syscall): skip
             * the sleep and catch up immediately.              */
            if (capture_elapsed_ns > replay_elapsed_ns) {
                uint64_t sleep_ns =
                    capture_elapsed_ns - replay_elapsed_ns;

                if (sleep_ns > 1000000000ULL)
                    sleep_ns = 1000000000ULL;

                struct timespec ts = {
                    .tv_sec  = (time_t)(sleep_ns / 1000000000ULL),
                    .tv_nsec = (long)  (sleep_ns % 1000000000ULL)
                };
                nanosleep(&ts, NULL);
            }
        }

        ctx->syscalls_total++;

        /* In thread-aware mode (write_barrier != NULL): synchronise all
         * workers before each I/O syscall so concurrent captured writes
         * are replayed concurrently — reproducing the page-cache
         * coalescing that produced large Q events in the original trace.
         * Barrier is a no-op in serial mode (write_barrier == NULL).   */
        if (ctx->write_barrier != NULL && is_io_syscall(op.syscall_nr))
            flex_barrier_wait(ctx->write_barrier);

        errno = 0;
        long actual_ret = dispatch_one(&op, ctx->mmap);
        int  actual_err = errno;

        if (actual_ret == -2) {
            /* skipped: addr/fd not mapped, or unsupported op */
            ctx->syscalls_skipped++;
        } else if (actual_ret == -1) {
            fprintf(stderr,
                    "[replayer] FAIL ts=%-16lu pid=%-6d %-12s "
                    "fd=%-4d size=%-8ld off=%-8ld "
                    "errno=%d (%s) filename='%s'\n",
                    (unsigned long)op.timestamp_ns,
                    op.pid, op.syscall_name,
                    op.fd, (long)op.size, (long)op.offset,
                    actual_err, strerror(actual_err), op.filename);
            ctx->syscalls_failed_verification++;
        } else {
	  /*
         * Syscall succeeded — check mismatch BEFORE printing OK.
         * Skip mismatch check for syscalls whose return values
         * legitimately differ between capture and replay:
         *   mmap(9)/munmap(11) — address will always differ
         *   open(2)/openat(257) — fd number will always differ
         */
        int is_mismatch = 0;
        if (ctx->verify &&
            op.syscall_nr != 9  && op.syscall_nr != 11 &&
            op.syscall_nr != 2  && op.syscall_nr != 257 &&
	    op.ret != -1) { /* if captured ret is  -1 then it means entry only probe so cant consider that mismatch*/

            if (actual_ret != (long)op.ret) {
                is_mismatch = 1;
            }
        }

        if (is_mismatch) {
            /* print MISMATCH only when captured and replay have non negative return values */
            fprintf(stderr,
                    "[replayer] MISMATCH ts=%-16lu pid=%-6d %-12s "
                    "fd=%-4d size=%-8ld off=%-8ld "
                    "got ret=%-6ld expected ret=%-6d filename='%s'\n",
                    (unsigned long)op.timestamp_ns,
                    op.pid, op.syscall_name,
                    op.fd, (long)op.size, (long)op.offset,
                    actual_ret, op.ret, op.filename);
            ctx->syscalls_replayed_failed++;
        } else {
            /* exact match or exempted syscall — print OK */
            fprintf(stderr,
                    "[replayer] OK   ts=%-16lu pid=%-6d %-12s "
                    "fd=%-4d size=%-8ld off=%-8ld "
                    "got ret=%-6ld\n",
                    (unsigned long)op.timestamp_ns,
                    op.pid, op.syscall_name,
                    op.fd, (long)op.size, (long)op.offset,
                    actual_ret);
            ctx->syscalls_replayed_ok++;
        }
    }
}
    /* Unregister from barrier BEFORE printing "finished".
     * This wakes any threads waiting at the barrier so they
     * are not blocked on a thread that has already exited. */
    if (ctx->write_barrier != NULL)
        flex_barrier_unregister(ctx->write_barrier);

    fprintf(stderr,
            "[replayer] dispatcher finished — "
            "total=%-6lu ok=%-6lu failed=%-6lu skipped=%-6lu mismatch=%-6lu\n",
            (unsigned long)ctx->syscalls_total,
            (unsigned long)ctx->syscalls_replayed_ok,
            (unsigned long)ctx->syscalls_failed_verification,
            (unsigned long)ctx->syscalls_skipped,
            (unsigned long)ctx->syscalls_replayed_failed);
    return NULL;
}
/* main */

int main(int argc, char *argv[])
{

	const char *json_file = "final_replay.json";
	int paced = 0;
	int serial = 0;   /* default: thread-aware (one worker per captured pid) */

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--paced") == 0) {
			paced = 1;
		} else if (strcmp(argv[i], "--serial") == 0) {
			serial = 1;          /* legacy single-thread mode for A/B */
		} else if (strcmp(argv[i], "--per-process") == 0) {
			serial = 0;          /* explicit; this is the default     */
		} else if (argv[i][0] != '-') {
			json_file = argv[i];
		}
	}

	FILE *fp = fopen(json_file, "r");

	if (!fp) {
		fprintf(stderr, "Error opening file '%s'\n", json_file);
		return -1;
	}
	printf("[main] Starting syscall replayer -file=%s paced=%s mode=%s\n",
	       json_file, paced ? "yes" : "no",
	       serial ? "serial(legacy)" : "per-process(thread-aware)");

	char line[LINE_BUF];
	char *json_buffer = calloc(1, JSON_BUFFER_SIZE);
	if (!json_buffer) {
		fprintf(stderr, "Error: failed to allocate json_buffer\n");
		fclose(fp);
		return -1;
	}
	size_t json_buf_used = 0;
	int lineno = 0;
	int errors = 0;
	int brace_count = 0;  // Track opening/closing braces
	int in_object = 0;    // Flag to know if we're inside a JSON object
	struct fd_map   *fdmap = calloc(1, sizeof(struct fd_map));
	struct mmap_map *mmap = calloc(1, sizeof(struct mmap_map));
	struct dispatcher_ctx totals = {0};
	struct worker_pool wpool;

	if (!fdmap || !mmap) {
		fprintf(stderr, "Error: failed to allocate fd_map or mmap \n");
		free(fdmap);
		free((mmap));
		fclose(fp);
		return -1;
	}

	/* Initialize buffers */
	memset(line, 0, sizeof(line));

	fd_map_init(fdmap);
	mmap_map_init(mmap);

	/* ------------------------------------------------------------------ *
	 * Pre-pass: find the global minimum timestamp across all records.
	 * In thread-aware mode every per-pid worker must pace against the
	 * SAME capture origin, otherwise each worker would anchor on its own
	 * first record and cross-process ordering (hence concurrency, hence
	 * block-layer merging) would be lost.  This pass is cheap: it only
	 * scans for the timestamp_ns field, it does not build records.
	 * ------------------------------------------------------------------ */
	uint64_t capture_start_ns = UINT64_MAX;
	if (paced) {
		char pline[LINE_BUF];
		while (fgets(pline, sizeof(pline), fp)) {
			char *p = strstr(pline, "\"timestamp_ns\"");
			if (!p) continue;
			p = strchr(p, ':');
			if (!p) continue;
			p++;
			while (*p == ' ' || *p == '\t' || *p == '"') p++;
			uint64_t ts = strtoull(p, NULL, 10);
			if (ts > 0 && ts < capture_start_ns)
				capture_start_ns = ts;
		}
		if (capture_start_ns == UINT64_MAX)
			capture_start_ns = 0;
		rewind(fp);
	} else {
		capture_start_ns = 0;
	}

	worker_pool_init(&wpool, fdmap, mmap, /*verify=*/1, paced, serial,
	                 capture_start_ns);

	if (!serial) {
        uint32_t seen_pids[MAX_WORKERS];
        int      seen_count = 0;
        char     pline[LINE_BUF];

        while (fgets(pline, sizeof(pline), fp)) {
            char *p = strstr(pline, "\"pid\"");
            if (!p) continue;
            p = strchr(p, ':');
            if (!p) continue;
            uint32_t pid = (uint32_t)strtoul(p + 1, NULL, 10);
            if (pid == 0) continue;
            int found = 0;
            for (int i = 0; i < seen_count; i++)
                if (seen_pids[i] == pid) { found = 1; break; }
            if (!found && seen_count < MAX_WORKERS)
                seen_pids[seen_count++] = pid;
        }
        rewind(fp);

        fprintf(stderr, "[replayer] found %d unique pids\n", seen_count);
        worker_pool_init_barrier(&wpool, seen_count);
       }

	while(fgets(line, sizeof(line), fp)) {
		++lineno;

		// Skip empty lines and whitespace-only lines
		if (line[0] == '\n' || line[0] == '\r' || line[0] == '\0')
		   continue;

		// Count braces to detect complete JSON objects
		for (int i = 0; line[i] != '\0'; i++) {
			if (line[i] == '{') {
				brace_count++;
				in_object = 1;
			} else if (line[i] == '}') {
				brace_count--;
			}
		}

		// Accumulate lines into buffer
		if (in_object) {
			size_t line_len = strlen(line);
			if (json_buf_used + line_len >= JSON_BUFFER_SIZE - 1) {
				fprintf(stderr, "Warning: JSON buffer full at line %d, resetting\n", lineno);
				json_buffer[0] = '\0';
				json_buf_used = 0;
				in_object = 0;
				brace_count = 0;
				continue;
			}
			memcpy(json_buffer + json_buf_used, line, line_len);
			json_buf_used += line_len;
			json_buffer[json_buf_used] = '\0';
		}

		// When braces balance (brace_count == 0), we have a complete JSON object
		if (in_object && brace_count == 0) {
			// Remove trailing newlines/carriage returns from buffer
			size_t len = strlen(json_buffer);
			while (len > 0 && (json_buffer[len - 1] == '\n' || json_buffer[len - 1] == '\r')) {
				json_buffer[--len] = '\0';
			}

			// Parse the complete JSON object
			syscall_opt *entry = calloc(1, sizeof(syscall_opt));
			if (!entry) {
				fprintf(stderr, "Error allocating memory for entry\n");
				json_buffer[0] = '\0';
				in_object = 0;
				continue;
			}

			if (callsys_from_json(json_buffer, entry) == 0) {
				/* filter out sys_exit tracepoint as ret and error code not needed for replay */
				if ((int)entry->fd == -1      &&
                                        entry->size   == 1       &&
                                        entry->offset == 0       &&
                                        entry->filename[0] == '\0') {
                                        free(entry);
                                        //continue;
					goto reset;
                                }
				/* Route the parsed entry to the worker that owns its
				 * captured pid.  Records for the same pid stay in
				 * timestamp order (the trace is ordered); records for
				 * different pids run on independent threads so the
				 * captured concurrency is reproduced.               */
				struct replay_worker *w =
					worker_pool_get(&wpool, (uint32_t)entry->pid);
				if (!w) {
					fprintf(stderr,
						"Error: no worker for pid=%d (line %d)\n",
						entry->pid, lineno);
				} else if (ring_buf_enqueue(w->rb, entry) != 0) {
					fprintf(stderr, "Error enqueuing entry to ring buffer\n");
				}
				free(entry); /* ring buffer copies by value; ptr no longer needed */
			} else {
				fprintf(stderr, "Error parsing JSON object starting at line %d\n", lineno);
				errors++;
				free(entry);
			}
		   reset:
			// Reset for next object
			json_buffer[0] = '\0';
			json_buf_used = 0;
			in_object = 0;
		}
	}

	fclose(fp);

	if (errors > 0) {
		fprintf(stderr, "JSON parsing finished with %d errors\n", errors);
	} else {
		printf("JSON parsing finished successfully\n");
	}

	/* Drain every worker queue, join all worker threads, and aggregate. */
	worker_pool_finish(&wpool, &totals);

	fprintf(stderr,
	        "[replayer] ALL WORKERS DONE — workers=%d "
	        "total=%-6lu ok=%-6lu failed=%-6lu skipped=%-6lu mismatch=%-6lu\n",
	        wpool.count,
	        (unsigned long)totals.syscalls_total,
	        (unsigned long)totals.syscalls_replayed_ok,
	        (unsigned long)totals.syscalls_failed_verification,
	        (unsigned long)totals.syscalls_skipped,
	        (unsigned long)totals.syscalls_replayed_failed);

	free_all_pid_fdmaps();
        mmap_map_destroy(mmap);
	fd_map_destroy(fdmap);
	worker_pool_destroy(&wpool);
	free(fdmap);
	free(mmap);
	free(json_buffer);
	printf("[main] replay complete.\n");

	return errors > 0 ? 1 : 0;
}
