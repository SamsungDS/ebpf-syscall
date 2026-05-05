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
#include <stdbool.h>


#define MAX_PROCNAME 256
#define MAX_SYSCALLNAME 64
#define MAX_FILENAME 4096
#define MAX_IODIR 16
#define LINE_BUF (MAX_FILENAME + 512)
#define JSON_BUFFER_SIZE (MAX_FILENAME * 20)  // Large buffer for multi-line JSON objects
#define RING_BUF_SIZE  4096  /* number of ring buffer entries */
#define FD_MAP_BUCKETS 65536
#define MAX_FD  65536
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
	char filename[MAX_FILENAME];   /* is derived only from openat syscall */
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
	int32_t replayed_fd;
	int valid;
};

struct fd_map {
	struct fd_map_entry buckets[FD_MAP_BUCKETS];
	pthread_mutex_t lock;
};

struct dispatcher_ctx {
	struct ring_buf *rb;
	struct fd_map *fdmap;
	struct mmap_map *mmap;
	int verify;
	uint64_t syscalls_total;
	uint64_t syscalls_replayed_ok;
	uint64_t syscalls_replayed_failed;
	uint64_t syscalls_skipped;
	uint64_t syscalls_failed_verification;
};

/* define dispatcher */
void *dispatcher_thread(void *arg);
void fd_map_init(struct fd_map *fdmap);
int fd_map_get(struct fd_map *fdmap, int32_t captured_fd);
void fd_map_set(struct fd_map *fdmap, int32_t captured_fd, int32_t replayed_fd);
void fd_map_destroy(struct fd_map *fdmap);

/* ------------------------------------------------------------------ */
/* mmap address translation table                                      */
/*                                                                     */
/* mmap() returns a void* (8 bytes on x86-64) which does not fit in   */
/* syscall_opt.ret (int32_t).  The tracer encodes the captured return  */
/* address as a hex string in filename[].  On replay, each successful  */
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
            return 0;
        }
    }

    fprintf(stderr, "[replayer] mmap_pending_set: table full\n");
    return -1;
}


/* ── get ───────────────────────────────────────────────────────────────── */
static mmap_pending_t *mmap_pending_get(uint32_t pid, uint64_t timestamp_ns)
{
    uint32_t idx = mmap_pending_hash(pid, timestamp_ns);

    for (uint32_t i = 0; i < MMAP_PENDING_MAX; i++) {
        mmap_pending_slot_t *s = &mmap_pending_table[(idx + i) % MMAP_PENDING_MAX];

        if (!s->occupied)
            return NULL;   // empty slot = not found

        if (s->key.pid == pid && s->key.timestamp_ns == timestamp_ns)
            return &s->val;
    }

    return NULL;
}


/* ── clear ─────────────────────────────────────────────────────────────── */
static void mmap_pending_clear(uint32_t pid, uint64_t timestamp_ns)
{
    uint32_t idx = mmap_pending_hash(pid, timestamp_ns);

    for (uint32_t i = 0; i < MMAP_PENDING_MAX; i++) {
        mmap_pending_slot_t *s = &mmap_pending_table[(idx + i) % MMAP_PENDING_MAX];

        if (!s->occupied)
            return;   // not found

        if (s->key.pid == pid && s->key.timestamp_ns == timestamp_ns) {
            s->occupied = false;
            memset(&s->key, 0, sizeof(s->key));
            memset(&s->val, 0, sizeof(s->val));
            return;
        }
    }
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

static void callsys_printf(const syscall_opt *s)
{
    printf("timestamp_ns: %llu\n",(unsigned long long) s->timestamp_ns);
    printf("timestamp_ms: %.3f\n", s->timestamp_ms);
    printf("pid: %d\n", s->pid);
    printf("process_name: %s\n", s->process_name);
    printf("syscall_nr: %d\n", s->syscall_nr);
    printf("syscall_name: %s\n", s->syscall_name);
    printf("fd: %d\n", s->fd);
    printf("size: %ld\n", s->size);
    printf("offset: %ld\n", s->offset);
    printf("filename: %s\n", s->filename[0] != '\0' ? s->filename : "(empty)");
    printf("io_direction: %s\n", s->io_direction);
    printf("open_flags_hex: 0x%x\n", s->open_flags_hex);
    printf("open_flags_str: %s\n", s->open_flags_str[0] != '\0' ? s->open_flags_str : "(empty)");
    printf("ret: %d\n", s->ret);
    printf("error_code: %d\n", s->error_code);

}

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
	memset(fdmap->buckets , 0 , sizeof(fdmap->buckets));
	pthread_mutex_init(&fdmap->lock, NULL);
}

void fd_map_destroy(struct fd_map *fdmap)
{
	pthread_mutex_destroy(&fdmap->lock);
}

int fd_map_get(struct fd_map *fdmap, int32_t captured_fd)
{
	if (!fdmap) return -1;
	uint32_t key = (uint32_t)captured_fd;
	uint32_t slot = _fd_hash(key);
	int result  = -1;

	pthread_mutex_lock(&fdmap->lock);

	for (uint32_t i = 0; i < FD_MAP_BUCKETS; i++) {
		uint32_t idx = (slot + i) & (FD_MAP_BUCKETS - 1);
		struct fd_map_entry *entry = &fdmap->buckets[idx];
		if (!entry->valid) {
			break; /* Not found */
		}
		if (entry->valid && entry->captured_fd == captured_fd) {
			result = entry->replayed_fd;
			break;
		}
	}

	pthread_mutex_unlock(&fdmap->lock);
	return result; /* Not found */
}

void fd_map_set(struct fd_map *fdmap, int32_t captured_fd, int32_t replayed_fd)
{
	if (!fdmap) return;
	uint32_t key = (uint32_t)captured_fd;
	uint32_t slot = _fd_hash(key);

	pthread_mutex_lock(&fdmap->lock);

	for (uint32_t i = 0; i < FD_MAP_BUCKETS; i++) {
		uint32_t idx = (slot + i) & (FD_MAP_BUCKETS - 1);
		struct fd_map_entry *entry = &fdmap->buckets[idx];
		if (!entry->valid || entry->captured_fd == captured_fd) {
			entry->captured_fd = captured_fd;
			entry->replayed_fd = replayed_fd;
			entry->valid = 1;
			break;
		}
	}
	pthread_mutex_unlock(&fdmap->lock);
	return;
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

    char *saveptr = NULL;
    char *tok = strtok_r(buf, "|", &saveptr); /* used to seperate the tokens in a continous string with | as delimiter */
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
/* kprobe returns only iovcnt , hence allocate struct iovec for the
iovcnt with len assumed =4K */

static struct iovec *alloc_iov(int iovcnt){
      if (iovcnt <=0 || iovcnt > 2048)
	  return NULL;
      struct iovec *iov = calloc(iovcnt, sizeof(struct iovec));
      if (!iov)    return NULL;
      for (int i = 0; i < iovcnt; i++) {
	  iov[i].iov_base = calloc(1, 4096); /* Allocate 4KB for each iovec */
	  if (!iov[i].iov_base) {
	      for (int j = 0; j < i; j++) {
		  free(iov[j].iov_base);
	      }
	      free(iov);
	      return NULL;
	  }
	  iov[i].iov_len = 4096;
      }
      return iov;

}

static void free_iov(struct iovec *iov) {

	if (!iov) return;
        for (int i = 0; i < 2048; i++) {
	    free(iov[i].iov_base);
    }
    free(iov);
}

long dispatch_one(const syscall_opt *opt, struct fd_map *fdmap, struct mmap_map *m)
{
    long ret = -1;
    void *buf = NULL;
    int replayed_fd = resolve_fd(fdmap, opt);
    if (replayed_fd < 0 && opt->syscall_nr != 2 && opt->syscall_nr != 257) {
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
		    fd_map_set(fdmap, opt->ret, (int32_t) ret); /* map captured retval fd -> replayed fd */
	        break;
	case 3: /* close */
	        if (replayed_fd == -1 || replayed_fd ==-2)
		        return -2;
		ret = close(replayed_fd);
		fd_map_set(fdmap, opt->fd, -1);
	        break;
	case 8: /*lseek*/
	        if (opt->ret == -1) {
                        fprintf(stderr,
                        "[replayer] lseek ts=%lu pid=%u: original failed, skipping\n",
                        (unsigned long)opt->timestamp_ns, opt->pid);
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
	    if (replayed_fd >= 0) {
		/* Create a dummy buffer and iovec for vector read */
		int iovcnt = (int)opt->size; /* Using size field to store iovcnt for readv/writev */
		struct iovec *iov = alloc_iov(iovcnt);
		if (!iov)
		    return -ENOMEM;
		ret = readv(replayed_fd, iov, iovcnt);
		free_iov(iov);
	      }
	       break;
	case 20: /*writev*/
	    if (replayed_fd >= 0) {
		/* Create a dummy buffer and iovec for vector write */
		int iovcnt = (int)opt->size; /* Using size field to store iovcnt for readv/writev */
		struct iovec *iov = alloc_iov(iovcnt);
		if (!iov)
		    return -ENOMEM;
		ret = writev(replayed_fd, iov, iovcnt);
		free_iov(iov);
	                }
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
                    dirfd = fd_map_get(fdmap, opt->fd);
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
            fd_map_set(fdmap, opt->ret, ret);
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

       /* Resolve fd at entry time while fd_map is still valid */
        int resolved_fd = -1;
        if (!(map_flags & MAP_ANONYMOUS)) {
                if (opt->fd == -1 || opt->fd == 0) {
                map_flags |= MAP_ANONYMOUS;
                resolved_fd = -1;
        } else {
                resolved_fd = fd_map_get(fdmap, opt->fd);
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

        ret = 0;
	goto mmap_done;

case_mmap_exit:
	mmap_pending_t *p = mmap_pending_get(opt->pid, opt->timestamp_ns);
        if (!p) {
                fprintf(stderr,
                "[replayer] mmap exit ts=%lu: no matching entry record for "
                "pid=%u, skipping\n",
                (unsigned long)opt->timestamp_ns, opt->pid);
                 return -2;
        }

        /* cap_addr is the kernel-assigned address from the original run */
        uint64_t cap_addr = parse_hex_addr(opt->filename);

        /* replay the mmap */
        void *addr = mmap(NULL,
                      p->mmap_len,
                      p->prot,
                      p->map_flags,
                      p->resolved_fd,
                      (off_t)p->offset);

        mmap_pending_clear(opt->pid, opt->timestamp_ns);

        if (addr == MAP_FAILED) {
                fprintf(stderr,
                "[replayer] mmap exit ts=%lu: mmap() failed: %s\n",
                (unsigned long)opt->timestamp_ns, strerror(errno));
                ret = -1;
		goto mmap_done;
        }

        if (cap_addr != 0) {
                if (mmap_map_set(m, cap_addr, addr, p->mmap_len) < 0) {
                        munmap(addr, p->mmap_len);
                        ret = -1;
                        goto mmap_done;
        }
        fprintf(stderr,
            "[replayer] mmap  cap=0x%016lx → replay=%p  len=%zu\n",
            (unsigned long)cap_addr, addr, p->mmap_len);
        }

        ret = 0;
        goto mmap_done;

mmap_done:
    if (buf)
	free(buf);

    return ret;
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

        ctx->syscalls_total++;

        errno = 0;
        long actual_ret = dispatch_one(&op, ctx->fdmap, ctx->mmap);
        int  actual_err = errno;

        if (actual_ret == -2) {
            /* skipped: addr/fd not mapped, or unsupported op */
            ctx->syscalls_skipped++;
        } else if (actual_ret == -1) {
            fprintf(stderr,
                    "[replayer] FAIL ts=%-16lu pid=%-6d %-12s "
                    "fd=%-4d size=%-8ld off=%-8ld "
                    "errno=%d (%s)\n",
                    (unsigned long)op.timestamp_ns,
                    op.pid, op.syscall_name,
                    op.fd, (long)op.size, (long)op.offset,
                    actual_err, strerror(actual_err));
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
            op.syscall_nr != 2  && op.syscall_nr != 257) {

            if (actual_ret != (long)op.ret) {
                is_mismatch = 1;
            }
        }

        if (is_mismatch) {
            /* do NOT print OK — print MISMATCH only */
            fprintf(stderr,
                    "[replayer] MISMATCH ts=%-16lu pid=%-6d %-12s "
                    "fd=%-4d size=%-8ld off=%-8ld "
                    "got ret=%-6ld expected ret=%-6d\n",
                    (unsigned long)op.timestamp_ns,
                    op.pid, op.syscall_name,
                    op.fd, (long)op.size, (long)op.offset,
                    actual_ret, op.ret);
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

int main(void)
{
	FILE *fp = fopen("test_lseek_fsync_prw.json", "r");
	if (!fp) {
		fprintf(stderr, "Error opening file\n");
		return -1;
	}
	printf("[main] Starting syscall replayer...\n");

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
	struct ring_buf *rb = calloc(1, sizeof(struct ring_buf));
	struct fd_map   *fdmap = calloc(1, sizeof(struct fd_map));
	struct mmap_map *mmap = calloc(1, sizeof(struct mmap_map));
	struct dispatcher_ctx ctx = {0};
	pthread_t dispatcher_tid;

	if (!rb || !fdmap || !mmap) {
		fprintf(stderr, "Error: failed to allocate ring_buf or fd_map or mmap \n");
		free(rb); free(fdmap);
		free((mmap));
		fclose(fp);
		return -1;
	}

	/* Initialize buffers */
	memset(line, 0, sizeof(line));

	ring_buf_init(rb);
	fd_map_init(fdmap);
	mmap_map_init(mmap);

	ctx.rb     = rb;
	ctx.fdmap  = fdmap;
	ctx.mmap = mmap;
	ctx.verify = 1;

	/* Create and start dispatcher thread before parsing */
	pthread_create(&dispatcher_tid, NULL, dispatcher_thread, &ctx);

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
				printf("[parser] Enqueuing syscall: pid=%d syscall_nr=%d fd=%d\n",
				       entry->pid, entry->syscall_nr, entry->fd);
				callsys_printf(entry);    /*Uncomment only to print the parsed struct members */
				/* Enqueue the parsed entry to the ring buffer */
				if (ring_buf_enqueue(rb, entry) != 0) {
					fprintf(stderr, "Error enqueuing entry to ring buffer\n");
				}
				free(entry); /* ring buffer copies by value; ptr no longer needed */
			} else {
				fprintf(stderr, "Error parsing JSON object starting at line %d\n", lineno);
				errors++;
				free(entry);
			}
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

	/* Signal dispatcher thread to shut down after processing all entries */
	ring_buf_shutdown(rb);

	/* Wait for dispatcher thread to complete */
	pthread_join(dispatcher_tid, NULL);

        mmap_map_destroy(mmap);
	fd_map_destroy(fdmap);
	ring_buf_destroy(rb);
	free(fdmap);
	free(rb);
	free(json_buffer);
	printf("[main] replay complete.\n");

	return errors > 0 ? 1 : 0;
}