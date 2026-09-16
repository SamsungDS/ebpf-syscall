//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/*
 * memcpy inside a BPF program is not a libbpf helper; it resolves to a
 * normal C library call, which clang refuses to emit against the BPF
 * target. Historically libbpf headers (and older clang versions) were
 * lenient and allowed the implicit declaration to slip through, but
 * clang 14+ with the BPF target rejects the implicit prototype:
 *
 *   syscall_monitor.bpf.c:159:5: error: call to undeclared library
 *   function 'memcpy' with type 'void *(void *, const void *, unsigned
 *   long)'; ISO C99 and later do not support implicit function
 *   declarations
 *
 * This fails the build on Debian trixie (clang 19, kernel 6.16) even
 * though the code was compiling fine on older toolchains.
 *
 * The compiler provides __builtin_memcpy, which clang happily lowers to
 * the BPF memory moves the verifier already understands. Route every
 * memcpy() in this translation unit through the builtin via a macro
 * shim so the BPF source stays readable and future copies do not have
 * to remember the quirk.
 */
#ifndef memcpy
#define memcpy(dst, src, n) __builtin_memcpy((dst), (src), (n))
#endif

/*
 * PT_REGS_PARM6 is missing in many libbpf versions because
 * the 6th syscall arg doesn't pass through a standard calling
 * convention register on all archs. Define it per-arch if absent.
 */
#ifndef PT_REGS_PARM6
  #if defined(__TARGET_ARCH_x86)
    #define PT_REGS_PARM6(x)       ((__u64)(x)->r9)
    #define PT_REGS_PARM6_CORE(x)  BPF_CORE_READ((x), r9)
  #elif defined(__TARGET_ARCH_arm64)
    #define PT_REGS_PARM6(x)       ((__u64)(x)->regs[5])
    #define PT_REGS_PARM6_CORE(x)  BPF_CORE_READ((x), regs[5])
  #elif defined(__TARGET_ARCH_s390)
    #define PT_REGS_PARM6(x)       ((__u64)(x)->gprs[7])
    #define PT_REGS_PARM6_CORE(x)  BPF_CORE_READ((x), gprs[7])
  #elif defined(__TARGET_ARCH_powerpc)
    #define PT_REGS_PARM6(x)       ((__u64)(x)->gpr[8])
    #define PT_REGS_PARM6_CORE(x)  BPF_CORE_READ((x), gpr[8])
  #elif defined(__TARGET_ARCH_riscv)
    #define PT_REGS_PARM6(x)       ((__u64)(x)->a5)
    #define PT_REGS_PARM6_CORE(x)  BPF_CORE_READ((x), a5)
  #elif defined(__TARGET_ARCH_loongarch)
    #define PT_REGS_PARM6(x)       ((__u64)(x)->regs[9])
    #define PT_REGS_PARM6_CORE(x)  BPF_CORE_READ((x), regs[9])
  #else
    #error "PT_REGS_PARM6: unsupported architecture"
  #endif
#endif

#define MAX_COMM_LEN 16
#define MAX_ENTRIES 8192
#define MAX_MMAP_REGIONS 1024
#define PAGE_SIZE  4096
#define EVENT_NR_PAGE_FAULT 1024

/* file access modes */
#define O_ACCMODE   00000003
#define O_RDONLY    00000000
#define O_WRONLY    00000001
#define O_RDWR      00000002

/* file creation and status flags */
#define O_CREAT     00000100
#define O_EXCL      00000200
#define O_NOCTTY    00000400
#define O_TRUNC     00001000
#define O_APPEND    00002000
#define O_NONBLOCK  00004000
#define O_DSYNC     00010000
#define FASYNC      00020000
#define O_DIRECT    00040000
#define O_LARGEFILE 00100000
#define O_DIRECTORY 00200000
#define O_NOFOLLOW  00400000
#define O_CLOEXEC   02000000
#define O_SYNC      04000000
#define O_PATH      010000000

#define MAP_ANONYMOUS 0x20

enum io_direction {
	READ,
	WRITE,
	VREAD,
	VWRITE
};

// Syscall event structure
struct syscall_event {
    u64 timestamp;
    u32 pid;
    u32 syscall_nr;
    u32 fd;
    u64 size;
    s64 offset;
    char comm[MAX_COMM_LEN];
    char filename[256];
    u32 open_flags_hex;
    char open_flags_str[128];
    enum io_direction ddir;
    long ret;  /* holds the number of bytes transferred */
    long error_code;  /* holds the error code returned by the syscall */
};

struct mmap_region_slot {
    u64 start;
    u64 len;
    u64 file_offset; // byte offset into the backing file at `start`
};

struct mmap_region_table {
    u32 next;
    struct mmap_region_slot slots[MAX_MMAP_REGIONS];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);   // tgid
    __type(value, struct mmap_region_table);
} mmap_region_table_map SEC(".maps");

/*
 * Initialize single-entry per cpu array as scratch map
 * for first entry insertion into a new per-tgid table
 * entry in mmap_region_table_map to avoid large stack usage
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct mmap_region_table);
} mmap_region_table_scratch SEC(".maps");

struct mmap_pending {
    u64 length;
    u64 file_offset;
    int fd;
    int map_flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);   // bpf_get_current_pid_tgid() (tid)
    __type(value, struct mmap_pending);
} mmap_pending_map SEC(".maps");

static __always_inline struct mmap_region_slot *mmap_region_find(struct mmap_region_table *t, u64 addr)
{
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        struct mmap_region_slot *s = &t->slots[i];
        if (s->len && addr >= s->start && addr < s->start + s->len)
            return s;
    }
    return NULL;
}

static __always_inline void encode_filename(char filename[256], u64 addr)
{
    const char hex[] = "0123456789abcdef";
    filename[0] = '0';
    filename[1] = 'x';
    #pragma unroll
    for (int i = 0; i < 16; i++)
        filename[2 + i] = hex[(addr >> ((15 - i) * 4)) & 0xF];
    filename[18] = '\0';
}

static __always_inline u32 tgid_from_tid(u64 tid)
{
    return tid >> 32;
}

static __always_inline void mmap_region_insert(u32 tgid, u64 start, u64 len, u64 file_offset)
{
    struct mmap_region_table *t = bpf_map_lookup_elem(&mmap_region_table_map, &tgid);

    if (t) {
        u32 idx = t->next % MAX_MMAP_REGIONS;
        t->slots[idx].start = start;
        t->slots[idx].len = len;
        t->slots[idx].file_offset = file_offset;
        t->next = idx + 1;
        return;
    }

    u32 zero = 0;
    struct mmap_region_table *scratch = bpf_map_lookup_elem(&mmap_region_table_scratch, &zero);
    if (!scratch)
        return;

    scratch->next = 1;
    scratch->slots[0].start = start;
    scratch->slots[0].len = len;
    scratch->slots[0].file_offset = file_offset;

    /* BPF_NOEXIST: if another thread of the same tgid raced us and already
     * created the table, drop this region */
    bpf_map_update_elem(&mmap_region_table_map, &tgid, scratch, BPF_NOEXIST);
}

static __always_inline void mmap_region_remove(u32 tgid, u64 addr, u64 length)
{
    struct mmap_region_table *t = bpf_map_lookup_elem(&mmap_region_table_map, &tgid);
    if (!t)
        return;

    u64 end = addr + length;
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        struct mmap_region_slot *s = &t->slots[i];
        if (s->len && s->start < end && addr < s->start + s->len) {
            s->start = 0;
            s->len = 0;
            s->file_offset = 0;
        }
    }
}

// Maps for syscall statistics
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, u64);
} syscall_sizes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, u64);
} syscall_counts SEC(".maps");

// Ring buffer for detailed events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);  // 8MB ring buffer (increased from 256KB)
} events SEC(".maps");

// struct used to map the timestamps to pid_tgid
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);     // pid_tgid
    __type(value, u64);   // timestamp captured at mmap entry
} mmap_entry_map SEC(".maps");


// Global flag to control detailed logging
volatile const bool detailed_logging = true;
volatile const unsigned int sampling_rate = 1;  // Sample 1 out of every N events (1 = capture all)

// enter/exit join: stash read/write-family enter args by TID so sys_exit can attach the bytes the
// syscall RETURNED. Without this, enter events carry (fd,count,offset) but ret=-1, and the generic
// sys_exit carries ret but fd=-1/count=1/offset=0 -- the two are never correlated, so neither
// requested-vs-returned nor per-fd byte accounting is recoverable. This restores a single joined
// record {fd, offset, requested count, returned bytes} emitted at completion.
struct io_ctx {
    u32 syscall_nr;
    u32 fd;
    u64 count;   // requested bytes (or iovcnt for readv/writev)
    u64 offset;  // absolute offset for pread/pwrite, 0 otherwise
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u64);            // bpf_get_current_pid_tgid()
    __type(value, struct io_ctx);
} io_inflight SEC(".maps");

static __always_inline void stash_io_enter(u32 syscall_nr, u32 fd, u64 count, u64 offset)
{
    u64 tid = bpf_get_current_pid_tgid();
    struct io_ctx c = {};
    c.syscall_nr = syscall_nr;
    c.fd = fd;
    c.count = count;
    c.offset = offset;
    bpf_map_update_elem(&io_inflight, &tid, &c, BPF_ANY);
}

static __always_inline void update_stats(u32 syscall_nr, u64 size)
{
    u64 *val;
    u64 init_val = size;
    u64 count = 1;

    val = bpf_map_lookup_elem(&syscall_sizes, &syscall_nr);
    if (val) {
        __sync_fetch_and_add(val, size);
    } else {
        bpf_map_update_elem(&syscall_sizes, &syscall_nr, &init_val, BPF_ANY);
    }

    val = bpf_map_lookup_elem(&syscall_counts, &syscall_nr);
    if (val) {
        __sync_fetch_and_add(val, 1);
    } else {
        bpf_map_update_elem(&syscall_counts, &syscall_nr, &count, BPF_ANY);
    }
}

static __always_inline void log_event(u32 syscall_nr, u32 fd, u64 size, s64 offset, char filename[256], int open_flags_hex, char  open_flags_str[128], long ret, long error_code)
{
    struct syscall_event *event;

    if (!detailed_logging)
        return;

    // Sampling: only log every Nth event
    if (sampling_rate > 1) {
        static __u32 counter = 0;
        counter++;
        if (counter % sampling_rate != 0)
            return;
    }

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return;

    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    if (syscall_nr == 9) {   /* mmap */
        if (filename[0] == '\0') {
            /*
             * mmap ENTRY — capture fresh timestamp, save it
             * in map keyed by pid_tgid for exit to reuse
             */
            u64 ts = bpf_ktime_get_ns();
            event->timestamp = ts;
            bpf_map_update_elem(&mmap_entry_map, &pid_tgid, &ts, BPF_ANY);

        } else {
            /*
             * mmap EXIT — reuse the exact timestamp from entry
             * so both log records are correlated by (pid_tgid, timestamp)
             */
            u64 *saved_ts = bpf_map_lookup_elem(&mmap_entry_map, &pid_tgid);
            event->timestamp = saved_ts ? *saved_ts : bpf_ktime_get_ns();
            bpf_map_delete_elem(&mmap_entry_map, &pid_tgid);  // cleanup
        }
    } else {
        // all other syscalls — fresh timestamp
        event->timestamp = bpf_ktime_get_ns();
    }
    event->syscall_nr = syscall_nr;
    event->fd = fd;
    event->size = size;
    event->offset = offset;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    __builtin_memcpy(event->filename, filename , sizeof(event->filename));
    event->open_flags_hex = open_flags_hex;
    __builtin_memcpy(event->open_flags_str, open_flags_str, sizeof(event->open_flags_str));
    if (syscall_nr == 0 || syscall_nr == 17)
        event->ddir = READ;
    else if (syscall_nr == 1 || syscall_nr == 18)
        event->ddir = WRITE;
    else if (syscall_nr == 19)
        event->ddir = VREAD;
    else if (syscall_nr == 20)
        event->ddir = VWRITE;
    event->ret = ret;
    event->error_code = error_code;

    bpf_ringbuf_submit(event, 0);
}

// read syscall tracepoint
SEC("kprobe/__x64_sys_read")
int trace_read_entry(struct pt_regs *ctx)
{
    u32 syscall_nr = 0; // read
    struct pt_regs inner = {};
    struct pt_regs *inner_ptr = (struct pt_regs *)PT_REGS_PARM1(ctx);
    if (bpf_probe_read_kernel(&inner, sizeof(inner), inner_ptr) < 0)
        return 0;

    struct pt_regs *p = &inner;
    unsigned int fd   = (unsigned int)PT_REGS_PARM1(p);  /* rdi ✓ */
    size_t       size = (size_t)PT_REGS_PARM3(p);        /* rdx ✓ */
    /* read has no offset — positional read uses file position */

    update_stats(syscall_nr, size);
    log_event(syscall_nr, fd, size, 0, "", 0, "", -1,-1);

    return 0;
}

// write syscall tracepoint
SEC("kprobe/__x64_sys_write")
int trace_write_entry(struct pt_regs *ctx)
{
    u32 syscall_nr = 1; // write
    struct pt_regs inner = {};
    struct pt_regs *inner_ptr = (struct pt_regs *)PT_REGS_PARM1(ctx);
    if (bpf_probe_read_kernel(&inner, sizeof(inner), inner_ptr) < 0)
        return 0;

    struct pt_regs *p = &inner;
    unsigned int fd   = (unsigned int)PT_REGS_PARM1(p);  /* rdi ✓ */
    size_t       size = (size_t)PT_REGS_PARM3(p);        /* rdx ✓ */
    /* write has no offset — positional write uses file position */

    update_stats(syscall_nr, size);
    log_event(syscall_nr, fd, size, 0, "", 0, "", -1, -1);

    return 0;
}

SEC("kprobe/__x64_sys_open")
int trace_open_entry(struct pt_regs *ctx)
{
    u32 syscall_nr = 2; // open

    update_stats(syscall_nr, 1);
    log_event(syscall_nr, -1, 1, 0, "", 0, "", -1, -1);

    return 0;
}

//openat syscall tracepoint
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    char filename[256];
    u32 syscall_nr = 257;
    int dfd = (int)ctx->args[0];
    const char *filenameptr = (const char *)ctx->args[1];
    uint32_t open_flags_hex = (uint32_t)ctx->args[2];

    if (bpf_probe_read_user_str(filename, sizeof(filename), filenameptr) < 0) {
        bpf_printk("failed to read filename\n");
        return 0;
    }

    char open_flags_str[128] = {0};

    int accmode  = open_flags_hex & O_ACCMODE;

    /*decode the hex flags for file access modes */
    if (accmode == O_RDONLY) {
       bpf_snprintf(open_flags_str, sizeof(open_flags_str), "O_RDONLY", NULL, 0);
    } else if (accmode == O_WRONLY) {
       bpf_snprintf(open_flags_str, sizeof(open_flags_str), "O_WRONLY", NULL, 0);
    } else if (accmode == O_RDWR) {
       bpf_snprintf(open_flags_str, sizeof(open_flags_str), "O_RDWR", NULL, 0);
    }


    if (open_flags_hex & O_CREAT) {
        bpf_snprintf(open_flags_str, sizeof(open_flags_str), "O_CREAT", NULL, 0);
    }
    if (open_flags_hex & O_EXCL) {
       bpf_snprintf(open_flags_str, sizeof(open_flags_str), "O_EXCL", NULL, 0);
    }
    if (open_flags_hex & O_NOCTTY) {
       bpf_snprintf(open_flags_str, sizeof(open_flags_str), "O_NOCTTY", NULL, 0);
    }
    if (open_flags_hex & O_TRUNC) {
       bpf_snprintf(open_flags_str, sizeof(open_flags_str), "O_TRUNC", NULL, 0);
    }
    if (open_flags_hex & O_APPEND) {
       bpf_snprintf(open_flags_str, sizeof(open_flags_str), "O_APPEND", NULL, 0);
    }
    if (open_flags_hex & O_NONBLOCK) {
       bpf_snprintf(open_flags_str, sizeof(open_flags_str), "O_NONBLOCK", NULL, 0);
    }
    if (open_flags_hex & O_DSYNC) {
       bpf_snprintf(open_flags_str, sizeof(open_flags_str), "O_DSYNC", NULL, 0);
    }
    if (open_flags_hex & FASYNC) {
       bpf_snprintf(open_flags_str, sizeof(open_flags_str), "FASYNC", NULL, 0);
    }
    if (open_flags_hex & O_DIRECT) {
       bpf_snprintf(open_flags_str, sizeof(open_flags_str), "O_DIRECT", NULL, 0);
    }
    if (open_flags_hex & O_LARGEFILE) {
       bpf_snprintf(open_flags_str, sizeof(open_flags_str), "O_LARGEFILE", NULL, 0);
    }
    if (open_flags_hex & O_DIRECTORY) {
       bpf_snprintf(open_flags_str, sizeof(open_flags_str), "O_DIRECTORY", NULL, 0);
    }
    if (open_flags_hex & O_NOFOLLOW) {
       bpf_snprintf(open_flags_str, sizeof(open_flags_str), "O_NOFOLLOW", NULL, 0);
    }
    if (open_flags_hex & O_CLOEXEC) {
       bpf_snprintf(open_flags_str, sizeof(open_flags_str), "O_CLOEXEC", NULL, 0);
    }
    if (open_flags_hex & O_SYNC) {
       bpf_snprintf(open_flags_str, sizeof(open_flags_str), "O_SYNC", NULL, 0);
    }
    if (open_flags_hex & O_PATH) {
       bpf_snprintf(open_flags_str, sizeof(open_flags_str), "O_PATH", NULL, 0);
    }

    update_stats(syscall_nr, 1);
    log_event(syscall_nr, dfd, 1, 0, filename, open_flags_hex, open_flags_str, -1, -1);

    return 0;
}

// close syscall tracepoint
SEC("kprobe/__x64_sys_close")
int trace_close_entry(struct pt_regs *ctx)
{
    u32 syscall_nr = 3; // close
    struct pt_regs inner = {};
    struct pt_regs *inner_ptr = (struct pt_regs *)PT_REGS_PARM1(ctx);
    if (bpf_probe_read_kernel(&inner, sizeof(inner), inner_ptr) < 0)
        return 0;
    struct pt_regs *p = &inner;

    unsigned int fd = (unsigned int)PT_REGS_PARM1(p);  /* rdi */

    update_stats(syscall_nr, 1);
    log_event(syscall_nr, fd, 1, 0, "", 0, "", -1, -1);

    return 0;
}

// lseek syscall tracepoint
SEC("kprobe/__x64_sys_lseek")
int trace_lseek_entry(struct pt_regs *ctx)
{
    u32 syscall_nr = 8; // lseek
    struct pt_regs inner = {};
    struct pt_regs *inner_ptr = (struct pt_regs *)PT_REGS_PARM1(ctx);
    if (bpf_probe_read_kernel(&inner, sizeof(inner), inner_ptr) < 0)
        return 0;

    struct pt_regs *p = &inner;

    unsigned int fd     = (unsigned int)PT_REGS_PARM1(p);  /* rdi ✓ */
    s64        offset = (s64)PT_REGS_PARM2(p);         /* rsi ✓ */
    unsigned int whence = (unsigned int)PT_REGS_PARM3(p);  /* rdx ✓ */

    u64 abs_offset = offset > 0 ? (u64)offset : (u64)-offset;

    update_stats(syscall_nr, abs_offset);
    log_event(syscall_nr, fd, abs_offset, (loff_t)offset, "", whence, "", -1, -1);

    return 0;
}

// pread64 syscall tracepoint
SEC("kprobe/__x64_sys_pread64")
int trace_pread_entry(struct pt_regs *ctx)
{
    u32 syscall_nr = 17; // pread64
    struct pt_regs inner = {};
    struct pt_regs *inner_ptr = (struct pt_regs *)PT_REGS_PARM1(ctx);
    if (bpf_probe_read_kernel(&inner, sizeof(inner), inner_ptr) < 0)
        return 0;

    struct pt_regs *p = &inner;

    unsigned int fd     = (unsigned int)PT_REGS_PARM1(p);  /* rdi ✓ */
    u64          buf    = (u64)PT_REGS_PARM2(p);           /* rsi — buf ptr, not logged */
    size_t       size   = (size_t)PT_REGS_PARM3(p);        /* rdx ✓ */

    /* pread64 arg4 = offset uses r10 not rcx — same as mmap arg4 */
    loff_t offset = (loff_t)inner.r10;

    update_stats(syscall_nr, size);
    log_event(syscall_nr, fd, size, offset, "", 0, "", -1, -1);

    return 0;
}

// pwrite64 syscall tracepoint
SEC("kprobe/__x64_sys_pwrite64")
int trace_pwrite_entry(struct pt_regs *ctx)
{
    u32 syscall_nr = 18; // pwrite64
    struct pt_regs inner = {};
    struct pt_regs *inner_ptr = (struct pt_regs *)PT_REGS_PARM1(ctx);
    if (bpf_probe_read_kernel(&inner, sizeof(inner), inner_ptr) < 0)
        return 0;

    struct pt_regs *p = &inner;

    unsigned int fd     = (unsigned int)PT_REGS_PARM1(p);
    size_t       size   = (size_t)PT_REGS_PARM3(p);
    loff_t       offset = (loff_t)inner.r10;   /* arg4 = r10 ✓ */

    update_stats(syscall_nr, size);
    log_event(syscall_nr, fd, size, offset, "", 0, "", -1, -1);

    return 0;
}

// mmap syscall tracepoint
SEC("kprobe/__x64_sys_mmap")
int trace_mmap_entry(struct pt_regs *ctx)
{
    u32 syscall_nr = 9; // mmap syscall
    /*
     * Read six registers mmap needs directly from inner_ptr
     * to save BPF stack memory.
     */
    struct pt_regs *inner_ptr = (struct pt_regs *)PT_REGS_PARM1(ctx);
    unsigned long si = 0, dx = 0, r10 = 0, r8 = 0, r9 = 0;
    bpf_probe_read_kernel(&si,  sizeof(si),  &inner_ptr->si);
    bpf_probe_read_kernel(&dx,  sizeof(dx),  &inner_ptr->dx);
    bpf_probe_read_kernel(&r10, sizeof(r10), &inner_ptr->r10);
    bpf_probe_read_kernel(&r8,  sizeof(r8),  &inner_ptr->r8);
    bpf_probe_read_kernel(&r9,  sizeof(r9),  &inner_ptr->r9);

    unsigned int fd        = (unsigned int)r8;
    size_t       length    = (size_t)si;
    loff_t       offset    = (loff_t)r9;
    int          prot      = (int)dx;
    int          map_flags = (int)r10;
    char open_flags_str[128] = {};
    __u32 pos    = 0;
    int   need_sep = 0;

     /*
     * Pack prot and map_flags as "PROT:FLAGS" hex string — tiny, fixed size,
     * no unrolled loops. Decoded in userspace parse_mmap_flags().
     * e.g. prot=3, map_flags=2 → "0x00000003:0x00000002"
     */

    /* emit "0x" + 8 hex digits for prot */
    const char hex[] = "0123456789abcdef";
    open_flags_str[pos++] = '0';
    open_flags_str[pos++] = 'x';
    #pragma unroll
    for (int i = 7; i >= 0; i--)
        open_flags_str[pos++] = hex[((unsigned)prot >> (i * 4)) & 0xF];

    open_flags_str[pos++] = ':';

    /* emit "0x" + 8 hex digits for map_flags */
    open_flags_str[pos++] = '0';
    open_flags_str[pos++] = 'x';
    #pragma unroll
    for (int i = 7; i >= 0; i--)
        open_flags_str[pos++] = hex[((unsigned)map_flags >> (i * 4)) & 0xF];

    open_flags_str[pos] = '\0';
    /* result: "0x00000003:0x00000002" — 21 bytes, fixed, verifier-friendly */

    open_flags_str[pos] = '\0';

    u64 tid = bpf_get_current_pid_tgid();
    struct mmap_pending pending = {
        .length = length,
        .file_offset = (u64)offset,
        .fd = (int)fd,
        .map_flags = map_flags,
    };
    bpf_map_update_elem(&mmap_pending_map, &tid, &pending, BPF_ANY);

    update_stats(syscall_nr, length);
    log_event(syscall_nr, fd, length, offset, "", 0, open_flags_str, -1, -1);

    return 0;
}

/*mmap exit syscall tracepoint */
SEC("kretprobe/__x64_sys_mmap")
int trace_mmap_exit(struct pt_regs *ctx)
{
    u32 syscall_nr = 9; // mmap syscall
    unsigned long ret_addr = (unsigned long)PT_REGS_RC(ctx);

    u64 tid = bpf_get_current_pid_tgid();
    struct mmap_pending *pending = bpf_map_lookup_elem(&mmap_pending_map, &tid);
    if (pending && ret_addr != (unsigned long)-1UL) {

        if (!(pending->map_flags & MAP_ANONYMOUS))
            mmap_region_insert(tgid_from_tid(tid), (u64)ret_addr, pending->length, pending->file_offset);
    }
    if (pending)
        bpf_map_delete_elem(&mmap_pending_map, &tid);

    char filename[256] = {};
    if (ret_addr == (unsigned long)-1UL) {
        filename[0] = '0'; filename[1] = 'x'; filename[2] = '0'; filename[3] = '\0';
    } else {
        const char hex[] = "0123456789abcdef";
        filename[0] = '0';
        filename[1] = 'x';
        #pragma unroll
        for (int i = 0; i < 16; i++)
            filename[2 + i] = hex[(ret_addr >> ((15 - i) * 4)) & 0xF];
        filename[18] = '\0';
    }

    update_stats(syscall_nr, 0);
    log_event(syscall_nr, 0, 0, 0, filename, 0, "", -1, -1);

    return 0;
}

//munmap syscall tracepoint
SEC("kprobe/__x64_sys_munmap")
int trace_munmap_entry(struct pt_regs *ctx)
{
    u32 syscall_nr = 11;
    /* read only the two registers we need — not full pt_regs */
    struct pt_regs *inner_ptr = (struct pt_regs *)PT_REGS_PARM1(ctx);

    unsigned long addr   = 0;
    size_t        length = 0;

    /* read addr (rdi = offset 112) and length (rsi = offset 104) directly */
    bpf_probe_read_kernel(&addr,   sizeof(addr),   &inner_ptr->di);
    bpf_probe_read_kernel(&length, sizeof(length),  &inner_ptr->si);

    mmap_region_remove(tgid_from_tid(bpf_get_current_pid_tgid()), (u64)addr, (u64)length);

    /* encode addr as hex into filename[] — replayer uses it as cap_addr key */
    char filename[256] = {};
    const char hex[] = "0123456789abcdef";
    filename[0] = '0';
    filename[1] = 'x';
    #pragma unroll
    for (int i = 0; i < 16; i++)
        filename[2 + i] = hex[(addr >> ((15 - i) * 4)) & 0xF];
    filename[18] = '\0';

    update_stats(syscall_nr, length);
    log_event(syscall_nr, -1, length, 0, filename, 0, "", -1, -1);

    return 0;
}

// readv syscall tracepoint
SEC("kprobe/__x64_sys_readv")
int trace_readv_entry(struct pt_regs *ctx)
{
    u32 syscall_nr = 19;
    struct pt_regs inner = {};
    struct pt_regs *inner_ptr = (struct pt_regs *)PT_REGS_PARM1(ctx);
    if (bpf_probe_read_kernel(&inner, sizeof(inner), inner_ptr) < 0)
        return 0;

    struct pt_regs *p = &inner;
    unsigned int fd    = (unsigned int)PT_REGS_PARM1(p);  /* rdi */
    unsigned long count = (unsigned long)PT_REGS_PARM3(p); /* rdx = iovcnt */

    update_stats(syscall_nr, count);
    log_event(syscall_nr, fd, count, 0, "", 0, "", -1, -1);

    return 0;
}

// writev syscall tracepoint
SEC("kprobe/__x64_sys_writev")
int trace_writev_entry(struct pt_regs *ctx)
{
    u32 syscall_nr = 20; // writev
    struct pt_regs inner = {};
    struct pt_regs *inner_ptr = (struct pt_regs *)PT_REGS_PARM1(ctx);
    if (bpf_probe_read_kernel(&inner, sizeof(inner), inner_ptr) < 0)
        return 0;

    struct pt_regs *p = &inner;
    unsigned int fd    = (unsigned int)PT_REGS_PARM1(p);  /* rdi ✓ */
    unsigned long count = (unsigned long)PT_REGS_PARM3(p); /* rdx = iovcnt ✓ */

    update_stats(syscall_nr, count);
    log_event(syscall_nr, fd, count, 0, "", 0, "", -1, -1);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsync")
int trace_fsync_entry(struct trace_event_raw_sys_enter *ctx)
{
    u32 syscall_nr = 74; // fsync
    unsigned int fd = (unsigned int)ctx->args[0];

    update_stats(syscall_nr, 1);
    log_event(syscall_nr, fd, 1, 0, "", 0, "", -1, -1);

    return 0;
}

SEC("tp_btf/page_fault_user")
int BPF_PROG(trace_page_fault_user, unsigned long address, struct pt_regs *regs, unsigned long error_code)
{
    u64 fault_addr = (u64)address;
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct mmap_region_table *t;

    t = bpf_map_lookup_elem(&mmap_region_table_map, &tgid);
    if (!t)
        return 0;

    struct mmap_region_slot *slot = mmap_region_find(t, fault_addr);
    if (!slot)
        return 0;

    s64 fault_offset = (s64)(slot->file_offset + (fault_addr - slot->start));

    char filename[256] = {};
    encode_filename(filename, fault_addr);

    update_stats(EVENT_NR_PAGE_FAULT, PAGE_SIZE);
    log_event(EVENT_NR_PAGE_FAULT, -1, PAGE_SIZE, fault_offset, filename, (int)error_code, "", -1, -1);

    return 0;
}

// syscall exit tracepoint
SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
    u32 syscall_nr  = ctx->id;   // syscall number
    long ret = ctx->ret; // return value
    long error_code  = (ret < 0) ? ret : 0;   /* negative errno or 0 */

    /* filter to tracked syscalls only */
    if (syscall_nr != 0  && syscall_nr != 1  && syscall_nr != 2  &&
        syscall_nr != 3  && syscall_nr != 8  && syscall_nr != 9  &&
        syscall_nr != 11 && syscall_nr != 17 && syscall_nr != 18 &&
        syscall_nr != 19 && syscall_nr != 20 && syscall_nr != 74 &&
        syscall_nr != 257)
        return 0;

    /*
     * Exit record — fd=-1, size=1, offset=0 signals to the replayer
     * that this is an exit record and should be skipped.
     * Contains only ret and error_code — no syscall args.
     */
    log_event(syscall_nr, -1, 1, 0, "", 0, "", ret, error_code);

    return 0;
}

char _license[] SEC("license") = "GPL";
