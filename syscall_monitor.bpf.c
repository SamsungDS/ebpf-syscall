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
    u64 offset;
    char comm[MAX_COMM_LEN];
    char filename[256];
    u32 open_flags_hex;
    char open_flags_str[20];
    enum io_direction ddir;
    long ret;  /* holds the number of bytes transferred */
    long error_code;  /* holds the error code returned by the syscall */
};

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

// Global flag to control detailed logging
volatile const bool detailed_logging = true;
volatile const unsigned int sampling_rate = 1;  // Sample 1 out of every N events (1 = capture all)

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

static __always_inline void log_event(u32 syscall_nr, u32 fd, u64 size, u64 offset, char filename[256], int open_flags_hex, char  open_flags_str[20], long ret, long error_code)
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
    event->syscall_nr = syscall_nr;
    event->fd = fd;
    event->size = size;
    event->offset = offset;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    memcpy(event->filename, filename , sizeof(event->filename));
    event->open_flags_hex = open_flags_hex;
    memcpy(event->open_flags_str, open_flags_str, sizeof(event->open_flags_str));
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
    int fd = (int)PT_REGS_PARM1(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);

    update_stats(syscall_nr, count);
    log_event(syscall_nr, fd, count, 0, "", 0, "", -1,-1);

    return 0;
}

// write syscall tracepoint
SEC("kprobe/__x64_sys_write")
int trace_write_entry(struct pt_regs *ctx)
{
    u32 syscall_nr = 1; // write
    int fd = (int)PT_REGS_PARM1(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);

    update_stats(syscall_nr, count);
    log_event(syscall_nr, fd, count, 0, "", 0, "", -1, -1);

    return 0;
}

// open syscall tracepoint
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

    char open_flags_str[80] = {0};

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
    unsigned int fd = (unsigned int)PT_REGS_PARM1(ctx);

    update_stats(syscall_nr, 1);
    log_event(syscall_nr, fd, 1, 0, "", 0, "", -1, -1);

    return 0;
}

// lseek syscall tracepoint
SEC("kprobe/__x64_sys_lseek")
int trace_lseek_entry(struct pt_regs *ctx)
{
    u32 syscall_nr = 8; // lseek
    unsigned int fd = (unsigned int)PT_REGS_PARM1(ctx);
    off_t offset = (off_t)PT_REGS_PARM2(ctx);
    u64 abs_offset = offset > 0 ? offset : -offset;

    update_stats(syscall_nr, abs_offset);
    log_event(syscall_nr, fd, abs_offset, offset, "", 0, "", -1, -1);

    return 0;
}

// pread64 syscall tracepoint
SEC("kprobe/__x64_sys_pread64")
int trace_pread_entry(struct pt_regs *ctx)
{
    u32 syscall_nr = 17; // pread64
    unsigned int fd = (unsigned int)PT_REGS_PARM1(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);
    loff_t pos = (loff_t)PT_REGS_PARM4(ctx);

    update_stats(syscall_nr, count);
    log_event(syscall_nr, fd, count, pos, "", 0, "", -1, -1);

    return 0;
}

// pwrite64 syscall tracepoint
SEC("kprobe/__x64_sys_pwrite64")
int trace_pwrite_entry(struct pt_regs *ctx)
{
    u32 syscall_nr = 18; // pwrite64
    unsigned int fd = (unsigned int)PT_REGS_PARM1(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);
    loff_t pos = (loff_t)PT_REGS_PARM4(ctx);

    update_stats(syscall_nr, count);
    log_event(syscall_nr, fd, count, pos, "", 0, "", -1, -1);

    return 0;
}

// mmap syscall tracepoint
SEC("kprobe/__x64_sys_mmap")
int trace_mmap_entry(struct pt_regs *ctx)
{
    u32 syscall_nr = 9; // mmap syscall
    unsigned int fd = (unsigned int)PT_REGS_PARM5(ctx);
    size_t length = (size_t)PT_REGS_PARM2(ctx);
    loff_t offset = (loff_t)PT_REGS_PARM6(ctx);

    update_stats(syscall_nr, length);
    log_event(syscall_nr, fd, length, offset, "", 0, "", -1, -1);

    return 0;
}

//munmap syscall tracepoint
SEC("kprobe/__x64_sys_munmap")
int trace_munmap_entry(struct pt_regs *ctx)
{
    u32 syscall_nr = 11; //munmap syscall
    unsigned int fd = (unsigned int)PT_REGS_PARM5(ctx);
    size_t length = (size_t)PT_REGS_PARM2(ctx);
    loff_t offset = (loff_t)PT_REGS_PARM6(ctx);

    update_stats(syscall_nr, length);
    log_event(syscall_nr, fd, length, offset, "", 0, "", -1, -1);

    return 0;
}

// readv syscall tracepoint
SEC("kprobe/__x64_sys_readv")
int trace_readv_entry(struct pt_regs *ctx)
{
    u32 syscall_nr = 19; // readv
    unsigned int fd = (unsigned int)PT_REGS_PARM1(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);
    loff_t pos = (loff_t)PT_REGS_PARM4(ctx);

    update_stats(syscall_nr, count);
    log_event(syscall_nr, fd, count, pos, "", 0, "", -1, -1);

    return 0;
}

// writev syscall tracepoint
SEC("kprobe/__x64_sys_writev")
int trace_writev_entry(struct pt_regs *ctx)
{
    u32 syscall_nr = 20; // writev
    unsigned int fd = (unsigned int)PT_REGS_PARM1(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);
    loff_t pos = (loff_t)PT_REGS_PARM4(ctx);

    update_stats(syscall_nr, count);
    log_event(syscall_nr, fd, count, pos, "", 0, "", -1, -1);

    return 0;
}

// fsync syscall tracepoint
SEC("kprobe/__x64_sys_fsync")
int trace_fsync_entry(struct pt_regs *ctx)
{
    u32 syscall_nr = 74; // fsync
    unsigned int fd = (unsigned int)PT_REGS_PARM1(ctx);

    update_stats(syscall_nr, 1);
    log_event(syscall_nr, fd, 1, 0, "", 0, "", -1, -1);

    return 0;
}

// syscall exit tracepoint
SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
    u32 syscall_nr  = ctx->id;   // syscall number
    long ret = ctx->ret; // return value
    long error_code = 0;
    if (ret < 0 ) {
	error_code  = -ret;
    }

    if (syscall_nr == 0 || syscall_nr == 1 || syscall_nr == 2 ||
    syscall_nr == 257 || syscall_nr == 3 || syscall_nr == 8
    || syscall_nr == 17 || syscall_nr == 18 || syscall_nr == 9 ||
    syscall_nr == 11 || syscall_nr == 19 || syscall_nr == 20 || syscall_nr == 74) {
        update_stats(syscall_nr, 1);
        log_event(syscall_nr, -1, 1, 0,"", 0, "", ret, error_code);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
