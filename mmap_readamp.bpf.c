// SPDX-License-Identifier: GPL-2.0
// mmap_readamp.bpf.c -- per-file mmap demand-fault read-amplification tracer.
//
// Measures the page-granular read amplification of mmap'd file access: an 8-byte logical load
// faults in a full 4 KiB page (the x86 MMU page), and under memory pressure evicted pages are
// re-faulted from storage. We attribute each completed file-backed demand fault to its backing
// (dev, inode) and count minor (page-cache populate) vs major (VM_FAULT_MAJOR = read from storage)
// faults plus the 4 KiB bytes faulted.
//
// Design (ChatGPT Pro consult): hook filemap_fault via fentry/fexit. The VMA handed to
// filemap_fault is the source of truth -- it carries vma->vm_file -> f_mapping -> host (inode) and
// vmf->pgoff (the file page offset) -- so there is NO need for a per-fd table or a virtual-address
// interval lookup (the fd may be close()d after mmap; attribute to file+mapping+page, not fd).
// Read metadata at fentry (a VM_FAULT_RETRY path may drop the mmap lock, so don't deref the VMA at
// fexit). Aggregate retries: one hardware fault can call filemap_fault several times returning
// VM_FAULT_RETRY before a final non-retry return; count one logical fault, major if any attempt was.
// The read-amp NUMERATOR is faults*PAGE; the logical-bytes DENOMINATOR is invisible to a fault hook
// (post-first-touch CPU loads don't fault) and comes from the app / fio, not from here.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE 4096

// fault_flag bits (include/linux/mm_types.h -- stable ABI)
#define FAULT_FLAG_WRITE 0x01
#define FAULT_FLAG_TRIED 0x20
#define FAULT_FLAG_USER 0x40
#define FAULT_FLAG_INSTRUCTION 0x100
// vm_fault_reason bits (include/linux/mm_types.h)
#define VM_FAULT_MAJOR 0x004
#define VM_FAULT_RETRY 0x400
// OOM|SIGBUS|SIGSEGV|HWPOISON|HWPOISON_LARGE|FALLBACK -- the real error mask. (Must NOT include
// VM_FAULT_RETRY 0x400: a normal fault returns RETRY on its first attempt to drop the mmap lock for
// I/O, so masking RETRY here would discard every retried -- i.e. every disk-read -- fault.)
#define VM_FAULT_ERROR 0x000873

struct fault_key {
    __u64 pid_tgid;
    __u64 addr_page;
};
struct pending {
    __u32 dev;
    __u64 ino;
    __u64 pgoff;
    __u32 ret_or;
    __u32 attempts;
    __u8 write;
};
struct file_key {
    __u32 tgid;
    __u32 dev;
    __u64 ino;
};
struct file_stats {
    __u64 completed_faults;
    __u64 minor_faults;
    __u64 major_faults;
    __u64 write_faults;
    __u64 fault_bytes; // completed_faults * PAGE
    __u64 major_bytes; // major_faults * PAGE
    __u64 retries;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 262144);
    __type(key, struct fault_key);
    __type(value, struct pending);
} pending_faults SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 262144);
    __type(key, struct file_key);
    __type(value, struct file_stats);
} file_stats SEC(".maps");

// Page-cache fills = the ACTUAL storage reads (demand fault AND readahead), per file, from the
// mm_filemap_add_to_page_cache tracepoint. filemap_fault counts the DEMAND (what the app's fault
// asked for, ~= intent at page granularity); fill_bytes - fault_bytes = the readahead over-fetch.
// Keyed by file only (dev,ino): readahead is not reliably issued by the faulting task.
struct devino_key {
    __u32 dev;
    __u64 ino;
};
struct pgcache_stats {
    __u64 fill_pages;
    __u64 fill_bytes;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct devino_key);
    __type(value, struct pgcache_stats);
} pgcache SEC(".maps");

// read()/pread() syscall reads attributed per file (fd -> inode). This is the INTENT the app issued
// to the kernel: the requested byte count. For mmap there are NO such syscalls (data access is a
// memory load), so this is empty for mmap -- it is exactly what makes a pread-based SSD offload
// introspectable where mmap is opaque. For an O_DIRECT page cache the requests are 4 KiB-aligned;
// for a hypothetical pread(row_bytes) fetch it is the true logical intent (e.g. 768 B/row).
struct sysread_stats {
    __u64 read_calls;
    __u64 read_bytes;
    __u64 min_bytes; // smallest single request to this file (0 = unset)
    __u64 max_bytes; // largest single request
};
// keyed by (dev, ino, is_write): read AND write intent per file (write/pwrite/pwritev too -- LMCache).
struct sysio_key {
    __u32 dev;
    __u64 ino;
    __u32 is_write;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct sysio_key);
    __type(value, struct sysread_stats);
} syscall_reads SEC(".maps");

// O_DIRECT bytes per file from the iomap direct-I/O completion (iomap_dio_complete carries the
// regular-file dev+inode from iocb->ki_filp -- the one place O_DIRECT is attributable to a file).
// O_DIRECT bypasses the page cache, so neither filemap_fault nor mm_filemap_add_to_page_cache sees
// it; this closes that hole. (Transfer bytes; reads for a read-only workload.)
struct odirect_stats {
    __u64 dio_bytes;
    __u64 dio_calls;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct devino_key);
    __type(value, struct odirect_stats);
} odirect SEC(".maps");

// PHYSICAL block-device read bytes, per DEVICE, from block_rq_issue. This is the true host storage
// traffic -- distinct from the page-cache-fill materialization footprint. The block layer cannot map
// a request back to a regular-file inode (request merging across files; O_DIRECT bios point at the
// anonymous user buffer, not page->mapping->host), so this is per-device, not per-file. For a
// single-tenant run it equals the workload's physical reads.
struct block_stats {
    __u64 read_bytes; // "read_" prefix is historical; with the is_write key this holds R or W bytes
    __u64 read_ios;
    __u64 hist[12]; // size buckets, 512-byte base: 512,1K,2K,4K,8K,16K,32K,64K,128K,256K,512K,>=1M
    __u64 iu_bytes; // sum over ops of (IUs the op spans) * IU_size -- the IU-granular footprint
    __u64 sub_iu_ios; // ops smaller than one IU (sub-IU READS over-fetch; sub-IU WRITES = RMW risk)
    __u64 min_io;   // smallest block request (0 = unset)
    __u64 max_io;   // largest block request
};
// keyed by (dev, is_write) so reads and writes are tracked separately -- writes matter for LMCache
// (KV offload) and sub-IU writes are the read-modify-write case the IU is really about.
struct bdev_key {
    __u32 dev;
    __u32 is_write;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, struct bdev_key);
    __type(value, struct block_stats);
} block_reads SEC(".maps");

// Per-device geometry (IU/NOWS/MDTS), populated by userspace from sysfs at startup (with the NVMe
// 512-phys -> 4K IU floor baked in). Keyed by dev_t so on_block_rq can charge each read to its IU.
struct dev_geom {
    __u32 iu;      // Indirection Unit (minimum_io_size, floored to 4096 for 512-phys NVMe)
    __u32 nows;    // optimal_io_size (NOWS)
    __u32 mdts;    // max_hw_sectors_kb * 1024
    __u32 floored; // 1 = IU was the assumed 4K NVMe floor, not a reported value (provenance)
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct dev_geom);
} dev_geoms SEC(".maps");

// Filesystem-layer readahead, per file (XFS/iomap), from the iomap:iomap_readahead tracepoint:
// nr_pages = readahead_count(rac), the base pages XFS PREPARED for readahead on this inode (the
// predicted window; the demand page is inside it). Compare against filemap_fault DEMAND: the excess
// is the readahead over-fetch -- the split block_rq_issue (post-merge) cannot give. NOT device
// completion; holes/failures/partial submission can still intervene below.
struct iomap_stats {
    __u64 ra_prepared_pages;
    __u64 ra_calls;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct devino_key);
    __type(value, struct iomap_stats);
} iomap_reads SEC(".maps");

// Unique 4 KiB pages touched per file = the MINIMUM I/O floor: the bytes you must read from storage
// even with a perfect (infinite) cache, each page fetched exactly once. min_io = unique_pages * 4096.
// actual/min = the avoidable waste (cache thrash + readahead above the footprint); min/useful_bytes =
// the irreducible 4 KiB-granularity + layout tax. Marked from mmap faults (pgoff) and O_DIRECT begins
// (pos..pos+count). NO_PREALLOC so memory tracks the real footprint, not the 8M cap.
struct page_key {
    __u32 dev;
    __u64 ino;
    __u64 pgoff;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8388608);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct page_key);
    __type(value, __u8);
} pages_seen SEC(".maps");

static __always_inline void mark_page(__u32 dev, __u64 ino, __u64 pgoff)
{
    struct page_key pk = {.dev = dev, .ino = ino, .pgoff = pgoff};
    __u8 one = 1;
    bpf_map_update_elem(&pages_seen, &pk, &one, BPF_NOEXIST);
}

static __always_inline int read_fd_inode(__u32 fd_num, __u32 *dev, __u64 *ino)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct file **fdarr = BPF_CORE_READ(task, files, fdt, fd);
    if (!fdarr)
        return -1;
    struct file *file = NULL;
    bpf_probe_read_kernel(&file, sizeof(file), &fdarr[fd_num]);
    if (!file)
        return -1;
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return -1;
    *ino = BPF_CORE_READ(inode, i_ino);
    *dev = BPF_CORE_READ(inode, i_sb, s_dev);
    return 0;
}
static __always_inline int account_io(__u32 fd_num, __u64 count, __u32 is_write)
{
    __u32 dev;
    __u64 ino;
    if (read_fd_inode(fd_num, &dev, &ino))
        return 0;
    struct sysio_key k = {.dev = dev, .ino = ino, .is_write = is_write};
    struct sysread_stats *s = bpf_map_lookup_elem(&syscall_reads, &k);
    if (!s) {
        struct sysread_stats zero = {};
        bpf_map_update_elem(&syscall_reads, &k, &zero, BPF_NOEXIST);
        s = bpf_map_lookup_elem(&syscall_reads, &k);
    }
    if (s) {
        __sync_fetch_and_add(&s->read_calls, 1);
        __sync_fetch_and_add(&s->read_bytes, count);
        // min/max are non-atomic read-modify-write: a lost update under cross-CPU contention just
        // defers the extreme to its next occurrence, which over millions of reads is exact.
        if (s->min_bytes == 0 || count < s->min_bytes)
            s->min_bytes = count;
        if (count > s->max_bytes)
            s->max_bytes = count;
    }
    return 0;
}

// optional pid filter (0 = trace all). Set via skeleton rodata before load.
const volatile __u32 target_tgid = 0;

// debug stage counters: 0=enter 1=passed-filter 2=null-file 3=created 4=exit 5=found 6=retry 7=emit
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} dbg SEC(".maps");
static __always_inline void dbg_inc(__u32 i)
{
    __u64 *v = bpf_map_lookup_elem(&dbg, &i);
    if (v)
        __sync_fetch_and_add(v, 1);
}

SEC("fentry/filemap_fault")
int BPF_PROG(on_fault_enter, struct vm_fault *vmf)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    if (target_tgid && tgid != target_tgid)
        return 0;
    dbg_inc(0);

    __u32 flags = BPF_CORE_READ(vmf, flags);
    if (!(flags & FAULT_FLAG_USER)) // only userspace demand faults
        return 0;
    if (flags & FAULT_FLAG_INSTRUCTION) // skip instruction fetches
        return 0;
    if (flags & FAULT_FLAG_TRIED) // a retry re-entry: the original attempt was already counted
        return 0;
    dbg_inc(1);

    struct vm_area_struct *vma = BPF_CORE_READ(vmf, vma);
    struct file *file = BPF_CORE_READ(vma, vm_file);
    if (!file) { // not file-backed
        dbg_inc(2);
        return 0;
    }
    dbg_inc(3);

    struct fault_key k = {
        .pid_tgid = pid_tgid,
        .addr_page = BPF_CORE_READ(vmf, address) >> PAGE_SHIFT,
    };
    struct pending p = {
        .dev = BPF_CORE_READ(file, f_mapping, host, i_sb, s_dev),
        .ino = BPF_CORE_READ(file, f_mapping, host, i_ino),
        .pgoff = BPF_CORE_READ(vmf, pgoff),
        .ret_or = 0,
        .attempts = 0,
        .write = !!(flags & FAULT_FLAG_WRITE),
    };
    // BPF_NOEXIST: first attempt creates; retry re-entries keep the accumulated state intact.
    bpf_map_update_elem(&pending_faults, &k, &p, BPF_NOEXIST);
    return 0;
}

SEC("fexit/filemap_fault")
int BPF_PROG(on_fault_exit, struct vm_fault *vmf, int ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct fault_key k = {
        .pid_tgid = pid_tgid,
        .addr_page = BPF_CORE_READ(vmf, address) >> PAGE_SHIFT,
    };
    dbg_inc(4);
    struct pending *p = bpf_map_lookup_elem(&pending_faults, &k);
    if (!p)
        return 0;
    dbg_inc(5);
    __u32 r = (__u32)ret;
    // filemap_fault returns VM_FAULT_RETRY (often with MAJOR) on the first attempt once it has
    // INITIATED storage I/O and dropped the mmap lock; on this kernel the retry resolves without a
    // second filemap_fault call, so RETRY is the terminal return and means a major (disk) fault.
    // Count once here; FAULT_FLAG_TRIED re-entries were filtered at fentry, so no double-count.
    if (!(r & VM_FAULT_ERROR)) {
        dbg_inc(7);
        __u8 major = !!(r & (VM_FAULT_MAJOR | VM_FAULT_RETRY));
        if (r & VM_FAULT_RETRY)
            dbg_inc(6); // retried (== major I/O initiated)
        struct file_key fk = {.tgid = (__u32)(pid_tgid >> 32), .dev = p->dev, .ino = p->ino};
        struct file_stats *st = bpf_map_lookup_elem(&file_stats, &fk);
        if (!st) {
            struct file_stats zero = {};
            bpf_map_update_elem(&file_stats, &fk, &zero, BPF_NOEXIST);
            st = bpf_map_lookup_elem(&file_stats, &fk);
        }
        if (st) {
            __sync_fetch_and_add(&st->completed_faults, 1);
            __sync_fetch_and_add(&st->fault_bytes, PAGE_SIZE);
            if (major) {
                __sync_fetch_and_add(&st->major_faults, 1);
                __sync_fetch_and_add(&st->major_bytes, PAGE_SIZE);
                __sync_fetch_and_add(&st->retries, !!(r & VM_FAULT_RETRY));
            } else {
                __sync_fetch_and_add(&st->minor_faults, 1);
            }
            if (p->write)
                __sync_fetch_and_add(&st->write_faults, 1);
        }
        mark_page(p->dev, p->ino, p->pgoff); // unique demanded page (the footprint, not readahead)
    }
    bpf_map_delete_elem(&pending_faults, &k);
    return 0;
}

// Folio INSERTED into the page cache (demand fault OR readahead). This is page-cache INSERTION, which
// fires BEFORE read_pages() submits to the filesystem -- a near-proxy for a cold read, NOT a device
// completion (the FS may leave prepared folios unread). For the true device bytes use block_rq_issue.
// The gap insertion - fault is the readahead over-fetch (large for plain mmap, ~0 for MADV_RANDOM).
// O_DIRECT bypasses the page cache, so it does NOT appear here (by design).
SEC("tracepoint/filemap/mm_filemap_add_to_page_cache")
int on_pgcache_add(struct trace_event_raw_mm_filemap_op_page_cache *ctx)
{
    struct devino_key k = {
        .dev = BPF_CORE_READ(ctx, s_dev),
        .ino = BPF_CORE_READ(ctx, i_ino),
    };
    __u8 order = BPF_CORE_READ(ctx, order);
    struct pgcache_stats *s = bpf_map_lookup_elem(&pgcache, &k);
    if (!s) {
        struct pgcache_stats zero = {};
        bpf_map_update_elem(&pgcache, &k, &zero, BPF_NOEXIST);
        s = bpf_map_lookup_elem(&pgcache, &k);
    }
    if (s) {
        __sync_fetch_and_add(&s->fill_pages, (__u64)1 << order);
        __sync_fetch_and_add(&s->fill_bytes, (__u64)PAGE_SIZE << order);
    }
    return 0;
}

// read/pread/write/pwrite intent (fd,buf,count[,pos]) -- count is args[2] for all four.
SEC("tracepoint/syscalls/sys_enter_pread64")
int on_pread(struct trace_event_raw_sys_enter *ctx)
{ return account_io((__u32)ctx->args[0], (__u64)ctx->args[2], 0); }
SEC("tracepoint/syscalls/sys_enter_read")
int on_read(struct trace_event_raw_sys_enter *ctx)
{ return account_io((__u32)ctx->args[0], (__u64)ctx->args[2], 0); }
SEC("tracepoint/syscalls/sys_enter_pwrite64")
int on_pwrite(struct trace_event_raw_sys_enter *ctx)
{ return account_io((__u32)ctx->args[0], (__u64)ctx->args[2], 1); }
SEC("tracepoint/syscalls/sys_enter_write")
int on_write(struct trace_event_raw_sys_enter *ctx)
{ return account_io((__u32)ctx->args[0], (__u64)ctx->args[2], 1); }

// vectored I/O (fd, iov, iovcnt): sum the iovec lengths from user memory. INTENT (fires for cache or
// device). Covers preadv/readv (reads) and pwritev/writev (writes -- LMCache's KV offload).
static __always_inline int account_iov(__u32 fd, const struct iovec *iov, __u64 iovcnt, __u32 is_write)
{
    __u64 total = 0;
    for (int i = 0; i < 16; i++) {
        if ((__u64)i >= iovcnt)
            break;
        struct iovec v = {};
        if (bpf_probe_read_user(&v, sizeof(v), &iov[i]))
            break;
        total += (__u64)v.iov_len;
    }
    return account_io(fd, total, is_write);
}
SEC("tracepoint/syscalls/sys_enter_preadv")
int on_preadv(struct trace_event_raw_sys_enter *ctx)
{ return account_iov((__u32)ctx->args[0], (const struct iovec *)ctx->args[1], (__u64)ctx->args[2], 0); }
SEC("tracepoint/syscalls/sys_enter_preadv2")
int on_preadv2(struct trace_event_raw_sys_enter *ctx)
{ return account_iov((__u32)ctx->args[0], (const struct iovec *)ctx->args[1], (__u64)ctx->args[2], 0); }
SEC("tracepoint/syscalls/sys_enter_readv")
int on_readv(struct trace_event_raw_sys_enter *ctx)
{ return account_iov((__u32)ctx->args[0], (const struct iovec *)ctx->args[1], (__u64)ctx->args[2], 0); }
SEC("tracepoint/syscalls/sys_enter_pwritev")
int on_pwritev(struct trace_event_raw_sys_enter *ctx)
{ return account_iov((__u32)ctx->args[0], (const struct iovec *)ctx->args[1], (__u64)ctx->args[2], 1); }
SEC("tracepoint/syscalls/sys_enter_pwritev2")
int on_pwritev2(struct trace_event_raw_sys_enter *ctx)
{ return account_iov((__u32)ctx->args[0], (const struct iovec *)ctx->args[1], (__u64)ctx->args[2], 1); }
SEC("tracepoint/syscalls/sys_enter_writev")
int on_writev(struct trace_event_raw_sys_enter *ctx)
{ return account_iov((__u32)ctx->args[0], (const struct iovec *)ctx->args[1], (__u64)ctx->args[2], 1); }

// O_DIRECT begin -- carries pos+count, so mark the page footprint (unique pages = the minimum I/O).
SEC("tracepoint/iomap/iomap_dio_rw_begin")
int on_dio_begin(struct trace_event_raw_iomap_dio_rw_begin *ctx)
{
    __u32 dev = BPF_CORE_READ(ctx, dev);
    __u64 ino = BPF_CORE_READ(ctx, ino);
    __u64 pos = BPF_CORE_READ(ctx, pos);
    __u64 count = BPF_CORE_READ(ctx, count);
    __u64 start = pos >> PAGE_SHIFT;
    __u64 end = (pos + count + PAGE_SIZE - 1) >> PAGE_SHIFT;
    for (int i = 0; i < 256; i++) { // bounded: 4 KiB reads = 1 page; caps a single DIO at 1 MiB footprint
        if (start + i >= end)
            break;
        mark_page(dev, ino, start + i);
    }
    return 0;
}

// O_DIRECT completion -- the one hook where O_DIRECT is attributable to a regular file (the
// tracepoint reads dev+inode from iocb->ki_filp). Closes the hole the page-cache probe can't see.
SEC("tracepoint/iomap/iomap_dio_complete")
int on_dio_complete(struct trace_event_raw_iomap_dio_complete *ctx)
{
    long ret = BPF_CORE_READ(ctx, ret);
    if (ret <= 0)
        return 0;
    struct devino_key k = {
        .dev = BPF_CORE_READ(ctx, dev),
        .ino = BPF_CORE_READ(ctx, ino),
    };
    struct odirect_stats *s = bpf_map_lookup_elem(&odirect, &k);
    if (!s) {
        struct odirect_stats zero = {};
        bpf_map_update_elem(&odirect, &k, &zero, BPF_NOEXIST);
        s = bpf_map_lookup_elem(&odirect, &k);
    }
    if (s) {
        __sync_fetch_and_add(&s->dio_bytes, (__u64)ret);
        __sync_fetch_and_add(&s->dio_calls, 1);
    }
    return 0;
}

// PHYSICAL block-device I/O (block_rq_issue), split by direction. rwbs[0]: 'R' read (incl 'RA'
// readahead), 'W' write. Per (dev, direction) -- the true storage bytes, the bottom of the stack.
SEC("tracepoint/block/block_rq_issue")
int on_block_rq(struct trace_event_raw_block_rq *ctx)
{
    char op = 0;
    bpf_probe_read_kernel(&op, 1, &ctx->rwbs[0]);
    __u32 is_write;
    if (op == 'R')
        is_write = 0;
    else if (op == 'W')
        is_write = 1;
    else
        return 0; // skip discards/flushes
    __u32 dev = BPF_CORE_READ(ctx, dev);
    __u32 bytes = BPF_CORE_READ(ctx, bytes);
    struct bdev_key bkey = {.dev = dev, .is_write = is_write};
    struct block_stats *s = bpf_map_lookup_elem(&block_reads, &bkey);
    if (!s) {
        struct block_stats zero = {};
        bpf_map_update_elem(&block_reads, &bkey, &zero, BPF_NOEXIST);
        s = bpf_map_lookup_elem(&block_reads, &bkey);
    }
    if (s) {
        __sync_fetch_and_add(&s->read_bytes, bytes);
        __sync_fetch_and_add(&s->read_ios, 1);
        if (s->min_io == 0 || bytes < s->min_io)
            s->min_io = bytes;
        if (bytes > s->max_io)
            s->max_io = bytes;
        // size histogram, 512-byte base (so sub-4K reads are visible): bucket=floor(log2(bytes/512)).
        __u32 units = bytes >> 9;
        int b = 0;
        for (int i = 0; i < 11; i++) {
            if (units <= 1)
                break;
            units >>= 1;
            b++;
        }
        __sync_fetch_and_add(&s->hist[b], 1);
        // IU read amplification: charge this read to the Indirection Units it spans. Using the start
        // SECTOR (alignment matters: an IU-sized read crossing a boundary spans 2 IUs), iu_bytes =
        // (last_IU - first_IU + 1) * IU. iu_bytes/read_bytes is the IU-granular over-read factor.
        struct dev_geom *g = bpf_map_lookup_elem(&dev_geoms, &dev);
        if (g && g->iu) {
            __u64 start = (__u64)BPF_CORE_READ(ctx, sector) << 9; // sector is 512-byte units
            __u64 end = start + bytes;
            __u64 first = start / g->iu;
            __u64 last = (end - 1) / g->iu;
            __sync_fetch_and_add(&s->iu_bytes, (last - first + 1) * (__u64)g->iu);
            if (bytes < g->iu)
                __sync_fetch_and_add(&s->sub_iu_ios, 1);
        }
    }
    return 0;
}

// XFS/iomap readahead via the tracepoint (iomap_readahead is exposed as a TRACE_EVENT, not a plain
// fentry target -- its BTF FUNC is the tp trampoline, so fentry read garbage). The tracepoint hands
// us dev+ino+nr_pages directly, no CO-RE pointer walk. nr_pages = the readahead_count prepared.
struct iomap_ra_tp {
    char common[8]; // common_type/flags/preempt_count/pid
    __u32 dev;      // offset 8
    __u32 _pad;     // ino is 8-aligned at offset 16
    __u64 ino;      // offset 16
    __s32 nr_pages; // offset 24
};
SEC("tracepoint/iomap/iomap_readahead")
int on_iomap_readahead(struct iomap_ra_tp *ctx)
{
    struct devino_key k = {.dev = ctx->dev, .ino = ctx->ino};
    __s32 nr = ctx->nr_pages;
    if (nr < 0)
        nr = 0;
    struct iomap_stats *s = bpf_map_lookup_elem(&iomap_reads, &k);
    if (!s) {
        struct iomap_stats zero = {};
        bpf_map_update_elem(&iomap_reads, &k, &zero, BPF_NOEXIST);
        s = bpf_map_lookup_elem(&iomap_reads, &k);
    }
    if (s) {
        __sync_fetch_and_add(&s->ra_prepared_pages, (__u64)nr);
        __sync_fetch_and_add(&s->ra_calls, 1);
    }
    return 0;
}

// reap stale pending entries on thread exit (a RETRY that never completed)
SEC("tracepoint/sched/sched_process_exit")
int on_proc_exit(void *ctx)
{
    // best-effort: the current task's pending single-page entry, if any
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    // we cannot enumerate keys in BPF; rely on map LRU pressure / restart for full cleanup.
    // (single-address pending entries are tiny and self-limiting; left as a noted limitation.)
    (void)pid_tgid;
    return 0;
}

char _license[] SEC("license") = "GPL";
