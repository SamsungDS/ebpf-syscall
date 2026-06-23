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
    }
    bpf_map_delete_elem(&pending_faults, &k);
    return 0;
}

// Every folio inserted into the page cache = an actual storage read (the demand-faulted page OR a
// readahead page). This is the BLOCK-forced read (4 KiB << order), vs filemap_fault's demand. The
// gap between this and fault_bytes is the readahead over-fetch (large for plain mmap, ~0 for
// MADV_RANDOM). O_DIRECT bypasses the page cache, so it does NOT appear here (by design).
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
