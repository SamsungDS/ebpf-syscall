// SPDX-License-Identifier: GPL-2.0
// mmap_readamp.c -- loader for the mmap demand-fault read-amplification tracer.
// Attaches the filemap_fault fentry/fexit programs, runs until Ctrl-C (or --dur N), then dumps the
// per-file fault counters. Read-amp numerator = fault_bytes (faults * 4 KiB); the logical-bytes
// denominator comes from the workload (fio iolog / the app), reported separately.
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "mmap_readamp.skel.h"

struct file_key {
    unsigned int tgid;
    unsigned int dev;
    unsigned long long ino;
};
struct file_stats {
    unsigned long long completed_faults, minor_faults, major_faults, write_faults;
    unsigned long long fault_bytes, major_bytes, retries;
};
struct devino_key {
    unsigned int dev;
    unsigned long long ino;
};
struct pgcache_stats {
    unsigned long long fill_pages, fill_bytes;
};
struct sysread_stats {
    unsigned long long read_calls, read_bytes;
};
struct odirect_stats {
    unsigned long long dio_bytes, dio_calls;
};
struct block_stats {
    unsigned long long read_bytes, read_ios;
};

static volatile int stop;
static void on_sig(int s) { (void)s; stop = 1; }

int main(int argc, char **argv)
{
    int dur = 0;
    unsigned int pid = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--pid") && i + 1 < argc) pid = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--dur") && i + 1 < argc) dur = atoi(argv[++i]);
    }

    struct mmap_readamp_bpf *skel = mmap_readamp_bpf__open();
    if (!skel) { fprintf(stderr, "open failed\n"); return 1; }
    skel->rodata->target_tgid = pid;
    if (mmap_readamp_bpf__load(skel)) { fprintf(stderr, "load failed (verifier?)\n"); return 1; }
    if (mmap_readamp_bpf__attach(skel)) { fprintf(stderr, "attach failed (filemap_fault fentry?)\n"); return 1; }

    signal(SIGINT, on_sig); signal(SIGTERM, on_sig); signal(SIGALRM, on_sig);
    fprintf(stderr, "tracing filemap_fault demand faults%s%u ... Ctrl-C to stop\n",
            pid ? " for pid " : " (all pids)", pid);
    if (dur) alarm(dur);
    while (!stop) pause();

    int dfd = bpf_map__fd(skel->maps.dbg);
    const char *names[8] = {"enter", "passed-filter", "null-file", "created",
                            "exit", "found", "retry", "emit"};
    fprintf(stderr, "\n[debug stages]\n");
    for (unsigned int i = 0; i < 8; i++) {
        unsigned long long val = 0;
        bpf_map_lookup_elem(dfd, &i, &val);
        fprintf(stderr, "  %-14s %llu\n", names[i], val);
    }

    int fd = bpf_map__fd(skel->maps.file_stats);
    struct file_key k, nk;
    struct file_stats v;
    int first = 1, any = 0;
    printf("\n%-8s %-22s %12s %12s %12s %12s %12s %9s\n",
           "tgid", "dev:inode", "faults", "minor", "major", "fault_MB", "major_MB", "retries");
    memset(&k, 0xff, sizeof(k));
    while (bpf_map_get_next_key(fd, first ? NULL : &k, &nk) == 0) {
        first = 0;
        if (bpf_map_lookup_elem(fd, &nk, &v) == 0) {
            char di[40];
            snprintf(di, sizeof(di), "%u:%llu", nk.dev, nk.ino);
            printf("%-8u %-22s %12llu %12llu %12llu %12.2f %12.2f %9llu\n",
                   nk.tgid, di, v.completed_faults, v.minor_faults, v.major_faults,
                   v.fault_bytes / 1e6, v.major_bytes / 1e6, v.retries);
            any = 1;
        }
        k = nk;
    }
    if (!any) printf("(no file-backed demand faults captured)\n");

    // ACTUAL storage reads per file (demand + readahead) from mm_filemap_add_to_page_cache.
    // fill_MB is what the block layer was forced to read; fault_MB (above) is the demand (intent).
    // readahead over-fetch = fill_MB - fault_MB (large for plain mmap, ~0 for MADV_RANDOM).
    // O_DIRECT reads do NOT appear here (they bypass the page cache).
    int pfd = bpf_map__fd(skel->maps.pgcache);
    struct devino_key pk, pnk;
    struct pgcache_stats pv;
    int pfirst = 1, pany = 0;
    printf("\n%-16s %14s %14s\n", "dev:inode", "fill_pages", "actual_fill_MB");
    memset(&pk, 0xff, sizeof(pk));
    while (bpf_map_get_next_key(pfd, pfirst ? NULL : &pk, &pnk) == 0) {
        pfirst = 0;
        if (bpf_map_lookup_elem(pfd, &pnk, &pv) == 0) {
            char di[40];
            snprintf(di, sizeof(di), "%u:%llu", pnk.dev, pnk.ino);
            printf("%-16s %14llu %14.2f\n", di, pv.fill_pages, pv.fill_bytes / 1e6);
            pany = 1;
        }
        pk = pnk;
    }
    if (!pany) printf("(no page-cache fills captured)\n");

    // INTENT via read()/pread() syscalls, per file (fd -> inode). Empty for pure mmap (no syscalls);
    // populated for a pread/O_DIRECT offload -- this is what the app asked the kernel to read.
    int sfd = bpf_map__fd(skel->maps.syscall_reads);
    struct devino_key sk, snk;
    struct sysread_stats sv;
    int sfirst = 1, sany = 0;
    printf("\n%-16s %14s %16s %14s\n", "dev:inode", "read_calls", "read_bytes(MB)", "avg_req(B)");
    memset(&sk, 0xff, sizeof(sk));
    while (bpf_map_get_next_key(sfd, sfirst ? NULL : &sk, &snk) == 0) {
        sfirst = 0;
        if (bpf_map_lookup_elem(sfd, &snk, &sv) == 0) {
            char di[40];
            snprintf(di, sizeof(di), "%u:%llu", snk.dev, snk.ino);
            printf("%-16s %14llu %16.2f %14.0f\n", di, sv.read_calls, sv.read_bytes / 1e6,
                   sv.read_calls ? (double)sv.read_bytes / sv.read_calls : 0.0);
            sany = 1;
        }
        sk = snk;
    }
    if (!sany) printf("(no read/pread syscalls -- expected for pure mmap)\n");

    // O_DIRECT bytes per file (iomap DIO) -- the offload's actual reads, which bypass the page cache.
    int ofd = bpf_map__fd(skel->maps.odirect);
    struct devino_key ok, onk;
    struct odirect_stats ov;
    int ofirst = 1, oany = 0;
    printf("\n%-16s %14s %16s\n", "dev:inode", "dio_calls", "odirect_MB");
    memset(&ok, 0xff, sizeof(ok));
    while (bpf_map_get_next_key(ofd, ofirst ? NULL : &ok, &onk) == 0) {
        ofirst = 0;
        if (bpf_map_lookup_elem(ofd, &onk, &ov) == 0) {
            char di[40];
            snprintf(di, sizeof(di), "%u:%llu", onk.dev, onk.ino);
            printf("%-16s %14llu %16.2f\n", di, ov.dio_calls, ov.dio_bytes / 1e6);
            oany = 1;
        }
        ok = onk;
    }
    if (!oany) printf("(no O_DIRECT reads captured)\n");

    // PHYSICAL block-device reads, per device (block_rq_issue) -- the true storage bytes (vs the
    // page-cache materialization footprint above). Not per-file: the block layer loses the inode.
    int bfd = bpf_map__fd(skel->maps.block_reads);
    unsigned int bk, bnk;
    struct block_stats bv;
    int bfirst = 1, bany = 0;
    printf("\n%-10s %14s %16s\n", "device", "read_ios", "physical_MB");
    memset(&bk, 0xff, sizeof(bk));
    while (bpf_map_get_next_key(bfd, bfirst ? NULL : &bk, &bnk) == 0) {
        bfirst = 0;
        if (bpf_map_lookup_elem(bfd, &bnk, &bv) == 0) {
            printf("%-10u %14llu %16.2f\n", bnk, bv.read_ios, bv.read_bytes / 1e6);
            bany = 1;
        }
        bk = bnk;
    }
    if (!bany) printf("(no block reads captured)\n");

    mmap_readamp_bpf__destroy(skel);
    return 0;
}
