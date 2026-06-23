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
    mmap_readamp_bpf__destroy(skel);
    return 0;
}
