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
#include <dirent.h>
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
    unsigned long long read_calls, read_bytes, min_bytes, max_bytes;
};
struct sysio_key {
    unsigned int dev;
    unsigned long long ino;
    unsigned int is_write;
};
struct bdev_key {
    unsigned int dev, is_write;
};
struct odirect_stats {
    unsigned long long dio_bytes, dio_calls;
};
struct block_stats {
    unsigned long long read_bytes, read_ios, hist[12], iu_bytes, sub_iu_ios, min_io, max_io;
};
struct dev_geom {
    unsigned int iu, nows, mdts, floored;
};
struct iomap_stats {
    unsigned long long ra_prepared_pages, ra_calls;
};
struct page_key {
    unsigned int dev;
    unsigned long long ino;
    unsigned long long pgoff;
};

static volatile int stop;
static void on_sig(int s) { (void)s; stop = 1; }

static unsigned int read_u32_file(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    unsigned long v = 0;
    if (fscanf(f, "%lu", &v) != 1) v = 0;
    fclose(f);
    return (unsigned int)v;
}

// Human-friendly byte size into a caller buffer (B / KiB / MiB / GiB / TiB).
static const char *hsize(unsigned long long b, char *buf, size_t n)
{
    static const char *u[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double v = (double)b;
    int i = 0;
    while (v >= 1024.0 && i < 4) { v /= 1024.0; i++; }
    if (i == 0) snprintf(buf, n, "%llu %s", b, u[0]);
    else if (v == (double)(long long)v) snprintf(buf, n, "%.0f %s", v, u[i]);
    else snprintf(buf, n, "%.1f %s", v, u[i]);
    return buf;
}

// Scrape per-device geometry from sysfs into dev_geoms so the BPF can charge each read to its IU.
// IU = minimum_io_size, but for an NVMe namespace reporting physical_block_size==512 we bake in the
// 4 KiB floor (512 LBA is compatibility-only; every real NVMe drive has an IU of >= 4 KiB).
static void scrape_geometry(int gfd)
{
    DIR *d = opendir("/sys/block");
    if (!d) return;
    struct dirent *e;
    char p[600];
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        snprintf(p, sizeof(p), "/sys/block/%s/dev", e->d_name);
        FILE *f = fopen(p, "r");
        if (!f) continue;
        unsigned int maj = 0, mi = 0;
        int ok = fscanf(f, "%u:%u", &maj, &mi) == 2;
        fclose(f);
        if (!ok) continue;
        unsigned int dev = (maj << 20) | mi;
        snprintf(p, sizeof(p), "/sys/block/%s/queue/minimum_io_size", e->d_name);
        unsigned int min_io = read_u32_file(p);
        snprintf(p, sizeof(p), "/sys/block/%s/queue/physical_block_size", e->d_name);
        unsigned int phys = read_u32_file(p);
        snprintf(p, sizeof(p), "/sys/block/%s/queue/optimal_io_size", e->d_name);
        unsigned int nows = read_u32_file(p);
        snprintf(p, sizeof(p), "/sys/block/%s/queue/max_hw_sectors_kb", e->d_name);
        unsigned int mdts = read_u32_file(p) * 1024;
        int is_nvme = strncmp(e->d_name, "nvme", 4) == 0;
        unsigned int iu = min_io, floored = 0;
        if (is_nvme && phys == 512 && iu < 4096) { iu = 4096; floored = 1; } // baked-in NVMe IU floor
        if (iu == 0) iu = phys ? phys : 512;
        struct dev_geom g = {.iu = iu, .nows = nows, .mdts = mdts, .floored = floored};
        bpf_map_update_elem(gfd, &dev, &g, BPF_ANY);
    }
    closedir(d);
}

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
    scrape_geometry(bpf_map__fd(skel->maps.dev_geoms)); // populate per-device IU/NOWS/MDTS before tracing
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
    printf("\n%-16s %14s %16s   (page-cache INSERTION, pre-FS-submission, not device completion)\n",
           "dev:inode", "fill_pages", "insertion_MB");
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

    // INTENT via read/pread/preadv AND write/pwrite/pwritev syscalls, per file+direction (fd->inode).
    // Empty for pure mmap (no syscalls); populated for a pread/pwrite/O_DIRECT path -- LMCache writes here.
    int sfd = bpf_map__fd(skel->maps.syscall_reads);
    struct sysio_key sk, snk;
    struct sysread_stats sv;
    int sfirst = 1, sany = 0;
    printf("\n%-16s %3s %12s %12s %9s %9s %9s   (per-op INTENT size: what the app asks the kernel)\n",
           "dev:inode", "rw", "calls", "bytes", "min", "avg", "max");
    memset(&sk, 0xff, sizeof(sk));
    while (bpf_map_get_next_key(sfd, sfirst ? NULL : &sk, &snk) == 0) {
        sfirst = 0;
        if (bpf_map_lookup_elem(sfd, &snk, &sv) == 0) {
            char di[40], bb[24], bmn[24], bav[24], bmx[24];
            unsigned long long avg = sv.read_calls ? sv.read_bytes / sv.read_calls : 0;
            snprintf(di, sizeof(di), "%u:%llu", snk.dev, snk.ino);
            printf("%-16s %3s %12llu %12s %9s %9s %9s\n", di, snk.is_write ? "W" : "R", sv.read_calls,
                   hsize(sv.read_bytes, bb, sizeof(bb)), hsize(sv.min_bytes, bmn, sizeof(bmn)),
                   hsize(avg, bav, sizeof(bav)), hsize(sv.max_bytes, bmx, sizeof(bmx)));
            sany = 1;
        }
        sk = snk;
    }
    if (!sany) printf("(no read/write syscalls -- expected for pure mmap)\n");

    // O_DIRECT bytes per file (iomap DIO) -- the offload's actual reads, which bypass the page cache.
    int ofd = bpf_map__fd(skel->maps.odirect);
    struct devino_key ok, onk;
    struct odirect_stats ov;
    int ofirst = 1, oany = 0;
    printf("\n%-16s %14s %16s %12s\n", "dev:inode", "dio_calls", "odirect_MB", "avg_io_B");
    memset(&ok, 0xff, sizeof(ok));
    while (bpf_map_get_next_key(ofd, ofirst ? NULL : &ok, &onk) == 0) {
        ofirst = 0;
        if (bpf_map_lookup_elem(ofd, &onk, &ov) == 0) {
            char di[40];
            snprintf(di, sizeof(di), "%u:%llu", onk.dev, onk.ino);
            printf("%-16s %14llu %16.2f %12.0f\n", di, ov.dio_calls, ov.dio_bytes / 1e6,
                   ov.dio_calls ? (double)ov.dio_bytes / ov.dio_calls : 0.0);
            oany = 1;
        }
        ok = onk;
    }
    if (!oany) printf("(no O_DIRECT reads captured)\n");

    // PHYSICAL block-device reads, per device (block_rq_issue) -- the true storage bytes (vs the
    // page-cache insertion above). Not per-file: the block layer loses the inode. The SIZE HISTOGRAM
    // is the point: an average hides whether 23 KB means "mostly 4K + rare 128K" or "uniformly 23K".
    int bfd = bpf_map__fd(skel->maps.block_reads);
    int ggfd = bpf_map__fd(skel->maps.dev_geoms);
    struct bdev_key bk, bnk;
    struct block_stats bv;
    int bfirst = 1, bany = 0, floored_any = 0, opt_unrep = 0;
    const char *hl[12] = {"512", "1K",  "2K",   "4K",   "8K",   "16K",
                          "32K", "64K", "128K", "256K", "512K", ">=1M"};
    printf("\n%-9s %3s %9s %9s %9s %9s %9s %9s %9s %9s %8s %7s\n", "device", "rw", "ios", "bytes",
           "min", "avg", "max", "IU", "opt_io", "MDTS", "IU_amp", "sub-IU%");
    printf("  (IU_amp = IU-granular bytes / actual; sub-IU%% = ops below the IU; W sub-IU = RMW risk)\n");
    memset(&bk, 0xff, sizeof(bk));
    while (bpf_map_get_next_key(bfd, bfirst ? NULL : &bk, &bnk) == 0) {
        bfirst = 0;
        if (bpf_map_lookup_elem(bfd, &bnk, &bv) == 0) {
            struct dev_geom g = {0, 0, 0, 0};
            bpf_map_lookup_elem(ggfd, &bnk.dev, &g);
            double amp = bv.read_bytes ? (double)bv.iu_bytes / bv.read_bytes : 0.0;
            double subp = bv.read_ios ? 100.0 * bv.sub_iu_ios / bv.read_ios : 0.0;
            unsigned long long avg = bv.read_ios ? bv.read_bytes / bv.read_ios : 0;
            char bp[24], bmin[24], bavg[24], bmax[24], biu[24], bno[24], bmd[24], iustr[28];
            hsize(g.iu, biu, sizeof(biu));
            snprintf(iustr, sizeof(iustr), "%s%s", biu, g.floored ? "*" : "");
            if (g.floored) floored_any = 1;
            // opt_io = optimal_io_size verbatim. >0 -> the device's preferred sustained-I/O unit;
            // 0 -> the device reports no optimal I/O size (kernel ABI). Show it raw, never fake it.
            if (g.nows) hsize(g.nows, bno, sizeof(bno));
            else { snprintf(bno, sizeof(bno), "0"); opt_unrep = 1; }
            printf("%-9u %3s %9llu %9s %9s %9s %9s %9s %9s %9s %6.2fx %6.1f%%\n", bnk.dev,
                   bnk.is_write ? "W" : "R", bv.read_ios, hsize(bv.read_bytes, bp, sizeof(bp)),
                   hsize(bv.min_io, bmin, sizeof(bmin)), hsize(avg, bavg, sizeof(bavg)),
                   hsize(bv.max_io, bmax, sizeof(bmax)), iustr, bno, hsize(g.mdts, bmd, sizeof(bmd)),
                   amp, subp);
            printf("  size hist(ops): ");
            for (int i = 0; i < 12; i++) {
                unsigned int bsz = 512u << i;
                char m = ' ';
                if (g.iu && bsz == g.iu) m = 'I';
                else if (g.nows && bsz == g.nows) m = 'O';
                else if (g.mdts && bsz == g.mdts) m = 'M';
                printf("%s%c=%llu ", hl[i], m, bv.hist[i]);
            }
            printf("  [I=IU O=opt_io M=MDTS]\n");
            bany = 1;
        }
        bk = bnk;
    }
    if (!bany) printf("(no block reads captured)\n");
    if (floored_any)
        printf("  * IU assumed 4 KiB (NVMe 512-LBA; device did not report a larger one)\n");
    if (opt_unrep)
        printf("  opt_io (optimal_io_size) = 0: device reports no optimal I/O size (kernel ABI) -- the\n"
               "         preferred unit for SUSTAINED throughput; rare on SSDs, usually a RAID stripe width\n");

    // FS-layer demand vs readahead (XFS/iomap), per file: readahead-PREPARED pages (the speculative
    // window) vs DEMAND folio reads. This is the split block_rq_issue cannot give (it is post-merge).
    int ifd = bpf_map__fd(skel->maps.iomap_reads);
    struct devino_key ik, ink;
    struct iomap_stats iv;
    int ifirst = 1, iany = 0;
    printf("\n%-16s %16s %12s   (XFS readahead PREPARED; vs fault_MB demand above = over-fetch)\n",
           "dev:inode", "ra_prepared_MB", "ra_calls");
    memset(&ik, 0xff, sizeof(ik));
    while (bpf_map_get_next_key(ifd, ifirst ? NULL : &ik, &ink) == 0) {
        ifirst = 0;
        if (bpf_map_lookup_elem(ifd, &ink, &iv) == 0) {
            char di[40];
            snprintf(di, sizeof(di), "%u:%llu", ink.dev, ink.ino);
            printf("%-16s %16.2f %12llu\n", di, iv.ra_prepared_pages * 4096.0 / 1e6, iv.ra_calls);
            iany = 1;
        }
        ik = ink;
    }
    if (!iany) printf("(no iomap readahead -- O_DIRECT, MADV_RANDOM, or non-iomap fs)\n");

    // PAGE FOOTPRINT: unique 4 KiB pages per file. NOT the application's intent and NOT the absolute
    // minimum -- it is the floor AT THE CURRENT ON-DISK LAYOUT (perfect cache, each touched page read
    // once). footprint_MB = unique_pages * 4 KiB. The app's useful bytes (rows x row_size, supplied by
    // you) are smaller; the gap footprint/useful is the scatter tax that a row REPACK removes, and
    // actual/footprint is the cache thrash that more cache removes. Tally per (dev,ino) open-addressed.
    int gfd = bpf_map__fd(skel->maps.pages_seen);
    struct page_key gk, gnk;
    unsigned char gv;
    enum { NT = 1 << 18 };
    static struct { unsigned int dev; unsigned long long ino, pages; } tal[NT];
    int gfirst = 1;
    unsigned long long npg = 0;
    memset(&gk, 0xff, sizeof(gk));
    while (bpf_map_get_next_key(gfd, gfirst ? NULL : &gk, &gnk) == 0) {
        gfirst = 0;
        if (bpf_map_lookup_elem(gfd, &gnk, &gv) == 0) {
            npg++;
            unsigned long long h = (gnk.ino * 1099511628211ULL) ^ gnk.dev;
            for (int probe = 0; probe < NT; probe++) {
                unsigned int b = (h + probe) & (NT - 1);
                if (tal[b].pages == 0) { tal[b].dev = gnk.dev; tal[b].ino = gnk.ino; tal[b].pages = 1; break; }
                if (tal[b].dev == gnk.dev && tal[b].ino == gnk.ino) { tal[b].pages++; break; }
            }
        }
        gk = gnk;
    }
    printf("\n%-16s %14s %16s   (distinct pages x 4KiB = floor AT THE CURRENT LAYOUT,"
           " not the app's useful bytes; a repack shrinks it toward useful)\n",
           "dev:inode", "unique_pages", "footprint_MB");
    if (!npg) printf("(no pages tracked)\n");
    for (int b = 0; b < NT; b++)
        if (tal[b].pages) {
            char di[40];
            snprintf(di, sizeof(di), "%u:%llu", tal[b].dev, tal[b].ino);
            printf("%-16s %14llu %14.2f\n", di, tal[b].pages, tal[b].pages * 4096.0 / 1e6);
        }

    mmap_readamp_bpf__destroy(skel);
    return 0;
}
