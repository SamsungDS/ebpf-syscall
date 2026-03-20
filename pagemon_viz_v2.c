/*
 * pagemon_viz.c — Fast page-level memory monitor for I/O path observer
 *
 * Multi-mmap aware: groups regions by backing file, coalesces adjacent/
 * overlapping mappings, and provides unified file-level visualization
 * even when the kernel splits a single file into hundreds of VMA regions.
 *
 * Build:  gcc -O2 -o pagemon_viz pagemon_viz.c -lm
 * Usage:  ./pagemon_viz <pid> <mode> [start_hex end_hex interval_ms count]
 *
 * Modes:
 *   0 = snapshot     : one-shot scan, print page states
 *   1 = softdirty    : clear soft-dirty, poll, report newly dirtied pages
 *   2 = heatmap      : continuous monitoring, output per-block dirty counts
 *   3 = timeline     : track dirty page count over time
 *   4 = region_all   : scan ALL file-backed regions (multi-mmap aware)
 *   5 = file_unified : coalesced file-offset heatmap across all VMAs
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/resource.h>

#define PAGE_SIZE       4096UL
#define PAGEMAP_ENTRY   8
#define MAX_REGIONS     4096
#define MAX_FILES       128
#define MAX_VMAS_PER_COAL 64
#define HEATMAP_COLS    64

/* ── Pagemap bits ── */
#define PM_PRESENT      (1ULL << 63)
#define PM_SWAPPED      (1ULL << 62)
#define PM_FILE         (1ULL << 61)
#define PM_SOFTDIRTY    (1ULL << 55)
#define PM_MMAP_EXCL    (1ULL << 56)
#define PM_PFN_MASK     ((1ULL << 55) - 1)

/* ── Region from /proc/<pid>/maps ── */
typedef struct {
    uint64_t start;
    uint64_t end;
    char     perms[8];
    uint64_t file_offset;
    char     pathname[512];
    int      is_file_backed;
    int      file_group_id;
} region_t;

/* ── Coalesced region: merged adjacent/overlapping VMAs of one file ── */
typedef struct {
    uint64_t file_offset_start;
    uint64_t file_offset_end;
    int      n_vmas;
    uint64_t vma_starts[MAX_VMAS_PER_COAL];
    uint64_t vma_ends[MAX_VMAS_PER_COAL];
    uint64_t vma_offsets[MAX_VMAS_PER_COAL];
} coalesced_region_t;

/* ── File group: all regions backed by the same file ── */
typedef struct {
    char     pathname[512];
    int      region_indices[MAX_REGIONS];
    int      n_regions;
    uint64_t total_mapped_bytes;
    uint64_t file_offset_min;
    uint64_t file_offset_max;
    coalesced_region_t *coalesced;
    int      n_coalesced;
} file_group_t;

/* ── Page state ── */
typedef struct {
    uint8_t present;
    uint8_t swapped;
    uint8_t file_mapped;
    uint8_t soft_dirty;
    uint8_t exclusive;
    uint64_t pfn;
} page_state_t;

/* ── Block stats ── */
typedef struct {
    uint32_t total_pages;
    uint32_t present;
    uint32_t dirty;
    uint32_t swapped;
    uint32_t file_mapped;
} block_stats_t;

/* ── Globals ── */
static int g_pagemap_fd = -1;
static int g_clear_refs_fd = -1;
static int g_pid = 0;

static region_t     g_regions[MAX_REGIONS];
static int          g_n_regions = 0;
static file_group_t g_file_groups[MAX_FILES];
static int          g_n_file_groups = 0;

/* ══════════════════════════════════════════════════════════════════════
 * Low-level helpers
 * ══════════════════════════════════════════════════════════════════════ */

static int open_pagemap(int pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/pagemap", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        fprintf(stderr, "ERROR: Cannot open %s: %s (needs root)\n",
                path, strerror(errno));
    return fd;
}

static int open_clear_refs(int pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/clear_refs", pid);
    int fd = open(path, O_WRONLY);
    if (fd < 0)
        fprintf(stderr, "WARNING: Cannot open %s: soft-dirty unavailable\n", path);
    return fd;
}

static int clear_soft_dirty(int fd) {
    if (fd < 0) return -1;
    if (lseek(fd, 0, SEEK_SET) < 0) return -1;
    return (write(fd, "4", 1) == 1) ? 0 : -1;
}

static int read_pagemap_bulk(int pm_fd, uint64_t start, uint64_t end,
                              page_state_t *states, int max_pages) {
    uint64_t n_pages = (end - start) / PAGE_SIZE;
    if ((uint64_t)max_pages < n_pages) n_pages = max_pages;

    off_t off = (start / PAGE_SIZE) * PAGEMAP_ENTRY;
    if (lseek(pm_fd, off, SEEK_SET) < 0) return 0;

    uint64_t buf[4096];
    int total = 0;
    uint64_t rem = n_pages;
    while (rem > 0) {
        uint64_t chunk = rem > 4096 ? 4096 : rem;
        ssize_t bytes = read(pm_fd, buf, chunk * PAGEMAP_ENTRY);
        if (bytes <= 0) break;
        int entries = bytes / PAGEMAP_ENTRY;
        for (int i = 0; i < entries && total < max_pages; i++) {
            uint64_t e = buf[i];
            states[total].present     = !!(e & PM_PRESENT);
            states[total].swapped     = !!(e & PM_SWAPPED);
            states[total].file_mapped = !!(e & PM_FILE);
            states[total].soft_dirty  = !!(e & PM_SOFTDIRTY);
            states[total].exclusive   = !!(e & PM_MMAP_EXCL);
            states[total].pfn         = (e & PM_PRESENT) ? (e & PM_PFN_MASK) : 0;
            total++;
        }
        rem -= entries;
    }
    return total;
}

/* Forward declarations for timing functions (defined in overhead section) */
static uint64_t now_ns(void);
static uint64_t now_ms(void);

/* ══════════════════════════════════════════════════════════════════════
 * Multi-mmap: Parse → Group → Coalesce
 * ══════════════════════════════════════════════════════════════════════ */

static int is_skip_lib(const char *p) {
    return (strstr(p, "/usr/lib") || strstr(p, "/lib/x86_64") ||
            strstr(p, "ld-linux") || strstr(p, "/usr/share") ||
            strstr(p, "libc.so") || strstr(p, "libm.so") ||
            strstr(p, "libpthread") || strstr(p, "libdl") ||
            strstr(p, "libgcc") || strstr(p, "libstdc++") ||
            strstr(p, "linux-vdso"));
}

static void parse_maps_all(int pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "ERROR: Cannot open %s\n", path); return; }

    g_n_regions = 0;
    char line[1024];
    while (fgets(line, sizeof(line), f) && g_n_regions < MAX_REGIONS) {
        uint64_t s, e, off;
        int inode;
        char perms[8], dev[16], pn[512];
        pn[0] = '\0';
        int n = sscanf(line, "%lx-%lx %7s %lx %15s %d %511[^\n]",
                        &s, &e, perms, &off, dev, &inode, pn);
        if (n < 6) continue;
        char *p = pn;
        while (*p == ' ' || *p == '\t') p++;

        region_t *r = &g_regions[g_n_regions];
        r->start = s;
        r->end = e;
        r->file_offset = off;
        r->file_group_id = -1;
        strncpy(r->perms, perms, 7); r->perms[7] = '\0';
        strncpy(r->pathname, p, 511); r->pathname[511] = '\0';
        r->is_file_backed = (p[0] != '\0' && p[0] != '[');
        g_n_regions++;
    }
    fclose(f);
    fprintf(stderr, "INFO: Parsed %d map regions from PID %d\n",
            g_n_regions, pid);
}

static void group_by_file(int skip_libs) {
    g_n_file_groups = 0;
    for (int i = 0; i < g_n_regions; i++) {
        region_t *r = &g_regions[i];
        if (!r->is_file_backed) continue;
        if (skip_libs && is_skip_lib(r->pathname)) continue;

        int gid = -1;
        for (int g = 0; g < g_n_file_groups; g++) {
            if (strcmp(g_file_groups[g].pathname, r->pathname) == 0) {
                gid = g; break;
            }
        }
        if (gid < 0) {
            if (g_n_file_groups >= MAX_FILES) continue;
            gid = g_n_file_groups++;
            file_group_t *fg = &g_file_groups[gid];
            memset(fg, 0, sizeof(*fg));
            strncpy(fg->pathname, r->pathname, 511);
            fg->file_offset_min = UINT64_MAX;
        }

        file_group_t *fg = &g_file_groups[gid];
        if (fg->n_regions < MAX_REGIONS)
            fg->region_indices[fg->n_regions++] = i;
        r->file_group_id = gid;

        uint64_t sz = r->end - r->start;
        fg->total_mapped_bytes += sz;
        if (r->file_offset < fg->file_offset_min)
            fg->file_offset_min = r->file_offset;
        if (r->file_offset + sz > fg->file_offset_max)
            fg->file_offset_max = r->file_offset + sz;
    }
    fprintf(stderr, "INFO: %d unique file(s) grouped\n", g_n_file_groups);
}

static int cmp_offset(const void *a, const void *b) {
    int ia = *(const int *)a, ib = *(const int *)b;
    if (g_regions[ia].file_offset < g_regions[ib].file_offset) return -1;
    if (g_regions[ia].file_offset > g_regions[ib].file_offset) return 1;
    uint64_t sa = g_regions[ia].end - g_regions[ia].start;
    uint64_t sb = g_regions[ib].end - g_regions[ib].start;
    return (sa > sb) ? -1 : (sa < sb) ? 1 : 0;
}

/*
 * Coalesce: merge overlapping / adjacent VMAs of each file.
 *
 * Why: the kernel may split a single mmap into many VMAs due to
 * permission changes (r-- vs rw-), mprotect calls, or ASLR gaps.
 * A 1 GB file can have 200+ VMAs. We merge them by file offset so
 * the heatmap shows a continuous file view.
 *
 * Overlap handling: if VMA-A (rw-s, offset=0, 256MB) and VMA-B
 * (r--s, offset=0, 256MB) both exist, we keep both as scanning
 * sources but treat them as one coalesced file-offset range. The
 * scan function maps pages from each VMA to the correct file-offset
 * block, avoiding double-counting by using a seen-offset bitmap.
 */
static void coalesce_all(void) {
    for (int g = 0; g < g_n_file_groups; g++) {
        file_group_t *fg = &g_file_groups[g];
        if (fg->n_regions == 0) continue;

        qsort(fg->region_indices, fg->n_regions, sizeof(int), cmp_offset);

        /* Allocate coalesced array */
        fg->coalesced = calloc(fg->n_regions, sizeof(coalesced_region_t));
        if (!fg->coalesced) { fg->n_coalesced = 0; continue; }
        fg->n_coalesced = 0;

        region_t *first = &g_regions[fg->region_indices[0]];
        uint64_t cur_end = first->file_offset + (first->end - first->start);

        coalesced_region_t *cc = &fg->coalesced[0];
        cc->file_offset_start = first->file_offset;
        cc->file_offset_end = cur_end;
        cc->n_vmas = 1;
        cc->vma_starts[0]  = first->start;
        cc->vma_ends[0]    = first->end;
        cc->vma_offsets[0] = first->file_offset;

        for (int i = 1; i < fg->n_regions; i++) {
            region_t *r = &g_regions[fg->region_indices[i]];
            uint64_t r_fend = r->file_offset + (r->end - r->start);

            if (r->file_offset <= cur_end) {
                /* Overlapping or adjacent */
                if (r_fend > cur_end) cur_end = r_fend;
                cc->file_offset_end = cur_end;
                if (cc->n_vmas < MAX_VMAS_PER_COAL) {
                    int vi = cc->n_vmas++;
                    cc->vma_starts[vi]  = r->start;
                    cc->vma_ends[vi]    = r->end;
                    cc->vma_offsets[vi] = r->file_offset;
                }
            } else {
                /* Gap — new coalesced region */
                fg->n_coalesced++;
                cc = &fg->coalesced[fg->n_coalesced];
                memset(cc, 0, sizeof(*cc));
                cur_end = r_fend;
                cc->file_offset_start = r->file_offset;
                cc->file_offset_end = cur_end;
                cc->n_vmas = 1;
                cc->vma_starts[0]  = r->start;
                cc->vma_ends[0]    = r->end;
                cc->vma_offsets[0] = r->file_offset;
            }
        }
        fg->n_coalesced++;

        if (fg->n_coalesced < fg->n_regions)
            fprintf(stderr, "INFO: %s: %d VMAs → %d coalesced span(s)\n",
                    fg->pathname, fg->n_regions, fg->n_coalesced);
    }
}

static void free_coalesced(void) {
    for (int g = 0; g < g_n_file_groups; g++)
        free(g_file_groups[g].coalesced);
}

/* ══════════════════════════════════════════════════════════════════════
 * Mode 0: Snapshot
 * ══════════════════════════════════════════════════════════════════════ */
static void mode_snapshot(uint64_t start, uint64_t end) {
    uint64_t np = (end - start) / PAGE_SIZE;
    page_state_t *st = calloc(np, sizeof(page_state_t));
    if (!st) return;
    int count = read_pagemap_bulk(g_pagemap_fd, start, end, st, np);

    int pres = 0, dirty = 0, swap = 0, fm = 0;
    for (int i = 0; i < count; i++) {
        pres  += st[i].present;
        dirty += st[i].soft_dirty;
        swap  += st[i].swapped;
        fm    += st[i].file_mapped;
    }
    printf("{\"mode\":\"snapshot\",\"pid\":%d,"
           "\"start\":\"0x%lx\",\"end\":\"0x%lx\","
           "\"total_pages\":%d,\"scanned\":%d,"
           "\"present\":%d,\"dirty\":%d,\"swapped\":%d,\"file_mapped\":%d,"
           "\"resident_pct\":%.1f,\"dirty_pct\":%.1f,\"pages\":\"",
           g_pid, start, end, (int)np, count, pres, dirty, swap, fm,
           count > 0 ? 100.0*pres/count : 0,
           pres > 0 ? 100.0*dirty/pres : 0);
    for (int i = 0; i < count; i++) {
        char ch = '.';
        if (st[i].present) {
            ch = st[i].soft_dirty ? 'D' : st[i].file_mapped ? 'F' : 'P';
        } else if (st[i].swapped) ch = 'S';
        printf("%c", ch);
    }
    printf("\"}\n");
    free(st);
}

/* ══════════════════════════════════════════════════════════════════════
 * Mode 1: Soft-dirty
 * ══════════════════════════════════════════════════════════════════════ */
static void mode_softdirty(uint64_t start, uint64_t end,
                            int ival, int iters) {
    uint64_t np = (end - start) / PAGE_SIZE;
    page_state_t *st = calloc(np, sizeof(page_state_t));
    if (!st) return;
    printf("{\"mode\":\"softdirty\",\"pid\":%d,"
           "\"start\":\"0x%lx\",\"end\":\"0x%lx\","
           "\"total_pages\":%lu,\"interval_ms\":%d,\"snapshots\":[\n",
           g_pid, start, end, np, ival);
    for (int it = 0; it < iters; it++) {
        clear_soft_dirty(g_clear_refs_fd);
        usleep(ival * 1000);
        int count = read_pagemap_bulk(g_pagemap_fd, start, end, st, np);
        int d = 0, p = 0, fd_idx = -1, ld_idx = -1;
        for (int i = 0; i < count; i++) {
            if (st[i].present) p++;
            if (st[i].soft_dirty) { d++; if (fd_idx<0) fd_idx=i; ld_idx=i; }
        }
        if (it > 0) printf(",\n");
        printf("  {\"iter\":%d,\"ts_ms\":%lu,\"present\":%d,"
               "\"newly_dirty\":%d,\"dirty_kb\":%d",
               it, now_ms(), p, d, d*(int)(PAGE_SIZE/1024));
        if (fd_idx >= 0)
            printf(",\"first_dirty_offset\":%lu,\"last_dirty_offset\":%lu,"
                   "\"dirty_span_kb\":%lu",
                   (uint64_t)fd_idx*PAGE_SIZE, (uint64_t)ld_idx*PAGE_SIZE,
                   (uint64_t)(ld_idx-fd_idx+1)*PAGE_SIZE/1024);
        printf(",\"bitmap\":\"");
        for (int i = 0; i < count; i++) printf("%c", st[i].soft_dirty?'1':'0');
        printf("\"}");
        fflush(stdout);
    }
    printf("\n]}\n");
    free(st);
}

/* ══════════════════════════════════════════════════════════════════════
 * Mode 2: Heatmap (single VA range)
 * ══════════════════════════════════════════════════════════════════════ */
static void mode_heatmap(uint64_t start, uint64_t end,
                          int ival, int iters, int block_kb) {
    uint64_t np = (end - start) / PAGE_SIZE;
    page_state_t *st = calloc(np, sizeof(page_state_t));
    if (!st) return;

    int ppb;
    int nb;
    if (block_kb > 0) {
        /* User-specified granularity */
        ppb = (block_kb * 1024) / PAGE_SIZE;
        if (ppb < 1) ppb = 1;
    } else {
        /* Auto-calculate: target ~HEATMAP_COLS^2 blocks */
        nb = HEATMAP_COLS * HEATMAP_COLS;
        if ((uint64_t)nb > np) nb = np > 0 ? (int)np : 1;
        ppb = np / nb; if (ppb < 1) ppb = 1;
    }
    nb = (np + ppb - 1) / ppb;
    block_stats_t *bl = calloc(nb, sizeof(block_stats_t));
    if (!bl) { free(st); return; }

    printf("{\"mode\":\"heatmap\",\"pid\":%d,"
           "\"start\":\"0x%lx\",\"end\":\"0x%lx\","
           "\"total_pages\":%lu,\"n_blocks\":%d,"
           "\"pages_per_block\":%d,\"block_size_kb\":%d,"
           "\"cols\":%d,\"interval_ms\":%d,\"snapshots\":[\n",
           g_pid, start, end, np, nb, ppb, ppb*(int)(PAGE_SIZE/1024),
           HEATMAP_COLS, ival);

    for (int it = 0; it < iters; it++) {
        clear_soft_dirty(g_clear_refs_fd);
        usleep(ival * 1000);
        int count = read_pagemap_bulk(g_pagemap_fd, start, end, st, np);
        memset(bl, 0, nb * sizeof(block_stats_t));
        for (int i = 0; i < count; i++) {
            int bi = i / ppb; if (bi >= nb) bi = nb - 1;
            bl[bi].total_pages++;
            bl[bi].present += st[i].present;
            bl[bi].dirty += st[i].soft_dirty;
        }
        int td = 0, tp = 0;
        for (int b = 0; b < nb; b++) { td += bl[b].dirty; tp += bl[b].present; }
        if (it > 0) printf(",\n");
        printf("  {\"iter\":%d,\"ts_ms\":%lu,\"total_dirty\":%d,"
               "\"total_present\":%d,\"dirty_kb\":%d,\"blocks\":[",
               it, now_ms(), td, tp, td*(int)(PAGE_SIZE/1024));
        for (int b = 0; b < nb; b++) {
            if (b > 0) printf(",");
            printf("%d", bl[b].total_pages>0 ? (100*bl[b].dirty)/bl[b].total_pages : 0);
        }
        printf("]}");
        fflush(stdout);
    }
    printf("\n]}\n");
    free(bl); free(st);
}

/* ══════════════════════════════════════════════════════════════════════
 * Mode 3: Timeline
 * ══════════════════════════════════════════════════════════════════════ */
static void mode_timeline(uint64_t start, uint64_t end,
                           int ival, int iters) {
    uint64_t np = (end - start) / PAGE_SIZE;
    page_state_t *st = calloc(np, sizeof(page_state_t));
    if (!st) return;
    printf("{\"mode\":\"timeline\",\"pid\":%d,"
           "\"start\":\"0x%lx\",\"end\":\"0x%lx\","
           "\"total_pages\":%lu,\"interval_ms\":%d,\"samples\":[\n",
           g_pid, start, end, np, ival);
    uint64_t t0 = now_ms();
    for (int it = 0; it < iters; it++) {
        clear_soft_dirty(g_clear_refs_fd);
        usleep(ival * 1000);
        int count = read_pagemap_bulk(g_pagemap_fd, start, end, st, np);
        int p = 0, d = 0, sw = 0;
        for (int i = 0; i < count; i++) {
            p += st[i].present; d += st[i].soft_dirty; sw += st[i].swapped;
        }
        if (it > 0) printf(",\n");
        printf("  {\"iter\":%d,\"elapsed_ms\":%lu,\"present\":%d,"
               "\"dirty\":%d,\"swapped\":%d,\"dirty_kb\":%d,"
               "\"dirty_rate_kb_s\":%.1f}",
               it, now_ms()-t0, p, d, sw, d*(int)(PAGE_SIZE/1024),
               d*(PAGE_SIZE/1024.0)/(ival/1000.0));
        fflush(stdout);
    }
    printf("\n]}\n");
    free(st);
}

/* ══════════════════════════════════════════════════════════════════════
 * Mode 4: Region-all (multi-mmap aware, grouped by file)
 * ══════════════════════════════════════════════════════════════════════ */
static void mode_region_all(int ival, int iters) {
    parse_maps_all(g_pid);
    group_by_file(1);
    coalesce_all();

    printf("{\"mode\":\"region_all\",\"pid\":%d,"
           "\"total_map_entries\":%d,\"unique_files\":%d,\"files\":[\n",
           g_pid, g_n_regions, g_n_file_groups);

    for (int g = 0; g < g_n_file_groups; g++) {
        file_group_t *fg = &g_file_groups[g];
        uint64_t tp = 0, tpres = 0, tdirty = 0;

        for (int i = 0; i < fg->n_regions; i++) {
            region_t *r = &g_regions[fg->region_indices[i]];
            uint64_t np = (r->end - r->start) / PAGE_SIZE;
            if (np > 2000000) continue;
            page_state_t *st = calloc(np, sizeof(page_state_t));
            if (!st) continue;
            int c = read_pagemap_bulk(g_pagemap_fd, r->start, r->end, st, np);
            for (int p = 0; p < c; p++) {
                tp++; tpres += st[p].present; tdirty += st[p].soft_dirty;
            }
            free(st);
        }

        if (g > 0) printf(",\n");
        printf("  {\"pathname\":\"%s\","
               "\"n_vmas\":%d,\"n_coalesced\":%d,"
               "\"mapped_kb\":%lu,"
               "\"file_offset_range\":[\"0x%lx\",\"0x%lx\"],"
               "\"total_pages\":%lu,\"present\":%lu,\"dirty\":%lu,"
               "\"resident_pct\":%.1f,\"dirty_pct\":%.1f,"
               "\"vmas\":[",
               fg->pathname, fg->n_regions, fg->n_coalesced,
               fg->total_mapped_bytes / 1024,
               fg->file_offset_min, fg->file_offset_max,
               tp, tpres, tdirty,
               tp > 0 ? 100.0*tpres/tp : 0,
               tpres > 0 ? 100.0*tdirty/tpres : 0);

        for (int i = 0; i < fg->n_regions; i++) {
            region_t *r = &g_regions[fg->region_indices[i]];
            if (i > 0) printf(",");
            printf("{\"va\":\"0x%lx-0x%lx\",\"perms\":\"%s\","
                   "\"file_off\":\"0x%lx\",\"size_kb\":%lu}",
                   r->start, r->end, r->perms,
                   r->file_offset, (r->end - r->start) / 1024);
        }
        printf("]}");
    }

    if (iters > 0) {
        printf("],\"tracking\":[\n");
        for (int it = 0; it < iters; it++) {
            clear_soft_dirty(g_clear_refs_fd);
            usleep(ival * 1000);
            if (it > 0) printf(",\n");
            printf("  {\"iter\":%d,\"ts_ms\":%lu,\"files\":[", it, now_ms());
            for (int g = 0; g < g_n_file_groups; g++) {
                file_group_t *fg = &g_file_groups[g];
                int fd_total = 0;
                for (int i = 0; i < fg->n_regions; i++) {
                    region_t *r = &g_regions[fg->region_indices[i]];
                    uint64_t np = (r->end - r->start) / PAGE_SIZE;
                    if (np > 2000000) continue;
                    page_state_t *st = calloc(np, sizeof(page_state_t));
                    if (!st) continue;
                    int c = read_pagemap_bulk(g_pagemap_fd, r->start,
                                               r->end, st, np);
                    for (int p = 0; p < c; p++) fd_total += st[p].soft_dirty;
                    free(st);
                }
                if (g > 0) printf(",");
                printf("{\"path\":\"%s\",\"dirty\":%d,\"dirty_kb\":%d}",
                       fg->pathname, fd_total, fd_total*(int)(PAGE_SIZE/1024));
            }
            printf("]}");
            fflush(stdout);
        }
        printf("\n]");
    } else {
        printf("]");
    }
    printf("}\n");
    free_coalesced();
}

/* ══════════════════════════════════════════════════════════════════════
 * Mode 5: File-unified heatmap
 *
 * For each file, builds a unified heatmap indexed by FILE OFFSET (not VA).
 * Scans all VMAs belonging to the file, maps each page to its file-offset
 * block. Overlapping VMAs (same file offset, different perms) are handled
 * by tracking which file-offset pages have already been counted.
 * ══════════════════════════════════════════════════════════════════════ */
static void mode_file_unified(int ival, int iters, int block_kb) {
    parse_maps_all(g_pid);
    group_by_file(1);
    coalesce_all();

    printf("{\"mode\":\"file_unified\",\"pid\":%d,"
           "\"unique_files\":%d,\"interval_ms\":%d,\"files\":[\n",
           g_pid, g_n_file_groups, ival);

    for (int g = 0; g < g_n_file_groups; g++) {
        file_group_t *fg = &g_file_groups[g];
        uint64_t fspan = fg->file_offset_max - fg->file_offset_min;
        uint64_t fpages = fspan / PAGE_SIZE;
        if (fpages == 0) continue;

        int ppb;
        int nb;
        if (block_kb > 0) {
            ppb = (block_kb * 1024) / PAGE_SIZE;
            if (ppb < 1) ppb = 1;
        } else {
            nb = HEATMAP_COLS * HEATMAP_COLS;
            if ((uint64_t)nb > fpages) nb = (int)fpages;
            if (nb < 1) nb = 1;
            ppb = fpages / nb; if (ppb < 1) ppb = 1;
        }
        nb = (fpages + ppb - 1) / ppb;

        block_stats_t *bl = calloc(nb, sizeof(block_stats_t));
        if (!bl) continue;

        /*
         * Overlap dedup bitmap: one bit per file-offset page.
         * If a page at file offset X was already counted from VMA-A,
         * we skip it when scanning VMA-B (which maps the same offset
         * with different permissions). This prevents double-counting.
         * Only allocated per-iteration; freed after each scan.
         */
        uint64_t bitmap_bytes = (fpages + 7) / 8;
        /* Cap bitmap at 128 MB to avoid OOM on huge files */
        int use_dedup = (bitmap_bytes <= 128ULL * 1024 * 1024);

        if (g > 0) printf(",\n");
        printf("  {\"pathname\":\"%s\","
               "\"n_vmas\":%d,\"n_coalesced\":%d,"
               "\"file_offset_range\":[\"0x%lx\",\"0x%lx\"],"
               "\"file_span_kb\":%lu,\"file_pages\":%lu,"
               "\"n_blocks\":%d,\"pages_per_block\":%d,"
               "\"block_size_kb\":%d,\"cols\":%d,"
               "\"overlap_dedup\":%s,"
               "\"snapshots\":[\n",
               fg->pathname, fg->n_regions, fg->n_coalesced,
               fg->file_offset_min, fg->file_offset_max,
               fspan/1024, fpages, nb, ppb,
               ppb*(int)(PAGE_SIZE/1024), HEATMAP_COLS,
               use_dedup ? "true" : "false");

        for (int it = 0; it < iters; it++) {
            clear_soft_dirty(g_clear_refs_fd);
            usleep(ival * 1000);
            memset(bl, 0, nb * sizeof(block_stats_t));

            /* Allocate dedup bitmap per iteration */
            uint8_t *seen = NULL;
            if (use_dedup) {
                seen = calloc(1, bitmap_bytes);
                /* OK if calloc fails — we just skip dedup */
            }

            int total_dirty = 0;

            /* Scan each coalesced region's VMAs */
            for (int c = 0; c < fg->n_coalesced; c++) {
                coalesced_region_t *cc = &fg->coalesced[c];
                for (int v = 0; v < cc->n_vmas; v++) {
                    uint64_t vs = cc->vma_starts[v];
                    uint64_t ve = cc->vma_ends[v];
                    uint64_t voff = cc->vma_offsets[v];
                    uint64_t vnp = (ve - vs) / PAGE_SIZE;

                    page_state_t *st = calloc(vnp, sizeof(page_state_t));
                    if (!st) continue;
                    int cnt = read_pagemap_bulk(g_pagemap_fd, vs, ve, st, vnp);

                    for (int p = 0; p < cnt; p++) {
                        uint64_t pfoff = voff + (uint64_t)p * PAGE_SIZE;
                        if (pfoff < fg->file_offset_min) { continue; }
                        uint64_t rel = pfoff - fg->file_offset_min;
                        uint64_t page_idx = rel / PAGE_SIZE;

                        /* Dedup: skip if this file-offset page already counted */
                        if (seen && page_idx < fpages) {
                            uint64_t byte_idx = page_idx / 8;
                            uint8_t  bit_mask = 1 << (page_idx % 8);
                            if (seen[byte_idx] & bit_mask) continue;
                            seen[byte_idx] |= bit_mask;
                        }

                        int bi = (int)(page_idx / ppb);
                        if (bi < 0 || bi >= nb) continue;

                        bl[bi].total_pages++;
                        bl[bi].present     += st[p].present;
                        bl[bi].dirty       += st[p].soft_dirty;
                        bl[bi].swapped     += st[p].swapped;
                        bl[bi].file_mapped += st[p].file_mapped;
                        if (st[p].soft_dirty) total_dirty++;
                    }
                    free(st);
                }
            }
            free(seen);

            int tp = 0;
            for (int b = 0; b < nb; b++) tp += bl[b].present;

            if (it > 0) printf(",\n");
            printf("    {\"iter\":%d,\"ts_ms\":%lu,"
                   "\"total_dirty\":%d,\"total_present\":%d,"
                   "\"dirty_kb\":%d,\"blocks\":[",
                   it, now_ms(), total_dirty, tp,
                   total_dirty*(int)(PAGE_SIZE/1024));
            for (int b = 0; b < nb; b++) {
                if (b > 0) printf(",");
                printf("%d", bl[b].total_pages>0
                       ? (100*bl[b].dirty)/bl[b].total_pages : 0);
            }
            printf("]}");
            fflush(stdout);
        }
        printf("\n  ]}");
        free(bl);
    }
    printf("\n]}\n");
    free_coalesced();
}

/* ══════════════════════════════════════════════════════════════════════ */

static void auto_detect_range(uint64_t *out_s, uint64_t *out_e) {
    parse_maps_all(g_pid);
    group_by_file(1);
    coalesce_all();

    int best = -1; uint64_t best_sz = 0;
    for (int g = 0; g < g_n_file_groups; g++) {
        if (g_file_groups[g].total_mapped_bytes > best_sz) {
            best_sz = g_file_groups[g].total_mapped_bytes; best = g;
        }
    }
    if (best < 0) {
        fprintf(stderr, "ERROR: No workload file-backed regions\n");
        free_coalesced(); return;
    }

    file_group_t *fg = &g_file_groups[best];
    fprintf(stderr, "INFO: Auto-detected '%s' (%d VMAs, %lu KB, %d coalesced)\n",
            fg->pathname, fg->n_regions, fg->total_mapped_bytes/1024,
            fg->n_coalesced);

    /* Return largest single VMA for modes 0-3 */
    uint64_t max_vma = 0;
    for (int i = 0; i < fg->n_regions; i++) {
        region_t *r = &g_regions[fg->region_indices[i]];
        uint64_t sz = r->end - r->start;
        if (sz > max_vma) { max_vma = sz; *out_s = r->start; *out_e = r->end; }
    }
    fprintf(stderr, "INFO: Largest VMA 0x%lx-0x%lx (%lu KB)\n",
            *out_s, *out_e, (*out_e - *out_s)/1024);
    if (fg->n_regions > 1)
        fprintf(stderr, "INFO: File has %d VMAs — use mode 5 for unified view\n",
                fg->n_regions);
    free_coalesced();
}

/* ══════════════════════════════════════════════════════════════════════
 * Overhead instrumentation
 * ══════════════════════════════════════════════════════════════════════ */
typedef struct {
    uint64_t wall_ns;       /* wall-clock nanoseconds */
    uint64_t user_us;       /* user CPU microseconds */
    uint64_t sys_us;        /* system CPU microseconds */
    long     peak_rss_kb;   /* peak resident set size */
    uint64_t bytes_read;    /* bytes read from /proc */
    int      pages_scanned;
    int      pages_dirty;
} overhead_t;

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* Millisecond wrapper used throughout modes 0-5 */
static uint64_t now_ms(void) {
    return now_ns() / 1000000ULL;
}

static void overhead_start(overhead_t *o) {
    memset(o, 0, sizeof(*o));
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    o->user_us = ru.ru_utime.tv_sec * 1000000ULL + ru.ru_utime.tv_usec;
    o->sys_us  = ru.ru_stime.tv_sec * 1000000ULL + ru.ru_stime.tv_usec;
    o->wall_ns = now_ns();
}

static void overhead_stop(overhead_t *o) {
    uint64_t end_wall = now_ns();
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    uint64_t end_user = ru.ru_utime.tv_sec * 1000000ULL + ru.ru_utime.tv_usec;
    uint64_t end_sys  = ru.ru_stime.tv_sec * 1000000ULL + ru.ru_stime.tv_usec;

    o->wall_ns  = end_wall - o->wall_ns;
    o->user_us  = end_user - o->user_us;
    o->sys_us   = end_sys  - o->sys_us;
    o->peak_rss_kb = ru.ru_maxrss;  /* in KB on Linux */
}

static void overhead_print_json(const char *label, overhead_t *o) {
    double wall_ms  = o->wall_ns / 1e6;
    double cpu_ms   = (o->user_us + o->sys_us) / 1e3;
    double cpu_pct  = (wall_ms > 0) ? 100.0 * cpu_ms / wall_ms : 0;
    printf("  {\"label\":\"%s\",\"wall_ms\":%.3f,\"cpu_ms\":%.3f,"
           "\"user_ms\":%.3f,\"sys_ms\":%.3f,\"cpu_pct\":%.1f,"
           "\"peak_rss_kb\":%ld,\"bytes_read\":%lu,"
           "\"pages_scanned\":%d,\"pages_dirty\":%d}",
           label, wall_ms, cpu_ms,
           o->user_us / 1e3, o->sys_us / 1e3, cpu_pct,
           o->peak_rss_kb, o->bytes_read,
           o->pages_scanned, o->pages_dirty);
}

/* ══════════════════════════════════════════════════════════════════════
 * /proc/<pid>/mem helper — read process memory contents
 * ══════════════════════════════════════════════════════════════════════ */
static int open_proc_mem(int pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        fprintf(stderr, "ERROR: Cannot open %s: %s (needs root + PTRACE)\n",
                path, strerror(errno));
    return fd;
}

/*
 * Read a page of process memory via /proc/<pid>/mem.
 * Returns bytes read (4096 on success), 0 on failure.
 */
static int read_proc_mem_page(int mem_fd, uint64_t vaddr, uint8_t *buf) {
    if (lseek(mem_fd, (off_t)vaddr, SEEK_SET) < 0) return 0;
    ssize_t n = read(mem_fd, buf, PAGE_SIZE);
    return (n > 0) ? (int)n : 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * Mode 6: Sub-page byte-level diff
 *
 * How it works:
 *   pagemap can only report whether a 4 KB page is dirty — it has no
 *   sub-page resolution because the hardware MMU dirty bit covers the
 *   entire page. To find WHICH BYTES changed within a dirty page, we
 *   take a different approach:
 *
 *   1. Read the page's byte contents via /proc/<pid>/mem → snapshot A
 *   2. Sleep for the polling interval
 *   3. Read the page again → snapshot B
 *   4. XOR byte-by-byte: any non-zero result = that byte was written
 *
 *   This is a memory-content-diff approach, NOT a pagemap approach.
 *   The tradeoff is much higher overhead: reading 4096 bytes per page
 *   instead of checking a single bit.
 *
 * Granularity parameter (sub_block_bytes):
 *   0 or 1 = report every changed byte individually
 *   8      = report per 8-byte (word) granularity
 *   64     = report per cache-line (64 bytes)
 *   256    = report per 256-byte sub-block
 *
 * Output: JSON with per-page changed-byte lists and sub-block heatmaps.
 * ══════════════════════════════════════════════════════════════════════ */
static void mode_sub_page_diff(uint64_t start, uint64_t end,
                                int interval_ms, int iterations,
                                int sub_block_bytes) {
    uint64_t n_pages = (end - start) / PAGE_SIZE;
    if (n_pages == 0) { fprintf(stderr, "ERROR: empty range\n"); return; }
    if (n_pages > 65536) {
        fprintf(stderr, "WARNING: %lu pages — capping at 65536 (256 MB) "
                "to limit memory\n", n_pages);
        n_pages = 65536;
        end = start + n_pages * PAGE_SIZE;
    }

    if (sub_block_bytes <= 0) sub_block_bytes = 1;
    int blocks_per_page = PAGE_SIZE / sub_block_bytes;

    /* Open /proc/<pid>/mem */
    int mem_fd = open_proc_mem(g_pid);
    if (mem_fd < 0) return;

    /* Allocate snapshot buffers: two full copies of all pages */
    uint8_t *snap_a = calloc(n_pages, PAGE_SIZE);
    uint8_t *snap_b = calloc(n_pages, PAGE_SIZE);
    page_state_t *pstates = calloc(n_pages, sizeof(page_state_t));
    if (!snap_a || !snap_b || !pstates) {
        fprintf(stderr, "ERROR: Cannot allocate %.1f MB for snapshots\n",
                n_pages * PAGE_SIZE * 2.0 / (1024*1024));
        free(snap_a); free(snap_b); free(pstates);
        close(mem_fd);
        return;
    }

    printf("{\"mode\":\"sub_page_diff\",\"pid\":%d,"
           "\"start\":\"0x%lx\",\"end\":\"0x%lx\","
           "\"total_pages\":%lu,\"sub_block_bytes\":%d,"
           "\"blocks_per_page\":%d,\"interval_ms\":%d,"
           "\"snapshots\":[\n",
           g_pid, start, end, n_pages, sub_block_bytes,
           blocks_per_page, interval_ms);

    for (int iter = 0; iter < iterations; iter++) {
        overhead_t ov;
        overhead_start(&ov);

        /* Step 1: check pagemap for present pages */
        int pm_count = read_pagemap_bulk(g_pagemap_fd, start, end,
                                          pstates, n_pages);
        ov.pages_scanned = pm_count;

        /* Step 2: read snapshot A — only present pages */
        int pages_readable = 0;
        for (int p = 0; p < pm_count; p++) {
            if (pstates[p].present) {
                uint64_t va = start + (uint64_t)p * PAGE_SIZE;
                int n = read_proc_mem_page(mem_fd, va, snap_a + p * PAGE_SIZE);
                if (n > 0) {
                    pages_readable++;
                    ov.bytes_read += n;
                }
            }
        }

        /* Step 3: clear soft-dirty and sleep */
        clear_soft_dirty(g_clear_refs_fd);
        usleep(interval_ms * 1000);

        /* Step 4: re-check pagemap for newly dirty pages */
        int pm_count2 = read_pagemap_bulk(g_pagemap_fd, start, end,
                                           pstates, n_pages);

        /* Step 5: read snapshot B — only dirty pages */
        int dirty_pages = 0;
        for (int p = 0; p < pm_count2; p++) {
            if (pstates[p].soft_dirty && pstates[p].present) {
                dirty_pages++;
                uint64_t va = start + (uint64_t)p * PAGE_SIZE;
                int n = read_proc_mem_page(mem_fd, va, snap_b + p * PAGE_SIZE);
                if (n > 0) ov.bytes_read += n;
            }
        }
        ov.pages_dirty = dirty_pages;

        /* Step 6: byte-by-byte diff on dirty pages */
        int total_changed_bytes = 0;
        int total_changed_blocks = 0;

        if (iter > 0) printf(",\n");
        printf("  {\"iter\":%d,\"ts_ms\":%lu,"
               "\"pages_readable\":%d,\"pages_dirty\":%d,",
               iter, now_ms(),
               pages_readable, dirty_pages);

        printf("\"dirty_pages\":[");
        int first_page = 1;

        for (int p = 0; p < pm_count2; p++) {
            if (!(pstates[p].soft_dirty && pstates[p].present)) continue;

            uint8_t *a = snap_a + p * PAGE_SIZE;
            uint8_t *b = snap_b + p * PAGE_SIZE;

            /* Count changed bytes and build sub-block density */
            int page_changed_bytes = 0;
            int block_dirty[4096 / 1]; /* max blocks per page at 1-byte gran */
            memset(block_dirty, 0, blocks_per_page * sizeof(int));

            for (int byte_idx = 0; byte_idx < (int)PAGE_SIZE; byte_idx++) {
                if (a[byte_idx] != b[byte_idx]) {
                    page_changed_bytes++;
                    int bi = byte_idx / sub_block_bytes;
                    if (bi < blocks_per_page) block_dirty[bi]++;
                }
            }

            if (page_changed_bytes == 0) continue;  /* false positive */

            total_changed_bytes += page_changed_bytes;
            total_changed_blocks++;

            if (!first_page) printf(",");
            first_page = 0;

            uint64_t page_va = start + (uint64_t)p * PAGE_SIZE;
            printf("{\"page\":\"0x%lx\",\"changed_bytes\":%d,"
                   "\"changed_pct\":%.1f,\"sub_blocks\":[",
                   page_va, page_changed_bytes,
                   100.0 * page_changed_bytes / PAGE_SIZE);

            /* Emit sub-block density array */
            for (int bi = 0; bi < blocks_per_page; bi++) {
                if (bi > 0) printf(",");
                /* Density: what % of bytes in this sub-block changed */
                int density = sub_block_bytes > 0
                    ? (100 * block_dirty[bi]) / sub_block_bytes : 0;
                printf("%d", density);
            }
            printf("]");

            /* If sub_block is 1 byte, also emit first 16 changed byte offsets */
            if (sub_block_bytes == 1 && page_changed_bytes <= 64) {
                printf(",\"byte_offsets\":[");
                int first = 1, count = 0;
                for (int byte_idx = 0; byte_idx < (int)PAGE_SIZE && count < 64; byte_idx++) {
                    if (a[byte_idx] != b[byte_idx]) {
                        if (!first) printf(",");
                        first = 0;
                        printf("{\"off\":%d,\"old\":%d,\"new\":%d}",
                               byte_idx, a[byte_idx], b[byte_idx]);
                        count++;
                    }
                }
                printf("]");
            }
            printf("}");

            /* Update snap_a with snap_b for next iteration's diff baseline */
            memcpy(a, b, PAGE_SIZE);
        }

        printf("],\"total_changed_bytes\":%d,\"total_changed_pages\":%d",
               total_changed_bytes, total_changed_blocks);

        /* Overhead metrics */
        overhead_stop(&ov);
        printf(",\"overhead\":");
        overhead_print_json("sub_page_diff", &ov);

        printf("}");
        fflush(stdout);
    }
    printf("\n]}\n");

    free(snap_a);
    free(snap_b);
    free(pstates);
    close(mem_fd);
}

/* ══════════════════════════════════════════════════════════════════════
 * Mode 7: Overhead benchmark — compare 4K (pagemap) vs sub-page (mem diff)
 *
 * Runs both approaches on the same region and reports side-by-side
 * overhead metrics: wall time, CPU%, peak RSS, bytes read.
 * ══════════════════════════════════════════════════════════════════════ */
static void mode_overhead_bench(uint64_t start, uint64_t end,
                                 int interval_ms, int iterations) {
    uint64_t n_pages = (end - start) / PAGE_SIZE;
    if (n_pages == 0) return;
    if (n_pages > 65536) { n_pages = 65536; end = start + n_pages * PAGE_SIZE; }

    int mem_fd = open_proc_mem(g_pid);

    printf("{\"mode\":\"overhead_bench\",\"pid\":%d,"
           "\"start\":\"0x%lx\",\"end\":\"0x%lx\","
           "\"total_pages\":%lu,\"interval_ms\":%d,"
           "\"iterations\":%d,\"benchmarks\":[\n",
           g_pid, start, end, n_pages, interval_ms, iterations);

    /* ── Benchmark 1: pagemap-only (4K granularity) ── */
    {
        page_state_t *states = calloc(n_pages, sizeof(page_state_t));
        overhead_t total;
        memset(&total, 0, sizeof(total));

        for (int iter = 0; iter < iterations; iter++) {
            overhead_t ov;
            overhead_start(&ov);

            clear_soft_dirty(g_clear_refs_fd);
            usleep(interval_ms * 1000);

            int count = read_pagemap_bulk(g_pagemap_fd, start, end, states, n_pages);
            ov.pages_scanned = count;
            ov.bytes_read = count * PAGEMAP_ENTRY;

            int dirty = 0;
            for (int i = 0; i < count; i++)
                if (states[i].soft_dirty) dirty++;
            ov.pages_dirty = dirty;

            overhead_stop(&ov);
            total.wall_ns    += ov.wall_ns;
            total.user_us    += ov.user_us;
            total.sys_us     += ov.sys_us;
            total.bytes_read += ov.bytes_read;
            total.pages_scanned += ov.pages_scanned;
            total.pages_dirty   += ov.pages_dirty;
            if (ov.peak_rss_kb > total.peak_rss_kb)
                total.peak_rss_kb = ov.peak_rss_kb;
        }
        /* Average per iteration */
        total.wall_ns   /= iterations;
        total.user_us   /= iterations;
        total.sys_us    /= iterations;
        total.bytes_read /= iterations;
        total.pages_scanned /= iterations;
        total.pages_dirty   /= iterations;

        printf("  ");
        overhead_print_json("pagemap_4k", &total);
        free(states);
    }

    /* ── Benchmark 2: sub-page mem-diff (byte granularity) ── */
    if (mem_fd >= 0) {
        printf(",\n");
        uint8_t *snap_a = calloc(n_pages, PAGE_SIZE);
        uint8_t *snap_b = calloc(n_pages, PAGE_SIZE);
        page_state_t *states = calloc(n_pages, sizeof(page_state_t));
        overhead_t total;
        memset(&total, 0, sizeof(total));

        if (snap_a && snap_b && states) {
            for (int iter = 0; iter < iterations; iter++) {
                overhead_t ov;
                overhead_start(&ov);

                /* Read snapshot A (present pages only) */
                int pm_count = read_pagemap_bulk(g_pagemap_fd, start, end,
                                                  states, n_pages);
                for (int p = 0; p < pm_count; p++) {
                    if (states[p].present) {
                        uint64_t va = start + (uint64_t)p * PAGE_SIZE;
                        int n = read_proc_mem_page(mem_fd, va,
                                                    snap_a + p * PAGE_SIZE);
                        ov.bytes_read += n;
                    }
                }
                ov.pages_scanned = pm_count;

                clear_soft_dirty(g_clear_refs_fd);
                usleep(interval_ms * 1000);

                /* Read snapshot B (dirty pages only) */
                pm_count = read_pagemap_bulk(g_pagemap_fd, start, end,
                                              states, n_pages);
                int dirty = 0;
                for (int p = 0; p < pm_count; p++) {
                    if (states[p].soft_dirty && states[p].present) {
                        dirty++;
                        uint64_t va = start + (uint64_t)p * PAGE_SIZE;
                        int n = read_proc_mem_page(mem_fd, va,
                                                    snap_b + p * PAGE_SIZE);
                        ov.bytes_read += n;
                    }
                }
                ov.pages_dirty = dirty;

                /* Diff */
                int changed = 0;
                for (int p = 0; p < pm_count; p++) {
                    if (!(states[p].soft_dirty && states[p].present)) continue;
                    uint8_t *a = snap_a + p * PAGE_SIZE;
                    uint8_t *b = snap_b + p * PAGE_SIZE;
                    for (int j = 0; j < (int)PAGE_SIZE; j++)
                        if (a[j] != b[j]) changed++;
                    memcpy(a, b, PAGE_SIZE);
                }

                overhead_stop(&ov);
                total.wall_ns    += ov.wall_ns;
                total.user_us    += ov.user_us;
                total.sys_us     += ov.sys_us;
                total.bytes_read += ov.bytes_read;
                total.pages_scanned += ov.pages_scanned;
                total.pages_dirty   += ov.pages_dirty;
                if (ov.peak_rss_kb > total.peak_rss_kb)
                    total.peak_rss_kb = ov.peak_rss_kb;
            }

            total.wall_ns   /= iterations;
            total.user_us   /= iterations;
            total.sys_us    /= iterations;
            total.bytes_read /= iterations;
            total.pages_scanned /= iterations;
            total.pages_dirty   /= iterations;

            printf("  ");
            overhead_print_json("mem_diff_byte", &total);
        }
        free(snap_a); free(snap_b); free(states);
    }

    /* ── Benchmark 3: sub-page mem-diff at 64-byte (cache-line) granularity ── */
    if (mem_fd >= 0) {
        printf(",\n");
        uint8_t *snap_a = calloc(n_pages, PAGE_SIZE);
        uint8_t *snap_b = calloc(n_pages, PAGE_SIZE);
        page_state_t *states = calloc(n_pages, sizeof(page_state_t));
        overhead_t total;
        memset(&total, 0, sizeof(total));

        if (snap_a && snap_b && states) {
            for (int iter = 0; iter < iterations; iter++) {
                overhead_t ov;
                overhead_start(&ov);

                int pm_count = read_pagemap_bulk(g_pagemap_fd, start, end,
                                                  states, n_pages);
                for (int p = 0; p < pm_count; p++) {
                    if (states[p].present) {
                        uint64_t va = start + (uint64_t)p * PAGE_SIZE;
                        int n = read_proc_mem_page(mem_fd, va,
                                                    snap_a + p * PAGE_SIZE);
                        ov.bytes_read += n;
                    }
                }
                ov.pages_scanned = pm_count;

                clear_soft_dirty(g_clear_refs_fd);
                usleep(interval_ms * 1000);

                pm_count = read_pagemap_bulk(g_pagemap_fd, start, end,
                                              states, n_pages);
                int dirty = 0;
                for (int p = 0; p < pm_count; p++) {
                    if (states[p].soft_dirty && states[p].present) {
                        dirty++;
                        uint64_t va = start + (uint64_t)p * PAGE_SIZE;
                        int n = read_proc_mem_page(mem_fd, va,
                                                    snap_b + p * PAGE_SIZE);
                        ov.bytes_read += n;
                    }
                }
                ov.pages_dirty = dirty;

                /* 64-byte block diff */
                for (int p = 0; p < pm_count; p++) {
                    if (!(states[p].soft_dirty && states[p].present)) continue;
                    uint64_t *a = (uint64_t *)(snap_a + p * PAGE_SIZE);
                    uint64_t *b = (uint64_t *)(snap_b + p * PAGE_SIZE);
                    /* Compare 8 bytes at a time (word-level) for cache-line blocks */
                    for (int w = 0; w < (int)(PAGE_SIZE / 8); w++)
                        if (a[w] != b[w]) { /* found diff in 8-byte word */ }
                    memcpy(snap_a + p * PAGE_SIZE, snap_b + p * PAGE_SIZE, PAGE_SIZE);
                }

                overhead_stop(&ov);
                total.wall_ns    += ov.wall_ns;
                total.user_us    += ov.user_us;
                total.sys_us     += ov.sys_us;
                total.bytes_read += ov.bytes_read;
                total.pages_scanned += ov.pages_scanned;
                total.pages_dirty   += ov.pages_dirty;
                if (ov.peak_rss_kb > total.peak_rss_kb)
                    total.peak_rss_kb = ov.peak_rss_kb;
            }

            total.wall_ns   /= iterations;
            total.user_us   /= iterations;
            total.sys_us    /= iterations;
            total.bytes_read /= iterations;
            total.pages_scanned /= iterations;
            total.pages_dirty   /= iterations;

            printf("  ");
            overhead_print_json("mem_diff_cacheline64", &total);
        }
        free(snap_a); free(snap_b); free(states);
    }

    printf("\n]}\n");
    if (mem_fd >= 0) close(mem_fd);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr,
            "Usage: %s <pid> <mode> [start end interval_ms count block_kb]\n\n"
            "Modes:\n"
            "  0 = snapshot      Single-shot page state scan\n"
            "  1 = softdirty     Soft-dirty tracking\n"
            "  2 = heatmap       Block-level dirty density grid\n"
            "  3 = timeline      Dirty page count over time\n"
            "  4 = region_all    All file-backed regions (multi-mmap grouped)\n"
            "  5 = file_unified  Unified file-offset heatmap (coalesced)\n"
            "  6 = sub_page      Sub-4K byte-level diff via /proc/<pid>/mem\n"
            "  7 = overhead      Benchmark: 4K pagemap vs sub-page mem-diff\n\n"
            "block_kb (arg 7): heatmap block granularity in KB. 0=auto.\n"
            "  For mode 6, arg 7 = sub-block bytes (1,8,64,256). 0=1 byte.\n\n"
            "Examples:\n"
            "  %s 12345 6 0x7f.. 0x7f.. 100 50 1    # byte-level diff\n"
            "  %s 12345 6 0x7f.. 0x7f.. 100 50 64   # cache-line diff\n"
            "  %s 12345 7 0x7f.. 0x7f.. 200 10       # overhead bench\n"
            "  %s 12345 5 0 0 500 10 0               # auto heatmap\n",
            argv[0], argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    g_pid = atoi(argv[1]);
    int mode = atoi(argv[2]);
    uint64_t start = 0, end = 0;
    int ival = 1000, cnt = 10;
    int block_kb = 0;  /* 0 = auto-calculate based on region size */
    if (argc > 3) start = strtoull(argv[3], NULL, 16);
    if (argc > 4) end   = strtoull(argv[4], NULL, 16);
    if (argc > 5) ival  = atoi(argv[5]);
    if (argc > 6) cnt   = atoi(argv[6]);
    if (argc > 7) block_kb = atoi(argv[7]);

    if (g_pid <= 0) { fprintf(stderr, "ERROR: Invalid PID\n"); return 1; }

    g_pagemap_fd = open_pagemap(g_pid);
    if (g_pagemap_fd < 0) return 1;
    g_clear_refs_fd = open_clear_refs(g_pid);

    if (mode <= 3 && (start == 0 || end == 0 || end <= start)) {
        auto_detect_range(&start, &end);
        if (start == 0 || end == 0) { close(g_pagemap_fd); return 1; }
    }
    /* Modes 6-7 also need a VA range */
    if ((mode == 6 || mode == 7) && (start == 0 || end == 0 || end <= start)) {
        auto_detect_range(&start, &end);
        if (start == 0 || end == 0) { close(g_pagemap_fd); return 1; }
    }

    switch (mode) {
        case 0: mode_snapshot(start, end); break;
        case 1: mode_softdirty(start, end, ival, cnt); break;
        case 2: mode_heatmap(start, end, ival, cnt, block_kb); break;
        case 3: mode_timeline(start, end, ival, cnt); break;
        case 4: mode_region_all(ival, cnt); break;
        case 5: mode_file_unified(ival, cnt, block_kb); break;
        case 6: mode_sub_page_diff(start, end, ival, cnt, block_kb); break;
        case 7: mode_overhead_bench(start, end, ival, cnt); break;
        default: fprintf(stderr, "Unknown mode %d\n", mode); break;
    }

    close(g_pagemap_fd);
    if (g_clear_refs_fd >= 0) close(g_clear_refs_fd);
    return 0;
}
