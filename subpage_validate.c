/*
 * subpage_validate.c — Validation program for sub-page granularity capture
 *
 * Creates a 4K mmap region, writes 1 byte at known offsets, and pauses
 * between writes so an external tracer (pagemon_viz mode 6 or eBPF) can
 * detect exactly which bytes changed.
 *
 * Build:   gcc -O0 -o subpage_validate subpage_validate.c
 * Usage:   ./subpage_validate [mode] [file]
 *
 * Modes:
 *   0 = sequential   : write 1 byte at offsets 0,1,2,...,4095 (1-byte stride)
 *   1 = strided       : write 1 byte every 64 bytes (cache-line stride)
 *   2 = sparse        : write 4 bytes at offsets 0, 1000, 2000, 3000
 *   3 = burst         : write 256 bytes at offset 1024 (single memset)
 *   4 = interactive   : wait for Enter between each write (for manual tracing)
 *
 * The program prints its PID and the mmap address so the tracer can attach.
 * It creates a signal file (.subpage_ready) when ready for tracing.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>

#define TEST_FILE_SIZE  4096
#define READY_FILE      "/mnt/drives/nvme0n1/.subpage_ready"

static volatile int g_running = 1;

static void sighandler(int sig) {
    (void)sig;
    g_running = 0;
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/*
 * Write a "ready" signal file so the test harness knows when to start tracing.
 * Contains PID and mmap address.
 */
static void signal_ready(void *addr) {
    FILE *f = fopen(READY_FILE, "w");
    if (f) {
        fprintf(f, "pid=%d\n", getpid());
        fprintf(f, "addr=%p\n", addr);
        fprintf(f, "size=%d\n", TEST_FILE_SIZE);
        fclose(f);
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * Test mode 0: Sequential — write 1 byte at every offset 0..4095
 * ══════════════════════════════════════════════════════════════════════ */
static void test_sequential(volatile uint8_t *region) {
    printf("[mode 0] Sequential: writing 1 byte at each offset 0..4095\n");
    printf("         Each write separated by 10ms for tracer to observe\n\n");

    for (int i = 0; i < TEST_FILE_SIZE && g_running; i++) {
        region[i] = (uint8_t)(i & 0xFF);

        /* Print progress every 256 bytes */
        if (i % 256 == 0) {
            printf("  offset %4d: wrote 0x%02x\n", i, (uint8_t)(i & 0xFF));
        }

        usleep(10000);  /* 10ms between each byte */
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * Test mode 1: Strided — write 1 byte every 64 bytes (cache-line stride)
 * ══════════════════════════════════════════════════════════════════════ */
static void test_strided(volatile uint8_t *region) {
    printf("[mode 1] Strided: writing 1 byte every 64 bytes (cache-line)\n");
    printf("         64 writes total, 50ms apart\n\n");

    for (int i = 0; i < TEST_FILE_SIZE && g_running; i += 64) {
        region[i] = 0xAA;
        printf("  offset %4d: wrote 0xAA\n", i);
        usleep(50000);  /* 50ms */
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * Test mode 2: Sparse — write 4 bytes at specific offsets
 * ══════════════════════════════════════════════════════════════════════ */
static void test_sparse(volatile uint8_t *region) {
    int offsets[] = {0, 1000, 2000, 3000};
    int n = sizeof(offsets) / sizeof(offsets[0]);

    printf("[mode 2] Sparse: writing 4 bytes at offsets 0, 1000, 2000, 3000\n");
    printf("         4 writes total, 200ms apart\n\n");

    for (int i = 0; i < n && g_running; i++) {
        region[offsets[i]]     = 0xDE;
        region[offsets[i] + 1] = 0xAD;
        region[offsets[i] + 2] = 0xBE;
        region[offsets[i] + 3] = 0xEF;
        printf("  offset %4d: wrote 0xDEADBEEF\n", offsets[i]);
        usleep(200000);  /* 200ms */
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * Test mode 3: Burst — write 256 bytes at offset 1024
 * ══════════════════════════════════════════════════════════════════════ */
static void test_burst(volatile uint8_t *region) {
    printf("[mode 3] Burst: writing 256 bytes starting at offset 1024\n\n");

    /* Wait 500ms before the burst so tracer captures the "before" snapshot */
    usleep(500000);

    memset((void *)(region + 1024), 0xFF, 256);
    printf("  offset 1024..1279: wrote 256 bytes of 0xFF\n");

    /* Wait 500ms after the burst so tracer captures the "after" snapshot */
    usleep(500000);
}

/* ══════════════════════════════════════════════════════════════════════
 * Test mode 4: Interactive — wait for Enter between each write
 * ══════════════════════════════════════════════════════════════════════ */
static void test_interactive(volatile uint8_t *region) {
    int offsets[] = {0, 100, 512, 1024, 2048, 3072, 4000, 4095};
    int n = sizeof(offsets) / sizeof(offsets[0]);

    printf("[mode 4] Interactive: press Enter before each write\n\n");

    for (int i = 0; i < n && g_running; i++) {
        printf("  Next: write 0x%02X at offset %d [Press Enter]", i + 1, offsets[i]);
        fflush(stdout);
        getchar();
        region[offsets[i]] = (uint8_t)(i + 1);
        printf("  -> wrote 0x%02X at offset %d\n", i + 1, offsets[i]);
    }
}

/* ══════════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[]) {
    int mode = 0;
    const char *filepath = "/mnt/drives/nvme0n1/subpage_test.dat";

    if (argc > 1) mode = atoi(argv[1]);
    if (argc > 2) filepath = argv[2];

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    printf("══════════════════════════════════════════════════════════════\n");
    printf("  Sub-Page Validation Test\n");
    printf("  PID:  %d\n", getpid());
    printf("  File: %s\n", filepath);
    printf("  Mode: %d\n", mode);
    printf("══════════════════════════════════════════════════════════════\n\n");

    /* Create and initialize the test file with zeros */
    int fd = open(filepath, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    /* Write 4K of zeros */
    uint8_t zeros[TEST_FILE_SIZE];
    memset(zeros, 0, sizeof(zeros));
    if (write(fd, zeros, sizeof(zeros)) != sizeof(zeros)) {
        perror("write");
        close(fd);
        return 1;
    }

    /* mmap the file */
    void *addr = mmap(NULL, TEST_FILE_SIZE, PROT_READ | PROT_WRITE,
                      MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

    printf("mmap address: %p – %p (%d bytes)\n",
           addr, (char *)addr + TEST_FILE_SIZE, TEST_FILE_SIZE);
    printf("Tracer command:\n");
    printf("  sudo ./pagemon_viz %d 6 %lx %lx 100 50 0\n\n",
           getpid(),
           (unsigned long)addr,
           (unsigned long)addr + TEST_FILE_SIZE);

    /* Signal readiness */
    signal_ready(addr);

    /* Pause to let tracer attach */
    printf("Waiting 2 seconds for tracer to attach...\n\n");
    sleep(2);

    volatile uint8_t *region = (volatile uint8_t *)addr;
    uint64_t t_start = now_ns();

    switch (mode) {
        case 0: test_sequential(region); break;
        case 1: test_strided(region); break;
        case 2: test_sparse(region); break;
        case 3: test_burst(region); break;
        case 4: test_interactive(region); break;
        default:
            fprintf(stderr, "Unknown mode %d\n", mode);
            break;
    }

    uint64_t t_end = now_ns();
    double elapsed_ms = (t_end - t_start) / 1e6;

    /* Force flush to disk */
    msync(addr, TEST_FILE_SIZE, MS_SYNC);

    printf("\nDone. Elapsed: %.1f ms\n", elapsed_ms);
    printf("Keeping mmap alive for 3 more seconds for final tracer scan...\n");
    sleep(3);

    /* Cleanup */
    munmap(addr, TEST_FILE_SIZE);
    close(fd);
    unlink(READY_FILE);

    printf("Exiting.\n");
    return 0;
}
