#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdint.h>
#include "syscall_monitor.skel.h"

#define MAX_COMM_LEN 16
#define MAX_EVENTS 1000000  // Increased from 100000 to 1 million
#define MAX_PROCESSES 1000

// Syscall event structure (must match BPF program)
struct syscall_event {
    uint64_t timestamp;
    uint32_t pid;
    uint32_t syscall_nr;
    uint32_t fd;
    uint64_t size;
    uint64_t offset;
    char comm[MAX_COMM_LEN];
};

// Syscall statistics
struct syscall_stat {
    uint32_t syscall_nr;
    char syscall_name[32];
    uint64_t total_size;
    uint64_t count;
    double avg_size;
};

// Process statistics
struct process_stat {
    uint32_t pid;
    char process_name[MAX_COMM_LEN];
    uint64_t total_events;
    uint64_t total_size;
    struct {
        char syscall_name[32];
        uint64_t count;
        uint64_t total_size;
    } syscalls[50];
    int syscall_count;
};

// File descriptor statistics
struct fd_stat {
    uint32_t fd;
    uint64_t count;
    uint64_t total_size;
    char syscalls_used[256];
};

// Global variables
static volatile bool running = true;
static struct syscall_event *events = NULL;
static int event_count = 0;
static int max_events = MAX_EVENTS;
static bool detailed_logging = false;
static int events_dropped = 0;

// Syscall name mapping
static const char* get_syscall_name(uint32_t nr) {
    switch(nr) {
        case 0: return "read";
        case 1: return "write";
        case 2: return "open";
        case 3: return "close";
        case 8: return "lseek";
        case 17: return "pread64";
        case 18: return "pwrite64";
        case 257: return "openat";
        default: {
            static char buf[32];
            snprintf(buf, sizeof(buf), "syscall_%u", nr);
            return buf;
        }
    }
}

// Signal handler
static void sig_handler(int sig) {
    printf("\nReceived signal %d, stopping monitor...\n", sig);
    running = false;
}

// Ring buffer event handler with dynamic reallocation
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct syscall_event *e = data;
    
    // Check if we need to grow the buffer
    if (event_count >= max_events) {
        int new_max = max_events * 2;  // Double the size
        
        // Limit maximum to prevent excessive memory usage (e.g., 10 million events = ~760MB)
        if (new_max > 10000000) {
            events_dropped++;
            if (events_dropped == 1) {
                fprintf(stderr, "\nWarning: Reached maximum event buffer size (10M events)\n");
                fprintf(stderr, "Consider reducing monitoring duration or disabling detailed logging\n");
            }
            return 0;
        }
        
        struct syscall_event *new_events = realloc(events, new_max * sizeof(struct syscall_event));
        if (!new_events) {
            events_dropped++;
            if (events_dropped == 1) {
                fprintf(stderr, "\nWarning: Failed to allocate more memory for events\n");
            }
            return 0;
        }
        
        events = new_events;
        max_events = new_max;
        fprintf(stderr, "\nInfo: Expanded event buffer to %d events (%.1f MB)\n", 
                max_events, (max_events * sizeof(struct syscall_event)) / (1024.0 * 1024.0));
    }
    
    memcpy(&events[event_count], e, sizeof(*e));
    event_count++;
    
    return 0;
}

// Comparison functions for qsort
static int compare_syscall_stats_by_size(const void *a, const void *b) {
    const struct syscall_stat *sa = a;
    const struct syscall_stat *sb = b;
    if (sa->total_size > sb->total_size) return -1;
    if (sa->total_size < sb->total_size) return 1;
    return 0;
}

static int compare_syscall_stats_by_count(const void *a, const void *b) {
    const struct syscall_stat *sa = a;
    const struct syscall_stat *sb = b;
    if (sa->count > sb->count) return -1;
    if (sa->count < sb->count) return 1;
    return 0;
}

static int compare_process_stats(const void *a, const void *b) {
    const struct process_stat *pa = a;
    const struct process_stat *pb = b;
    if (pa->total_events > pb->total_events) return -1;
    if (pa->total_events < pb->total_events) return 1;
    return 0;
}

static int compare_fd_stats(const void *a, const void *b) {
    const struct fd_stat *fa = a;
    const struct fd_stat *fb = b;
    if (fa->count > fb->count) return -1;
    if (fa->count < fb->count) return 1;
    return 0;
}

// Display functions
static void print_separator(char c, int length) {
    for(int i = 0; i < length; i++) printf("%c", c);
    printf("\n");
}

static void display_syscall_stats(struct syscall_stat *stats, int count, const char *title) {
    printf("\n");
    print_separator('=', 85);
    printf("%s\n", title);
    print_separator('=', 85);
    
    printf("%-4s %-15s %-15s %-10s %-15s\n", 
           "Rank", "Syscall", "Total Size (KB)", "Count", "Avg Size (B)");
    print_separator('-', 85);
    
    int display_limit = count < 10 ? count : 10;
    for(int i = 0; i < display_limit; i++) {
        double total_size_kb = stats[i].total_size / 1024.0;
        printf("%-4d %-15s %-15.2f %-10lu %-15.2f\n",
               i + 1, stats[i].syscall_name, total_size_kb,
               stats[i].count, stats[i].avg_size);
    }
}

static void display_all_syscalls(struct syscall_stat *stats, int count) {
    printf("\n");
    print_separator('=', 85);
    printf("ALL SYSCALLS CAPTURED (%d unique syscalls)\n", count);
    print_separator('=', 85);
    
    printf("%-4s %-15s %-15s %-10s %-15s\n", 
           "Rank", "Syscall", "Total Size (KB)", "Count", "Avg Size (B)");
    print_separator('-', 85);
    
    for(int i = 0; i < count; i++) {
        double total_size_kb = stats[i].total_size / 1024.0;
        printf("%-4d %-15s %-15.2f %-10lu %-15.2f\n",
               i + 1, stats[i].syscall_name, total_size_kb,
               stats[i].count, stats[i].avg_size);
    }
}

static void display_detailed_events(int limit) {
    if (event_count == 0) {
        printf("\nNo detailed events captured\n");
        return;
    }
    
    printf("\n");
    print_separator('=', 120);
    printf("DETAILED SYSCALL EVENTS (showing first %d of %d)\n", 
           limit < event_count ? limit : event_count, event_count);
    print_separator('=', 120);
    
    printf("%-15s %-8s %-15s %-10s %-5s %-10s %-10s\n",
           "Timestamp", "PID", "Process", "Syscall", "FD", "Size", "Offset");
    print_separator('-', 120);
    
    int display_count = (limit < event_count) ? limit : event_count;
    for(int i = 0; i < display_count; i++) {
        struct syscall_event *e = &events[i];
        double timestamp_ms = e->timestamp / 1000000.0;
        
        char fd_str[8];
        if (e->fd == (uint32_t)-1) {
            strcpy(fd_str, "N/A");
        } else {
            snprintf(fd_str, sizeof(fd_str), "%u", e->fd);
        }
        
        char offset_str[12];
        if (e->offset == 0) {
            strcpy(offset_str, "N/A");
        } else {
            snprintf(offset_str, sizeof(offset_str), "%lu", e->offset);
        }
        
        printf("%-15.3f %-8u %-15s %-10s %-5s %-10lu %-10s\n",
               timestamp_ms, e->pid, e->comm, get_syscall_name(e->syscall_nr),
               fd_str, e->size, offset_str);
    }
}

static void analyze_processes(struct process_stat **processes_out, int *process_count_out) {
    if (event_count == 0) {
        *processes_out = NULL;
        *process_count_out = 0;
        return;
    }
    
    struct process_stat *processes = calloc(MAX_PROCESSES, sizeof(struct process_stat));
    if (!processes) {
        fprintf(stderr, "Failed to allocate memory for process analysis\n");
        *processes_out = NULL;
        *process_count_out = 0;
        return;
    }
    
    int process_count = 0;
    
    // Process each event
    for(int i = 0; i < event_count; i++) {
        struct syscall_event *e = &events[i];
        
        // Find existing process or create new one
        int proc_idx = -1;
        for(int j = 0; j < process_count; j++) {
            if (processes[j].pid == e->pid) {
                proc_idx = j;
                break;
            }
        }
        
        if (proc_idx == -1) {
            if (process_count >= MAX_PROCESSES) {
                continue; // Skip if we've reached max processes
            }
            proc_idx = process_count++;
            processes[proc_idx].pid = e->pid;
            strncpy(processes[proc_idx].process_name, e->comm, MAX_COMM_LEN - 1);
            processes[proc_idx].process_name[MAX_COMM_LEN - 1] = '\0';
        }
        
        // Update process totals
        processes[proc_idx].total_events++;
        processes[proc_idx].total_size += e->size;
        
        // Update syscall-specific stats for this process
        const char *syscall_name = get_syscall_name(e->syscall_nr);
        int syscall_idx = -1;
        
        for(int k = 0; k < processes[proc_idx].syscall_count; k++) {
            if (strcmp(processes[proc_idx].syscalls[k].syscall_name, syscall_name) == 0) {
                syscall_idx = k;
                break;
            }
        }
        
        if (syscall_idx == -1) {
            if (processes[proc_idx].syscall_count < 50) {
                syscall_idx = processes[proc_idx].syscall_count++;
                strncpy(processes[proc_idx].syscalls[syscall_idx].syscall_name, 
                       syscall_name, 31);
                processes[proc_idx].syscalls[syscall_idx].syscall_name[31] = '\0';
            }
        }
        
        if (syscall_idx != -1) {
            processes[proc_idx].syscalls[syscall_idx].count++;
            processes[proc_idx].syscalls[syscall_idx].total_size += e->size;
        }
    }
    
    // Sort by event count
    qsort(processes, process_count, sizeof(struct process_stat), compare_process_stats);
    
    *processes_out = processes;
    *process_count_out = process_count;
}

static void display_process_analysis(struct process_stat *processes, int process_count) {
    if (!processes || process_count == 0) {
        printf("\nNo process data available\n");
        return;
    }
    
    printf("\n");
    print_separator('=', 120);
    printf("SYSCALL ANALYSIS BY PROCESS\n");
    print_separator('=', 120);
    
    int display_count = process_count > 15 ? 15 : process_count;
    for(int i = 0; i < display_count; i++) {
        struct process_stat *proc = &processes[i];
        
        printf("\nProcess: %s (PID: %u)\n", proc->process_name, proc->pid);
        printf("Total Events: %lu, Total Size: %lu bytes\n", 
               proc->total_events, proc->total_size);
        print_separator('-', 80);
        
        printf("%-15s %-8s %-12s %-12s %-12s\n",
               "Syscall", "Count", "Total Size", "Avg Size", "% of Process");
        print_separator('-', 80);
        
        for(int j = 0; j < proc->syscall_count; j++) {
            double percentage = (proc->syscalls[j].count * 100.0) / proc->total_events;
            double avg_size = proc->syscalls[j].count > 0 ? 
                            (double)proc->syscalls[j].total_size / proc->syscalls[j].count : 0;
            
            printf("%-15s %-8lu %-12lu %-12.2f %-12.1f%%\n",
                   proc->syscalls[j].syscall_name,
                   proc->syscalls[j].count,
                   proc->syscalls[j].total_size,
                   avg_size,
                   percentage);
        }
    }
}

static void analyze_fd_usage() {
    if (event_count == 0) {
        return;
    }
    
    struct fd_stat fd_stats[10000] = {0};
    int fd_count = 0;
    
    // Analyze FD usage
    for(int i = 0; i < event_count; i++) {
        struct syscall_event *e = &events[i];
        
        if (e->fd == (uint32_t)-1 || e->fd > 9999) {
            continue; // Skip invalid FDs
        }
        
        // Find or create FD entry
        int fd_idx = -1;
        for(int j = 0; j < fd_count; j++) {
            if (fd_stats[j].fd == e->fd) {
                fd_idx = j;
                break;
            }
        }
        
        if (fd_idx == -1) {
            if (fd_count >= 10000) continue;
            fd_idx = fd_count++;
            fd_stats[fd_idx].fd = e->fd;
            fd_stats[fd_idx].syscalls_used[0] = '\0';
        }
        
        fd_stats[fd_idx].count++;
        fd_stats[fd_idx].total_size += e->size;
        
        // Add syscall to list if not already present
        const char *syscall = get_syscall_name(e->syscall_nr);
        if (strstr(fd_stats[fd_idx].syscalls_used, syscall) == NULL) {
            if (strlen(fd_stats[fd_idx].syscalls_used) > 0) {
                strncat(fd_stats[fd_idx].syscalls_used, ", ", 
                       sizeof(fd_stats[fd_idx].syscalls_used) - strlen(fd_stats[fd_idx].syscalls_used) - 1);
            }
            strncat(fd_stats[fd_idx].syscalls_used, syscall,
                   sizeof(fd_stats[fd_idx].syscalls_used) - strlen(fd_stats[fd_idx].syscalls_used) - 1);
        }
    }
    
    if (fd_count == 0) {
        return;
    }
    
    // Sort by operation count
    qsort(fd_stats, fd_count, sizeof(struct fd_stat), compare_fd_stats);
    
    printf("\n");
    print_separator('=', 80);
    printf("FILE DESCRIPTOR USAGE ANALYSIS\n");
    print_separator('=', 80);
    printf("%-5s %-12s %-12s %-50s\n", "FD", "Operations", "Total Size", "Syscalls Used");
    print_separator('-', 80);
    
    int display_count = fd_count > 20 ? 20 : fd_count;
    for(int i = 0; i < display_count; i++) {
        printf("%-5u %-12lu %-12lu %-50s\n",
               fd_stats[i].fd,
               fd_stats[i].count,
               fd_stats[i].total_size,
               fd_stats[i].syscalls_used);
    }
}

static void export_to_json(struct syscall_stat *stats, int stat_count, 
                          struct process_stat *processes, int process_count,
                          const char *filename_input) {
    time_t now;
    struct tm *tm_info;
    char timestamp[32];
    char filename[256];
    
    time(&now);
    tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);
    
    if (filename_input && strlen(filename_input) > 0) {
        strncpy(filename, filename_input, sizeof(filename) - 1);
        filename[sizeof(filename) - 1] = '\0';
    } else {
        snprintf(filename, sizeof(filename), "syscall_analysis_%s.json", timestamp);
    }
    
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        printf("Failed to create JSON export file: %s\n", strerror(errno));
        return;
    }
    
    // Calculate monitoring duration
    double duration = 0;
    if (event_count > 1) {
        uint64_t start_time = events[0].timestamp;
        uint64_t end_time = events[event_count - 1].timestamp;
        duration = (end_time - start_time) / 1e9; // Convert to seconds
    }
    
    // Calculate total I/O bytes
    uint64_t total_io_bytes = 0;
    for(int i = 0; i < stat_count; i++) {
        const char *name = stats[i].syscall_name;
        if (strcmp(name, "read") == 0 || strcmp(name, "write") == 0 ||
            strcmp(name, "pread64") == 0 || strcmp(name, "pwrite64") == 0) {
            total_io_bytes += stats[i].total_size;
        }
    }
    
    // Start JSON
    fprintf(fp, "{\n");
    
    // Metadata
    fprintf(fp, "  \"metadata\": {\n");
    fprintf(fp, "    \"timestamp\": \"%s\",\n", timestamp);
    fprintf(fp, "    \"total_events\": %d,\n", event_count);
    fprintf(fp, "    \"monitoring_duration\": %.3f,\n", duration);
    fprintf(fp, "    \"unique_syscalls\": %d,\n", stat_count);
    fprintf(fp, "    \"unique_processes\": %d\n", process_count);
    fprintf(fp, "  },\n");
    
    // Summary
    fprintf(fp, "  \"summary\": {\n");
    fprintf(fp, "    \"total_io_bytes\": %lu,\n", total_io_bytes);
    fprintf(fp, "    \"most_active_process\": \"%s\",\n", 
            process_count > 0 ? processes[0].process_name : "N/A");
    fprintf(fp, "    \"most_active_process_pid\": %u\n",
            process_count > 0 ? processes[0].pid : 0);
    fprintf(fp, "  },\n");
    
    // Aggregated syscall stats
    fprintf(fp, "  \"aggregated_stats\": {\n");
    fprintf(fp, "    \"all_syscalls\": [\n");
    for(int i = 0; i < stat_count; i++) {
        fprintf(fp, "      {\n");
        fprintf(fp, "        \"syscall_nr\": %u,\n", stats[i].syscall_nr);
        fprintf(fp, "        \"syscall_name\": \"%s\",\n", stats[i].syscall_name);
        fprintf(fp, "        \"total_size\": %lu,\n", stats[i].total_size);
        fprintf(fp, "        \"count\": %lu,\n", stats[i].count);
        fprintf(fp, "        \"avg_size\": %.2f\n", stats[i].avg_size);
        fprintf(fp, "      }%s\n", (i < stat_count - 1) ? "," : "");
    }
    fprintf(fp, "    ]\n");
    fprintf(fp, "  },\n");
    
    // Process analysis
    fprintf(fp, "  \"process_analysis\": [\n");
    for(int i = 0; i < process_count; i++) {
        struct process_stat *proc = &processes[i];
        fprintf(fp, "    {\n");
        fprintf(fp, "      \"pid\": %u,\n", proc->pid);
        fprintf(fp, "      \"process_name\": \"%s\",\n", proc->process_name);
        fprintf(fp, "      \"total_events\": %lu,\n", proc->total_events);
        fprintf(fp, "      \"total_size\": %lu,\n", proc->total_size);
        fprintf(fp, "      \"syscalls\": [\n");
        
        for(int j = 0; j < proc->syscall_count; j++) {
            fprintf(fp, "        {\n");
            fprintf(fp, "          \"syscall_name\": \"%s\",\n", proc->syscalls[j].syscall_name);
            fprintf(fp, "          \"count\": %lu,\n", proc->syscalls[j].count);
            fprintf(fp, "          \"total_size\": %lu\n", proc->syscalls[j].total_size);
            fprintf(fp, "        }%s\n", (j < proc->syscall_count - 1) ? "," : "");
        }
        
        fprintf(fp, "      ]\n");
        fprintf(fp, "    }%s\n", (i < process_count - 1) ? "," : "");
    }
    fprintf(fp, "  ],\n");
    
    // Raw events
    if (detailed_logging && event_count > 0) {
        fprintf(fp, "  \"raw_events\": [\n");
        for(int i = 0; i < event_count; i++) {
            struct syscall_event *e = &events[i];
            fprintf(fp, "    {\n");
            fprintf(fp, "      \"timestamp_ns\": %lu,\n", e->timestamp);
            fprintf(fp, "      \"timestamp_ms\": %.3f,\n", e->timestamp / 1000000.0);
            fprintf(fp, "      \"pid\": %u,\n", e->pid);
            fprintf(fp, "      \"process_name\": \"%s\",\n", e->comm);
            fprintf(fp, "      \"syscall_nr\": %u,\n", e->syscall_nr);
            fprintf(fp, "      \"syscall_name\": \"%s\",\n", get_syscall_name(e->syscall_nr));
            fprintf(fp, "      \"fd\": %u,\n", e->fd);
            fprintf(fp, "      \"size\": %lu,\n", e->size);
            fprintf(fp, "      \"offset\": %lu\n", e->offset);
            fprintf(fp, "    }%s\n", (i < event_count - 1) ? "," : "");
        }
        fprintf(fp, "  ]\n");
    } else {
        fprintf(fp, "  \"raw_events\": []\n");
    }
    
    fprintf(fp, "}\n");
    fclose(fp);
    
    struct stat st;
    if (stat(filename, &st) == 0) {
        printf("\nData exported to %s\n", filename);
        printf("  - Raw events: %d\n", event_count);
        printf("  - Unique processes: %d\n", process_count);
        printf("  - Unique syscalls: %d\n", stat_count);
        printf("  - File size: %.1f KB\n", st.st_size / 1024.0);
    }
}

static int check_requirements() {
    if (geteuid() != 0) {
        printf("Error: This program must be run as root (use sudo)\n");
        return 0;
    }
    return 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    // Only print warnings and errors
    if (level == LIBBPF_WARN || level == LIBBPF_INFO) {
        return vfprintf(stderr, format, args);
    }
    return 0;
}

int main(int argc, char **argv) {
    struct syscall_monitor_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;
    int duration = 10;
    char input[256];
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--max-events") == 0 && i + 1 < argc) {
            max_events = atoi(argv[i + 1]);
            if (max_events < 1000) max_events = 1000;
            if (max_events > 10000000) max_events = 10000000;
            i++;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [OPTIONS]\n", argv[0]);
            printf("Options:\n");
            printf("  --max-events N    Set maximum events to capture (default: %d)\n", MAX_EVENTS);
            printf("  --help, -h        Show this help message\n");
            return 0;
        }
    }
    
    if (!check_requirements()) {
        return 1;
    }
    
    // Allocate event buffer
    events = calloc(max_events, sizeof(struct syscall_event));
    if (!events) {
        fprintf(stderr, "Failed to allocate event buffer\n");
        return 1;
    }
    
    // Setup libbpf logging
    libbpf_set_print(libbpf_print_fn);
    
    // Ask user about detailed logging
    printf("Enable detailed event logging? (y/N): ");
    fflush(stdout);
    if (fgets(input, sizeof(input), stdin)) {
        detailed_logging = (input[0] == 'y' || input[0] == 'Y');
    }
    
    // Get monitoring duration
    printf("Enter monitoring duration in seconds (default %d): ", duration);
    fflush(stdout);
    if (fgets(input, sizeof(input), stdin) && strlen(input) > 1) {
        int user_duration = atoi(input);
        if (user_duration > 0 && user_duration <= 3600) {
            duration = user_duration;
        }
    }
    
    // Open and load BPF application
    skel = syscall_monitor_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        err = -1;
        goto cleanup;
    }
    
    // Set detailed logging flag
    skel->rodata->detailed_logging = detailed_logging;
    
    // Load and verify BPF application
    err = syscall_monitor_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
        fprintf(stderr, "Make sure you have the correct kernel version and BTF support\n");
        goto cleanup;
    }
    
    // Attach tracepoints
    err = syscall_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }
    
    printf("BPF program loaded successfully\n");
    
    // Set up ring buffer if detailed logging is enabled
    if (detailed_logging) {
        rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
        if (!rb) {
            fprintf(stderr, "Failed to create ring buffer\n");
            err = -1;
            goto cleanup;
        }
        printf("Detailed event logging enabled\n");
    }
    
    // Set up signal handling
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    printf("Monitoring syscalls for %d seconds...\n", duration);
    printf("Press Ctrl+C to stop early\n\n");
    
    // Main monitoring loop
    time_t start_time = time(NULL);
    while (running && (time(NULL) - start_time) < duration) {
        if (rb) {
            err = ring_buffer__poll(rb, 100);
            if (err < 0 && err != -EINTR) {
                fprintf(stderr, "Error polling ring buffer: %d\n", err);
                break;
            }
        }
        
        int elapsed = time(NULL) - start_time;
        int remaining = duration - elapsed;
        printf("Monitoring... %ds elapsed, %ds remaining [%d events captured]\r", 
               elapsed, remaining, event_count);
        fflush(stdout);
        
        usleep(100000); // 100ms
    }
    
    printf("\nCollecting results... Captured %d individual events\n", event_count);
    
    // Collect aggregated syscall data from BPF maps
    struct syscall_stat stats[256] = {0};
    int stat_count = 0;
    
    uint32_t key = 0, next_key;
    uint64_t size_val, count_val;
    
    // Iterate through syscall_sizes map
    while (bpf_map_get_next_key(bpf_map__fd(skel->maps.syscall_sizes), &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.syscall_sizes), &next_key, &size_val) == 0) {
            count_val = 0;
            bpf_map_lookup_elem(bpf_map__fd(skel->maps.syscall_counts), &next_key, &count_val);
            
            if (stat_count < 256) {
                stats[stat_count].syscall_nr = next_key;
                strncpy(stats[stat_count].syscall_name, get_syscall_name(next_key), 31);
                stats[stat_count].syscall_name[31] = '\0';
                stats[stat_count].total_size = size_val;
                stats[stat_count].count = count_val;
                stats[stat_count].avg_size = count_val > 0 ? (double)size_val / count_val : 0;
                stat_count++;
            }
        }
        key = next_key;
    }
    
    if (stat_count == 0) {
        printf("\nNo syscall data collected.\n");
        printf("Try running some file operations in another terminal:\n");
        printf("  cat /etc/passwd\n");
        printf("  ls -la\n");
        printf("  echo 'test' > /tmp/test.txt\n");
        goto cleanup;
    }
    
    // Sort by total size
    qsort(stats, stat_count, sizeof(struct syscall_stat), compare_syscall_stats_by_size);
    
    // Display results
    display_syscall_stats(stats, stat_count, "TOP 10 SYSCALLS BY TOTAL I/O SIZE");
    display_all_syscalls(stats, stat_count);
    
    // Analyze and display process data
    struct process_stat *processes = NULL;
    int process_count = 0;
    
    if (detailed_logging && event_count > 0) {
        analyze_processes(&processes, &process_count);
        display_detailed_events(20);
        display_process_analysis(processes, process_count);
        analyze_fd_usage();
    }
    
    // Summary statistics
    printf("\n");
    print_separator('=', 80);
    printf("SUMMARY STATISTICS\n");
    print_separator('=', 80);
    
    uint64_t total_syscalls = 0;
    uint64_t total_io_bytes = 0;
    uint64_t file_ops = 0;
    
    for(int i = 0; i < stat_count; i++) {
        total_syscalls += stats[i].count;
        
        const char *name = stats[i].syscall_name;
        if (strcmp(name, "read") == 0 || strcmp(name, "write") == 0 ||
            strcmp(name, "pread64") == 0 || strcmp(name, "pwrite64") == 0) {
            total_io_bytes += stats[i].total_size;
        }
        
        if (strcmp(name, "open") == 0 || strcmp(name, "openat") == 0 ||
            strcmp(name, "close") == 0) {
            file_ops += stats[i].count;
        }
    }
    
    printf("Total syscalls captured: %lu\n", total_syscalls);
    printf("Total I/O bytes: %lu (%.2f MB)\n", total_io_bytes, total_io_bytes / (1024.0 * 1024.0));
    printf("File operations (open/close): %lu\n", file_ops);
    printf("Unique syscalls observed: %d\n", stat_count);
    printf("Unique processes: %d\n", process_count);
    printf("Events captured: %d\n", event_count);
    if (events_dropped > 0) {
        printf("Events dropped: %d (buffer limit reached)\n", events_dropped);
    }
    printf("Memory used for events: %.2f MB\n", 
           (event_count * sizeof(struct syscall_event)) / (1024.0 * 1024.0));
    
    if (event_count > 1) {
        uint64_t start_time = events[0].timestamp;
        uint64_t end_time = events[event_count - 1].timestamp;
        double duration_actual = (end_time - start_time) / 1e9;
        printf("Actual monitoring duration: %.3f seconds\n", duration_actual);
        
        if (duration_actual > 0) {
            printf("Average syscalls per second: %.2f\n", total_syscalls / duration_actual);
            printf("Average I/O throughput: %.2f KB/s\n", 
                   (total_io_bytes / 1024.0) / duration_actual);
        }
    }
    
    // Ask about JSON export
    printf("\nExport data to JSON? (Y/n): ");
    fflush(stdout);
    if (fgets(input, sizeof(input), stdin)) {
        if (input[0] != 'n' && input[0] != 'N') {
            printf("Enter filename (or press Enter for auto-generated): ");
            fflush(stdout);
            
            char filename_input[256] = {0};
            if (fgets(filename_input, sizeof(filename_input), stdin)) {
                // Remove newline
                size_t len = strlen(filename_input);
                if (len > 0 && filename_input[len-1] == '\n') {
                    filename_input[len-1] = '\0';
                }
                
                export_to_json(stats, stat_count, processes, process_count, 
                             strlen(filename_input) > 0 ? filename_input : NULL);
            }
        }
    }
    
    printf("\nMonitoring complete!\n");
    
cleanup:
    if (rb)
        ring_buffer__free(rb);
    if (skel)
        syscall_monitor_bpf__destroy(skel);
    if (events)
        free(events);
    if (processes)
        free(processes);
    
    return err < 0 ? -err : 0;
}
