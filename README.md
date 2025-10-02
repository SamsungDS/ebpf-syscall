# Setting up and Running Syscall Monitor

## 1. Verify System Requirements
```
# Check Kernel Version (need 4.18+)
uname -r

# Check if BTF is available
ls -al /sys/kernel/btf/vmlinux

# Check current user
whoami

# Verify you can use sudo
sudo -v
```
## 2. Clone repository
```
git clone https://github.com/SamsungDS/ebpf-syscall.git
cd ebpf-syscall

# Update package list
sudo apt-get update

# Install all dependencies at once
sudo apt-get install -y \
    clang \
    llvm \
    libelf-dev \
    zlib1g-dev \
    linux-tools-common \
    linux-tools-generic \
    linux-tools-$(uname -r) \
    build-essential \
    git \
    curl

# Verify installations
clang --version
bpftool version

```
### Expected Output
```
ssgroot@test82:~/ProfilingTools/syscall_tool$ clang --version
Ubuntu clang version 14.0.0-1ubuntu1.1
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /usr/bin

```
```
ssgroot@test82:~/ProfilingTools/syscall_tool$ bpftool --version
bpftool v7.4.0
using libbpf v1.4
features: libbpfd, libbpf, skeleton

```

## 3. Build the tool
```
make all

```
Check all the files that are generated:
```
ls -lh

```
Final output is as below:
```
ssgroot@test82:~/ProfilingTools/syscall_tool$ make all
Setting up libbpf...
Cloning into './libbpf'...
remote: Enumerating objects: 156, done.
remote: Counting objects: 100% (156/156), done.
remote: Compressing objects: 100% (142/142), done.
remote: Total 156 (delta 1), reused 85 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (156/156), 2.37 MiB | 7.19 MiB/s, done.
Resolving deltas: 100% (1/1), done.
make[1]: Entering directory '/home/ssgroot/ProfilingTools/syscall_tool/libbpf/src'
  MKDIR    staticobjs
  CC       staticobjs/bpf.o
  CC       staticobjs/btf.o
  CC       staticobjs/libbpf.o
  CC       staticobjs/libbpf_errno.o
  CC       staticobjs/netlink.o
  CC       staticobjs/nlattr.o
  CC       staticobjs/str_error.o
  CC       staticobjs/libbpf_probes.o
  CC       staticobjs/bpf_prog_linfo.o
  CC       staticobjs/btf_dump.o
  CC       staticobjs/hashmap.o
  CC       staticobjs/ringbuf.o
  CC       staticobjs/strset.o
  CC       staticobjs/linker.o
  CC       staticobjs/gen_loader.o
  CC       staticobjs/relo_core.o
  CC       staticobjs/usdt.o
  CC       staticobjs/zip.o
  CC       staticobjs/elf.o
  CC       staticobjs/features.o
  CC       staticobjs/btf_iter.o
  CC       staticobjs/btf_relocate.o
  AR       libbpf.a
  MKDIR    sharedobjs
  CC       sharedobjs/bpf.o
  CC       sharedobjs/btf.o
  CC       sharedobjs/libbpf.o
  CC       sharedobjs/libbpf_errno.o
  CC       sharedobjs/netlink.o
  CC       sharedobjs/nlattr.o
  CC       sharedobjs/str_error.o
  CC       sharedobjs/libbpf_probes.o
  CC       sharedobjs/bpf_prog_linfo.o
  CC       sharedobjs/btf_dump.o
  CC       sharedobjs/hashmap.o
  CC       sharedobjs/ringbuf.o
  CC       sharedobjs/strset.o
  CC       sharedobjs/linker.o
  CC       sharedobjs/gen_loader.o
  CC       sharedobjs/relo_core.o
  CC       sharedobjs/usdt.o
  CC       sharedobjs/zip.o
  CC       sharedobjs/elf.o
  CC       sharedobjs/features.o
  CC       sharedobjs/btf_iter.o
  CC       sharedobjs/btf_relocate.o
  CC       libbpf.so.1.7.0
make[1]: Leaving directory '/home/ssgroot/ProfilingTools/syscall_tool/libbpf/src'
Checking for bpftool...
Generating vmlinux.h...
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I./libbpf/src -I. -c syscall_monitor.bpf.c -o syscall_monitor.bpf.o
bpftool gen skeleton syscall_monitor.bpf.o > syscall_monitor.skel.h
gcc -g -O2 -Wall -Wextra -I./libbpf/src -I. syscall_monitor.c -L./libbpf/src -lbpf -lelf -lz -o syscall_monitor
syscall_monitor.c: In function ‘handle_event’:
syscall_monitor.c:92:31: warning: unused parameter ‘ctx’ [-Wunused-parameter]
   92 | static int handle_event(void *ctx, void *data, size_t data_sz) {
      |                         ~~~~~~^~~
syscall_monitor.c:92:55: warning: unused parameter ‘data_sz’ [-Wunused-parameter]
   92 | static int handle_event(void *ctx, void *data, size_t data_sz) {
      |                                                ~~~~~~~^~~~~~~
At top level:
syscall_monitor.c:118:12: warning: ‘compare_syscall_stats_by_count’ defined but not used [-Wunused-function]
  118 | static int compare_syscall_stats_by_count(const void *a, const void *b) {
      |            ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
syscall_monitor.c: In function ‘main’:
syscall_monitor.c:210:47: warning: ‘%u’ directive output may be truncated writing between 1 and 10 bytes into a region of size 8 [-Wformat-truncation=]
  210 |             snprintf(fd_str, sizeof(fd_str), "%u", e->fd);
      |                                               ^~
syscall_monitor.c:210:46: note: directive argument in the range [0, 4294967294]
  210 |             snprintf(fd_str, sizeof(fd_str), "%u", e->fd);
      |                                              ^~~~
In file included from /usr/include/stdio.h:894,
                 from syscall_monitor.c:1:
/usr/include/x86_64-linux-gnu/bits/stdio2.h:71:10: note: ‘__builtin___snprintf_chk’ output between 2 and 11 bytes into a destination of size 8
   71 |   return __builtin___snprintf_chk (__s, __n, __USE_FORTIFY_LEVEL - 1,
      |          ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   72 |                                    __glibc_objsize (__s), __fmt,
      |                                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   73 |                                    __va_arg_pack ());
      |                                    ~~~~~~~~~~~~~~~~~
syscall_monitor.c:217:55: warning: ‘%lu’ directive output may be truncated writing between 1 and 20 bytes into a region of size 12 [-Wformat-truncation=]
  217 |             snprintf(offset_str, sizeof(offset_str), "%lu", e->offset);
      |                                                       ^~~
syscall_monitor.c:217:54: note: directive argument in the range [1, 18446744073709551615]
  217 |             snprintf(offset_str, sizeof(offset_str), "%lu", e->offset);
      |                                                      ^~~~~
In file included from /usr/include/stdio.h:894,
                 from syscall_monitor.c:1:
/usr/include/x86_64-linux-gnu/bits/stdio2.h:71:10: note: ‘__builtin___snprintf_chk’ output between 2 and 21 bytes into a destination of size 12
   71 |   return __builtin___snprintf_chk (__s, __n, __USE_FORTIFY_LEVEL - 1,
      |          ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   72 |                                    __glibc_objsize (__s), __fmt,
      |                                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   73 |                                    __va_arg_pack ());
      |                                    ~~~~~~~~~~~~~~~~~
syscall_monitor.c:803:9: warning: ‘processes’ may be used uninitialized in this function [-Wmaybe-uninitialized]
  803 |         free(processes);
      |         ^~~~~~~~~~~~~~~
ssgroot@test82:~/ProfilingTools/syscall_tool$ ls -al
total 3388
drwxrwxr-x  3 ssgroot ssgroot    4096 Oct  2 04:28 .
drwxrwxr-x  4 ssgroot ssgroot    4096 Oct  2 04:22 ..
-rw-rw-r--  1 ssgroot ssgroot    2866 Oct  2 04:23 Makefile
drwxrwxr-x 11 ssgroot ssgroot    4096 Oct  2 04:27 libbpf
-rwxrwxr-x  1 ssgroot ssgroot  122536 Oct  2 04:28 syscall_monitor
-rw-rw-r--  1 ssgroot ssgroot    4689 Oct  2 04:23 syscall_monitor.bpf.c
-rw-rw-r--  1 ssgroot ssgroot   34496 Oct  2 04:28 syscall_monitor.bpf.o
-rw-rw-r--  1 ssgroot ssgroot   27139 Oct  2 04:25 syscall_monitor.c
-rw-rw-r--  1 ssgroot ssgroot  108771 Oct  2 04:28 syscall_monitor.skel.h
-rw-rw-r--  1 ssgroot ssgroot 3143612 Oct  2 04:28 vmlinux.h

```
## 4. Test Run with a simple workload
```
cd ebpf-syscall
sudo ./syscall_monitor
```
In second terminal run a simple workload to verify:
```
# Simple file operations
cat /etc/hostname
ls -la /tmp
echo "test data" > /tmp/test.txt
cat /tmp/test.txt
rm /tmp/test.txt
```

## Sample Output from monitoring
```
ssgroot@test82:~/ProfilingTools/syscall_tool$ sudo ./syscall_monitor
Enable detailed event logging? (y/N): y
Enter monitoring duration in seconds (default 10): 60
BPF program loaded successfully
Detailed event logging enabled
Monitoring syscalls for 60 seconds...
Press Ctrl+C to stop early

Monitoring... 59s elapsed, 1s remaining [93868 events captured]]
Collecting results... Captured 93868 individual events

=====================================================================================
TOP 10 SYSCALLS BY TOTAL I/O SIZE
=====================================================================================
Rank Syscall         Total Size (KB) Count      Avg Size (B)
-------------------------------------------------------------------------------------
1    lseek           3.69            472        8.00
2    write           0.00            23150      0.00

=====================================================================================
ALL SYSCALLS CAPTURED (2 unique syscalls)
=====================================================================================
Rank Syscall         Total Size (KB) Count      Avg Size (B)
-------------------------------------------------------------------------------------
1    lseek           3.69            472        8.00
2    write           0.00            23150      0.00

========================================================================================================================
DETAILED SYSCALL EVENTS (showing first 20 of 93868)
========================================================================================================================
Timestamp       PID      Process         Syscall    FD    Size       Offset
------------------------------------------------------------------------------------------------------------------------
1788888331.140  2900312  syscall_monitor read       1084455 0          N/A
1788888331.147  2900312  syscall_monitor read       1084455 0          N/A
1788888331.157  2900312  syscall_monitor read       1084455 0          N/A
1788888331.160  2900312  syscall_monitor read       1084455 0          N/A
1788888336.904  2900312  syscall_monitor read       1084455 0          N/A
1788888336.909  2900312  syscall_monitor read       1084455 0          N/A
1788888336.918  2900312  syscall_monitor read       1084455 0          N/A
1788888336.920  2900312  syscall_monitor read       1084455 0          N/A
1788888342.365  2900312  syscall_monitor read       1084455 0          N/A
1788888342.369  2900312  syscall_monitor read       1084455 0          N/A
1788888342.377  2900312  syscall_monitor read       1084455 0          N/A
1788888342.379  2900312  syscall_monitor read       1084455 0          N/A
1788888347.205  2900312  syscall_monitor openat     1084455 1          N/A
1788888347.216  2900312  syscall_monitor read       1084455 0          N/A
1788888347.220  2900312  syscall_monitor read       1084455 0          N/A
1788888347.223  2900312  syscall_monitor openat     1084455 1          N/A
1788888347.228  2900312  syscall_monitor read       1084455 0          N/A
1788888347.229  2900312  syscall_monitor read       1084455 0          N/A
1788888349.332  19113    milvus          write      4291510 0          N/A
1788888349.367  19113    milvus          read       1612020 0          N/A

========================================================================================================================
SYSCALL ANALYSIS BY PROCESS
========================================================================================================================

Process: milvus (PID: 19113)
Total Events: 49894, Total Size: 7664 bytes
--------------------------------------------------------------------------------
Syscall         Count    Total Size   Avg Size     % of Process
--------------------------------------------------------------------------------
write           16523    0            0.00         33.1        %
read            25707    0            0.00         51.5        %
openat          3831     3831         1.00         7.7         %
close           3833     3833         1.00         7.7         %

Process: node_exporter (PID: 2123)
Total Events: 19335, Total Size: 11817 bytes
--------------------------------------------------------------------------------
Syscall         Count    Total Size   Avg Size     % of Process
--------------------------------------------------------------------------------
read            7500     0            0.00         38.8        %
openat          6003     6003         1.00         31.0        %
close           5814     5814         1.00         30.1        %
write           18       0            0.00         0.1         %

Process: irqbalance (PID: 1786)
Total Events: 4764, Total Size: 192 bytes
--------------------------------------------------------------------------------
Syscall         Count    Total Size   Avg Size     % of Process
--------------------------------------------------------------------------------
openat          96       96           1.00         2.0         %
read            4569     0            0.00         95.9        %
close           96       96           1.00         2.0         %
write           3        0            0.00         0.1         %

Process: etcd (PID: 18192)
Total Events: 2597, Total Size: 198 bytes
--------------------------------------------------------------------------------
Syscall         Count    Total Size   Avg Size     % of Process
--------------------------------------------------------------------------------
write           1164     0            0.00         44.8        %
read            1310     0            0.00         50.4        %
lseek           23       184          8.00         0.9         %
pwrite64        86       0            0.00         3.3         %
openat          6        6            1.00         0.2         %
close           8        8            1.00         0.3         %

Process: bash (PID: 2900331)
Total Events: 2502, Total Size: 4222 bytes
--------------------------------------------------------------------------------
Syscall         Count    Total Size   Avg Size     % of Process
--------------------------------------------------------------------------------
close           292      292          1.00         11.7        %
read            494      0            0.00         19.7        %
openat          1338     1338         1.00         53.5        %
pread64         4        0            0.00         0.2         %
lseek           324      2592         8.00         12.9        %
write           50       0            0.00         2.0         %

Process: dockerd (PID: 2122)
Total Events: 1860, Total Size: 68 bytes
--------------------------------------------------------------------------------
Syscall         Count    Total Size   Avg Size     % of Process
--------------------------------------------------------------------------------
write           605      0            0.00         32.5        %
read            1187     0            0.00         63.8        %
openat          34       34           1.00         1.8         %
close           34       34           1.00         1.8         %

Process: containerd-shim (PID: 18981)
Total Events: 1416, Total Size: 56 bytes
--------------------------------------------------------------------------------
Syscall         Count    Total Size   Avg Size     % of Process
--------------------------------------------------------------------------------
read            873      0            0.00         61.7        %
write           487      0            0.00         34.4        %
openat          22       22           1.00         1.6         %
close           34       34           1.00         2.4         %

Process: runc:[1:CHILD] (PID: 2900391)
Total Events: 1267, Total Size: 881 bytes
--------------------------------------------------------------------------------
Syscall         Count    Total Size   Avg Size     % of Process
--------------------------------------------------------------------------------
close           68       68           1.00         5.4         %
read            68       0            0.00         5.4         %
write           321      0            0.00         25.3        %
openat          803      803          1.00         63.4        %
pread64         4        0            0.00         0.3         %
open            2        2            1.00         0.2         %
lseek           1        8            8.00         0.1         %

Process: runc:[1:CHILD] (PID: 2900463)
Total Events: 1267, Total Size: 881 bytes
--------------------------------------------------------------------------------
Syscall         Count    Total Size   Avg Size     % of Process
--------------------------------------------------------------------------------
close           68       68           1.00         5.4         %
read            68       0            0.00         5.4         %
write           321      0            0.00         25.3        %
openat          803      803          1.00         63.4        %
pread64         4        0            0.00         0.3         %
open            2        2            1.00         0.2         %
lseek           1        8            8.00         0.1         %

Process: sshd (PID: 2896466)
Total Events: 1203, Total Size: 0 bytes
--------------------------------------------------------------------------------
Syscall         Count    Total Size   Avg Size     % of Process
--------------------------------------------------------------------------------
read            602      0            0.00         50.0        %
write           601      0            0.00         50.0        %

Process: sudo (PID: 2900310)
Total Events: 1202, Total Size: 0 bytes
--------------------------------------------------------------------------------
Syscall         Count    Total Size   Avg Size     % of Process
--------------------------------------------------------------------------------
read            601      0            0.00         50.0        %
write           601      0            0.00         50.0        %

Process: containerd (PID: 1800)
Total Events: 753, Total Size: 0 bytes
--------------------------------------------------------------------------------
Syscall         Count    Total Size   Avg Size     % of Process
--------------------------------------------------------------------------------
write           302      0            0.00         40.1        %
read            451      0            0.00         59.9        %

Process: syscall_monitor (PID: 2900312)
Total Events: 646, Total Size: 14 bytes
--------------------------------------------------------------------------------
Syscall         Count    Total Size   Avg Size     % of Process
--------------------------------------------------------------------------------
read            28       0            0.00         4.3         %
openat          8        8            1.00         1.2         %
close           6        6            1.00         0.9         %
write           604      0            0.00         93.5        %

Process: runc:[1:CHILD] (PID: 2900371)
Total Events: 615, Total Size: 505 bytes
--------------------------------------------------------------------------------
Syscall         Count    Total Size   Avg Size     % of Process
--------------------------------------------------------------------------------
close           68       68           1.00         11.1        %
read            125      0            0.00         20.3        %
write           321      0            0.00         52.2        %
openat          53       53           1.00         8.6         %
lseek           48       384          8.00         7.8         %

Process: runc:[1:CHILD] (PID: 2900444)
Total Events: 614, Total Size: 505 bytes
--------------------------------------------------------------------------------
Syscall         Count    Total Size   Avg Size     % of Process
--------------------------------------------------------------------------------
close           68       68           1.00         11.1        %
read            124      0            0.00         20.2        %
write           321      0            0.00         52.3        %
openat          53       53           1.00         8.6         %
lseek           48       384          8.00         7.8         %

================================================================================
SUMMARY STATISTICS
================================================================================
Total syscalls captured: 23622
Total I/O bytes: 0 (0.00 MB)
File operations (open/close): 0
Unique syscalls observed: 2
Unique processes: 53
Events captured: 93868
Actual monitoring duration: 59.983 seconds
Average syscalls per second: 393.81
Average I/O throughput: 0.00 KB/s

Export data to JSON? (Y/n): y
Enter filename (or press Enter for auto-generated): testsyscall.txt

Data exported to testsyscall.txt
  - Raw events: 93868
  - Unique processes: 53
  - Unique syscalls: 2
  - File size: 23635.5 KB

Monitoring complete!
```
