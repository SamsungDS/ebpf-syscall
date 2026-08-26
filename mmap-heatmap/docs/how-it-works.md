# How mmap-heatmap Captures Data

mmap-heatmap monitors write activity in file-backed mmap regions at
sub-page granularity (down to 8 bytes) without modifying the target
process or the kernel. It combines three Linux proc interfaces to
detect which bytes changed between sampling intervals.

## The Three Interfaces

### 1. /proc/PID/pagemap — Which Pages Were Written

The kernel maintains a soft-dirty bit (bit 55) in each page table entry.
When a process writes to a page, the CPU sets the PTE dirty bit and the
kernel propagates this to the soft-dirty bit. mmap-heatmap reads the
pagemap file to find which pages have been modified since the last
sample.

**Syscall**: `pread(pagemap_fd, buf, num_pages * 8, start_vpn * 8)`

Each 8-byte entry in pagemap corresponds to one virtual page. The file
offset is the virtual page number (virtual address / page size)
multiplied by 8. The tool reads the entire monitored range in a single
pread call — for an 8 MiB region (2048 pages), this is one 16 KiB read.

**Bit layout of each entry** (from `Documentation/admin-guide/mm/pagemap.rst`):

    Bit 55: soft-dirty (set by kernel when page is written)
    Bit 63: page present
    Bit 62: page swapped

The tool checks only bit 55. Pages with this bit set have been written
since the last clear.

### 2. /proc/PID/clear_refs — Reset Dirty Tracking

After reading the pagemap and identifying dirty pages, the tool clears
all soft-dirty bits so the next sample starts fresh.

**Syscall**: `write(clear_refs_fd, "4", 1)`

Writing the value 4 (`CLEAR_REFS_SOFT_DIRTY`) to this file clears the
soft-dirty bit on every PTE in the process. The kernel walks the process
page tables and clears bit 55 on each entry, then write-protects the
pages so that the next write will trigger a fault that re-sets the
soft-dirty bit.

This is the mechanism that enables per-sample dirty tracking: clear,
wait, check which pages became dirty during the wait.

### 3. /proc/PID/mem — Read Page Contents for Byte-Level Diffing

Knowing which pages were written (from pagemap) tells us the 4 KiB
granularity. To find which bytes within those pages actually changed,
the tool reads the current page contents and compares them against a
shadow buffer (a saved copy from the previous sample).

**Syscall**: `pread(mem_fd, buf, num_pages * 4096, virtual_address)`

The tool detects contiguous runs of dirty pages and reads them in a
single pread call. For sequential writes that dirty 50 consecutive
pages, this is one 200 KiB read instead of 50 separate 4 KiB reads.

The diff compares 8-byte words as u64 values. For each dirty page (4096
bytes = 512 words), the tool performs 512 integer comparisons. Words
that differ are marked as changed. The shadow buffer is then updated
with the new contents.

Only dirty pages (identified by pagemap) are read and diffed. Clean
pages are skipped entirely. This means the cost scales with the number
of pages actually written, not the total region size.

## The Sampling Loop

Each sample follows this sequence:

    1. pread(pagemap_fd, ...)        — find dirty pages (1 syscall)
    2. For each contiguous run of dirty pages:
       pread(mem_fd, ...)            — read current contents (1 syscall per run)
       diff against shadow           — find changed 8-byte words (CPU only)
       update shadow buffer          — memcpy new contents (CPU only)
    3. write(clear_refs_fd, "4")     — clear soft-dirty bits (1 syscall)
    4. Update heat maps              — CPU only, O(changed_words)
    5. Render frame to stdout        — 1 write syscall

**Syscall budget per sample**: 2 + N, where N is the number of
contiguous dirty page runs. For random writes touching 50 scattered
pages, N ≈ 50. For sequential writes touching 50 consecutive pages,
N = 1. The pagemap read and clear_refs write are always 1 each.

## Auto-Detection

### Process mmap Region

The tool automatically finds the target process's file-backed mmap
region by parsing `/proc/PID/maps`. It performs a two-pass search:

**Pass 1** — Named file-backed shared mappings: looks for lines where
the permissions contain 's' (shared) and the path is a real file (not
`[heap]`, `[stack]`, `/dev/zero`, `(deleted)`, or `SYSV`). Selects the
largest matching mapping by byte size.

**Pass 2** — If pass 1 finds nothing, falls back to the largest shared
mapping of any kind (including anonymous shared).

For fio's mmap engine, the mapping appears as:

    7f4c21889000-7f4c22089000 -w-s 00000000 00:27 745345  /tmp/.../mmap-zipf.0.0

Note the permissions: `-w-s` (write-only shared). The `s` flag
identifies it as a shared mapping (MAP_SHARED), which is how mmap I/O
works — writes through the mapping are visible to other processes and
will be written back to the file.

The user can override auto-detection with `-m START -M END` to specify
the region manually.

### Terminal Size

Terminal dimensions are detected using the `TIOCGWINSZ` ioctl. The tool
tries stdout, stderr, and stdin in order. If all three fail (e.g., when
running under sudo with redirected I/O), it opens `/dev/tty` directly
as a fallback. If everything fails, it defaults to 80x40.

The overview and zoom panes dynamically size to fill the detected
terminal dimensions. The overview is capped to leave room for the zoom
pane (minimum 3 zoom rows reserved).

## Visualization Modes

The tool offers two modes for mapping write activity to the 0-9 digit
display. Toggle between them with the 'f' key. Both modes track every
block independently and both are updated on every sample so switching
is instant.

### Freq Mode (default)

Freq mode answers: "how active is this block right now?"

It uses a moving-sum algorithm adapted from the kernel's DAMON
subsystem (mm/damon/core.c, damon_moving_sum). Each block stores a
frequency value in basis points (0-10000). On each write, the value
increases by 10000/window. On each idle sample, it decays by
freq_bp/window (multiplied by the decay rate).

The digit mapping is: 0 = completely idle within the window, 9 = written
every sample. Any non-zero frequency shows as at least digit 1.

Key parameters:

    --window N    Number of samples in the sliding window (default: 20).
                  A block must be written in all N recent samples to
                  reach digit 9. Controls how long blocks "remember"
                  past activity.

    --decay N     Decay rate multiplier (default: 1). With decay=1,
                  an idle block fades to 0 in approximately `window`
                  samples. With decay=2, it fades in `window/2` samples.
                  With decay=0, blocks accumulate forever and never fade.

Example with window=20, decay=1, interval=0.1s:

    A block written every sample holds steady at digit 9.
    A block written once fades: 1 -> 1 -> 1 -> ... -> 0 over ~20
    samples (2 seconds).
    A block written every other sample oscillates around digit 4-5.

### Heat Mode

Heat mode answers: "how much total write activity has this block
accumulated?"

Each block stores a raw point counter. Each write adds 1 point. Each
idle sample subtracts `decay` points. The display digit is
raw_points / heat_inc, capped at 9. The internal maximum is
9 * heat_inc.

Key parameters:

    --heat-inc N  Writes needed to advance one digit level (default: 2).
                  With heat-inc=2, a block needs 2 writes to show digit
                  1, 18 writes for digit 9. With heat-inc=100, it needs
                  100 writes per level and 900 writes to max out.

    --decay N     Raw points subtracted per idle sample (default: 1).
                  With decay=0, blocks accumulate forever.

Example with heat-inc=2, decay=1, interval=0.1s:

    A block written once shows digit 0 (1 point / 2 = 0), then
    decays to 0 next sample.
    A block written twice in a row shows digit 1 (2/2), then
    fades: 1 -> 0 -> 0.
    A block written 18 times consecutively reaches digit 9
    (18/2 = 9).

### When to Use Each Mode

**Freq mode** is best for observing current access patterns — which
blocks are hot right now, with a natural time window. It saturates
quickly (window writes to max) so it emphasizes "active vs idle"
rather than "how much." This matches DAMON's heatmap semantics.

**Heat mode** is best for observing cumulative write intensity — which
blocks received the most writes over time. It has a wider dynamic range
(9 * heat_inc writes to max) so it differentiates between moderately
and heavily written blocks for much longer. Use it to find absolute
hot spots.

### Comparison with decay=0

With decay=0, both modes accumulate forever. The practical difference
is dynamic range:

    Writes   Freq (win=20)   Heat (inc=20)
    ------   -------------   -------------
    1        1               0
    10       5               0
    20       9 (saturated)   1
    40       9               2
    100      9               5
    180      9               9

Freq saturates at 20 writes and cannot distinguish a block written 20
times from one written 10,000 times. Heat with inc=20 needs 180 writes
to saturate and shows the full gradient across that range.

## What This Approach Cannot Do

**Sub-page triggers**: The soft-dirty mechanism fires at page (4 KiB)
granularity. The tool cannot detect which specific byte within a page
was written — it detects this by content diffing, which means it sees
the *result* of writes (which bytes changed) but not the *event* of
individual writes. If a byte is written twice with different values
between samples, only the final value is visible.

**Every-write tracing**: This is statistical in the sense that it
captures the state at sampling boundaries, not every individual write
event. If the sampling interval is 100ms and a byte is written 1000
times, the tool sees it as "this byte changed" once.

**Write ordering**: The tool cannot tell which byte was written first
within a sample interval. It sees a snapshot of all changes, not a
sequence.

**Anonymous memory**: The auto-detection targets file-backed shared
mappings (MAP_SHARED with a file path). Anonymous private mappings (heap,
stack) are not automatically detected, though they can be monitored
with manual `-m`/`-M` address specification.

## Kernel Requirements

The tool requires:

- `/proc/PID/pagemap` readable (requires `CAP_SYS_PTRACE` or root)
- `/proc/PID/mem` readable (same)
- `/proc/PID/clear_refs` writable (same)
- `CONFIG_MEM_SOFT_DIRTY=y` in the kernel (enabled by default on most
  distributions since Linux 3.12)

The soft-dirty mechanism was added in Linux 3.12 (2013) for checkpoint/
restore (CRIU). mmap-heatmap repurposes it for live monitoring.
