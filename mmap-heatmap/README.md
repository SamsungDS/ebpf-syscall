# mmap-heatmap

Sub-page change detection for file-backed `mmap` regions.

`mmap-heatmap` watches a running process, identifies its largest
file-backed shared `mmap` region, and shows a live TUI heatmap of write
activity down to 8-byte granularity. It does this without modifying the
target process or the kernel — it only reads three proc interfaces:
`/proc/PID/pagemap`, `/proc/PID/mem`, and `/proc/PID/clear_refs`.

Sub-page resolution comes from combining soft-dirty tracking (which
fires at 4 KiB page granularity) with a content diff of each dirty page
against a shadow buffer.

## Directory Layout

    mmap-heatmap/
    ├── Cargo.toml            Rust crate manifest
    ├── Cargo.lock
    ├── src/                  Rust source
    │   ├── main.rs           Arg parsing, main loop, signal handling, TUI input
    │   ├── display.rs        Frame rendering (header, overview, zoom, footer)
    │   ├── heat.rs           HeatMap + FreqMap with lazy decay
    │   ├── diff.rs           Shadow buffer and per-word change detection
    │   ├── proc.rs           /proc/PID/pagemap, /mem, /clear_refs, /maps
    │   ├── stats.rs          Running min/max/avg over samples
    │   └── consts.rs         PAGE_SIZE, FINEST (8-byte), DEFAULT_WINDOW
    ├── docs/
    │   └── how-it-works.md   Technical deep dive (proc interfaces, sampling
    │                         loop, freq vs heat mode, kernel requirements)
    └── examples/
        ├── fio-sequential.fio  Linear 8-byte sweep over an 8 MiB mmap file
        └── fio-zipf.fio        Zipfian hot-spot distribution

## Requirements

- Linux kernel with `CONFIG_MEM_SOFT_DIRTY=y` (default on most distros
  since Linux 3.12).
- Root: `/proc/PID/pagemap`, `/proc/PID/mem`, and `/proc/PID/clear_refs`
  all require `CAP_SYS_PTRACE`.
- Rust toolchain (stable).
- A target process with at least one file-backed shared mapping
  (e.g. a `fio` job using `ioengine=mmap`).

## Build

    cd mmap-heatmap
    cargo build --release

The binary lands at `target/release/mmap-heatmap`. There is no install
step; invoke it directly or copy it somewhere on `$PATH`.

## Quick Start

Start a workload that writes through an mmap region:

    sudo fio examples/fio-sequential.fio &

Attach the heatmap to that process:

    sudo ./target/release/mmap-heatmap -p $(pgrep -x fio | tail -1)

The tool auto-detects the largest file-backed shared `mmap` region and
begins sampling. Press `q` (or Ctrl-C) to quit; the terminal is
restored to its prior state on exit.

## Command-Line Options

    -p, --pid PID        Target process ID (required).
    -m, --start ADDR     Region start, hex (0x...) or decimal. Optional;
                         if both -m and -M are given, auto-detection is
                         bypassed.
    -M, --end ADDR       Region end (exclusive). Must be page-aligned.
    -i, --interval SECS  Sampling interval in seconds (default: 1.0).
                         Accepts sub-second floats, e.g. 0.02 = 50 Hz.
    -n, --count N        Stop after N samples. 0 = unlimited (default).
    --decay N            In freq mode: decay multiplier (0 = never
                         fade, 1 = DAMON default, 2 = fade twice as
                         fast). In heat mode: raw points subtracted
                         per idle sample. Default: 1.
    --heat-inc N         Heat mode only: writes needed to advance one
                         digit level (default: 2). Internal cap is
                         9 * heat-inc.
    --window N           Freq mode only: sliding-window length in
                         samples (default: 20). A block written in all
                         N recent samples reaches digit 9.
    -h, --help           Print usage.

Input polling is decoupled from the sampling interval. At `-i 60` the
UI still refreshes at ~30 FPS and keystrokes respond within one UI
tick; `--interval` only controls how often `/proc/PID/pagemap` and the
shadow diff run.

## UI Manual

A live frame has three stacked sections plus a bottom status bar:

```
mmap-heatmap  PID 3464897  mmap-zipf.0.0  8.0 MiB  [freq] interval 2s
  addr: 0x7f7022289000 - 0x7f7022a89000  8.0 MiB  2048 pages  perms: -w-s
[10:20:47] sample       17:  dirty pages     596  changed     0 B
  pages  min     538  p50     572  p95     602  p99     602  max     602  avg     574
  bytes  min   3 KiB  p50   3 KiB  p95   3 KiB  p99   3 KiB  max   3 KiB  avg   3 KiB
  0123456789  freq: window 20 samples, decay 0x, 0=idle 9=every

=== Overview: 4 KiB  (1827/2048 hot) ===
+     0 KiB  2121330302132131304111112132031116122233610122171131326121213271...
+   672 KiB  2222131120126112132630103170222327111324270122520121241120323110...
 ...
+  8064 KiB  31622213152023123712112171131117

=== Zoom: 512 B  (588 hot)  +   38,912 B - +1,587,200 B  (1.5 MiB window) ===
+   38912 B  0010000010010000003001100011010001000000000301000000000100030000...
+  124928 B  0000001000000001000001600010000100000010110100002000101001010000...
 ...

  h/l: scroll  j/k: page  g/G: start/end  +/-: granularity (512 B)  f: mode  c: cursor  space: pause  q: quit
```

Each cell in the overview and zoom panes is a single digit `0`-`9`
that encodes activity intensity. `0` renders as blank, colors run
from dim gray through yellow/orange to bright red as the digit grows.

### Header

Six lines at the top.

1. Tool name, target PID, mapped file basename, region size, active
   mode in brackets (`[freq]` or `[heat]`), sampling interval.
2. Region virtual address range, size, page count, permissions from
   `/proc/PID/maps`.
3. Wall-clock timestamp, sample counter, dirty-page count and bytes
   changed for the current sample.
4. Running percentile/min/avg/max of dirty pages across all samples.
5. Same for bytes changed.
6. Digit legend and mode parameters (`window`/`decay` for freq,
   `heat-inc`/`decay` for heat).

Status tags appear on line 1 after the interval: `[PAUSED]` when
sampling is halted (space/`p`) and `[EXITED]` when the target has
disappeared from `/proc` (the last captured frame stays on screen).

### Overview pane

`=== Overview: 4 KiB  (hot/total) ===`

One column per 4 KiB page across the **entire region**. Rows are
labelled with the byte offset of the first page on that row. The
`hot` counter is the number of pages with nonzero effective
intensity at this sample. The overview is always full-region and
does not respond to scrolling.

### Zoom pane

`=== Zoom: GRAN  (hot)  +start - +end  (window) ===`

One column per `GRAN` bytes, scoped to the current viewport (`start`
to `end` byte offsets, `window` is the total bytes covered). `GRAN`
halves with `+`/`=` down to 8 bytes and doubles with `-` up to
4 KiB. Scrolling (`h`/`l`/`j`/`k`, `g`/`G`) moves only this pane.

### Status bar

Bottom row, two variants.

Scroll mode (default):

```
  h/l: scroll  j/k: page  g/G: start/end  +/-: granularity (GRAN)  f: mode  c: cursor  space: pause  q: quit
```

Cursor mode (after pressing `c`), an extra status line is inserted
above the help line:

```
  +   38,912 B  page    9  512B:   76 (4/8)  64B:   608 (32/64)  8B:   4864 (256/512)  val:0

  [CURSOR]  h/l/j/k: move  n/N: next/prev page  +/-: gran (GRAN)  g/G: start/end  c: exit  q: quit
```

The cursor line shows (left to right): cursor byte offset in the
region, containing 4 KiB page index, and the surrounding-block
counts at three granularities (`GRAN_at_cursor`, `64B`, `8B`) in the
form `block_index (hot_siblings/total_siblings)`. `val` is the digit
at the cursor. `n`/`N` jump to the next/previous 4 KiB page boundary.

All keys in either mode:

    q, Ctrl-C   Quit.
    f           Toggle freq ⇄ heat.
    space, p    Pause/resume sampling (display keeps refreshing).
    c           Toggle cursor mode.
    +, =        Zoom in (halve GRAN, min 8 B).
    -           Zoom out (double GRAN, max 4 KiB).
    h/l, ←/→    Scroll or move cursor by one cell.
    k/j, ↑/↓    Scroll by page / move cursor by row.
    g, Home     Jump to region start.
    G, End      Jump to region end.
    n, N        (cursor mode) next / previous 4 KiB page.

### Modes: freq vs heat

- **Freq (default)** — DAMON-style moving sum over the last `--window`
  samples. Answers "how hot is this block right now?". Saturates
  quickly to 9.
- **Heat** — cumulative counter; one digit = `--heat-inc` writes.
  Answers "which blocks have the most accumulated activity?".

Both maps are updated every sample, so `f` is an instant render flip.
Full algorithm details in [`docs/how-it-works.md`](docs/how-it-works.md).

SIGWINCH is handled: panes rescale on terminal resize, cursor and
viewport are clamped to the new visible area.

## Example Workflow

Run the sequential fio job:

    sudo fio examples/fio-sequential.fio &

Watch the write front at 10 Hz:

    sudo ./target/release/mmap-heatmap -p $(pgrep -x fio | tail -1) -i 0.1

Try:

- Press `f` to compare freq vs heat. On the sequential sweep, freq
  shows a moving band; heat shows a cumulative wake behind it.
- Press `+` a few times to go from 4 KiB down to 8 bytes and see
  individual modified words inside each page.
- Press `c` to enable the cursor; `l`/`h` to scan byte by byte.
- Try `--decay 0` to disable fading and observe cumulative coverage.

The Zipfian example (`examples/fio-zipf.fio`) produces a very different
picture: a small set of hot blocks at one end of the region and a
long tail of cold ones. Use heat mode to see the hot spots stand out.

## Further Reading

See [`docs/how-it-works.md`](docs/how-it-works.md) for the technical
deep dive:

- The three `/proc` interfaces and their bit layouts.
- The sampling loop and syscall budget per sample.
- Auto-detection heuristics and terminal sizing.
- Freq vs heat algorithm details (DAMON moving-sum math, heat-inc
  mapping).
- What this approach cannot do (sub-page triggers, every-write tracing,
  write ordering).
- Kernel requirements and the soft-dirty history.

## License

copyleft-next-0.3.1 (see `Cargo.toml`).
