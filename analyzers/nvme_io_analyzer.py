#!/usr/bin/env python3
"""
nvme_io_analyzer.py  ─  NVMe + Filesystem Layer I/O Analyzer
=============================================================
Metrics covered
  • Queue Depth (time-series + distribution)
  • LBA Hotspot Heatmap (time × LBA zone)
  • I/O Size Distribution (count + bytes, read vs write)
  • IOPS Timeline
  • Throughput Timeline (MB/s)
  • Latency — histogram, CDF, percentile bar, latency-vs-size scatter
  • Read / Write ratio
  • NVMe SMART health log

Modes
  blktrace   Parse blkparse text output  (deep offline analysis)
  live       Real-time /proc/diskstats + nvme-cli  (zero overhead)
  fio        Parse fio --output-format=json results
  demo       Synthetic data — no hardware needed (testing / CI)
"""

import os, sys, re, time, subprocess, argparse, json, math, textwrap
import collections, warnings, random
from pathlib import Path
from datetime import datetime

# Suppress ALL warnings before importing any packages — prevents the
# NumPy 1.x/2.x ABI mismatch warnings that flood output under sudo
# (system scipy compiled vs NumPy 1.x, pip env has NumPy 2.x).
warnings.filterwarnings('ignore')
os.environ.setdefault('PYTHONWARNINGS', 'ignore')

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from matplotlib.colors import LogNorm, LinearSegmentedColormap
from matplotlib.ticker import FuncFormatter, MaxNLocator, AutoMinorLocator
import matplotlib.patches as mpatches

try:
    # Catch ImportError (not installed) AND AttributeError/_ARRAY_API errors
    # when system scipy was compiled against NumPy 1.x but active env has
    # NumPy 2.x — common when running under sudo on Ubuntu with mixed envs.
    from scipy.ndimage import gaussian_filter
    HAS_SCIPY = True
except Exception:
    HAS_SCIPY = False
    def gaussian_filter(arr, sigma=1.0):   # no-op fallback
        return arr

# ─────────────────────────────────────────────────────────────────────────────
# Global constants
# ─────────────────────────────────────────────────────────────────────────────
SECTOR_BYTES  = 512
MiB           = 1024 * 1024
GiB           = 1024 ** 3
SCRIPT_VER    = "1.3.1"

# Maximum raw events passed to any scatter / per-point plot.
# Larger datasets are randomly downsampled to this count before plotting
# to stay well inside matplotlib Agg's ~2M primitive limit.
MAX_PLOT_EVENTS = 500_000

# Cap the qd_ts list — only every Nth sample is kept for large traces.
MAX_QD_SAMPLES  = 200_000

PALETTE = dict(
    read       = '#4fc3f7',
    write      = '#ff7043',
    mixed      = '#ab47bc',
    qd         = '#26c6da',
    latency    = '#ffca28',
    throughput = '#66bb6a',
    iops       = '#ef5350',
    other      = '#78909c',
    bg         = '#0d0d1a',
    panel      = '#111122',
    border     = '#3a3a5a',
    fg         = '#dce0f0',
    accent     = '#00e5ff',
    grid       = '#1e1e35',
    warn       = '#ffa726',
    good       = '#66bb6a',
    bad        = '#ef5350',
)

RC = {
    'figure.facecolor' : PALETTE['bg'],
    'axes.facecolor'   : PALETTE['panel'],
    'axes.edgecolor'   : PALETTE['border'],
    'axes.labelcolor'  : PALETTE['fg'],
    'axes.titlecolor'  : PALETTE['accent'],
    'text.color'       : PALETTE['fg'],
    'xtick.color'      : PALETTE['fg'],
    'ytick.color'      : PALETTE['fg'],
    'grid.color'       : PALETTE['grid'],
    'grid.alpha'       : 0.5,
    'grid.linestyle'   : '--',
    'legend.facecolor' : '#12122a',
    'legend.edgecolor' : PALETTE['border'],
    'font.family'      : 'monospace',
    'font.size'        : 9,
    'axes.titlesize'   : 11,
    'axes.labelsize'   : 9,
    'lines.linewidth'  : 1.2,
}

# blkparse line — tolerant regex
#   "  8,0    3   232    0.024952877  23185  Q   WS 3728512 + 8 [kworker]"
_BLK_RE = re.compile(
    r'^\s*\d+,\d+\s+'      # device
    r'\d+\s+'              # cpu
    r'\d+\s+'              # seq
    r'([\d.]+)\s+'         # timestamp  (g1)
    r'\d+\s+'              # pid
    r'([A-Z]+)\s+'         # action     (g2)
    r'([A-Z0-9]+)\s+'      # rwbs       (g3)
    r'(\d+)\s+\+\s+(\d+)' # lba + secs (g4, g5)
)

SIZE_BINS   = [512, 1024, 2*1024, 4*1024, 8*1024, 16*1024, 32*1024,
               64*1024, 128*1024, 256*1024, 512*1024, MiB, np.inf]
SIZE_LABELS = ['512B','1K','2K','4K','8K','16K','32K',
               '64K','128K','256K','512K','1M+']

# ─────────────────────────────────────────────────────────────────────────────
# Blktrace Parser
# ─────────────────────────────────────────────────────────────────────────────

class BlktraceParser:
    """
    Parse blkparse text output into a structured DataFrame.

    QD fix
    ------
    The original code matched Q→C events by LBA.  This breaks when the
    I/O scheduler merges two adjacent requests: the completion LBA is that
    of the *first* sector of the merged bio, which may not match any queued
    LBA exactly.  We now track inflight using the sequence number (field 3
    on each blkparse line) as the correlation key, falling back to LBA when
    the sequence number is unavailable.

    Large-trace handling
    --------------------
    For traces with > MAX_PLOT_EVENTS completions we reservoir-sample during
    parsing so the in-memory DataFrame stays ≤ MAX_PLOT_EVENTS rows.
    Histograms and timeline aggregations are computed from ALL events before
    sampling, so statistical accuracy is preserved.
    """

    def __init__(self, filepath: str, max_events: int = MAX_PLOT_EVENTS):
        self.filepath   = filepath
        self.max_events = max_events
        self.events: list   = []
        self.qd_ts: list    = []
        # Pre-computed histogram arrays (all events, not downsampled)
        self.size_hist_r  = np.zeros(32, dtype=np.uint64)
        self.size_hist_w  = np.zeros(32, dtype=np.uint64)
        self.lat_hist_r   = np.zeros(32, dtype=np.uint64)
        self.lat_hist_w   = np.zeros(32, dtype=np.uint64)
        self._n_total     = 0      # total completions before sampling
        self._sampled     = False
        self._parse()

    def _rw_flag(self, rwbs: str) -> str:
        if 'R' in rwbs: return 'R'
        if 'W' in rwbs: return 'W'
        return 'O'

    @staticmethod
    def _log2b(v: int) -> int:
        if v <= 0: return 0
        return min(v.bit_length() - 1, 31)

    def _parse(self):
        print(f"  Parsing : {self.filepath}")

        # ── Tracking dicts ──────────────────────────────────────────────────
        # Key: (seq, lba) tuple for robustness; seq alone is unique per CPU
        # but blkparse merges all CPUs, so (seq, lba) is safer.
        q_seq: dict  = {}   # seq  → (ts, rw, lba)   primary   key
        q_lba: dict  = {}   # lba  → (ts, rw)         fallback  key

        inflight    = 0
        line_count  = 0
        comp_count  = 0
        qd_stride   = 1        # record every Nth QD sample (grows for big traces)
        qd_counter  = 0

        # Reservoir sampler state
        reservoir   = []
        reservoir_k = self.max_events
        rng         = random.Random(42)

        def _add_event(ev: dict):
            nonlocal comp_count
            comp_count += 1
            # Reservoir sampling (Algorithm R)
            if comp_count <= reservoir_k:
                reservoir.append(ev)
            else:
                j = rng.randint(0, comp_count - 1)
                if j < reservoir_k:
                    reservoir[j] = ev

        # blkparse line regex already compiled as _BLK_RE
        # Extended to also capture the sequence number (group 0 before ts)
        _BLK_RE_SEQ = re.compile(
            r'^\s*\d+,\d+\s+'      # device
            r'\d+\s+'              # cpu
            r'(\d+)\s+'            # seq     (g1)
            r'([\d.]+)\s+'         # ts      (g2)
            r'\d+\s+'              # pid
            r'([A-Z]+)\s+'         # action  (g3)
            r'([A-Z0-9]+)\s+'      # rwbs    (g4)
            r'(\d+)\s+\+\s+(\d+)' # lba+sec (g5,g6)
        )

        with open(self.filepath, 'r', errors='replace', buffering=1 << 20) as fh:
            for raw in fh:
                m = _BLK_RE_SEQ.match(raw)
                if not m:
                    continue
                line_count += 1
                seq_s, ts_s, action, rwbs, lba_s, secs_s = m.groups()
                seq    = int(seq_s)
                ts     = float(ts_s)
                lba    = int(lba_s)
                secs   = int(secs_s)
                rw     = self._rw_flag(rwbs)
                size_b = secs * SECTOR_BYTES

                if action == 'Q':
                    q_seq[seq] = (ts, rw, lba)
                    q_lba[lba] = (ts, rw)
                    inflight   += 1
                    qd_counter += 1
                    if qd_counter % qd_stride == 0:
                        self.qd_ts.append((ts, inflight))
                        # Dynamically widen stride to cap qd_ts list size
                        if len(self.qd_ts) >= MAX_QD_SAMPLES:
                            # Halve the list, double the stride going forward
                            self.qd_ts = self.qd_ts[::2]
                            qd_stride *= 2

                elif action == 'C':
                    lat_ms = None
                    # Try sequence-number match first (most accurate)
                    entry = q_seq.pop(seq, None)
                    if entry:
                        q_ts, q_rw, q_lba_val = entry
                        q_lba.pop(q_lba_val, None)
                        lat_ms = (ts - q_ts) * 1000.0
                        rw     = q_rw
                    else:
                        # Fallback: LBA match (handles pre-5.x kernels without seq)
                        entry2 = q_lba.pop(lba, None)
                        if entry2:
                            q_ts, q_rw = entry2
                            lat_ms = (ts - q_ts) * 1000.0
                            rw     = q_rw

                    inflight = max(0, inflight - 1)
                    qd_counter += 1
                    if qd_counter % qd_stride == 0:
                        self.qd_ts.append((ts, inflight))

                    # Update pre-computed histograms (all events)
                    sb = self._log2b(size_b)
                    if rw == 'R':
                        self.size_hist_r[sb] += 1
                    else:
                        self.size_hist_w[sb] += 1
                    if lat_ms is not None and lat_ms > 0:
                        lat_ns = int(lat_ms * 1e6)
                        lb = self._log2b(lat_ns)
                        if rw == 'R':
                            self.lat_hist_r[lb] += 1
                        else:
                            self.lat_hist_w[lb] += 1

                    _add_event(dict(
                        ts=ts, action='C', rw=rw,
                        lba=lba, size_b=size_b, lat_ms=lat_ms
                    ))

                elif action == 'D':
                    _add_event(dict(
                        ts=ts, action='D', rw=rw,
                        lba=lba, size_b=size_b, lat_ms=None
                    ))

        self._n_total = comp_count
        self._sampled = comp_count > reservoir_k
        self.events   = reservoir

        sampled_note = (f"  Sampled : {len(self.events):,} / {comp_count:,} "
                        f"({len(self.events)/max(comp_count,1)*100:.1f}%) — "
                        f"reservoir sampling, histograms use full {comp_count:,} events"
                        if self._sampled else "")
        print(f"  Lines   : {line_count:,}  |  Completions: {comp_count:,}")
        if sampled_note:
            print(sampled_note)

    def to_dataframe(self) -> pd.DataFrame:
        if not self.events:
            raise ValueError(
                "No I/O events parsed.\n"
                "Did you run:  blkparse <trace_prefix> -o <output.txt> ?\n"
                "Or use --demo to generate synthetic data."
            )
        df = pd.DataFrame(self.events)
        df.attrs['sampled']    = self._sampled
        df.attrs['n_total']    = self._n_total
        df.attrs['n_sampled']  = len(self.events)
        return df


# ─────────────────────────────────────────────────────────────────────────────
# Live /proc/diskstats Collector
# ─────────────────────────────────────────────────────────────────────────────

class LiveCollector:
    """
    Poll /proc/diskstats + /sys/block/<dev>/inflight at <interval>-second
    cadence for <duration> seconds.
    """

    # Field indices in /proc/diskstats (0-based over the full split line)
    _F = dict(name=2,
              rd_ios=3, rd_merge=4, rd_sect=5, rd_ms=6,
              wr_ios=7, wr_merge=8, wr_sect=9, wr_ms=10,
              ios_inflt=11, io_ticks=12, time_in_q=13,
              dc_ios=14, dc_merge=15, dc_sect=16, dc_ms=17)

    def __init__(self, device: str, duration: int, interval: float = 0.5):
        self.device   = device          # e.g. "nvme0n1"
        self.duration = duration
        self.interval = interval
        self.samples: list = []

    # ── helpers ──────────────────────────────────────────────────────────────

    def _diskstats(self):
        """Return raw diskstats row for self.device.
        Index 0-1 are major/minor (int), index 2 is the name (str),
        indices 3+ are counters (int).  We keep that mixed type so callers
        use self._F to index correctly without crashing on the name field."""
        with open('/proc/diskstats') as f:
            for line in f:
                parts = line.split()
                if len(parts) < 14:
                    continue
                if parts[self._F['name']] == self.device:
                    # Keep index 2 as str (device name), cast everything else to int
                    row = []
                    for i, v in enumerate(parts):
                        row.append(int(v) if i != self._F['name'] else v)
                    return row
        return None

    def _inflight_path(self) -> Path:
        """Resolve the sysfs inflight path for both whole-disk and partition devices.

        Whole disk  : /sys/block/nvme4n1/inflight
        Partition   : /sys/block/nvme4n1/nvme4n1p1/inflight
                      (partition sits as a sub-directory of its parent block dev)
        """
        # Direct match (whole disk)
        direct = Path(f'/sys/block/{self.device}/inflight')
        if direct.exists():
            return direct
        # Partition: strip trailing digit(s) preceded by 'p', e.g. nvme4n1p1 -> nvme4n1
        # Also handles sdaX -> sda style
        import re as _re
        parent = _re.sub(r'p\d+$', '', self.device)   # nvme4n1p1 -> nvme4n1
        if parent == self.device:
            parent = _re.sub(r'\d+$', '', self.device) # sda1 -> sda
        part_path = Path(f'/sys/block/{parent}/{self.device}/inflight')
        if part_path.exists():
            return part_path
        return None

    def _inflight(self) -> int:
        p = self._inflight_path()
        if p is not None:
            nums = p.read_text().split()
            return int(nums[0]) + int(nums[1])
        # Fallback: use ios_inflight field from /proc/diskstats
        ds = self._diskstats()
        return int(ds[self._F['ios_inflt']]) if ds else 0

    def _util(self, io_ticks_delta: int, dt_ms: float) -> float:
        return min(100.0, io_ticks_delta / dt_ms * 100) if dt_ms > 0 else 0

    # ── main loop ─────────────────────────────────────────────────────────────

    def collect(self) -> pd.DataFrame:
        print(f"  Device  : /dev/{self.device}")
        print(f"  Duration: {self.duration}s  |  Interval: {self.interval}s")
        prev = self._diskstats()
        if prev is None:
            try:
                devs = [ln.split()[2] for ln in open('/proc/diskstats')
                        if len(ln.split()) >= 3]
            except Exception:
                devs = []
            raise RuntimeError(
                f"Device '{self.device}' not found in /proc/diskstats.\n"
                f"  Available devices : {', '.join(devs)}\n"
                f"  Tip: use the bare kernel name shown by  lsblk  or"
                f"  cat /proc/diskstats | awk '{{print $3}}'"
            )
        prev_ts     = time.monotonic()
        t_start     = prev_ts
        end_ts      = prev_ts + self.duration
        interrupted = False
        now         = prev_ts   # safe default so finally-block never NameErrors

        print(f"  Press Ctrl+C at any time to stop early and generate charts")
        try:
            while time.monotonic() < end_ts:
                time.sleep(self.interval)
                now  = time.monotonic()
                curr = self._diskstats()
                if curr is None:
                    print(f"  \u26a0  {self.device} disappeared from diskstats — skipping sample")
                    continue
                dt    = now - prev_ts
                dt_ms = dt * 1000

                F = self._F
                d_rdios  = curr[F['rd_ios']]   - prev[F['rd_ios']]
                d_rdsect = curr[F['rd_sect']]  - prev[F['rd_sect']]
                d_rdms   = curr[F['rd_ms']]    - prev[F['rd_ms']]
                d_wrios  = curr[F['wr_ios']]   - prev[F['wr_ios']]
                d_wrsect = curr[F['wr_sect']]  - prev[F['wr_sect']]
                d_wrms   = curr[F['wr_ms']]    - prev[F['wr_ms']]
                d_iotk   = curr[F['io_ticks']] - prev[F['io_ticks']]

                self.samples.append(dict(
                    ts        = now - t_start,
                    rd_iops   = d_rdios  / dt,
                    wr_iops   = d_wrios  / dt,
                    rd_bw_mbs = (d_rdsect * SECTOR_BYTES) / (dt * MiB),
                    wr_bw_mbs = (d_wrsect * SECTOR_BYTES) / (dt * MiB),
                    rd_lat_ms = (d_rdms / d_rdios) if d_rdios > 0 else 0,
                    wr_lat_ms = (d_wrms / d_wrios) if d_wrios > 0 else 0,
                    qd        = self._inflight(),
                    util_pct  = self._util(d_iotk, dt_ms),
                ))
                prev    = curr
                prev_ts = now

        except KeyboardInterrupt:
            interrupted = True
            elapsed = now - t_start
            print(f"\n  \u26a1 Ctrl+C — stopped after {elapsed:.1f}s "
                  f"({len(self.samples)} samples)  — generating charts from partial data ...")

        if not self.samples:
            raise RuntimeError("No samples collected — cannot generate charts.")

        actual_dur = self.samples[-1]['ts']
        suffix = (f" [PARTIAL — {actual_dur:.1f}s / {self.duration}s]"
                  if interrupted else "")
        print(f"  Samples : {len(self.samples):,}  |  Actual duration: {actual_dur:.1f}s{suffix}")

        df = pd.DataFrame(self.samples)
        # Carry interrupt metadata so plot titles can reflect partial collection
        df.attrs['interrupted']  = interrupted
        df.attrs['actual_dur_s'] = actual_dur
        df.attrs['requested_s']  = self.duration
        return df


# ─────────────────────────────────────────────────────────────────────────────
# NVMe-Layer I/O Size Collector  (eBPF / block_rq_issue tracepoint)
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# FtraceIOCollector  —  NVMe-layer I/O size distribution via ftrace
# ─────────────────────────────────────────────────────────────────────────────
#
# WHY FTRACE INSTEAD OF BCC/BPF:
#   block:block_rq_issue is a shared kernel tracepoint.  On kernels < 5.7,
#   only ONE BPF program can attach via perf_event_open at a time.  If any
#   other tool (bpftrace, perf record, a previous crashed run, or an eBPF
#   syscall monitor) already holds the fd, BPF attachment fails with
#   PERF_EVENT_IOC_SET_BPF: File exists — regardless of root privilege.
#
#   Ftrace reads the SAME tracepoint data through the tracefs ring buffer
#   (/sys/kernel/debug/tracing/trace_pipe), which is INDEPENDENT of the
#   perf_event subsystem.  Multiple readers/BPF programs can coexist with
#   ftrace because they use completely separate kernel mechanisms.
#
# WHAT IT CAPTURES (identical data to BPF approach):
#   block_rq_issue  → timestamp, sector, nr_sector→bytes, rwbs, device
#   block_rq_complete → timestamp, sector (→ latency via issue match)
#
# REQUIREMENTS:  root + tracefs mounted (standard on all modern kernels)
# OVERHEAD:      ~same as blktrace — kernel writes to ring buffer regardless

class FtraceIOCollector:
    """
    Collect I/O size distribution, LBA heatmap, and latency histograms
    using ftrace block tracepoints.

    Works on ALL kernel versions (4.x – 6.x).
    Never conflicts with existing BPF/perf programs.
    Requires only root + /sys/kernel/debug/tracing/.
    """

    TRACEFS   = Path('/sys/kernel/debug/tracing')
    N_LBA     = 4096
    SIZE_EDGES = [2**i for i in range(32)]
    LAT_LABELS = [
        f'{2**i}ns'  if 2**i < 1_000 else
        f'{2**i//1_000}µs' if 2**i < 1_000_000 else
        f'{2**i//1_000_000}ms'
        for i in range(32)
    ]
    ZONE_SECS = 1_048_576        # 512 MB in 512-byte sectors

    # ftrace line pattern for block_rq_issue and block_rq_complete
    # Example:
    #   kworker-1234 [003] d..2 12345.678: block_rq_issue: 259,5 WS 524288 () 3256320 + 1024 [fio]
    #   kworker-0    [003] d..2 12345.679: block_rq_complete: 259,5 WS () 3256320 + 1024 [0]
    _RE_ISSUE = re.compile(
        r'block_rq_issue:\s+'
        r'(\d+),(\d+)\s+'       # major, minor
        r'([A-Z]+)\s+'          # rwbs
        r'(\d+)\s+'             # bytes (may be 0 on old kernels)
        r'\([^)]*\)\s+'         # (comm)
        r'(\d+)\s+\+\s+(\d+)'  # sector + nr_sector
    )
    _RE_COMP = re.compile(
        r'block_rq_complete:\s+'
        r'(\d+),(\d+)\s+'
        r'([A-Z]+)\s+'
        r'(?:\d+\s+)?'          # bytes field (optional in some kernels)
        r'\([^)]*\)\s+'
        r'(\d+)\s+\+\s+(\d+)'  # sector + nr_sector
    )
    _RE_TS = re.compile(r'(\d+\.\d+):')

    def __init__(self, device: str, duration: int):
        self.device   = device
        self.duration = duration

        dev_path = Path(f'/dev/{device}')
        if not dev_path.exists():
            raise RuntimeError(f'/dev/{device} not found')
        st = dev_path.stat()
        self.major = os.major(st.st_rdev)
        self.minor = os.minor(st.st_rdev)   # 0xFFFF = partition wildcard handled by filter

        if not self.TRACEFS.exists():
            raise RuntimeError(
                'tracefs not mounted.  Try:\n'
                '  mount -t tracefs nodev /sys/kernel/debug/tracing'
            )
        print(f"  Device  : /dev/{device}  [{self.major}:{self.minor}]")
        print(f"  Method  : ftrace via {self.TRACEFS}")
        print(f"  Duration: {duration}s")

    # ── tracefs helpers ──────────────────────────────────────────────────────

    def _tf(self, *parts) -> Path:
        return self.TRACEFS.joinpath(*parts)

    def _write(self, *parts, value: str):
        p = self._tf(*parts)
        try:
            # Use open() rather than write_text() — tracefs files are special
            # char devices that reject empty-string writes (EINVAL) on some kernels.
            with open(str(p), 'w') as fh:
                fh.write(value if value else '\n')
        except OSError as e:
            raise RuntimeError(f"Cannot write {value!r} to {p}: {e}") from e

    def _save_restore(self) -> dict:
        """Read current tracing state so we can restore it on exit."""
        state = {}
        for key, path in [
            ('tracing_on',        ('tracing_on',)),
            ('issue_enable',      ('events','block','block_rq_issue','enable')),
            ('comp_enable',       ('events','block','block_rq_complete','enable')),
            ('issue_filter',      ('events','block','block_rq_issue','filter')),
            ('comp_filter',       ('events','block','block_rq_complete','filter')),
        ]:
            try:
                state[key] = self._tf(*path).read_text().strip()
            except Exception:
                state[key] = None
        return state

    def _restore(self, state: dict):
        """Restore tracefs to its original state."""
        mapping = {
            'tracing_on':   ('tracing_on',),
            'issue_enable': ('events','block','block_rq_issue','enable'),
            'comp_enable':  ('events','block','block_rq_complete','enable'),
            'issue_filter': ('events','block','block_rq_issue','filter'),
            'comp_filter':  ('events','block','block_rq_complete','filter'),
        }
        for key, path in mapping.items():
            val = state.get(key)
            if val is not None:
                try:
                    self._tf(*path).write_text(val + '\n')
                except Exception:
                    pass

    # ── histogram builders ───────────────────────────────────────────────────

    @staticmethod
    def _log2b(v: int) -> int:
        if v <= 0: return 0
        b = v.bit_length() - 1
        return min(b, 31)

    # ── main collection loop ─────────────────────────────────────────────────

    def collect(self) -> dict:
        import threading

        state = self._save_restore()

        # tracefs filter field for block tracepoints is 'dev' — a packed u32
        # where dev = (major << 20) | minor.  'major' and 'minor' are NOT
        # separate filter fields (writing them gives EINVAL).
        #
        # For a whole namespace device (nvme4n1) we filter by major only,
        # passing all minors — any partition I/O on that disk is captured
        # and then filtered precisely in Python by major number.
        #
        # We try to write the kernel-side filter but silently skip it on
        # EINVAL (older kernels may not support all filter operators) and
        # fall back to pure Python filtering, which is always correct.
        packed_dev = (self.major << 20) | self.minor
        is_partition = bool(re.search(r'p\d+$', self.device))
        if is_partition:
            dev_filter = f'dev == {packed_dev}'        # exact partition match
        else:
            # Match all partitions on this disk: dev >> 20 == major
            # tracefs doesn't support >> operator; use dev range instead:
            #   major<<20 <= dev < (major+1)<<20
            dev_lo = self.major << 20
            dev_hi = (self.major + 1) << 20
            dev_filter = f'dev >= {dev_lo} && dev < {dev_hi}'

        try:
            # Clear old trace buffer
            self._write('trace', value='\n')  # clear ring buffer
            # Try kernel-side filter (reduces ring buffer volume on busy systems)
            for tp in ('block_rq_issue', 'block_rq_complete'):
                try:
                    self._write('events','block', tp, 'filter', value=dev_filter)
                except RuntimeError as fe:
                    # EINVAL = field/operator not supported on this kernel; skip
                    print(f"  ℹ  Kernel filter unsupported for {tp} ({fe}) "
                          f"— using Python-side filtering")
            # Enable events
            self._write('events','block','block_rq_issue','enable',    value='1')
            self._write('events','block','block_rq_complete','enable',  value='1')
            self._write('tracing_on', value='1')
        except RuntimeError as e:
            self._restore(state)
            raise

        print(f"  ✓  ftrace block events enabled")
        print(f"     kernel filter : {dev_filter}")
        print(f"     python filter : major == {self.major}")
        print(f"  Press Ctrl+C to stop early and generate charts")

        # ── Accumulators ────────────────────────────────────────────────────
        size_hist_r  = np.zeros(32, dtype=np.uint64)
        size_hist_w  = np.zeros(32, dtype=np.uint64)
        lat_hist_r   = np.zeros(32, dtype=np.uint64)
        lat_hist_w   = np.zeros(32, dtype=np.uint64)
        lba_hist_r   = np.zeros(self.N_LBA, dtype=np.uint64)
        lba_hist_w   = np.zeros(self.N_LBA, dtype=np.uint64)
        inflight     = {}     # sector → (issue_ts, is_read)
        qd_timeline  = []
        t_start      = time.monotonic()
        interrupted  = False

        # ── Parse trace_pipe in a background thread ──────────────────────────
        stop_flag = threading.Event()
        parse_errors = [0]

        def _reader():
            pipe_path = self._tf('trace_pipe')
            try:
                with open(pipe_path, 'r', errors='replace') as pipe:
                    while not stop_flag.is_set():
                        line = pipe.readline()
                        if not line:
                            continue
                        ts_m = self._RE_TS.search(line)
                        ts   = float(ts_m.group(1)) if ts_m else 0.0

                        m = self._RE_ISSUE.search(line)
                        if m:
                            maj, minn, rwbs, bstr, sec, nrs = m.groups()
                            if int(maj) != self.major: continue
                            nr     = int(nrs)
                            bytes_ = int(bstr) if int(bstr) > 0 else nr * 512
                            sector = int(sec)
                            is_r   = rwbs[0] == 'R'
                            bkt    = self._log2b(bytes_)
                            zone   = min(sector // self.ZONE_SECS, self.N_LBA - 1)
                            if is_r:
                                size_hist_r[bkt] += 1
                                lba_hist_r[zone] += 1
                            else:
                                size_hist_w[bkt] += 1
                                lba_hist_w[zone] += 1
                            inflight[sector] = (ts, is_r)
                            continue

                        m = self._RE_COMP.search(line)
                        if m:
                            maj, minn, rwbs, sec, nrs = m.groups()
                            if int(maj) != self.major: continue
                            sector = int(sec)
                            is_r   = rwbs[0] == 'R'
                            entry  = inflight.pop(sector, None)
                            if entry and ts > 0 and entry[0] > 0:
                                lat_ns = int((ts - entry[0]) * 1e9)
                                if lat_ns > 0:
                                    lb = self._log2b(lat_ns)
                                    if entry[1]: lat_hist_r[lb] += 1
                                    else:        lat_hist_w[lb] += 1

            except Exception as e:
                if not stop_flag.is_set():
                    parse_errors[0] += 1

        reader_thread = threading.Thread(target=_reader, daemon=True)
        reader_thread.start()

        # ── Main timing loop (QD sampling + progress) ────────────────────────
        try:
            end = t_start + self.duration
            while time.monotonic() < end:
                time.sleep(0.5)
                qd = max(0, len(inflight))
                qd_timeline.append((round(time.monotonic() - t_start, 2), qd))
                elapsed = time.monotonic() - t_start
                if int(elapsed) % 10 < 1:
                    nr_r = int(size_hist_r.sum())
                    nr_w = int(size_hist_w.sum())
                    rem  = max(0, self.duration - elapsed)
                    print(f"  [{elapsed:6.0f}s]  R={nr_r:>10,}  W={nr_w:>10,}"
                          f"  QD={qd:>4}  remaining={rem:.0f}s   ",
                          end='\r', flush=True)
        except KeyboardInterrupt:
            interrupted = True
            elapsed = time.monotonic() - t_start
            print(f"\n  ⚡ Ctrl+C — stopped after {elapsed:.1f}s")

        stop_flag.set()
        actual_dur = time.monotonic() - t_start
        print()

        # ── Disable tracing and restore state ────────────────────────────────
        try:
            self._write('events','block','block_rq_issue','enable',   value='0')
            self._write('events','block','block_rq_complete','enable', value='0')
        except Exception:
            pass
        self._restore(state)
        reader_thread.join(timeout=2.0)

        nr_r = int(size_hist_r.sum())
        nr_w = int(size_hist_w.sum())
        print(f"  I/Os captured  : R={nr_r:,}  W={nr_w:,}")
        print(f"  Actual duration: {actual_dur:.1f}s")
        if parse_errors[0]:
            print(f"  ⚠  Parse errors: {parse_errors[0]}")

        return dict(
            size_hist_r = size_hist_r,
            size_hist_w = size_hist_w,
            lba_hist_r  = lba_hist_r,
            lba_hist_w  = lba_hist_w,
            lat_hist_r  = lat_hist_r,
            lat_hist_w  = lat_hist_w,
            events_df   = pd.DataFrame(),
            qd_timeline = qd_timeline,
            actual_dur  = actual_dur,
            interrupted = interrupted,
            device      = self.device,
        )

    # ── Synthetic demo data ───────────────────────────────────────────────────
    @staticmethod
    def synthetic(device: str = 'nvme4n1', duration: float = 30.0,
                  seed: int = 42) -> dict:
        """Realistic synthetic data for testing without hardware."""
        np.random.seed(seed)
        n = 80_000

        size_r = np.random.choice([4096, 8192, 16384, 65536],
                                   n//2, p=[0.55, 0.25, 0.12, 0.08])
        size_w = np.random.choice([4096, 65536, 131072, 262144],
                                   n//2, p=[0.30, 0.15, 0.20, 0.35])

        def _hist(sizes):
            h = np.zeros(32, dtype=np.uint64)
            for s in sizes:
                h[min(int(s).bit_length()-1, 31)] += 1
            return h

        lba_r = np.zeros(4096, dtype=np.uint64)
        lba_w = np.zeros(4096, dtype=np.uint64)
        for _ in range(n//2):
            z = int(np.random.choice([50,200,800,2000],p=[.4,.3,.2,.1])
                    + np.random.exponential(5))
            lba_r[min(z,4095)] += 1
        for _ in range(n//2):
            z = int(np.random.choice([50,200,800,2000],p=[.3,.4,.2,.1])
                    + np.random.exponential(8))
            lba_w[min(z,4095)] += 1

        lat_r = np.random.lognormal(np.log(50e3),  0.7, n//2).astype(np.uint64)
        lat_w = np.random.lognormal(np.log(100e3), 0.6, n//2).astype(np.uint64)

        def _lhist(lats):
            h = np.zeros(32, dtype=np.uint64)
            for v in lats:
                h[min(int(v).bit_length()-1, 31)] += 1
            return h

        ts  = np.sort(np.random.uniform(0, duration, n))
        rw  = np.where(np.random.random(n) < 0.4, 'R', 'W')
        sz  = np.where(rw=='R',
                       np.random.choice(size_r, n),
                       np.random.choice(size_w, n))
        lba = np.random.choice([50,200,800,2000],n,p=[.4,.3,.2,.1])*1_048_576 \
              + np.random.exponential(1_048_576//4, n).astype(int)
        events_df = pd.DataFrame(dict(ts_s=ts, sector=lba, bytes=sz, rw=rw))

        qd_tl = [(t, int(np.random.choice([16,32,64,128,256],
                  p=[.1,.2,.3,.25,.15])))
                  for t in np.linspace(0, duration, 200)]

        return dict(
            size_hist_r = _hist(size_r),
            size_hist_w = _hist(size_w),
            lba_hist_r  = lba_r,
            lba_hist_w  = lba_w,
            lat_hist_r  = _lhist(lat_r),
            lat_hist_w  = _lhist(lat_w),
            events_df   = events_df,
            qd_timeline = qd_tl,
            actual_dur  = duration,
            interrupted = False,
            device      = device,
        )




# ─────────────────────────────────────────────────────────────────────────────
# FIO JSON Parser
# ─────────────────────────────────────────────────────────────────────────────

class FioParser:
    """Parse fio --output-format=json result files."""

    def __init__(self, filepath: str):
        with open(filepath) as f:
            self.raw = json.load(f)
        self.jobs = self.raw.get('jobs', [])

    def summary(self) -> pd.DataFrame:
        rows = []
        for job in self.jobs:
            name = job.get('jobname', 'job')
            qd   = job.get('iodepth', 1)
            bs   = job.get('job options', {}).get('bs', '?')
            for rw in ('read', 'write'):
                d = job.get(rw, {})
                if not d or d.get('io_bytes', 0) == 0:
                    continue
                lat = d.get('lat_ns', {})
                pct = lat.get('percentile', {})
                rows.append(dict(
                    job         = name,
                    rw          = rw,
                    bs          = bs,
                    qd          = qd,
                    iops        = d.get('iops', 0),
                    bw_mbs      = d.get('bw', 0) / 1024,
                    lat_mean_ms = lat.get('mean', 0) * 1e-6,
                    lat_p50_ms  = pct.get('50.000000',  0) * 1e-6,
                    lat_p90_ms  = pct.get('90.000000',  0) * 1e-6,
                    lat_p99_ms  = pct.get('99.000000',  0) * 1e-6,
                    lat_p999_ms = pct.get('99.900000',  0) * 1e-6,
                    lat_min_ms  = lat.get('min', 0) * 1e-6,
                    lat_max_ms  = lat.get('max', 0) * 1e-6,
                    io_gib      = d.get('io_bytes', 0) / GiB,
                ))
        return pd.DataFrame(rows)

    def lat_percentiles(self) -> dict:
        out = {}
        for job in self.jobs:
            name = job.get('jobname', 'job')
            for rw in ('read', 'write'):
                d   = job.get(rw, {})
                pct = d.get('lat_ns', {}).get('percentile', {})
                if pct:
                    out[f"{name}/{rw}"] = {
                        float(k): v * 1e-6 for k, v in pct.items()
                    }
        return out


# ─────────────────────────────────────────────────────────────────────────────
# Synthetic Demo Generator
# ─────────────────────────────────────────────────────────────────────────────

class DemoGenerator:
    """
    Generate synthetic but physically plausible blktrace-style DataFrames
    for a PM9D3a-class NVMe: seq write dominant with random read bursts.
    """

    def __init__(self, duration: float = 30.0, seed: int = 42):
        np.random.seed(seed)
        self.duration = duration

    def generate_blktrace(self) -> tuple:
        """Return (DataFrame, qd_ts)."""
        n = 40_000
        ts_sorted = np.sort(np.random.uniform(0, self.duration, n))

        # LBA space: 2 TB drive  → ~3.9e9 sectors; simulate 200 GB active window
        lba_hot   = np.random.choice([0, 200e6, 800e6, 1600e6], size=n, p=[0.4,0.3,0.2,0.1])
        lba_noise = np.random.exponential(2e6, n)
        lba = (lba_hot + lba_noise).astype(int)

        # I/O sizes: bimodal 4K random + 256K sequential
        is_seq  = np.random.random(n) < 0.55
        size_b  = np.where(is_seq,
                            np.random.choice([128*1024, 256*1024], n),
                            np.random.choice([4*1024, 8*1024, 16*1024], n,
                                             p=[0.6, 0.3, 0.1]))

        # R/W ratio
        rw = np.where(np.random.random(n) < 0.35, 'R', 'W')

        # Latency: seq write ~0.1–0.3ms, rand read ~0.05–0.5ms, tail ~2ms
        base_lat = np.where(rw == 'R',
                            np.random.lognormal(-2.0, 0.8, n),   # reads faster at low QD
                            np.random.lognormal(-2.3, 0.6, n))   # writes
        # QD-amplified tail
        qd_factor = np.random.choice([1, 2, 4, 8, 16, 32, 64, 128, 256], n,
                                      p=[0.05,0.05,0.1,0.15,0.2,0.2,0.1,0.1,0.05])
        lat_ms = base_lat * (1 + qd_factor / 256 * 2)

        # Track queue depth from latency model
        inflight = 0
        qd_ts = []
        for i, ts in enumerate(ts_sorted):
            inflight += 1
            qd_ts.append((ts, inflight))
            inflight = max(0, inflight - np.random.poisson(1.2))
            qd_ts.append((ts, inflight))

        df = pd.DataFrame(dict(
            ts     = ts_sorted,
            action = 'C',
            rw     = rw,
            lba    = lba,
            size_b = size_b,
            lat_ms = lat_ms,
        ))
        return df, qd_ts

    def generate_live(self) -> pd.DataFrame:
        """Simulate live diskstats-style samples."""
        n   = int(self.duration / 0.5)
        ts  = np.linspace(0, self.duration, n)

        # Simulate write burst at t=10–20s, then read phase
        phase = (ts > 10) & (ts < 20)
        wr_iops   = np.where(phase, 85_000 + np.random.normal(0, 5000, n),
                             15_000 + np.random.normal(0, 2000, n)).clip(0)
        rd_iops   = np.where(~phase, 45_000 + np.random.normal(0, 3000, n),
                              5_000 + np.random.normal(0, 500,  n)).clip(0)
        wr_bw     = wr_iops * 256 * 1024 / MiB   # ~256K avg sequential
        rd_bw     = rd_iops *   4 * 1024 / MiB
        qd_base   = np.where(phase, 128, 32) + np.random.randint(-8, 8, n)
        wr_lat    = (1000 / wr_iops.clip(1)) * qd_base
        rd_lat    = (1000 / rd_iops.clip(1)) * qd_base * 0.8
        util      = np.clip(wr_bw / 6800 * 100 + rd_bw / 6800 * 100, 0, 100)

        return pd.DataFrame(dict(
            ts=ts, rd_iops=rd_iops, wr_iops=wr_iops,
            rd_bw_mbs=rd_bw, wr_bw_mbs=wr_bw,
            rd_lat_ms=rd_lat, wr_lat_ms=wr_lat,
            qd=qd_base.clip(0), util_pct=util,
        ))


# ─────────────────────────────────────────────────────────────────────────────
# Plotter
# ─────────────────────────────────────────────────────────────────────────────

class IOAnalyzerPlotter:

    def __init__(self, output_dir: str):
        self.out = Path(output_dir)
        self.out.mkdir(parents=True, exist_ok=True)
        plt.rcParams.update(RC)

    # ── utility ───────────────────────────────────────────────────────────────

    def _save(self, fig, name: str, large: bool = False):
        p = self.out / f"{name}.png"
        dpi = 100 if large else 150   # lower DPI for large-trace plots
        fig.savefig(p, dpi=dpi, bbox_inches='tight',
                    facecolor=PALETTE['bg'], edgecolor='none')
        plt.close(fig)
        print(f"    ✓  {p.name}")
        return p

    @staticmethod
    def _downsample(df: pd.DataFrame, n: int = MAX_PLOT_EVENTS,
                    seed: int = 42) -> tuple:
        """
        Return (df_plot, note_str).
        If df has > n rows, randomly sample n rows for plotting.
        Histograms / aggregations should be computed BEFORE calling this.
        """
        if len(df) <= n:
            return df, ''
        sampled = df.sample(n=n, random_state=seed)
        pct  = n / len(df) * 100
        note = (f"  ⚡ Large trace: plotting {n:,} / {len(df):,} events "
                f"({pct:.1f}%)  — histograms computed from full dataset")
        return sampled, note

    @staticmethod
    def _sample_tag(df: pd.DataFrame) -> str:
        """Subtitle suffix shown when a DataFrame was downsampled."""
        if df.attrs.get('sampled'):
            n  = df.attrs.get('n_sampled', len(df))
            nt = df.attrs.get('n_total',   len(df))
            return f'  [sampled {n:,}/{nt:,}]'
        return ''

    @staticmethod
    def _kib_fmt(x, _):
        for unit, div in [('GiB', GiB), ('MiB', MiB), ('KiB', 1024), ('B', 1)]:
            if x >= div:
                return f'{x/div:.0f}{unit}'
        return str(int(x))

    @staticmethod
    def _annotate_peak(ax, x, y, color='white'):
        idx = np.argmax(y)
        ax.annotate(f'{y[idx]:.0f}',
                    xy=(x[idx], y[idx]),
                    xytext=(4, 6), textcoords='offset points',
                    fontsize=7, color=color,
                    arrowprops=dict(arrowstyle='->', color=color, lw=0.6))

    # ── 1. Blktrace Dashboard ─────────────────────────────────────────────────

    def plot_blktrace_dashboard(self, df: pd.DataFrame, qd_ts: list,
                                 device: str = 'nvme0n1'):
        print("  → dashboard ...")
        df_c = df[df['action'] == 'C'].copy()
        if df_c.empty: return

        # Aggregation uses all sampled events; scatter uses downsampled subset
        df_scatter, ds_note = self._downsample(df_c)
        if ds_note:
            print(ds_note)
        large = len(df) > MAX_PLOT_EVENTS
        stag  = self._sample_tag(df)

        t0 = df_c['ts'].min()
        df_c['t'] = df_c['ts'] - t0
        bkt = 0.1                                           # 100 ms buckets
        df_c['bkt'] = (df_c['t'] / bkt).astype(int)

        agg = (df_c.groupby(['bkt', 'rw'])
                   .agg(count=('lba', 'count'), bytes=('size_b', 'sum'))
                   .reset_index())
        agg['iops']   = agg['count'] / bkt
        agg['bw_mbs'] = agg['bytes'] / bkt / MiB
        agg['t']      = agg['bkt'] * bkt

        fig = plt.figure(figsize=(20, 15))
        gs  = gridspec.GridSpec(3, 3, figure=fig, hspace=0.48, wspace=0.35)
        fig.suptitle(f'NVMe I/O Analysis  ·  {device}  ·  '
                     f'{datetime.now():%Y-%m-%d %H:%M}{stag}',
                     fontsize=14, color=PALETTE['accent'], fontweight='bold',
                     y=0.98)

        def _fill_rw(ax, key, ylab, title):
            for rw, col, lab in [('R', PALETTE['read'],  'Read'),
                                  ('W', PALETTE['write'], 'Write')]:
                d = agg[agg['rw'] == rw]
                if d.empty: continue
                ax.fill_between(d['t'], d[key], alpha=0.35, color=col)
                ax.plot(d['t'], d[key], color=col, lw=1.2, label=lab)
                self._annotate_peak(ax, d['t'].values, d[key].values, col)
            ax.set_title(title); ax.set_ylabel(ylab)
            ax.set_xlabel('Time (s)'); ax.legend(fontsize=8); ax.grid(True)

        ax_iops = fig.add_subplot(gs[0, :])
        _fill_rw(ax_iops, 'iops', 'IOPS', 'IOPS Timeline')

        ax_bw = fig.add_subplot(gs[1, 0])
        _fill_rw(ax_bw, 'bw_mbs', 'MB/s', 'Throughput (MB/s)')

        # Queue Depth
        ax_qd = fig.add_subplot(gs[1, 1])
        if qd_ts:
            qa  = np.array(qd_ts)
            t_q = qa[:, 0] - t0
            q_v = qa[:, 1]
            ax_qd.step(t_q, q_v, color=PALETTE['qd'], where='post', lw=1.0)
            ax_qd.fill_between(t_q, q_v, alpha=0.25, color=PALETTE['qd'], step='post')
            mean_qd = q_v.mean()
            ax_qd.axhline(mean_qd, color=PALETTE['latency'], ls='--', lw=0.9,
                          label=f'Mean={mean_qd:.1f}')
            ax_qd.legend(fontsize=8)
        ax_qd.set_title('Queue Depth Over Time'); ax_qd.set_ylabel('In-Flight I/Os')
        ax_qd.set_xlabel('Time (s)'); ax_qd.grid(True)

        # Latency scatter (downsampled)
        ax_lsc = fig.add_subplot(gs[1, 2])
        df_lat = df_scatter[df_scatter['lat_ms'].notna()]
        for rw, col, lab in [('R', PALETTE['read'],  'Read'),
                              ('W', PALETTE['write'], 'Write')]:
            d = df_lat[df_lat['rw'] == rw]
            if d.empty: continue
            ax_lsc.scatter(d['t'], d['lat_ms'], s=0.8, alpha=0.25,
                           color=col, label=lab, rasterized=True)
        ax_lsc.set_yscale('log')
        ax_lsc.set_title('Latency Scatter (ms)'); ax_lsc.set_ylabel('Latency (ms)')
        ax_lsc.set_xlabel('Time (s)'); ax_lsc.legend(fontsize=8, markerscale=5)
        ax_lsc.grid(True)

        # R/W count pie
        ax_pie = fig.add_subplot(gs[2, 0])
        rw_cnt = df_c['rw'].value_counts()
        slices, colors_, labels_ = [], [], []
        for key, lab, col in [('R','Read',PALETTE['read']),
                               ('W','Write',PALETTE['write']),
                               ('O','Other',PALETTE['other'])]:
            if key in rw_cnt and rw_cnt[key]:
                slices.append(rw_cnt[key]); colors_.append(col)
                labels_.append(f"{lab}\n{rw_cnt[key]:,}")
        if slices:
            weds, texts, autos = ax_pie.pie(
                slices, labels=labels_, colors=colors_,
                autopct='%1.1f%%', startangle=90,
                textprops={'color': PALETTE['fg'], 'fontsize': 8},
                wedgeprops={'edgecolor': PALETTE['bg'], 'linewidth': 2})
            for at in autos: at.set_color(PALETTE['bg'])
        ax_pie.set_title('Read / Write Ratio')

        # Throughput efficiency bar
        ax_sum = fig.add_subplot(gs[2, 1:])
        ax_sum.axis('off')
        t_dur    = df_c['t'].max() - df_c['t'].min()
        tot_read = df_c[df_c['rw']=='R']['size_b'].sum()
        tot_writ = df_c[df_c['rw']=='W']['size_b'].sum()
        peak_r   = agg[agg['rw']=='R']['iops'].max() if 'R' in agg['rw'].values else 0
        peak_w   = agg[agg['rw']=='W']['iops'].max() if 'W' in agg['rw'].values else 0
        p99_r    = df_c[df_c['rw']=='R']['lat_ms'].quantile(0.99) if not df_c[df_c['rw']=='R'].empty else 0
        p99_w    = df_c[df_c['rw']=='W']['lat_ms'].quantile(0.99) if not df_c[df_c['rw']=='W'].empty else 0

        table_data = [
            ['', 'Read', 'Write'],
            ['Total I/Os', f"{(df_c['rw']=='R').sum():,}", f"{(df_c['rw']=='W').sum():,}"],
            ['Data Volume', f"{tot_read/GiB:.2f} GiB", f"{tot_writ/GiB:.2f} GiB"],
            ['Peak IOPS', f"{peak_r:.0f}", f"{peak_w:.0f}"],
            ['P99 Latency', f"{p99_r:.2f} ms", f"{p99_w:.2f} ms"],
            ['Duration', f"{t_dur:.1f}s", '—'],
        ]
        tbl = ax_sum.table(cellText=table_data[1:], colLabels=table_data[0],
                            cellLoc='center', loc='center')
        tbl.auto_set_font_size(False); tbl.set_fontsize(10); tbl.scale(1.2, 2.0)
        for (r, c), cell in tbl.get_celld().items():
            cell.set_facecolor('#0d0d2a' if r > 0 else '#1a3a5a')
            cell.set_edgecolor(PALETTE['border'])
            cell.set_text_props(color=PALETTE['fg'])
        ax_sum.set_title('Trace Summary', color=PALETTE['accent'], pad=15)

        self._save(fig, '01_dashboard', large=large)

    # ── 2. Latency Analysis ────────────────────────────────────────────────────

    def plot_latency_analysis(self, df: pd.DataFrame):
        print("  → latency analysis ...")
        df_c = df[(df['action']=='C') & df['lat_ms'].notna()].copy()
        if df_c.empty: return

        df_plot, ds_note = self._downsample(df_c)
        if ds_note: print(ds_note)
        large = len(df_c) > MAX_PLOT_EVENTS
        stag  = self._sample_tag(df)

        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle(f'Latency Analysis{stag}', fontsize=14,
                     color=PALETTE['accent'], fontweight='bold')

        rw_pairs = [('R', 'Read', PALETTE['read']),
                    ('W', 'Write', PALETTE['write'])]

        # Histogram (downsampled for speed, shape preserved)
        ax = axes[0, 0]
        for rw, lab, col in rw_pairs:
            d = df_plot[df_plot['rw']==rw]['lat_ms'].values
            if not len(d): continue
            lo = max(d.min(), 1e-4); hi = d.max() * 1.01
            bins = np.logspace(np.log10(lo), np.log10(hi), 64)
            ax.hist(d, bins=bins, alpha=0.65, color=col, label=lab, edgecolor='none')
        ax.set_xscale('log')
        ax.set_title('Latency Histogram'); ax.set_xlabel('Latency (ms)')
        ax.set_ylabel('Count'); ax.legend(); ax.grid(True)

        # CDF
        ax = axes[0, 1]
        for rw, lab, col in rw_pairs:
            d = np.sort(df_c[df_c['rw']==rw]['lat_ms'].values)
            if not len(d): continue
            cdf = np.arange(1, len(d)+1) / len(d)
            ax.plot(d, cdf, color=col, lw=1.8, label=lab)
        ax.set_xscale('log')
        for p, c, ls in [(0.99, PALETTE['warn'], '--'),
                          (0.999, PALETTE['bad'],  ':')]:
            ax.axhline(p, color=c, ls=ls, lw=0.9, label=f'P{int(p*100)}')
        ax.set_title('Latency CDF'); ax.set_xlabel('Latency (ms)')
        ax.set_ylabel('CDF'); ax.legend(fontsize=8); ax.grid(True)

        # Percentile bar chart
        ax = axes[1, 0]
        pcts = [50, 75, 90, 95, 99, 99.9]
        x    = np.arange(len(pcts)); width = 0.38
        for i, (rw, lab, col) in enumerate(rw_pairs):
            d = df_c[df_c['rw']==rw]['lat_ms']
            if d.empty: continue
            vals = [np.percentile(d, p) for p in pcts]
            bars = ax.bar(x + i*width, vals, width, label=lab,
                          color=col, alpha=0.85, edgecolor=PALETTE['bg'])
            for bar, v in zip(bars, vals):
                ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()*1.03,
                        f'{v:.2f}', ha='center', va='bottom',
                        fontsize=6.5, color=PALETTE['fg'])
        ax.set_xticks(x + width/2)
        ax.set_xticklabels([f'P{p}' for p in pcts])
        ax.set_title('Latency Percentiles (ms)'); ax.set_ylabel('ms')
        ax.legend(); ax.grid(True, axis='y')

        # Latency vs I/O size (downsampled)
        ax = axes[1, 1]
        for rw, lab, col in rw_pairs:
            d = df_plot[df_plot['rw']==rw]
            if d.empty: continue
            ax.scatter(d['size_b']/1024, d['lat_ms'],
                       s=1.5, alpha=0.15, color=col, label=lab, rasterized=True)
        ax.set_xscale('log'); ax.set_yscale('log')
        ax.xaxis.set_major_formatter(FuncFormatter(self._kib_fmt))
        ax.set_title('Latency vs I/O Size')
        ax.set_xlabel('I/O Size'); ax.set_ylabel('Latency (ms)')
        ax.legend(fontsize=8, markerscale=6); ax.grid(True)

        fig.tight_layout()
        self._save(fig, '02_latency', large=large)

    # ── 3. I/O Size Distribution ───────────────────────────────────────────────

    def plot_io_size_distribution(self, df: pd.DataFrame):
        print("  → I/O size distribution ...")
        df_c = df[df['action']=='C'].copy()
        if df_c.empty: return

        df_c['bin'] = pd.cut(df_c['size_b'], bins=SIZE_BINS,
                              labels=SIZE_LABELS, right=False)
        t0 = df_c['ts'].min()
        df_c['t']   = df_c['ts'] - t0
        df_c['bkt'] = (df_c['t'] / 1.0).astype(int)   # 1s buckets

        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('I/O Size Distribution', fontsize=14,
                     color=PALETTE['accent'], fontweight='bold')

        rw_pairs = [('R', 'Read', PALETTE['read']),
                    ('W', 'Write', PALETTE['write'])]

        # Count
        ax = axes[0, 0]
        x = np.arange(len(SIZE_LABELS))
        for i, (rw, lab, col) in enumerate(rw_pairs):
            cnts = (df_c[df_c['rw']==rw]['bin']
                        .value_counts().reindex(SIZE_LABELS).fillna(0))
            ax.bar(x + i*0.4, cnts.values, 0.4, color=col,
                   alpha=0.85, label=lab, edgecolor=PALETTE['bg'])
        ax.set_xticks(x+0.2); ax.set_xticklabels(SIZE_LABELS, rotation=45, ha='right')
        ax.set_title('I/O Count by Size'); ax.set_ylabel('Count')
        ax.legend(); ax.grid(True, axis='y')

        # Bytes
        ax = axes[0, 1]
        for i, (rw, lab, col) in enumerate(rw_pairs):
            vol = (df_c[df_c['rw']==rw]
                       .groupby('bin')['size_b'].sum()
                       .reindex(SIZE_LABELS).fillna(0) / MiB)
            ax.bar(x + i*0.4, vol.values, 0.4, color=col,
                   alpha=0.85, label=lab, edgecolor=PALETTE['bg'])
        ax.set_xticks(x+0.2); ax.set_xticklabels(SIZE_LABELS, rotation=45, ha='right')
        ax.set_title('Data Volume by Size (MiB)'); ax.set_ylabel('MiB')
        ax.legend(); ax.grid(True, axis='y')

        # Average size over time
        ax = axes[1, 0]
        for rw, lab, col in rw_pairs:
            avg = df_c[df_c['rw']==rw].groupby('bkt')['size_b'].mean() / 1024
            ax.plot(avg.index, avg.values, color=col, lw=1.5, label=lab)
        ax.set_title('Avg I/O Size Over Time'); ax.set_xlabel('Time (s)')
        ax.set_ylabel('Avg Size (KiB)'); ax.legend(); ax.grid(True)

        # Grouped pie
        ax = axes[1, 1]
        groups = {'≤4 KiB': (0, 4*1024), '4–64 KiB': (4*1024, 64*1024),
                  '64–256 KiB': (64*1024, 256*1024), '≥256 KiB': (256*1024, np.inf)}
        counts = {g: int(((df_c['size_b'] >= lo) & (df_c['size_b'] < hi)).sum())
                  for g, (lo, hi) in groups.items()}
        cols_ = [PALETTE['read'], PALETTE['write'], PALETTE['qd'], PALETTE['latency']]
        nonzero = {k:v for k,v in counts.items() if v}
        if nonzero:
            ax.pie(list(nonzero.values()), labels=list(nonzero.keys()),
                   colors=cols_[:len(nonzero)], autopct='%1.1f%%', startangle=90,
                   textprops={'color': PALETTE['fg'], 'fontsize': 9},
                   wedgeprops={'edgecolor': PALETTE['bg'], 'linewidth': 2})
        ax.set_title('I/O Size Groups')

        fig.tight_layout()
        self._save(fig, '03_io_sizes')

    # ── 4. LBA Heatmap ─────────────────────────────────────────────────────────

    def plot_lba_heatmap(self, df: pd.DataFrame, n_lba: int = 128, n_t: int = 100):
        print("  → LBA heatmap ...")
        df_c = df[df['action']=='C'].copy()
        if df_c.empty: return
        # Downsample for heatmap binning — 500K points is more than enough
        # for LBA zone resolution; using all 41M would take minutes
        df_c, ds_note = self._downsample(df_c, n=MAX_PLOT_EVENTS)
        if ds_note: print(ds_note)
        stag = self._sample_tag(df)

        t0   = df_c['ts'].min()
        df_c['t'] = df_c['ts'] - t0
        lba_min  = df_c['lba'].min();  lba_max = df_c['lba'].max()
        t_max    = df_c['t'].max()

        df_c['lb'] = pd.cut(df_c['lba'], bins=n_lba, labels=False)
        df_c['tb'] = pd.cut(df_c['t'],   bins=n_t,   labels=False)

        cmap = LinearSegmentedColormap.from_list(
            'nvme_heat',
            ['#0d0d1a','#0d1b4a','#0055dd','#00c8ff',
             '#00ff88','#ffdd00','#ff4500','#ff0088'])

        fig, axes = plt.subplots(1, 2, figsize=(20, 8))
        fig.suptitle(f'LBA Hotspot Heatmap  (time × LBA zone){stag}',
                     fontsize=14, color=PALETTE['accent'], fontweight='bold')

        for ax, rw, title in [(axes[0], 'R', 'Read  Hotspots'),
                               (axes[1], 'W', 'Write Hotspots')]:
            d = df_c[df_c['rw']==rw].dropna(subset=['lb','tb'])
            if d.empty:
                ax.text(0.5, 0.5, f'No {rw} I/Os', transform=ax.transAxes,
                        ha='center', color=PALETTE['fg'], fontsize=14)
                continue

            heat = np.zeros((n_lba, n_t))
            for _, row in d[['lb','tb']].iterrows():
                lb, tb = int(row['lb']), int(row['tb'])
                if 0 <= lb < n_lba and 0 <= tb < n_t:
                    heat[lb, tb] += 1

            heat_s = gaussian_filter(heat + 0.05, sigma=1.5)
            im = ax.imshow(heat_s, aspect='auto', origin='lower', cmap=cmap,
                           norm=LogNorm(vmin=0.05, vmax=heat_s.max()),
                           interpolation='bilinear')
            cb = plt.colorbar(im, ax=ax, label='I/O Count (log)', fraction=0.03, pad=0.02)
            cb.ax.yaxis.set_tick_params(color=PALETTE['fg'])
            plt.setp(cb.ax.yaxis.get_ticklabels(), color=PALETTE['fg'])

            # Axis labels
            xt = np.linspace(0, n_t-1, 6, dtype=int)
            ax.set_xticks(xt)
            ax.set_xticklabels([f'{t_max * i/(n_t-1):.1f}s' for i in xt])
            yt = np.linspace(0, n_lba-1, 7, dtype=int)
            lba_range = lba_max - lba_min
            ax.set_yticks(yt)
            ax.set_yticklabels([f'{(lba_min + lba_range*i/(n_lba-1))/1e6:.1f}M'
                                 for i in yt])
            ax.set_title(title, color=PALETTE['accent'])
            ax.set_xlabel('Time'); ax.set_ylabel('LBA (sectors, millions)')

        fig.tight_layout()
        self._save(fig, '04_lba_heatmap')

    # ── 5. Queue Depth Deep-dive ───────────────────────────────────────────────

    def plot_queue_depth(self, df: pd.DataFrame, qd_ts: list):
        print("  → queue depth analysis ...")
        stag = self._sample_tag(df)
        # Cap qd_ts for plotting — already downsampled during parse but cap here too
        if len(qd_ts) > MAX_QD_SAMPLES:
            step   = len(qd_ts) // MAX_QD_SAMPLES
            qd_ts  = qd_ts[::step]

        fig, axes = plt.subplots(2, 2, figsize=(16, 10))
        fig.suptitle(f'Queue Depth Analysis{stag}', fontsize=14,
                     color=PALETTE['accent'], fontweight='bold')

        t0 = df['ts'].min() if not df.empty else 0

        # Timeline
        ax = axes[0, 0]
        if qd_ts:
            qa = np.array(qd_ts)
            t_q = qa[:,0] - t0; qd_v = qa[:,1]
            ax.step(t_q, qd_v, color=PALETTE['qd'], where='post', lw=1.0)
            ax.fill_between(t_q, qd_v, alpha=0.25, color=PALETTE['qd'], step='post')
            for p, c, lbl in [(50,'yellow','P50'),
                               (99,PALETTE['warn'],'P99'),
                               (99.9,PALETTE['bad'],'P99.9')]:
                v = np.percentile(qd_v, p)
                ax.axhline(v, color=c, ls='--', lw=0.8, label=f'{lbl}={v:.0f}')
            ax.legend(fontsize=8)
        ax.set_title('QD Timeline'); ax.set_xlabel('Time (s)')
        ax.set_ylabel('In-Flight'); ax.grid(True)

        # Histogram
        ax = axes[0, 1]
        if qd_ts:
            qa = np.array(qd_ts)
            qd_v = qa[:,1]
            max_qd = max(int(qd_v.max()), 1)
            bins = np.arange(0, max_qd + 2) - 0.5
            ax.hist(qd_v, bins=bins, color=PALETTE['qd'], alpha=0.85,
                    edgecolor=PALETTE['bg'])
            for p, c in [(50,'yellow'), (99,PALETTE['bad'])]:
                v = np.percentile(qd_v, p)
                ax.axvline(v, color=c, ls='--', lw=1.0, label=f'P{p}={v:.0f}')
            ax.legend(fontsize=8)
        ax.set_title('QD Distribution'); ax.set_xlabel('Queue Depth')
        ax.set_ylabel('Count'); ax.grid(True, axis='y')

        # QD vs Latency (if blktrace)
        ax = axes[1, 0]
        df_c = df[(df['action']=='C') & df['lat_ms'].notna()].copy()
        if not df_c.empty:
            for rw, col, lab in [('R', PALETTE['read'],  'Read'),
                                  ('W', PALETTE['write'], 'Write')]:
                d = df_c[df_c['rw']==rw]
                if d.empty: continue
                # Bin latency by time-order proxy (size_b as surrogate for complexity)
                ax.scatter(d['size_b']/1024, d['lat_ms'],
                           s=1.2, alpha=0.2, color=col, label=lab, rasterized=True)
            ax.set_xscale('log'); ax.set_yscale('log')
            ax.xaxis.set_major_formatter(FuncFormatter(self._kib_fmt))
            ax.set_ylabel('Latency (ms)'); ax.set_xlabel('I/O Size')
            ax.legend(fontsize=8, markerscale=5)
        ax.set_title('Latency by I/O Size'); ax.grid(True)

        # CDF of QD
        ax = axes[1, 1]
        if qd_ts:
            qa = np.array(qd_ts)
            qd_sorted = np.sort(qa[:,1])
            cdf = np.arange(1, len(qd_sorted)+1) / len(qd_sorted)
            ax.plot(qd_sorted, cdf, color=PALETTE['qd'], lw=2.0)
            ax.fill_between(qd_sorted, cdf, alpha=0.2, color=PALETTE['qd'])
            for p, c in [(50,'yellow'), (90,PALETTE['warn']),
                          (99,PALETTE['bad']), (99.9,'#ff00aa')]:
                v = np.percentile(qd_sorted, p)
                ax.axvline(v, color=c, ls='--', lw=0.8, label=f'P{p}={v:.0f}')
            ax.legend(fontsize=8)
        ax.set_title('Queue Depth CDF'); ax.set_xlabel('Queue Depth')
        ax.set_ylabel('CDF'); ax.grid(True)

        fig.tight_layout()
        self._save(fig, '05_queue_depth')

    # ── 6. Live Dashboard ──────────────────────────────────────────────────────

    @staticmethod
    def _partial_tag(df: pd.DataFrame) -> str:
        """Return a title suffix if this DataFrame came from a Ctrl+C interrupted run."""
        if df.attrs.get('interrupted', False):
            actual  = df.attrs.get('actual_dur_s', df['ts'].max())
            req     = df.attrs.get('requested_s', '?')
            return f'  ⚡ PARTIAL {actual:.0f}s/{req}s'
        return ''

    def plot_live_dashboard(self, df: pd.DataFrame, device: str):
        print("  → live dashboard ...")
        if df.empty: return

        fig, axes = plt.subplots(3, 2, figsize=(18, 15))
        fig.suptitle(f'Live I/O Analysis  ·  /dev/{device}  ·  '
                     f'{datetime.now():%Y-%m-%d %H:%M}'
                     f'{self._partial_tag(df)}',
                     fontsize=14, color=PALETTE['accent'], fontweight='bold')

        ts = df['ts'].values

        def _dual(ax, ya, yb, la, lb, ca, cb, title, ylab):
            ax.fill_between(ts, ya, alpha=0.3, color=ca)
            ax.fill_between(ts, yb, alpha=0.3, color=cb)
            ax.plot(ts, ya, color=ca, lw=1.2, label=la)
            ax.plot(ts, yb, color=cb, lw=1.2, label=lb)
            ax.set_title(title); ax.set_ylabel(ylab)
            ax.set_xlabel('Time (s)'); ax.legend(fontsize=8); ax.grid(True)

        _dual(axes[0,0], df['rd_iops'], df['wr_iops'],
              'Read','Write', PALETTE['read'], PALETTE['write'],
              'IOPS', 'IOPS')

        _dual(axes[0,1], df['rd_bw_mbs'], df['wr_bw_mbs'],
              'Read','Write', PALETTE['read'], PALETTE['write'],
              'Throughput (MB/s)', 'MB/s')

        # Queue depth
        ax = axes[1,0]
        ax.step(ts, df['qd'], color=PALETTE['qd'], where='post', lw=1.2)
        ax.fill_between(ts, df['qd'], alpha=0.25, color=PALETTE['qd'], step='post')
        mq = df['qd'].mean()
        ax.axhline(mq, color=PALETTE['latency'], ls='--', lw=0.9,
                   label=f'Mean={mq:.1f}')
        ax.set_title('Queue Depth'); ax.set_ylabel('QD')
        ax.set_xlabel('Time (s)'); ax.legend(fontsize=8); ax.grid(True)

        # Latency
        _dual(axes[1,1], df['rd_lat_ms'], df['wr_lat_ms'],
              'Read','Write', PALETTE['read'], PALETTE['write'],
              'Avg I/O Latency (ms)', 'ms')

        # Device utilization
        ax = axes[2,0]
        ax.fill_between(ts, df['util_pct'], alpha=0.4, color=PALETTE['throughput'])
        ax.plot(ts, df['util_pct'], color=PALETTE['throughput'], lw=1.2)
        ax.axhline(100, color=PALETTE['bad'], ls='--', lw=0.7)
        ax.set_ylim(0, max(110, df['util_pct'].max()*1.05))
        ax.set_title('Device Utilization (%)'); ax.set_ylabel('Utilization %')
        ax.set_xlabel('Time (s)'); ax.grid(True)

        # Summary table
        ax = axes[2,1]; ax.axis('off')
        rows = [
            ['Peak Read IOPS',    f"{df['rd_iops'].max():.0f}"],
            ['Peak Write IOPS',   f"{df['wr_iops'].max():.0f}"],
            ['Peak Read BW',      f"{df['rd_bw_mbs'].max():.1f} MB/s"],
            ['Peak Write BW',     f"{df['wr_bw_mbs'].max():.1f} MB/s"],
            ['Avg Read Lat',      f"{df['rd_lat_ms'].mean():.2f} ms"],
            ['Avg Write Lat',     f"{df['wr_lat_ms'].mean():.2f} ms"],
            ['Peak QD',           f"{df['qd'].max():.0f}"],
            ['Avg QD',            f"{df['qd'].mean():.1f}"],
            ['Peak Utilization',  f"{df['util_pct'].max():.1f}%"],
        ]
        tbl = ax.table(cellText=rows, colLabels=['Metric','Value'],
                       cellLoc='left', loc='center')
        tbl.auto_set_font_size(False); tbl.set_fontsize(10); tbl.scale(1.3, 2.0)
        for (r,c), cell in tbl.get_celld().items():
            cell.set_facecolor('#0d0d2a' if r > 0 else '#1a3a5a')
            cell.set_edgecolor(PALETTE['border'])
            cell.set_text_props(color=PALETTE['fg'])
        ax.set_title('Live Collection Summary', color=PALETTE['accent'])

        fig.tight_layout()
        self._save(fig, '01_live_dashboard')

    # ── 7. FIO Analysis ────────────────────────────────────────────────────────

    def plot_fio_analysis(self, parser: FioParser):
        print("  → FIO analysis ...")
        summary = parser.summary()
        if summary.empty: return

        fig, axes = plt.subplots(2, 3, figsize=(20, 12))
        fig.suptitle('FIO Benchmark Analysis', fontsize=14,
                     color=PALETTE['accent'], fontweight='bold')

        labels = [f"{r['job']}\n{r['rw']}" for _, r in summary.iterrows()]
        colors = [PALETTE['read'] if r == 'read' else PALETTE['write']
                  for r in summary['rw']]
        x = np.arange(len(summary))

        # IOPS
        ax = axes[0,0]
        bars = ax.bar(x, summary['iops'], color=colors, alpha=0.85, edgecolor=PALETTE['bg'])
        for b, v in zip(bars, summary['iops']):
            ax.text(b.get_x()+b.get_width()/2, b.get_height()*1.01,
                    f'{v:.0f}', ha='center', va='bottom', fontsize=7, color=PALETTE['fg'])
        ax.set_xticks(x); ax.set_xticklabels(labels, rotation=30, ha='right', fontsize=8)
        ax.set_title('IOPS'); ax.set_ylabel('IOPS'); ax.grid(True, axis='y')

        # Throughput
        ax = axes[0,1]
        bars = ax.bar(x, summary['bw_mbs'], color=colors, alpha=0.85, edgecolor=PALETTE['bg'])
        for b, v in zip(bars, summary['bw_mbs']):
            ax.text(b.get_x()+b.get_width()/2, b.get_height()*1.01,
                    f'{v:.1f}', ha='center', va='bottom', fontsize=7, color=PALETTE['fg'])
        ax.set_xticks(x); ax.set_xticklabels(labels, rotation=30, ha='right', fontsize=8)
        ax.set_title('Throughput (MB/s)'); ax.set_ylabel('MB/s'); ax.grid(True, axis='y')

        # Latency percentile bars
        ax = axes[0,2]
        pct_cols = ['lat_p50_ms','lat_p90_ms','lat_p99_ms','lat_p999_ms']
        pct_labs = ['P50','P90','P99','P99.9']
        w = 0.18; off = np.linspace(-w*1.5, w*1.5, len(summary))
        for i, (_, row) in enumerate(summary.iterrows()):
            vals = [row[c] for c in pct_cols]
            col  = PALETTE['read'] if row['rw']=='read' else PALETTE['write']
            ax.bar(np.arange(4)+off[i], vals, w,
                   color=col, alpha=0.75, edgecolor=PALETTE['bg'],
                   label=f"{row['job']}/{row['rw']}")
        ax.set_xticks(np.arange(4)); ax.set_xticklabels(pct_labs)
        ax.set_title('Latency Percentiles (ms)'); ax.set_ylabel('ms')
        ax.legend(fontsize=6, ncol=2); ax.grid(True, axis='y')

        # Latency CDF
        ax = axes[1,0]
        lat_pcts = parser.lat_percentiles()
        for key, pct_data in lat_pcts.items():
            if not pct_data: continue
            sv = sorted(pct_data.items())
            xv = [v for _,v in sv]; yv = [p/100 for p,_ in sv]
            col = PALETTE['read'] if 'read' in key else PALETTE['write']
            ax.plot(xv, yv, label=key, color=col, lw=1.5)
        ax.set_xscale('log')
        ax.axhline(0.99, color=PALETTE['warn'], ls='--', lw=0.7)
        ax.set_title('Latency CDF'); ax.set_xlabel('Latency (ms)')
        ax.set_ylabel('CDF'); ax.legend(fontsize=7); ax.grid(True)

        # QD vs IOPS scatter
        ax = axes[1,1]
        for _, row in summary.iterrows():
            col = PALETTE['read'] if row['rw']=='read' else PALETTE['write']
            ax.scatter(row['qd'], row['iops'], s=160, color=col, zorder=5,
                       marker='D' if row['rw']=='write' else 'o',
                       edgecolors='white', lw=0.7)
            ax.annotate(f"{row['job']}", (row['qd'], row['iops']),
                        textcoords='offset points', xytext=(5,5),
                        fontsize=7, color=PALETTE['fg'])
        ax.set_title('QD vs IOPS'); ax.set_xlabel('Queue Depth')
        ax.set_ylabel('IOPS'); ax.grid(True)
        ax.legend(handles=[
            mpatches.Patch(color=PALETTE['read'],  label='Read'),
            mpatches.Patch(color=PALETTE['write'], label='Write')
        ], fontsize=8)

        # Summary table
        ax = axes[1,2]; ax.axis('off')
        rows = [[f"{r['job']}/{r['rw']}", f"{r['iops']:.0f}",
                 f"{r['bw_mbs']:.1f}", f"{r['lat_mean_ms']:.2f}",
                 f"{r['lat_p99_ms']:.2f}", f"{r['io_gib']:.2f}"]
                for _, r in summary.iterrows()]
        tbl = ax.table(cellText=rows,
                       colLabels=['Job','IOPS','BW(MB/s)','AvgLat','P99','GiB'],
                       cellLoc='center', loc='center')
        tbl.auto_set_font_size(False); tbl.set_fontsize(8); tbl.scale(1.1, 1.8)
        for (r,c), cell in tbl.get_celld().items():
            cell.set_facecolor('#0d0d2a' if r > 0 else '#1a3a5a')
            cell.set_edgecolor(PALETTE['border'])
            cell.set_text_props(color=PALETTE['fg'])
        ax.set_title('FIO Summary', color=PALETTE['accent'])

        fig.tight_layout()
        self._save(fig, '01_fio_summary')

    # ── 8. NVMe SMART ──────────────────────────────────────────────────────────

    @staticmethod
    def _resolve_nvme_device(device: str) -> list:
        """
        Return candidate /dev paths to try for 'nvme smart-log', ordered by
        preference.  smart-log requires the namespace or controller node —
        it refuses partition nodes (nvme4n1p1) and sometimes even the
        namespace (nvme4n1) depending on firmware; the controller (nvme4)
        is the most reliable.

        Examples
          nvme4n1p1  →  [nvme4n1, nvme4, nvme4n1p1]
          nvme4n1    →  [nvme4n1, nvme4]
          nvme4      →  [nvme4]
        """
        candidates = []
        # Strip partition suffix  nvme4n1p1 → nvme4n1
        ns = re.sub(r'p\d+$', '', device)
        if ns != device:
            candidates.append(ns)          # namespace first
        else:
            candidates.append(device)
        # Strip namespace suffix  nvme4n1 → nvme4
        ctrl = re.sub(r'n\d+$', '', ns)
        if ctrl != ns:
            candidates.append(ctrl)        # controller node
        # Original device as last resort (in case it was already a ctrl node)
        if device not in candidates:
            candidates.append(device)
        return candidates

    @staticmethod
    def _nvme_exec(args: list, timeout: int = 15) -> tuple:
        """Run nvme-cli, return (stdout_text, stderr_text, returncode).
        Never raises — let callers decide what to do with empty output."""
        try:
            proc = subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
            )
            return (proc.stdout.decode('utf-8', errors='replace'),
                    proc.stderr.decode('utf-8', errors='replace'),
                    proc.returncode)
        except FileNotFoundError:
            return ('', 'nvme-cli not found (install nvme-cli)', 127)
        except subprocess.TimeoutExpired:
            return ('', f'nvme-cli timed out after {timeout}s', -1)
        except Exception as exc:
            return ('', str(exc), -1)

    @staticmethod
    def _extract_json(text: str) -> dict:
        """Extract first complete JSON object from text (handles preamble lines)."""
        brace = text.find('{')
        if brace == -1:
            return None
        # Walk to find matching closing brace
        depth = 0
        for i, ch in enumerate(text[brace:], brace):
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[brace:i+1])
                    except json.JSONDecodeError:
                        return None
        return None

    @staticmethod
    def _parse_smart_text(text: str) -> dict:
        """
        Parse plain-text 'nvme smart-log' output into a dict with the same
        keys as the JSON format.  Handles both old and new nvme-cli layouts.

        Example lines:
          critical_warning                    : 0
          temperature                         : 308 K
          avail_spare                         : 100%
          Data Units Read                     : 1,234,567
        """
        smart = {}
        # Map of regex pattern → (key, conversion_fn)
        patterns = [
            (r'critical_warning\s*:\s*(\w+)',              'critical_warning',     lambda v: int(v, 0)),
            (r'temperature\s*:\s*([\d.]+)',                'temperature',          float),
            (r'avail_spare\s*:\s*([\d.]+)',                'avail_spare',          float),
            (r'spare_thresh\s*:\s*([\d.]+)',               'spare_thresh',         float),
            (r'percent_used\s*:\s*([\d.]+)',               'percent_used',         float),
            (r'data_units_read\s*:\s*([\d,]+)',            'data_units_read',      lambda v: int(v.replace(',',''))),
            (r'data_units_written\s*:\s*([\d,]+)',         'data_units_written',   lambda v: int(v.replace(',',''))),
            (r'host_read_commands\s*:\s*([\d,]+)',         'host_reads',           lambda v: int(v.replace(',',''))),
            (r'host_write_commands\s*:\s*([\d,]+)',        'host_writes',          lambda v: int(v.replace(',',''))),
            (r'power_cycles\s*:\s*([\d,]+)',               'power_cycles',         lambda v: int(v.replace(',',''))),
            (r'power_on_hours\s*:\s*([\d,]+)',             'power_on_hours',       lambda v: int(v.replace(',',''))),
            (r'unsafe_shutdowns\s*:\s*([\d,]+)',           'unsafe_shutdowns',     lambda v: int(v.replace(',',''))),
            (r'media_errors\s*:\s*([\d,]+)',               'media_errors',         lambda v: int(v.replace(',',''))),
            (r'num_err_log_entries\s*:\s*([\d,]+)',        'num_err_log_entries',  lambda v: int(v.replace(',',''))),
            # Alternate human-readable field names (older nvme-cli)
            (r'Data Units Read\s*:\s*([\d,]+)',            'data_units_read',      lambda v: int(v.replace(',',''))),
            (r'Data Units Written\s*:\s*([\d,]+)',         'data_units_written',   lambda v: int(v.replace(',',''))),
            (r'Power On Hours\s*:\s*([\d,]+)',             'power_on_hours',       lambda v: int(v.replace(',',''))),
            (r'Power Cycles\s*:\s*([\d,]+)',               'power_cycles',         lambda v: int(v.replace(',',''))),
            (r'Available Spare\s*:\s*([\d.]+)',            'avail_spare',          float),
            (r'Available Spare Threshold\s*:\s*([\d.]+)', 'spare_thresh',         float),
            (r'Percentage Used\s*:\s*([\d.]+)',            'percent_used',         float),
        ]
        for pattern, key, conv in patterns:
            if key in smart:           # already filled by an earlier pattern
                continue
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                try:
                    smart[key] = conv(m.group(1))
                except (ValueError, TypeError):
                    pass

        # Temperature: if in Kelvin (>200), keep as-is; caller converts to °C
        return smart if smart else None

    @staticmethod
    def _run_smart(dev_path: str) -> dict:
        """
        Attempt every known nvme-cli invocation style, in order:
          1. nvme smart-log <dev> -o json            (nvme-cli ≥ 1.x standard)
          2. nvme smart-log <dev> --output-format=json  (some distro builds)
          3. nvme smart-log <dev>                    (plain text → regex parse)
          4. check combined stdout+stderr for JSON   (some builds write to stderr)

        Returns a dict with the same keys the JSON format would have.
        Raises RuntimeError with a detailed diagnostic on complete failure.
        """
        # Each entry: (label, args_list, use_stderr_fallback)
        strategies = [
            ('json flag -o',              [dev_path, '-o', 'json'],             False),
            ('json flag --output-format', [dev_path, '--output-format=json'],   False),
            ('plain text',                [dev_path],                            False),
            ('json via stderr',           [dev_path, '-o', 'json'],             True),
        ]
        diag = []
        for label, extra_args, use_stderr in strategies:
            cmd = ['nvme', 'smart-log'] + extra_args
            stdout, stderr, rc = IOAnalyzerPlotter._nvme_exec(cmd)
            body = (stdout + '\n' + stderr) if use_stderr else stdout

            if not body.strip():
                diag.append(f"  [{label}]  returncode={rc}  stdout empty"
                            + (f"  stderr={stderr[:120]!r}" if stderr.strip() else ''))
                continue

            # Try JSON extraction first
            parsed = IOAnalyzerPlotter._extract_json(body)
            if parsed:
                return parsed

            # Try text parsing (only for the plain-text strategy)
            if label == 'plain text':
                parsed = IOAnalyzerPlotter._parse_smart_text(body)
                if parsed:
                    return parsed
                diag.append(f"  [{label}]  returncode={rc}  "
                            f"output not parseable:\n    {body[:300]!r}")
            else:
                diag.append(f"  [{label}]  returncode={rc}  no JSON found in output:\n"
                            f"    stdout={stdout[:120]!r}"
                            + (f"\n    stderr={stderr[:120]!r}" if stderr.strip() else ''))

        raise RuntimeError(
            f"All nvme-cli strategies failed for {dev_path}:\n" + '\n'.join(diag)
        )

    def plot_nvme_smart(self, device: str):
        print("  → NVMe SMART ...")
        candidates = self._resolve_nvme_device(device)
        smart  = None
        used   = None
        errors = []
        for cand in candidates:
            dev_path = f'/dev/{cand}'
            if not Path(dev_path).exists():
                errors.append(f"{dev_path}: device node not found")
                continue
            try:
                smart = self._run_smart(dev_path)
                used  = cand
                break
            except Exception as e:
                errors.append(f"{dev_path}: {e}")

        if smart is None:
            print(f"    ⚠  SMART unavailable — tried {candidates}")
            for err in errors:
                print(f"       {err}")
            print("       Hints:")
            print("         • Run with sudo (SMART needs CAP_SYS_ADMIN)")
            print("         • Verify nvme-cli is installed:  nvme version")
            print("         • Check device exists:  ls -la /dev/nvme4*")
            print("         • Try manually:  sudo nvme smart-log /dev/nvme4 -o json")
            return

        if used != device:
            print(f"    ℹ  SMART queried on /dev/{used} (partition {device} → namespace/ctrl)")

        title_dev = f'/dev/{used}' + (f'  (partition /dev/{device})' if used != device else '')
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle(f'NVMe SMART  ·  {title_dev}',
                     fontsize=14, color=PALETTE['accent'], fontweight='bold')

        spare  = smart.get('avail_spare', 0)
        thresh = smart.get('spare_thresh', 0)
        pused  = smart.get('percent_used', 0)
        # temperature: nvme-cli ≥2.x uses Kelvin; older versions already Celsius
        temp_raw = smart.get('temperature', 273)
        temp_c   = (temp_raw - 273) if temp_raw > 200 else temp_raw

        def _units(val):
            """Accept int, float, or comma-formatted string from nvme-cli."""
            if isinstance(val, (int, float)):
                return int(val)
            return int(str(val).replace(',', '').strip() or '0')

        host_r_tib = _units(smart.get('data_units_read',    0)) * 512_000 / GiB
        host_w_tib = _units(smart.get('data_units_written', 0)) * 512_000 / GiB

        # Health bars
        ax = axes[0,0]
        bars = ax.barh(['Available\nSpare','Spare\nThreshold','Percent\nUsed'],
                       [spare, thresh, pused],
                       color=[PALETTE['good'], PALETTE['warn'], PALETTE['bad']],
                       alpha=0.85, edgecolor=PALETTE['bg'])
        for b, v in zip(bars, [spare, thresh, pused]):
            ax.text(v+1, b.get_y()+b.get_height()/2,
                    f'{v:.0f}%', va='center', color=PALETTE['fg'])
        ax.set_xlim(0, 110)
        ax.set_title('NAND Health (%)'); ax.grid(True, axis='x')

        # Lifetime I/O
        ax = axes[0,1]
        ax.bar(['Host Read','Host Written'], [host_r_tib, host_w_tib],
               color=[PALETTE['read'], PALETTE['write']],
               alpha=0.85, edgecolor=PALETTE['bg'])
        for i, v in enumerate([host_r_tib, host_w_tib]):
            ax.text(i, v*1.01, f'{v:.2f} TiB', ha='center', va='bottom',
                    fontsize=10, color=PALETTE['fg'])
        ax.set_title('Lifetime Host Data (TiB)'); ax.set_ylabel('TiB'); ax.grid(True, axis='y')

        # Temperature gauge
        ax = axes[1,0]
        ax.set_aspect('equal')
        theta = np.linspace(np.pi, 0, 300)
        ro, ri = 1.0, 0.58
        for (lo,hi), col in [((0,50),'#4caf50'),((50,70),'#ffca28'),((70,100),'#ef5350')]:
            t0 = np.pi*(1-lo/100); t1 = np.pi*(1-hi/100)
            th = np.linspace(t0, t1, 80)
            ax.fill_between(np.cos(th), np.sin(th)*ri, np.sin(th)*ro, color=col, alpha=0.75)
        # Background arc
        ax.fill_between(np.cos(theta), np.sin(theta)*ri, np.sin(theta)*ro,
                        color='#1a1a3a', alpha=0.5, zorder=0)
        # Needle
        na = np.pi * (1 - min(max(temp_c,0),100)/100)
        ax.annotate('', xy=(0.80*np.cos(na), 0.80*np.sin(na)),
                    xytext=(0.05*np.cos(na+np.pi), 0.05*np.sin(na+np.pi)),
                    arrowprops=dict(arrowstyle='->', color='white', lw=2.5))
        ax.text(0, -0.15, f'{temp_c:.0f}°C', ha='center', fontsize=15,
                color='white', fontweight='bold')
        ax.text(0, -0.32, 'Drive Temp', ha='center', fontsize=8, color=PALETTE['fg'])
        ax.set_xlim(-1.25,1.25); ax.set_ylim(-0.5,1.15); ax.axis('off')
        ax.set_title('Temperature', color=PALETTE['accent'])

        # Log table
        ax = axes[1,1]; ax.axis('off')
        rows = [
            ['Power-On Hours',  f"{smart.get('power_on_hours',0):,}"],
            ['Power Cycles',    f"{smart.get('power_cycles',0):,}"],
            ['Unsafe Shutdowns',f"{smart.get('unsafe_shutdowns',0):,}"],
            ['Media Errors',    f"{smart.get('media_errors',0):,}"],
            ['Error Log Entries',f"{smart.get('num_err_log_entries',0):,}"],
            ['Host Reads (TiB)',f"{host_r_tib:.2f}"],
            ['Host Writes (TiB)',f"{host_w_tib:.2f}"],
            ['% Used (NAND)',   f"{pused}%"],
        ]
        tbl = ax.table(cellText=rows, colLabels=['Attribute','Value'],
                       cellLoc='left', loc='center')
        tbl.auto_set_font_size(False); tbl.set_fontsize(10); tbl.scale(1.3, 1.9)
        for (r,c), cell in tbl.get_celld().items():
            cell.set_facecolor('#0d0d2a' if r > 0 else '#1a3a5a')
            cell.set_edgecolor(PALETTE['border'])
            cell.set_text_props(color=PALETTE['fg'])
        ax.set_title('SMART Log Values', color=PALETTE['accent'])

        fig.tight_layout()
        self._save(fig, '06_nvme_smart')

    # ── 9. Live QD Deep-dive ───────────────────────────────────────────────────

    def plot_live_qd_analysis(self, df: pd.DataFrame, device: str):
        print("  → queue depth analysis ...")
        if df.empty: return
        qd = df['qd'].values
        ts = df['ts'].values

        fig, axes = plt.subplots(2, 2, figsize=(16, 11))
        fig.suptitle(f'Queue Depth Analysis  ·  /dev/{device}'
                     f'{self._partial_tag(df)}',
                     fontsize=14, color=PALETTE['accent'], fontweight='bold')

        # ── Timeline with rolling mean ──
        ax = axes[0, 0]
        roll = pd.Series(qd).rolling(10, min_periods=1).mean().values
        ax.step(ts, qd,   color=PALETTE['qd'],     where='post', lw=0.8, alpha=0.4, label='Instant')
        ax.plot(ts, roll, color=PALETTE['accent'],  lw=1.8,                          label='10-sample MA')
        for p, c, lbl in [(50, 'yellow', 'P50'),
                           (99, PALETTE['warn'],  'P99'),
                           (99.9, PALETTE['bad'], 'P99.9')]:
            v = np.percentile(qd, p)
            ax.axhline(v, color=c, ls='--', lw=0.9, label=f'{lbl}={v:.0f}')
        ax.set_title('Queue Depth Timeline')
        ax.set_xlabel('Time (s)'); ax.set_ylabel('In-Flight I/Os')
        ax.legend(fontsize=8); ax.grid(True)

        # ── Histogram ──
        ax = axes[0, 1]
        max_qd = max(int(qd.max()), 1)
        bins   = np.arange(0, max_qd + 2) - 0.5
        n, edges, patches = ax.hist(qd, bins=bins, color=PALETTE['qd'],
                                     alpha=0.85, edgecolor=PALETTE['bg'])
        # Colour bars by percentile zone
        for patch, left in zip(patches, edges[:-1]):
            pct = np.mean(qd <= left + 0.5) * 100
            patch.set_facecolor(
                PALETTE['good'] if pct < 50 else
                PALETTE['warn'] if pct < 90 else
                PALETTE['bad']
            )
        for p, c in [(50, 'yellow'), (99, PALETTE['bad'])]:
            v = np.percentile(qd, p)
            ax.axvline(v, color=c, ls='--', lw=1.2, label=f'P{p}={v:.0f}')
        ax.set_title('QD Distribution'); ax.set_xlabel('Queue Depth')
        ax.set_ylabel('Sample Count'); ax.legend(fontsize=8); ax.grid(True, axis='y')

        # ── CDF ──
        ax = axes[1, 0]
        qd_sorted = np.sort(qd)
        cdf       = np.arange(1, len(qd_sorted) + 1) / len(qd_sorted)
        ax.plot(qd_sorted, cdf * 100, color=PALETTE['qd'], lw=2.0)
        ax.fill_between(qd_sorted, cdf * 100, alpha=0.2, color=PALETTE['qd'])
        for p, c in [(50, 'yellow'), (90, PALETTE['warn']),
                     (99, PALETTE['bad']), (99.9, '#ff00aa')]:
            v = np.percentile(qd, p)
            ax.axvline(v, color=c, ls='--', lw=0.9, label=f'P{p}={v:.0f}')
        ax.set_title('Queue Depth CDF')
        ax.set_xlabel('Queue Depth'); ax.set_ylabel('Percentile (%)')
        ax.legend(fontsize=8); ax.grid(True)

        # ── QD vs Latency scatter ──
        ax = axes[1, 1]
        for lat_col, col, lab in [('rd_lat_ms', PALETTE['read'],  'Read'),
                                   ('wr_lat_ms', PALETTE['write'], 'Write')]:
            lat = df[lat_col].values
            mask = lat > 0
            if mask.sum() == 0: continue
            ax.scatter(qd[mask], lat[mask], s=4, alpha=0.35,
                       color=col, label=lab, rasterized=True)
        ax.set_yscale('log')
        ax.set_title('Queue Depth vs Latency')
        ax.set_xlabel('Queue Depth'); ax.set_ylabel('Avg Latency (ms)')
        ax.legend(fontsize=8, markerscale=4); ax.grid(True)

        fig.tight_layout()
        self._save(fig, '02_qd_analysis')

    # ── 10. Live Latency Analysis ──────────────────────────────────────────────

    def plot_live_latency_analysis(self, df: pd.DataFrame, device: str):
        print("  → latency analysis ...")
        if df.empty: return

        fig, axes = plt.subplots(2, 2, figsize=(16, 11))
        fig.suptitle(f'Latency Analysis  ·  /dev/{device}'
                     f'{self._partial_tag(df)}',
                     fontsize=14, color=PALETTE['accent'], fontweight='bold')

        rw_pairs = [('rd_lat_ms', 'Read',  PALETTE['read']),
                    ('wr_lat_ms', 'Write', PALETTE['write'])]

        # ── Timeline ──
        ax = axes[0, 0]
        for col, lab, color in rw_pairs:
            vals = df[col].replace(0, np.nan).dropna()
            idx  = df[col].replace(0, np.nan).dropna().index
            ax.plot(df['ts'].iloc[idx], vals.values, color=color,
                    lw=1.2, alpha=0.8, label=lab)
            roll = vals.rolling(10, min_periods=1).mean()
            ax.plot(df['ts'].iloc[idx], roll.values, color=color,
                    lw=2.0, alpha=0.5, ls='--')
        ax.set_yscale('log')
        ax.set_title('Avg I/O Latency Over Time (log scale)')
        ax.set_xlabel('Time (s)'); ax.set_ylabel('Latency (ms)')
        ax.legend(fontsize=8); ax.grid(True)

        # ── Histogram ──
        ax = axes[0, 1]
        for col, lab, color in rw_pairs:
            vals = df[col][df[col] > 0].values
            if not len(vals): continue
            lo   = vals.min(); hi = vals.max() * 1.01
            bins = np.logspace(np.log10(max(lo, 1e-3)), np.log10(hi), 50)
            ax.hist(vals, bins=bins, alpha=0.55, color=color,
                    label=lab, edgecolor='none')
        ax.set_xscale('log')
        ax.set_title('Latency Distribution')
        ax.set_xlabel('Latency (ms)'); ax.set_ylabel('Sample Count')
        ax.legend(fontsize=8); ax.grid(True)

        # ── Percentile bar chart ──
        ax = axes[1, 0]
        pcts  = [50, 75, 90, 95, 99]
        x     = np.arange(len(pcts))
        width = 0.38
        for i, (col, lab, color) in enumerate(rw_pairs):
            vals = df[col][df[col] > 0].values
            if not len(vals): continue
            ys   = [np.percentile(vals, p) for p in pcts]
            bars = ax.bar(x + i * width, ys, width, label=lab,
                          color=color, alpha=0.85, edgecolor=PALETTE['bg'])
            for bar, v in zip(bars, ys):
                ax.text(bar.get_x() + bar.get_width() / 2,
                        bar.get_height() * 1.03,
                        f'{v:.2f}', ha='center', va='bottom',
                        fontsize=6.5, color=PALETTE['fg'])
        ax.set_xticks(x + width / 2)
        ax.set_xticklabels([f'P{p}' for p in pcts])
        ax.set_title('Latency Percentiles (ms)')
        ax.set_ylabel('ms'); ax.legend(fontsize=8); ax.grid(True, axis='y')

        # ── CDF ──
        ax = axes[1, 1]
        for col, lab, color in rw_pairs:
            vals = np.sort(df[col][df[col] > 0].values)
            if not len(vals): continue
            cdf  = np.arange(1, len(vals) + 1) / len(vals)
            ax.plot(vals, cdf * 100, color=color, lw=1.8, label=lab)
        ax.set_xscale('log')
        for p, c, ls in [(90, PALETTE['warn'], '--'),
                          (99, PALETTE['bad'],  ':')]:
            ax.axhline(p, color=c, ls=ls, lw=0.9, label=f'P{p}')
        ax.set_title('Latency CDF')
        ax.set_xlabel('Latency (ms)'); ax.set_ylabel('Percentile (%)')
        ax.legend(fontsize=8); ax.grid(True)

        fig.tight_layout()
        self._save(fig, '03_latency')

    # ── 11. Live Throughput Analysis ───────────────────────────────────────────

    def plot_live_throughput_analysis(self, df: pd.DataFrame, device: str):
        print("  → throughput analysis ...")
        if df.empty: return

        ts    = df['ts'].values
        rd_bw = df['rd_bw_mbs'].values
        wr_bw = df['wr_bw_mbs'].values
        tot   = rd_bw + wr_bw
        util  = df['util_pct'].values

        fig, axes = plt.subplots(2, 2, figsize=(16, 11))
        fig.suptitle(f'Throughput Analysis  ·  /dev/{device}'
                     f'{self._partial_tag(df)}',
                     fontsize=14, color=PALETTE['accent'], fontweight='bold')

        # ── Stacked area ──
        ax = axes[0, 0]
        ax.fill_between(ts, 0,    rd_bw,         alpha=0.5, color=PALETTE['read'],  label='Read')
        ax.fill_between(ts, rd_bw, rd_bw + wr_bw, alpha=0.5, color=PALETTE['write'], label='Write')
        ax.plot(ts, tot, color='white', lw=1.0, alpha=0.6, label='Total')
        peak = tot.max()
        ax.axhline(peak, color=PALETTE['latency'], ls='--', lw=0.9,
                   label=f'Peak={peak:.0f} MB/s')
        ax.set_title('Read + Write BW (Stacked)')
        ax.set_xlabel('Time (s)'); ax.set_ylabel('MB/s')
        ax.legend(fontsize=8); ax.grid(True)

        # ── Rolling statistics ──
        ax = axes[0, 1]
        win  = max(1, len(df) // 20)   # ~5% of samples
        roll_mean = pd.Series(tot).rolling(win, min_periods=1).mean().values
        roll_max  = pd.Series(tot).rolling(win, min_periods=1).max().values
        roll_min  = pd.Series(tot).rolling(win, min_periods=1).min().values
        ax.fill_between(ts, roll_min, roll_max, alpha=0.25, color=PALETTE['throughput'],
                        label=f'{win}-sample min/max')
        ax.plot(ts, roll_mean, color=PALETTE['throughput'], lw=1.8, label='Rolling mean')
        ax.set_title(f'Total BW Rolling Statistics (window={win})')
        ax.set_xlabel('Time (s)'); ax.set_ylabel('MB/s')
        ax.legend(fontsize=8); ax.grid(True)

        # ── BW distribution histograms ──
        ax = axes[1, 0]
        for vals, lab, col in [(rd_bw, 'Read',  PALETTE['read']),
                                (wr_bw, 'Write', PALETTE['write'])]:
            v = vals[vals > 0]
            if not len(v): continue
            ax.hist(v, bins=40, alpha=0.6, color=col, label=lab, edgecolor='none')
        ax.set_title('BW Distribution')
        ax.set_xlabel('MB/s'); ax.set_ylabel('Sample Count')
        ax.legend(fontsize=8); ax.grid(True, axis='y')

        # ── Utilization + efficiency ──
        ax = axes[1, 1]
        ax2 = ax.twinx()
        ax.fill_between(ts, util, alpha=0.35, color=PALETTE['throughput'])
        ax.plot(ts, util, color=PALETTE['throughput'], lw=1.2, label='Util %')
        ax.axhline(100, color=PALETTE['bad'], ls='--', lw=0.7)
        ax.set_ylim(0, max(110, util.max() * 1.05))
        ax.set_ylabel('Utilization %', color=PALETTE['throughput'])
        ax.set_xlabel('Time (s)')
        # R/W balance ratio on right axis
        ratio = np.where((rd_bw + wr_bw) > 0, rd_bw / (rd_bw + wr_bw) * 100, 50)
        ax2.plot(ts, ratio, color=PALETTE['latency'], lw=1.0, alpha=0.7,
                 label='Read% of total BW')
        ax2.axhline(50, color=PALETTE['other'], ls=':', lw=0.7)
        ax2.set_ylim(0, 100); ax2.set_ylabel('Read % of BW', color=PALETTE['latency'])
        lines1, labels1 = ax.get_legend_handles_labels()
        lines2, labels2 = ax2.get_legend_handles_labels()
        ax.legend(lines1 + lines2, labels1 + labels2, fontsize=8)
        ax.set_title('Utilization & R/W Balance'); ax.grid(True)

        fig.tight_layout()
        self._save(fig, '04_throughput')

    # ── 12. Live IOPS Analysis ─────────────────────────────────────────────────

    def plot_live_iops_analysis(self, df: pd.DataFrame, device: str):
        print("  → IOPS analysis ...")
        if df.empty: return

        ts      = df['ts'].values
        rd_iops = df['rd_iops'].values
        wr_iops = df['wr_iops'].values
        tot     = rd_iops + wr_iops
        qd      = df['qd'].values

        fig, axes = plt.subplots(2, 2, figsize=(16, 11))
        fig.suptitle(f'IOPS Analysis  ·  /dev/{device}'
                     f'{self._partial_tag(df)}',
                     fontsize=14, color=PALETTE['accent'], fontweight='bold')

        # ── Stacked IOPS area ──
        ax = axes[0, 0]
        ax.fill_between(ts, 0,      rd_iops,           alpha=0.5,
                        color=PALETTE['read'],  label='Read')
        ax.fill_between(ts, rd_iops, rd_iops + wr_iops, alpha=0.5,
                        color=PALETTE['write'], label='Write')
        ax.plot(ts, tot, color='white', lw=0.8, alpha=0.5, label='Total')
        self._annotate_peak(ax, ts, tot, 'white')
        ax.set_title('Read + Write IOPS (Stacked)')
        ax.set_xlabel('Time (s)'); ax.set_ylabel('IOPS')
        ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f'{v/1e3:.0f}K' if v >= 1000 else f'{v:.0f}'))
        ax.legend(fontsize=8); ax.grid(True)

        # ── IOPS distribution ──
        ax = axes[0, 1]
        for vals, lab, col in [(rd_iops, 'Read',  PALETTE['read']),
                                (wr_iops, 'Write', PALETTE['write'])]:
            v = vals[vals > 0]
            if not len(v): continue
            ax.hist(v, bins=40, alpha=0.6, color=col, label=lab, edgecolor='none')
        ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f'{v/1e3:.0f}K' if v >= 1000 else str(int(v))))
        ax.set_title('IOPS Distribution')
        ax.set_xlabel('IOPS'); ax.set_ylabel('Sample Count')
        ax.legend(fontsize=8); ax.grid(True, axis='y')

        # ── IOPS CDF ──
        ax = axes[1, 0]
        for vals, lab, col in [(rd_iops, 'Read',  PALETTE['read']),
                                (wr_iops, 'Write', PALETTE['write']),
                                (tot,     'Total', PALETTE['mixed'])]:
            v = np.sort(vals[vals > 0])
            if not len(v): continue
            cdf = np.arange(1, len(v) + 1) / len(v) * 100
            ax.plot(v, cdf, color=col, lw=1.8, label=lab)
        ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f'{v/1e3:.0f}K' if v >= 1000 else str(int(v))))
        for p, c in [(50, 'yellow'), (90, PALETTE['warn']), (99, PALETTE['bad'])]:
            ax.axhline(p, color=c, ls='--', lw=0.7, label=f'P{p}')
        ax.set_title('IOPS CDF')
        ax.set_xlabel('IOPS'); ax.set_ylabel('Percentile (%)')
        ax.legend(fontsize=8, ncol=2); ax.grid(True)

        # ── IOPS vs Queue Depth scatter ──
        ax = axes[1, 1]
        for vals, lab, col in [(rd_iops, 'Read',  PALETTE['read']),
                                (wr_iops, 'Write', PALETTE['write'])]:
            mask = vals > 0
            if mask.sum() == 0: continue
            ax.scatter(qd[mask], vals[mask], s=5, alpha=0.4,
                       color=col, label=lab, rasterized=True)
        ax.set_title('IOPS vs Queue Depth')
        ax.set_xlabel('Queue Depth'); ax.set_ylabel('IOPS')
        ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f'{v/1e3:.0f}K' if v >= 1000 else str(int(v))))
        ax.legend(fontsize=8, markerscale=4); ax.grid(True)

        fig.tight_layout()
        self._save(fig, '05_iops_analysis')

    # ── 13. NVMe eBPF Layer Analysis ───────────────────────────────────────────

    def plot_nvme_ebpf_analysis(self, data: dict):
        """
        Plot I/O size distribution, LBA heatmap, latency histogram, and
        queue-depth timeline from eBPF-collected NVMe-layer data.
        """
        print("  → NVMe eBPF layer analysis ...")
        device      = data['device']
        partial_tag = (f"  ⚡ PARTIAL {data['actual_dur']:.0f}s"
                       if data.get('interrupted') else "")

        SIZE_EDGES  = FtraceIOCollector.SIZE_EDGES
        LAT_LABELS  = FtraceIOCollector.LAT_LABELS

        def _size_label(b: int) -> str:
            v = SIZE_EDGES[b]
            if v < 1024:            return f'{v}B'
            if v < 1024*1024:       return f'{v//1024}K'
            return f'{v//(1024*1024)}M'

        # ── Page 1: Size distribution ─────────────────────────────────────────
        fig, axes = plt.subplots(2, 2, figsize=(18, 12))
        fig.suptitle(f'NVMe Driver Layer — I/O Size Distribution  ·  /dev/{device}{partial_tag}',
                     fontsize=13, color=PALETTE['accent'], fontweight='bold')

        sh_r = data['size_hist_r']
        sh_w = data['size_hist_w']
        # Trim trailing zeros
        last  = max(np.flatnonzero(sh_r) [-1] if sh_r.any() else 0,
                    np.flatnonzero(sh_w) [-1] if sh_w.any() else 0) + 2
        last  = min(last, 31)
        bins  = np.arange(last)
        xlabs = [_size_label(i) for i in bins]
        x     = np.arange(len(bins))
        w     = 0.4

        # Count histogram
        ax = axes[0, 0]
        ax.bar(x - w/2, sh_r[:last], w, color=PALETTE['read'],
               alpha=0.85, label='Read',  edgecolor=PALETTE['bg'])
        ax.bar(x + w/2, sh_w[:last], w, color=PALETTE['write'],
               alpha=0.85, label='Write', edgecolor=PALETTE['bg'])
        ax.set_xticks(x); ax.set_xticklabels(xlabs, rotation=45, ha='right')
        ax.set_title('I/O Count by Size  (NVMe driver layer)')
        ax.set_ylabel('I/O Count'); ax.legend(); ax.grid(True, axis='y')
        ax.set_yscale('symlog', linthresh=1)

        # Bytes moved histogram
        ax = axes[0, 1]
        bytes_r = sh_r[:last] * np.array([SIZE_EDGES[i] for i in range(last)]) / MiB
        bytes_w = sh_w[:last] * np.array([SIZE_EDGES[i] for i in range(last)]) / MiB
        ax.bar(x - w/2, bytes_r, w, color=PALETTE['read'],
               alpha=0.85, label='Read',  edgecolor=PALETTE['bg'])
        ax.bar(x + w/2, bytes_w, w, color=PALETTE['write'],
               alpha=0.85, label='Write', edgecolor=PALETTE['bg'])
        ax.set_xticks(x); ax.set_xticklabels(xlabs, rotation=45, ha='right')
        ax.set_title('Data Volume by Size (MiB)')
        ax.set_ylabel('MiB'); ax.legend(); ax.grid(True, axis='y')

        # Cumulative % of I/Os by size (read)
        ax = axes[1, 0]
        for hist, lab, col in [(sh_r, 'Read',  PALETTE['read']),
                                (sh_w, 'Write', PALETTE['write'])]:
            total = hist.sum()
            if total == 0: continue
            cdf = np.cumsum(hist[:last]) / total * 100
            ax.plot(x, cdf, color=col, lw=2.0, marker='o', ms=4, label=lab)
            ax.fill_between(x, cdf, alpha=0.15, color=col)
        ax.set_xticks(x); ax.set_xticklabels(xlabs, rotation=45, ha='right')
        ax.axhline(50,  color='yellow',          ls=':', lw=0.8, label='50%')
        ax.axhline(90,  color=PALETTE['warn'],   ls=':', lw=0.8, label='90%')
        ax.axhline(99,  color=PALETTE['bad'],    ls=':', lw=0.8, label='99%')
        ax.set_title('Cumulative % of I/Os by Size')
        ax.set_ylabel('Cumulative %'); ax.legend(fontsize=8); ax.grid(True)

        # Grouped pie: ≤4K / 4-64K / 64-256K / ≥256K
        ax = axes[1, 1]
        groups = [('≤4K',   0, 13),   # 0..4096 = 2^12 → bucket 12
                  ('4–64K', 13, 17),
                  ('64–256K', 17, 19),
                  ('≥256K', 19, last)]
        gcols  = [PALETTE['read'], PALETTE['write'], PALETTE['qd'], PALETTE['latency']]
        for rw_label, hist, offset in [('Read',  sh_r, 0.0),
                                        ('Write', sh_w, 0.2)]:
            wedge_sizes  = [hist[lo:hi].sum() for _, lo, hi in groups]
            wedge_labels = [g[0] for g in groups]
            if sum(wedge_sizes) == 0: continue
            wedges, texts, autos = ax.pie(
                wedge_sizes, labels=wedge_labels if offset == 0 else ['','','',''],
                colors=gcols, autopct='%1.0f%%' if offset == 0 else '',
                startangle=90, radius=1.0 - offset,
                textprops={'color': PALETTE['fg'], 'fontsize': 8},
                wedgeprops={'edgecolor': PALETTE['bg'], 'linewidth': 1.5,
                            'alpha': 0.9 - offset})
        ax.set_title(f'Size Group Mix  (outer=Read, inner=Write)')

        fig.tight_layout()
        self._save(fig, '07_nvme_ebpf_sizes')

        # ── Page 2: LBA + Latency + QD ───────────────────────────────────────
        fig2, axes2 = plt.subplots(2, 2, figsize=(18, 12))
        fig2.suptitle(f'NVMe Driver Layer — LBA Hotspots & Latency  ·  /dev/{device}{partial_tag}',
                      fontsize=13, color=PALETTE['accent'], fontweight='bold')

        cmap = matplotlib.colors.LinearSegmentedColormap.from_list(
            'nvme', ['#0d0d1a','#0d1b4a','#0055dd','#00c8ff',
                     '#00ff88','#ffdd00','#ff4500'])

        # LBA heatmap (top N zones)
        ax = axes2[0, 0]
        lba_r = data['lba_hist_r']
        lba_w = data['lba_hist_w']
        lba_tot = lba_r + lba_w
        n_zones = (lba_tot > 0).sum()
        top_n   = min(64, max(8, n_zones))
        top_idx = np.argsort(lba_tot)[-top_n:][::-1]
        zone_mb = [f'{i*512:.0f}MB' for i in top_idx]
        xz      = np.arange(top_n)
        ax.bar(xz - 0.2, lba_r[top_idx], 0.4, color=PALETTE['read'],
               alpha=0.85, label='Read',  edgecolor=PALETTE['bg'])
        ax.bar(xz + 0.2, lba_w[top_idx], 0.4, color=PALETTE['write'],
               alpha=0.85, label='Write', edgecolor=PALETTE['bg'])
        ax.set_xticks(xz[::max(1, top_n//8)])
        ax.set_xticklabels([zone_mb[i] for i in range(0, top_n, max(1, top_n//8))],
                            rotation=45, ha='right', fontsize=7)
        ax.set_title('Top LBA Zones (512MB buckets)  [NVMe driver layer]')
        ax.set_ylabel('I/O Count'); ax.legend(); ax.grid(True, axis='y')

        # LBA zone sparkline (full range)
        ax = axes2[0, 1]
        active = np.flatnonzero(lba_r + lba_w)
        if len(active):
            lo, hi = active[0], active[-1] + 1
            zone_range = np.arange(lo, hi)
            ax.fill_between(zone_range, lba_r[lo:hi],
                            color=PALETTE['read'],  alpha=0.5, label='Read')
            ax.fill_between(zone_range, -lba_w[lo:hi],
                            color=PALETTE['write'], alpha=0.5, label='Write')
            ax.axhline(0, color=PALETTE['border'], lw=0.7)
            xt = np.linspace(lo, hi-1, 6, dtype=int)
            ax.set_xticks(xt)
            ax.set_xticklabels([f'{i*512}MB' for i in xt], rotation=30, ha='right')
        ax.set_title('LBA Access Profile  (R up / W down)')
        ax.set_ylabel('I/O Count'); ax.legend(fontsize=8); ax.grid(True)

        # Latency histogram
        ax = axes2[1, 0]
        lh_r = data['lat_hist_r']
        lh_w = data['lat_hist_w']
        last_l = max(np.flatnonzero(lh_r)[-1] if lh_r.any() else 10,
                     np.flatnonzero(lh_w)[-1] if lh_w.any() else 10) + 2
        last_l = min(last_l, 31)
        lb     = np.arange(last_l)
        xlat   = [LAT_LABELS[i] for i in lb]
        xll    = np.arange(len(lb))
        ax.bar(xll - w/2, lh_r[:last_l], w, color=PALETTE['read'],
               alpha=0.85, label='Read',  edgecolor=PALETTE['bg'])
        ax.bar(xll + w/2, lh_w[:last_l], w, color=PALETTE['write'],
               alpha=0.85, label='Write', edgecolor=PALETTE['bg'])
        ax.set_xticks(xll); ax.set_xticklabels(xlat, rotation=45, ha='right', fontsize=7)
        ax.set_title('Latency Histogram  (log2 ns buckets)  [NVMe driver layer]')
        ax.set_ylabel('I/O Count'); ax.legend(); ax.grid(True, axis='y')
        ax.set_yscale('symlog', linthresh=1)

        # QD timeline
        ax = axes2[1, 1]
        if data['qd_timeline']:
            qt  = np.array(data['qd_timeline'])
            ts_ = qt[:, 0]; qd_ = qt[:, 1]
            ax.step(ts_, qd_, color=PALETTE['qd'], where='post', lw=1.0)
            ax.fill_between(ts_, qd_, alpha=0.25, color=PALETTE['qd'], step='post')
            for p, c in [(50,'yellow'), (99,PALETTE['bad'])]:
                v = np.percentile(qd_, p)
                ax.axhline(v, color=c, ls='--', lw=0.9, label=f'P{p}={v:.0f}')
            ax.legend(fontsize=8)
        ax.set_title('Queue Depth Timeline  [NVMe driver layer]')
        ax.set_xlabel('Time (s)'); ax.set_ylabel('In-Flight Commands')
        ax.grid(True)

        fig2.tight_layout()
        self._save(fig2, '08_nvme_ebpf_lba_lat')

        # ── Page 3: Per-event timeline (if events were captured) ─────────────
        ev = data.get('events_df')
        if ev is not None and not ev.empty:
            fig3, axes3 = plt.subplots(2, 1, figsize=(18, 10))
            fig3.suptitle(f'NVMe Driver Layer — Per-Event Timeline  ·  /dev/{device}{partial_tag}',
                          fontsize=13, color=PALETTE['accent'], fontweight='bold')

            for rw, col, lab in [('R', PALETTE['read'],  'Read'),
                                  ('W', PALETTE['write'], 'Write')]:
                d = ev[ev['rw'] == rw]
                if d.empty: continue
                axes3[0].scatter(d['ts_s'], d['bytes']/1024, s=0.8,
                                 alpha=0.2, color=col, label=lab, rasterized=True)
                axes3[1].scatter(d['ts_s'], d['sector']/1e6, s=0.8,
                                 alpha=0.2, color=col, label=lab, rasterized=True)

            axes3[0].set_yscale('log')
            axes3[0].set_title('I/O Size Over Time')
            axes3[0].set_ylabel('Size (KiB)'); axes3[0].set_xlabel('Time (s)')
            axes3[0].legend(fontsize=8, markerscale=8); axes3[0].grid(True)

            axes3[1].set_title('LBA Access Over Time  (per I/O)')
            axes3[1].set_ylabel('LBA (millions)'); axes3[1].set_xlabel('Time (s)')
            axes3[1].legend(fontsize=8, markerscale=8); axes3[1].grid(True)

            fig3.tight_layout()
            self._save(fig3, '09_nvme_ebpf_timeline')


# ─────────────────────────────────────────────────────────────────────────────
# Console summary helper
# ─────────────────────────────────────────────────────────────────────────────

def _print_blktrace_summary(df: pd.DataFrame, qd_ts: list):
    df_c  = df[(df['action']=='C') & df['lat_ms'].notna()].copy()
    t_dur = df['ts'].max() - df['ts'].min() if not df.empty else 0
    rw_c  = df[df['action']=='C']['rw'].value_counts()
    print()
    print("  ┌─────────────────────────────────────────────────────────┐")
    print("  │                   TRACE SUMMARY                         │")
    print("  ├──────────────────────────┬────────────────┬─────────────┤")
    print(f"  │ Duration                 │ {t_dur:>12.2f}s │             │")
    print(f"  │ Total Completions        │ {len(df[df['action']=='C']):>12,} │             │")
    print(f"  │ Read  I/Os               │ {rw_c.get('R',0):>12,} │             │")
    print(f"  │ Write I/Os               │ {rw_c.get('W',0):>12,} │             │")
    for rw, lab in [('R','Read'),('W','Write')]:
        d = df_c[df_c['rw']==rw]['lat_ms']
        if d.empty: continue
        p = lambda q: np.percentile(d, q)
        print(f"  │ {lab} Lat avg/P50/P99      │"
              f" {d.mean():>7.3f} / {p(50):>6.3f} / {p(99):>6.3f} ms │ (all ms)    │")
    if qd_ts:
        qa = np.array(qd_ts)[:,1]
        print(f"  │ QD avg / P99             │ {qa.mean():>12.1f} / {np.percentile(qa,99):.0f} │             │")
    print("  └──────────────────────────┴────────────────┴─────────────┘")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# main()
# ─────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        prog='nvme_io_analyzer.py',
        description='NVMe + Filesystem Layer I/O Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        ╔══════════════════════════════════════════════════════════════╗
        ║           nvme_io_analyzer.py  Quick Reference               ║
        ╠══════════════════════════════════════════════════════════════╣
        ║  blktrace  ──  offline analysis from blkparse output         ║
        ║  live      ──  real-time /proc/diskstats + nvme-cli          ║
        ║  fio       ──  parse fio --output-format=json files          ║
        ║  demo      ──  synthetic data, no device required            ║
        ╚══════════════════════════════════════════════════════════════╝

        BLKTRACE WORKFLOW
          sudo blktrace -d /dev/nvme0n1 -o trace -w 30
          blkparse trace -o trace.blkparse.txt
          python3 nvme_io_analyzer.py blktrace --input trace.blkparse.txt

        LIVE WORKFLOW
          python3 nvme_io_analyzer.py live --device nvme0n1 --duration 60

        FIO WORKFLOW
          fio --name=seq --rw=randrw --bs=4k --iodepth=32 \\
              --filename=/dev/nvme0n1 --runtime=60 \\
              --output-format=json --output=fio.json
          python3 nvme_io_analyzer.py fio --input fio.json

        DEMO (no hardware)
          python3 nvme_io_analyzer.py demo --device PM9D3a
        """)
    )
    sub = ap.add_subparsers(dest='mode', required=True)

    # ── blktrace ──
    p = sub.add_parser('blktrace', help='Parse blkparse text output')
    p.add_argument('--input',      required=True, help='blkparse decoded text file')
    p.add_argument('--device',     default='nvme0n1')
    p.add_argument('--output',     default='io_analysis')
    p.add_argument('--lba-bins',   type=int, default=128)
    p.add_argument('--time-bins',  type=int, default=100)
    p.add_argument('--smart',      action='store_true')
    p.add_argument('--max-events', type=int, default=MAX_PLOT_EVENTS,
                   help=f'Max events kept for plotting (default {MAX_PLOT_EVENTS:,}). '
                        'Larger traces are reservoir-sampled. Histograms always '
                        'use the full dataset.')

    # ── live ──
    p = sub.add_parser('live', help='Real-time collection')
    p.add_argument('--device',   required=True)
    p.add_argument('--duration', type=int,   default=60)
    p.add_argument('--interval', type=float, default=0.5)
    p.add_argument('--output',   default='io_analysis')
    p.add_argument('--smart',    action='store_true')

    # ── fio ──
    p = sub.add_parser('fio', help='Parse fio JSON output')
    p.add_argument('--input',  required=True)
    p.add_argument('--device', default='nvme0n1')
    p.add_argument('--output', default='io_analysis')
    p.add_argument('--smart',  action='store_true')

    # ── demo ──
    p = sub.add_parser('demo', help='Synthetic data (no hardware needed)')
    p.add_argument('--device',   default='PM9D3a_sim')
    p.add_argument('--duration', type=float, default=30.0)
    p.add_argument('--output',   default='io_analysis_demo')

    # ── nvme-ebpf ──
    p = sub.add_parser('nvme-ebpf',
                       help='eBPF probe on block_rq_issue — NVMe driver layer I/O size distribution')
    p.add_argument('--device',   required=True,
                   help='NVMe device, e.g. nvme4n1 or nvme4n1p1')
    p.add_argument('--duration', type=int,   default=60,
                   help='Collection duration in seconds (Ctrl+C stops early)')
    p.add_argument('--output',   default='io_analysis_nvme_ebpf')
    p.add_argument('--demo',     action='store_true',
                   help='Use synthetic data — no root required')

    args = ap.parse_args()

    print()
    print(f"  ╔══════════════════════════════════════════════════════╗")
    print(f"  ║  nvme_io_analyzer  v{SCRIPT_VER}                         ║")
    print(f"  ║  mode={args.mode:<8}  device={getattr(args,'device','—'):<16}        ║")
    print(f"  ║  {datetime.now():%Y-%m-%d %H:%M:%S}                                ║")
    print(f"  ╚══════════════════════════════════════════════════════╝")
    print()

    pl = IOAnalyzerPlotter(args.output)

    # ── blktrace ──────────────────────────────────────────────────────────────
    if args.mode == 'blktrace':
        bp = BlktraceParser(args.input, max_events=args.max_events)
        df = bp.to_dataframe()
        _print_blktrace_summary(df, bp.qd_ts)
        pl.plot_blktrace_dashboard(df, bp.qd_ts, args.device)
        pl.plot_latency_analysis(df)
        pl.plot_io_size_distribution(df)
        pl.plot_queue_depth(df, bp.qd_ts)
        if not HAS_SCIPY:
            print("  ⚠  scipy not found — LBA heatmap uses no smoothing (pip install scipy)")
        pl.plot_lba_heatmap(df, args.lba_bins, args.time_bins)
        if args.smart:
            pl.plot_nvme_smart(args.device)

    # ── live ──────────────────────────────────────────────────────────────────
    elif args.mode == 'live':
        lc = LiveCollector(args.device, args.duration, args.interval)
        try:
            df = lc.collect()
        except KeyboardInterrupt:
            # collect() itself handles this, but guard in case it propagates
            if not lc.samples:
                print("  No samples — exiting.")
                sys.exit(0)
            df = pd.DataFrame(lc.samples)
            df.attrs['interrupted']  = True
            df.attrs['actual_dur_s'] = lc.samples[-1]['ts']
            df.attrs['requested_s']  = args.duration

        interrupted = df.attrs.get('interrupted', False)
        if interrupted:
            actual = df.attrs.get('actual_dur_s', df['ts'].max())
            print(f"  Plotting {len(df):,} samples covering {actual:.1f}s ...")

        pl.plot_live_dashboard(df, args.device)
        pl.plot_live_qd_analysis(df, args.device)
        pl.plot_live_latency_analysis(df, args.device)
        pl.plot_live_throughput_analysis(df, args.device)
        pl.plot_live_iops_analysis(df, args.device)
        if args.smart:
            pl.plot_nvme_smart(args.device)

    # ── fio ───────────────────────────────────────────────────────────────────
    elif args.mode == 'fio':
        fp = FioParser(args.input)
        pl.plot_fio_analysis(fp)
        if args.smart:
            pl.plot_nvme_smart(args.device)

    # ── demo ──────────────────────────────────────────────────────────────────
    elif args.mode == 'demo':
        print("  Generating synthetic workload data ...")
        gen = DemoGenerator(duration=args.duration)
        df_bt, qd_ts = gen.generate_blktrace()
        df_live      = gen.generate_live()

        print("  [blktrace-style plots]")
        pl.plot_blktrace_dashboard(df_bt, qd_ts, args.device)
        pl.plot_latency_analysis(df_bt)
        pl.plot_io_size_distribution(df_bt)
        pl.plot_queue_depth(df_bt, qd_ts)
        pl.plot_lba_heatmap(df_bt, 128, 100)

        print("  [live-style plots]")
        pl.plot_live_dashboard(df_live, args.device)
        pl.plot_live_qd_analysis(df_live, args.device)
        pl.plot_live_latency_analysis(df_live, args.device)
        pl.plot_live_throughput_analysis(df_live, args.device)
        pl.plot_live_iops_analysis(df_live, args.device)

        print("  [NVMe ftrace layer plots — synthetic]")
        ebpf_data = FtraceIOCollector.synthetic(args.device, args.duration)
        pl.plot_nvme_ebpf_analysis(ebpf_data)

    # ── nvme-ebpf ─────────────────────────────────────────────────────────────
    elif args.mode == 'nvme-ebpf':
        if args.demo:
            print("  [nvme-ebpf demo] Generating synthetic NVMe ftrace data ...")
            data = FtraceIOCollector.synthetic(args.device, args.duration)
        else:
            print("  [nvme-ebpf] Collecting via ftrace block tracepoints ...")
            print("  Requires: root + tracefs (/sys/kernel/debug/tracing must be mounted)")
            collector = FtraceIOCollector(args.device, args.duration)
            data      = collector.collect()
        pl.plot_nvme_ebpf_analysis(data)

    # ── finish ────────────────────────────────────────────────────────────────
    print()
    plots = sorted(Path(args.output).glob('*.png'))
    print(f"  Output directory  : {args.output}/")
    print(f"  Plots generated   : {len(plots)}")
    for p in plots:
        print(f"    {p.name}")
    if not HAS_SCIPY:
        print("\n  TIP: pip install scipy  →  enables Gaussian-smoothed LBA heatmaps")
    print()


if __name__ == '__main__':
    main()
