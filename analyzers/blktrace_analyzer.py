#!/usr/bin/env python3
"""
blktrace Analyzer — Queue Depth, LBA Hotspots, I/O Sizes, Throughput, Latency
              + IU/LBS Atomics-Aware SSD Analysis
================================================================================
Parses blkparse text output and generates comprehensive storage performance charts
with optional SSD geometry-aware analysis for indirection unit alignment, write
amplification estimation, NPWG/NPDG alignment, and atomic write boundary crossing.

Usage:
    python3 blktrace_analyzer.py trace.txt
    python3 blktrace_analyzer.py trace.txt --lbs 512 --iu-size 4096 --npwg 16384 --awun 16384
    python3 blktrace_analyzer.py --show-nvme-commands

TECHNICAL METHODOLOGY
=====================

Input Format (blkparse text)
-----------------------------
Each line from blkparse has the format:

    major,minor  cpu  seq  timestamp  pid  action  rwbs  sector + nblocks  [process]

Example:
    259,0   3    1    0.000012345  1234  Q  WS  2097152 + 8  [fio]
           |    |    |             |     |  |   |         |   |
           |    |    |             |     |  |   |         |   +-- process name
           |    |    |             |     |  |   |         +------ nblocks (in LBS sectors)
           |    |    |             |     |  |   +---------------- starting LBA sector
           |    |    |             |     |  +-------------------- RWBS flags (R/W/D + S/F/N)
           |    |    |             |     +----------------------- action code (Q/G/I/D/C/M/F/P/U)
           |    |    |             +----------------------------- PID
           |    |    +------------------------------------------- wall-clock timestamp (seconds)
           |    +------------------------------------------------ per-CPU sequence number
           +----------------------------------------------------- device (major,minor)

The analyzer uses three action codes:
  Q (Queue)    — application request enters block layer; represents the ORIGINAL
                 I/O before merging/splitting. Used for I/O size distribution and
                 IU alignment analysis because it captures application intent.
  D (Dispatch) — block layer dispatches to device driver; may be a merged request
                 combining multiple Q events. Used for queue depth tracking because
                 it represents what is actually in-flight to the device.
  C (Complete) — completion interrupt processed. Used for throughput/IOPS
                 calculation (bytes transferred) and as the endpoint for latency.

I/O Lifecycle & Latency Calculation
------------------------------------
Each I/O request follows the path: Q → D → C (simplest case).
The analyzer tracks this lifecycle using (sector, nblocks) as the matching key:

  1. On Q event: create IORequest with queue_time = timestamp
  2. On D event: find pending request by (sector, nblocks), set issue_time
  3. On C event: find pending request, set complete_time, move to completed_ios

This produces three latency intervals per I/O:

  Q→C (total latency):  Time from application submission to completion interrupt.
                         Includes block layer queueing, scheduler, driver, device
                         processing, and interrupt delivery. This is the latency
                         the application experiences.
                         Formula: (complete_time - queue_time) × 1e6 → microseconds

  D→C (device latency): Time from driver dispatch to completion. Approximates the
                         actual SSD command processing time. This is the closest
                         blktrace gets to NVMe command latency, though it includes
                         small overheads from doorbell writes and interrupt handling.
                         Formula: (complete_time - issue_time) × 1e6 → microseconds

  Q→D (software stack):  Time spent in the block layer — scheduler queueing, I/O
                         merging, plug/unplug delays. High Q→D values indicate
                         scheduler bottlenecks or plug accumulation.
                         Formula: (issue_time - queue_time) × 1e6 → microseconds

Matching limitations:
  - Uses FIFO matching: when multiple Q events share the same (sector, nblocks),
    the earliest Q is matched to the next D, then the next C. This is correct
    for typical block layer behavior but can mismatch under heavy requeue.
  - Block layer merging can change (sector, nblocks) between Q and D. If Q says
    sector=100 nblocks=8 and sector=108 nblocks=8, the merged D may be
    sector=100 nblocks=16. The individual Q events then have no matching D/C.
    These appear as unmatched Q events and are excluded from latency stats.
  - The script handles missing stages gracefully: a D without prior Q still creates
    an IORequest (with queue_time=None), and q2c/q2d will return None.

Queue Depth Calculation
------------------------
Queue depth measures I/Os that are in-flight between the block layer and the device:

  D event → depth += 1   (I/O dispatched to driver)
  C event → depth -= 1   (I/O completed)

Separate read/write/total counters are maintained. The depth value is clamped to
≥0 to handle out-of-order events at trace boundaries.

This is BLOCK LAYER queue depth, not NVMe submission queue depth. Differences:
  - NVMe driver may batch multiple D events into a single SQ doorbell write
  - Multi-queue NVMe uses per-CPU SQ pairs; this aggregates across all CPUs
  - NVMe CQ interrupt coalescing can delay C events relative to actual completion

For bucketed averages, all instantaneous QD samples within each time_bucket
window are arithmetic-averaged.

Throughput & IOPS Calculation
------------------------------
Both metrics use C (Complete) events only, since that's when data transfer is
confirmed done:

  Throughput: For each time bucket, sum size_bytes of all C events, then:
              MB/s = total_bytes_in_bucket / bucket_duration / (1024²)
              Read and write throughput are computed separately.

  IOPS:       For each time bucket, count C events, then:
              IOPS = event_count / bucket_duration
              Read and write IOPS are computed separately.

Using C events (not D) means throughput reflects actual data delivered, not
dispatched. The timing is based on the C event timestamp, so throughput
is attributed to the moment of completion, not submission.

I/O Size Distribution
----------------------
Uses Q (Queue) events with nblocks > 0. This captures the APPLICATION'S original
request sizes before block layer merging modifies them.

  size_bytes = nblocks × SECTOR_SIZE (where SECTOR_SIZE = LBS, typically 512B)

Sizes are bucketed into power-of-2 bins from 512B to 16MB. Each I/O is placed
in the bin for the smallest power-of-2 that is ≥ the I/O size.

Why Q not D: Two adjacent 4K Q events may merge into one 8K D event. If we used
D, the histogram would show 8K when the application issued 4K. The Q-based
histogram reveals the true application I/O pattern, which is what determines
IU alignment behavior at the individual request level.

LBA Heatmap & Hotspot Analysis
-------------------------------
Heatmap: A 2D array [lba_bins × time_bins] counts I/O events per spatial-temporal
cell. Each Q or D event's sector is mapped to an LBA bin, and its timestamp to
a time bin:

  lba_index  = floor(sector / (max_sector+1) × lba_bins)
  time_index = floor((timestamp - t0) / duration × time_bins)

The heatmap uses log-normalized color scaling (LogNorm) so both sparse and
dense regions are visible.

Histogram: The LBA range (0 to max_sector) is divided into lba_bins equal-width
segments. np.histogram counts Q events per segment, separately for reads and
writes. This reveals spatial access patterns (sequential, random, clustered).

Top Hotspots: The N bins with highest combined (read+write) counts are ranked
and displayed with their LBA offset in GB.

Latency Distributions & Time Series
-------------------------------------
Distribution: All completed_ios are iterated. For each, q2c/d2c/q2d latencies
(in microseconds) are collected into per-type arrays. These produce:
  - Histograms: density-normalized, 100 bins, x-axis clipped at p99.5
  - CDFs: sorted array plotted against percentile (1/N, 2/N, ..., N/N)
  - Annotated vertical lines at p50 and p99

Time series: Each time bucket collects all D→C (or Q→C fallback) latencies for
completed I/Os whose issue_time falls in that bucket. Per-bucket p50 and p99
are computed via np.median and np.percentile(99).

IU/LBS ATOMICS ANALYSIS
=========================
All IU analysis operates on Q events (application-level) to assess alignment
before block layer merging. Each Q event produces an IUAnalysisResult.

Indirection Unit (IU) Analysis
-------------------------------
The IU is the FTL's minimum mapping granularity. Sector addresses and nblocks
are converted to IU indices:

  iu_sectors  = iu_size / lbs         (e.g., 4096/512 = 8 sectors per IU)
  start_iu    = sector // iu_sectors  (first IU this I/O touches)
  end_iu      = (sector + nblocks - 1) // iu_sectors  (last IU)

From these:
  iu_crossings     = end_iu - start_iu       (0 = entirely within one IU)
  iu_units_touched = end_iu - start_iu + 1   (actual IU-sized units spanned)
  iu_units_ideal   = ceil(nblocks / iu_sectors)  (IUs needed if perfectly aligned)
  iu_aligned       = (sector % iu_sectors == 0) AND (nblocks % iu_sectors == 0)

Sub-IU detection (writes only): if nblocks < iu_sectors, the write is smaller
than one IU. The SSD must read-modify-write (RMW) the full IU internally.
Example: 512B write on 4K IU → SSD reads 4K, modifies 512B, writes 4K back.

Alignment-induced Write Amplification Factor (WAF):

  WAF_alignment = iu_units_touched / iu_units_ideal

  Example: 4K write at sector offset 4 (512B LBS, IU=8 sectors):
    start_iu = 4 // 8 = 0
    end_iu   = (4 + 8 - 1) // 8 = 11 // 8 = 1
    iu_units_touched = 2, iu_units_ideal = 1
    WAF = 2.0 (this single write programs two IU-sized NAND regions)

  Perfectly aligned 4K write at sector 0:
    start_iu = 0, end_iu = 0
    WAF = 1.0 (no extra work)

  WAF over time: per time_bucket, sum iu_units_touched and iu_units_ideal for
  all writes, then divide. This shows alignment efficiency trends.

  NOTE: This captures alignment-induced WAF only. GC/wear-leveling WAF requires
  SMART log data (e.g., nvme smart-log, host_bytes_written vs nand_bytes_written).

IU Quantization Histogram
---------------------------
Buckets I/O sizes by IU multiples: <1 IU, 1 IU, 2 IU, ..., 16 IU, >16 IU.
Each bucket shows read and write counts. Exact IU multiples (size % iu_size == 0)
are placed in their exact bucket; fractional sizes go to the floor bucket.
This reveals whether the application/filesystem issues IU-aware I/O sizes.

NPWG Analysis
--------------
NPWG (Namespace Preferred Write Granularity) from NVMe 1.4+ id-ns. Three
alignment categories for writes:

  Fully aligned:      (nblocks % npwg_sectors == 0) AND (sector % npwg_sectors == 0)
  Size-only aligned:  (nblocks % npwg_sectors == 0) AND (sector % npwg_sectors != 0)
  Unaligned:          nblocks is not a multiple of npwg_sectors

NPWG units touched per write: same index arithmetic as IU analysis but using
npwg_sectors as the divisor.

AWUN Analysis (writes only)
-----------------------------
AWUN (Atomic Write Unit Normal) defines the boundary within which writes are
guaranteed atomic during power loss. If a write spans multiple AWUN boundaries,
it can be partially completed (torn) on power failure.

  awun_sectors  = awun / lbs
  start_awun    = sector // awun_sectors
  end_awun      = (sector + nblocks - 1) // awun_sectors
  awun_crossings = end_awun - start_awun
  awun_safe      = (awun_crossings == 0)

Alignment-Latency Correlation
-------------------------------
Joins IU alignment classification with D→C device latency from completed_ios.
The join key is (sector, nblocks). For each completed write with valid D→C
latency, the corresponding IUAnalysisResult is looked up and the latency is
placed in aligned, misaligned, or sub_iu buckets. This enables direct
comparison of latency distributions between well-aligned and poorly-aligned
writes on the same device under the same workload.
"""

import re, sys, os, json, argparse, warnings, math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from matplotlib.gridspec import GridSpec
from matplotlib.colors import LogNorm

warnings.filterwarnings("ignore", category=UserWarning)

SECTOR_SIZE = 512
KB, MB, GB = 1024, 1024**2, 1024**3
ACTION_QUEUE, ACTION_ISSUE, ACTION_COMPLETE = "Q", "D", "C"
RWBS_READ, RWBS_WRITE, RWBS_DISCARD = "R", "W", "D"

# ─── SSD Geometry ─────────────────────────────────────────────────────────────
@dataclass
class SSDGeometry:
    """NVMe/SSD geometry parameters for IU/LBS-aware analysis.

    All sizes in bytes. Set to 0 to disable a specific check.

    Fields:
        lbs:         Logical Block Size — host-visible sector size (512 or 4096).
                     This is what blkparse reports as nblocks units.
        iu_size:     Indirection Unit — FTL's minimum mapping granularity. Not
                     directly in NVMe spec; check vendor datasheet. Typically 4096.
        npwg:        Namespace Preferred Write Granularity (NVMe 1.4+ id-ns field).
                     Optimal write size to avoid internal padding/partial-page writes.
                     Raw NVMe value is 0-based: actual = (npwg + 1) × LBS.
        npwa:        Namespace Preferred Write Alignment. Optimal starting LBA
                     alignment for writes. Same 0-based encoding as NPWG.
        npdg:        Namespace Preferred Deallocate Granularity. Optimal TRIM/unmap
                     granularity to avoid partial-block deallocation overhead.
        awun:        Atomic Write Unit Normal — max write size guaranteed atomic
                     during normal operation. Writes within one AWUN boundary cannot
                     be torn. Raw value is 0-based: actual = (nawun + 1) × LBS.
        awupf:       Atomic Write Unit Power Fail — max write size guaranteed
                     atomic during power failure. Usually same as AWUN.
        nand_page:   NAND page size if known. For informational WAF context.
        device_name: Device path for chart labeling (e.g., /dev/nvme0n1).
    """
    lbs: int = 512
    iu_size: int = 0
    npwg: int = 0
    npwa: int = 0
    npdg: int = 0
    awun: int = 0
    awupf: int = 0
    nand_page: int = 0
    device_name: str = ""

    @property
    def has_iu(self): return self.iu_size > 0
    @property
    def has_npwg(self): return self.npwg > 0
    @property
    def has_awun(self): return self.awun > 0
    @property
    def iu_sectors(self): return self.iu_size // self.lbs if self.iu_size > 0 and self.lbs > 0 else 0
    @property
    def npwg_sectors(self): return self.npwg // self.lbs if self.npwg > 0 and self.lbs > 0 else 0
    @property
    def awun_sectors(self): return self.awun // self.lbs if self.awun > 0 and self.lbs > 0 else 0

    def summary(self):
        lines = ["SSD Geometry:"]
        lines.append(f"  LBS (Logical Block Size) : {self.lbs} B")
        if self.iu_size: lines.append(f"  IU  (Indirection Unit)   : {self.iu_size} B ({self.iu_size//KB}K) = {self.iu_sectors} LBS sectors")
        if self.npwg:    lines.append(f"  NPWG (Pref Write Gran)   : {self.npwg} B ({self.npwg//KB}K)")
        if self.npwa:    lines.append(f"  NPWA (Pref Write Align)  : {self.npwa} B ({self.npwa//KB}K)")
        if self.npdg:    lines.append(f"  NPDG (Pref Dealloc Gran) : {self.npdg} B ({self.npdg//KB}K)")
        if self.awun:    lines.append(f"  AWUN (Atomic Write Norm)  : {self.awun} B ({self.awun//KB}K)")
        if self.awupf:   lines.append(f"  AWUPF (Atomic Write PF)  : {self.awupf} B ({self.awupf//KB}K)")
        if self.nand_page: lines.append(f"  NAND page size           : {self.nand_page} B ({self.nand_page//KB}K)")
        if self.device_name: lines.append(f"  Device                   : {self.device_name}")
        return "\n".join(lines)

# ─── Data Structures ─────────────────────────────────────────────────────────
@dataclass
class TraceEvent:
    """Single parsed blkparse line.

    Fields directly mapped from the regex capture groups:
        major, minor: device identification (e.g., 259,0 for /dev/nvme0n1)
        cpu:          CPU core that processed this event
        seq:          per-CPU monotonic sequence number
        timestamp:    wall-clock time in seconds (from trace start or boot)
        pid:          process ID that issued the I/O
        action:       single-char action code (Q/D/C/G/I/M/F/P/U)
        rwbs:         read/write/discard/sync/fua flags string (e.g., "WS", "R")
        sector:       starting LBA in LBS-sized sectors (NOT 512B always — depends on --lbs)
        nblocks:      number of LBS sectors in this I/O
        process:      process name from [brackets] in blkparse output
        is_read:      True if 'R' in rwbs
        is_write:     True if 'W' in rwbs
        is_discard:   True if 'D' in rwbs AND action is not 'D' (dispatch)
        size_bytes:   nblocks × SECTOR_SIZE (computed, not from trace)
    """
    major: int; minor: int; cpu: int; seq: int; timestamp: float; pid: int
    action: str; rwbs: str; sector: int; nblocks: int; process: str
    is_read: bool; is_write: bool; is_discard: bool; size_bytes: int

@dataclass
class IORequest:
    """Tracks a single I/O through its Q → D → C lifecycle for latency measurement.

    Matching strategy: (sector, nblocks) tuple is used as the lookup key.
    When a Q event arrives, an IORequest is created and appended to the pending
    list for that key. On D, the FIRST pending request for that key gets its
    issue_time set (FIFO). On C, the FIRST pending request is popped, given
    complete_time, and moved to completed_ios.

    Latency properties (all in microseconds, None if timestamps missing):
        q2c_latency_us: total latency     = (C - Q) × 1e6
        d2c_latency_us: device latency    = (C - D) × 1e6
        q2d_latency_us: software overhead = (D - Q) × 1e6
    """
    sector: int; nblocks: int; is_read: bool
    queue_time: Optional[float] = None
    issue_time: Optional[float] = None
    complete_time: Optional[float] = None

    @property
    def q2c_latency_us(self):
        if self.queue_time is not None and self.complete_time is not None:
            return (self.complete_time - self.queue_time) * 1e6
    @property
    def d2c_latency_us(self):
        if self.issue_time is not None and self.complete_time is not None:
            return (self.complete_time - self.issue_time) * 1e6
    @property
    def q2d_latency_us(self):
        if self.queue_time is not None and self.issue_time is not None:
            return (self.issue_time - self.queue_time) * 1e6

@dataclass
class IUAnalysisResult:
    """Per-I/O alignment analysis against SSD geometry (computed from Q events).

    IU fields:
        sub_iu:          True if write size < IU size (triggers read-modify-write)
        iu_crossings:    number of IU boundaries the I/O straddles (0 = within one IU)
        iu_aligned:      True if start sector AND size are both IU-aligned
        iu_units_touched: total IU-sized regions this I/O spans
        iu_units_ideal:  IUs needed if the I/O were perfectly aligned
        iu_waf:          iu_units_touched / iu_units_ideal (1.0 = no alignment overhead)

    NPWG fields:
        npwg_aligned:       True if size is a multiple of NPWG AND size >= NPWG
        npwg_start_aligned: True if start sector is NPWG-aligned
        npwg_units_touched: number of NPWG-sized regions spanned

    AWUN fields (writes only):
        awun_crossings: AWUN boundaries crossed (0 = within single atomic unit)
        awun_safe:      True if awun_crossings == 0 (write is power-fail atomic)
    """
    sector: int; nblocks: int; size_bytes: int; is_read: bool; timestamp: float
    sub_iu: bool = False; iu_crossings: int = 0; iu_aligned: bool = False
    iu_units_touched: int = 0; iu_units_ideal: int = 0; iu_waf: float = 1.0
    npwg_aligned: bool = False; npwg_start_aligned: bool = False; npwg_units_touched: int = 0
    awun_crossings: int = 0; awun_safe: bool = True

# ─── Parser ───────────────────────────────────────────────────────────────────
# Regex for blkparse default output format. Captures 11 groups:
#   1: major  2: minor  3: cpu  4: seq  5: timestamp  6: pid
#   7: action (single char: Q/D/C/G/I/M/F/P/U)
#   8: rwbs flags (R/W/D combined with S/F/N, e.g., "WS", "R", "DWSN")
#   9: sector (starting LBA in LBS-unit sectors)
#  10: nblocks (count of LBS-unit sectors)
#  11: process name (optional, in brackets)
#
# Lines that don't match this pattern (e.g., plug/unplug without sector,
# header/footer lines, blank lines) are silently skipped and counted as
# parse_errors for the user to see in the load summary.
BLKPARSE_RE = re.compile(
    r"^\s*(\d+),(\d+)\s+(\d+)\s+(\d+)\s+([\d.]+)\s+(\d+)\s+([A-Z])\s+([A-Z]*)\s+(\d+)\s*\+\s*(\d+)\s*(?:\[(.+?)\])?")

def parse_blkparse_line(line):
    m = BLKPARSE_RE.match(line)
    if not m: return None
    rwbs = m.group(8)
    nblocks = int(m.group(10))
    return TraceEvent(
        major=int(m.group(1)), minor=int(m.group(2)), cpu=int(m.group(3)),
        seq=int(m.group(4)), timestamp=float(m.group(5)), pid=int(m.group(6)),
        action=m.group(7), rwbs=rwbs, sector=int(m.group(9)), nblocks=nblocks,
        process=m.group(11) or "", is_read=RWBS_READ in rwbs,
        is_write=RWBS_WRITE in rwbs,
        is_discard=(RWBS_DISCARD in rwbs and m.group(7) != ACTION_ISSUE),
        size_bytes=nblocks * SECTOR_SIZE)

def load_trace(filepath):
    events, parse_errors, total_lines = [], 0, 0
    with open(filepath, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("CPU") or line.startswith("Total") or "==" in line:
                continue
            total_lines += 1
            ev = parse_blkparse_line(line)
            if ev: events.append(ev)
            else: parse_errors += 1
    events.sort(key=lambda e: e.timestamp)
    print(f"  Parsed {len(events):,} events from {total_lines:,} lines ({parse_errors} unparseable)")
    if events:
        print(f"  Trace duration: {events[-1].timestamp - events[0].timestamp:.3f} seconds")
    return events

# ─── Analysis Engine ──────────────────────────────────────────────────────────
class BlktraceAnalyzer:
    """Core analysis engine for blktrace data with optional IU/LBS awareness.

    Computation flow:
    1. Constructor filters events by type (read/write/discard), computes
       trace duration from first/last event timestamps.
    2. _compute_latencies() runs immediately — matches Q/D/C events into
       IORequest lifecycles using (sector, nblocks) FIFO matching.
    3. Individual compute_* methods are called lazily when charts are
       generated or print_summary() is invoked.
    4. IU analysis (analyze_iu_alignment) is computed once and cached in
       self._iu_results; all IU methods share this cached result.

    Parameters:
        events:      list of TraceEvent, must be time-sorted
        time_bucket: width of time bins in seconds for throughput/IOPS/latency
                     charts. Smaller = higher resolution but noisier.
        lba_bins:    number of LBA address bins for heatmap/histogram.
                     Higher = finer spatial resolution.
        geometry:    SSDGeometry instance for IU/NPWG/AWUN analysis. If None
                     or all fields are 0, IU charts are skipped.
    """
    def __init__(self, events, time_bucket=0.1, lba_bins=256, geometry=None, lba_extent=None):
        self.events = events
        self.time_bucket = time_bucket
        self.lba_bins = lba_bins
        self.geom = geometry or SSDGeometry()
        self.lba_extent = lba_extent
        if not events: raise ValueError("No events to analyze")
        self.t0 = events[0].timestamp
        self.t_end = events[-1].timestamp
        self.duration = self.t_end - self.t0
        self.reads = [e for e in events if e.is_read]
        self.writes = [e for e in events if e.is_write]
        self.discards = [e for e in events if e.is_discard]
        self._compute_latencies()
        self._iu_results = None

    def _compute_latencies(self):
        """Match Q → D → C event triples into IORequest lifecycles.

        Algorithm:
            pending = dict of (sector, nblocks) → list[IORequest]  (FIFO queue)

            For each event in timestamp order:
              Q: Create IORequest(queue_time=ts), append to pending[(sector, nblocks)]
              D: If pending list exists for key, set pending[0].issue_time = ts
                 Otherwise create new IORequest(issue_time=ts) — handles traces
                 that start mid-flight (D without prior Q).
              C: If pending list exists, pop(0), set complete_time = ts, add to
                 completed_ios list.

        The (sector, nblocks) key works because the block layer preserves these
        across the Q → D → C path for non-merged I/Os. For merged I/Os, the
        merged D event has a different (sector, nblocks) than the original Qs,
        so those Qs remain unmatched — they're excluded from latency stats
        but still counted in I/O size and IU analysis (which uses Q events).

        Output: self.completed_ios — list of IORequest with at least one
        timestamp pair set, enabling latency computation.
        """
        pending = defaultdict(list)
        self.completed_ios = []
        for ev in self.events:
            key = (ev.sector, ev.nblocks)
            if ev.action == ACTION_QUEUE:
                pending[key].append(IORequest(sector=ev.sector, nblocks=ev.nblocks,
                                              is_read=ev.is_read, queue_time=ev.timestamp))
            elif ev.action == ACTION_ISSUE:
                if pending[key]: pending[key][0].issue_time = ev.timestamp
                else: pending[key].append(IORequest(sector=ev.sector, nblocks=ev.nblocks,
                                                    is_read=ev.is_read, issue_time=ev.timestamp))
            elif ev.action == ACTION_COMPLETE:
                if pending[key]:
                    req = pending[key].pop(0)
                    req.complete_time = ev.timestamp
                    self.completed_ios.append(req)
        print(f"  Matched {len(self.completed_ios):,} complete I/O lifecycles")

    # ═══ IU / LBS / ATOMIC ANALYSIS ═══════════════════════════════════════
    def analyze_iu_alignment(self):
        """Analyze every Q event for IU alignment, NPWG alignment, and AWUN safety.

        Source events: Q (queue) with nblocks > 0. Uses Q rather than D to capture
        the application's original I/O geometry before block layer merging.

        For each Q event, computes IU/NPWG/AWUN metrics (see IUAnalysisResult
        docstring for field definitions). Results are cached — subsequent calls
        return the same list.

        IU alignment math example (IU=4096, LBS=512, iu_sectors=8):
            Write: sector=12, nblocks=8  (4K write starting at byte offset 6144)
            start_iu = 12 // 8 = 1
            end_iu   = (12 + 8 - 1) // 8 = 19 // 8 = 2
            iu_crossings = 2 - 1 = 1  (crosses one IU boundary)
            iu_units_touched = 2      (spans IU[1] and IU[2])
            iu_units_ideal = ceil(8/8) = 1
            iu_waf = 2/1 = 2.0        (alignment doubles the FTL write work)
            iu_aligned = (12 % 8 == 0) and (8 % 8 == 0) = False and True = False

        Returns: list of IUAnalysisResult, one per Q event.
        """
        if self._iu_results is not None: return self._iu_results
        q_events = [e for e in self.events if e.action == ACTION_QUEUE and e.nblocks > 0]
        results = []
        g = self.geom
        for ev in q_events:
            r = IUAnalysisResult(sector=ev.sector, nblocks=ev.nblocks,
                                 size_bytes=ev.size_bytes, is_read=ev.is_read, timestamp=ev.timestamp)
            if g.has_iu:
                iu_s = g.iu_sectors
                r.sub_iu = (ev.is_write and ev.nblocks < iu_s)
                start_iu = ev.sector // iu_s
                end_iu = (ev.sector + ev.nblocks - 1) // iu_s
                r.iu_crossings = end_iu - start_iu
                r.iu_units_touched = end_iu - start_iu + 1
                r.iu_units_ideal = max(1, math.ceil(ev.nblocks / iu_s))
                r.iu_aligned = (ev.sector % iu_s == 0) and (ev.nblocks % iu_s == 0)
                r.iu_waf = r.iu_units_touched / r.iu_units_ideal if r.iu_units_ideal > 0 else 1.0
            if g.has_npwg:
                npwg_s = g.npwg_sectors
                r.npwg_aligned = (ev.nblocks % npwg_s == 0) and (ev.nblocks >= npwg_s)
                r.npwg_start_aligned = (ev.sector % npwg_s == 0)
                start_npwg = ev.sector // npwg_s
                end_npwg = (ev.sector + ev.nblocks - 1) // npwg_s
                r.npwg_units_touched = end_npwg - start_npwg + 1
            if g.has_awun and ev.is_write:
                awun_s = g.awun_sectors
                start_awun = ev.sector // awun_s
                end_awun = (ev.sector + ev.nblocks - 1) // awun_s
                r.awun_crossings = end_awun - start_awun
                r.awun_safe = (r.awun_crossings == 0)
            results.append(r)
        self._iu_results = results
        return results

    def compute_iu_summary(self):
        """Aggregate IU/NPWG/AWUN alignment statistics across all Q events.

        Returns dict with keys 'total_ios', 'total_writes', 'total_reads', and
        optional sub-dicts 'iu', 'npwg', 'awun' (present only if corresponding
        geometry fields are set).

        IU sub-dict metrics:
            sub_iu_writes/pct:      writes with nblocks < iu_sectors (RMW triggers)
            iu_aligned_writes/pct:  writes with both start and size IU-aligned
            iu_crossing_writes/pct: writes straddling ≥1 IU boundary
            mean_waf / max_waf:     alignment WAF across all writes
            misaligned_mean_waf:    WAF averaged over only the misaligned subset

        NPWG sub-dict: fully_aligned (start+size), size_aligned_only, unaligned
        AWUN sub-dict: safe/unsafe counts, max boundary crossings observed
        """
        results = self.analyze_iu_alignment()
        if not results: return {}
        writes = [r for r in results if not r.is_read]
        reads = [r for r in results if r.is_read]
        g = self.geom
        summary = {"total_ios": len(results), "total_writes": len(writes), "total_reads": len(reads)}
        if g.has_iu:
            sub_iu_w = [r for r in writes if r.sub_iu]
            aligned_w = [r for r in writes if r.iu_aligned]
            crossing_w = [r for r in writes if r.iu_crossings > 0]
            aligned_r = [r for r in reads if r.iu_aligned]
            all_waf = [r.iu_waf for r in writes if r.iu_waf > 0]
            mis_waf = [r.iu_waf for r in writes if r.iu_waf > 1.0]
            summary["iu"] = {
                "sub_iu_writes": len(sub_iu_w), "sub_iu_pct": len(sub_iu_w)/max(1,len(writes))*100,
                "iu_aligned_writes": len(aligned_w), "iu_aligned_write_pct": len(aligned_w)/max(1,len(writes))*100,
                "iu_aligned_reads": len(aligned_r), "iu_aligned_read_pct": len(aligned_r)/max(1,len(reads))*100,
                "iu_crossing_writes": len(crossing_w), "iu_crossing_write_pct": len(crossing_w)/max(1,len(writes))*100,
                "mean_waf": np.mean(all_waf) if all_waf else 1.0,
                "max_waf": max(all_waf) if all_waf else 1.0,
                "misaligned_count": len(mis_waf),
                "misaligned_mean_waf": np.mean(mis_waf) if mis_waf else 1.0,
            }
        if g.has_npwg:
            full_align = [r for r in writes if r.npwg_aligned and r.npwg_start_aligned]
            size_only = [r for r in writes if r.npwg_aligned and not r.npwg_start_aligned]
            summary["npwg"] = {
                "fully_aligned_writes": len(full_align), "fully_aligned_pct": len(full_align)/max(1,len(writes))*100,
                "size_aligned_only": len(size_only), "size_aligned_only_pct": len(size_only)/max(1,len(writes))*100,
                "unaligned_writes": len(writes)-len(full_align)-len(size_only),
                "unaligned_pct": (len(writes)-len(full_align)-len(size_only))/max(1,len(writes))*100,
            }
        if g.has_awun:
            unsafe = [r for r in writes if not r.awun_safe]
            summary["awun"] = {
                "unsafe_writes": len(unsafe), "unsafe_pct": len(unsafe)/max(1,len(writes))*100,
                "safe_writes": len(writes)-len(unsafe), "safe_pct": (len(writes)-len(unsafe))/max(1,len(writes))*100,
                "max_crossings": max((r.awun_crossings for r in writes), default=0),
            }
        return summary

    def compute_iu_quantization_histogram(self):
        """Bucket I/O sizes by IU multiples: <1 IU, 1 IU, 2 IU, ..., 16 IU, >16 IU.

        For each Q event, computes size_bytes / iu_size. If the result is an exact
        integer AND ≤ 16, it goes in that bucket. Fractional ratios go to the floor
        bucket. Sizes < 1 IU go in bucket 0, sizes > 16 IU go in the overflow bucket.

        Returns (labels, read_counts, write_counts) — parallel lists for bar chart.
        Reveals whether the filesystem/application issues IU-aware I/O sizes.
        """
        results = self.analyze_iu_alignment()
        g = self.geom
        if not g.has_iu or not results: return [], [], []
        iu_bytes = g.iu_size
        max_bucket = 16
        labels = [f"<1 IU\n(<{iu_bytes//KB}K)"]
        for i in range(1, max_bucket+1): labels.append(f"{i} IU\n({i*iu_bytes//KB}K)")
        labels.append(f">{max_bucket} IU")
        r_counts = [0]*len(labels); w_counts = [0]*len(labels)
        for r in results:
            ratio = r.size_bytes / iu_bytes
            exact = (r.size_bytes % iu_bytes == 0)
            if ratio < 1.0: idx = 0
            elif exact and int(ratio) <= max_bucket: idx = int(ratio)
            elif ratio <= max_bucket: idx = int(ratio)
            else: idx = len(labels)-1
            if r.is_read: r_counts[idx] += 1
            else: w_counts[idx] += 1
        return labels, r_counts, w_counts

    def compute_waf_over_time(self):
        """Compute alignment-induced WAF per time bucket (writes only).

        For each time bucket:
            actual_iu_writes = sum of iu_units_touched for all writes in bucket
            ideal_iu_writes  = sum of iu_units_ideal for all writes in bucket
            waf = actual / ideal   (1.0 = perfectly aligned, >1.0 = alignment overhead)

        Also counts sub-IU writes per bucket (useful for identifying RMW bursts).

        Returns (times, waf_array, sub_iu_count_array).
        NOTE: This is host-side alignment WAF only. Total device WAF includes
        GC and wear-leveling overhead visible only via SMART data.
        """
        results = self.analyze_iu_alignment()
        if not self.geom.has_iu or not results:
            return np.array([0]), np.array([1.0]), np.array([0.0])
        n = max(1, int(np.ceil(self.duration / self.time_bucket)))
        actual = np.zeros(n); ideal = np.zeros(n); sub_ct = np.zeros(n)
        for r in results:
            if r.is_read: continue
            idx = min(int((r.timestamp - self.t0) / self.time_bucket), n-1)
            actual[idx] += r.iu_units_touched; ideal[idx] += r.iu_units_ideal
            if r.sub_iu: sub_ct[idx] += 1
        times = np.arange(n) * self.time_bucket
        with np.errstate(divide="ignore", invalid="ignore"):
            waf = np.where(ideal > 0, actual / ideal, 1.0)
        return times, waf, sub_ct

    def compute_alignment_vs_latency(self):
        """Correlate IU alignment classification with D→C device latency.

        Join strategy: builds a lookup dict of (sector, nblocks) → IUAnalysisResult
        for writes from analyze_iu_alignment(). Then iterates completed_ios (from
        _compute_latencies) and matches each completed write by (sector, nblocks).

        For each matched write with valid d2c_latency_us > 0:
            - If iu_aligned: latency goes to 'aligned' bucket
            - Else: latency goes to 'misaligned' bucket
            - If sub_iu: latency also goes to 'sub_iu' bucket (subset of misaligned)

        Returns dict with 'aligned', 'misaligned', 'sub_iu' numpy arrays of
        latencies in microseconds. Enables direct CDF comparison to quantify
        the latency impact of misalignment on the specific device under test.

        Limitation: Join is by (sector, nblocks), so merged I/Os that changed
        these values between Q and D/C will not match and are excluded.
        """
        if not self.geom.has_iu: return {}
        iu_map = {(r.sector, r.nblocks): r for r in self.analyze_iu_alignment() if not r.is_read}
        aligned_l, misaligned_l, sub_iu_l = [], [], []
        for req in self.completed_ios:
            if req.is_read: continue
            lat = req.d2c_latency_us
            if lat is None or lat <= 0: continue
            iu_r = iu_map.get((req.sector, req.nblocks))
            if iu_r is None: continue
            (aligned_l if iu_r.iu_aligned else misaligned_l).append(lat)
            if iu_r.sub_iu: sub_iu_l.append(lat)
        return {"aligned": np.array(aligned_l) if aligned_l else np.array([]),
                "misaligned": np.array(misaligned_l) if misaligned_l else np.array([]),
                "sub_iu": np.array(sub_iu_l) if sub_iu_l else np.array([])}

    # ═══ ORIGINAL METRICS ═════════════════════════════════════════════════
    def compute_queue_depth(self):
        """Compute instantaneous block-layer queue depth from D/C events.

        Algorithm: Walk all events in timestamp order. On D (dispatch), increment
        depth. On C (complete), decrement. Separate read/write/total counters.
        Depth is clamped to ≥ 0 to handle out-of-order events at trace boundaries.

        This measures BLOCK LAYER queue depth (I/Os dispatched but not completed),
        NOT NVMe submission queue depth. Differences:
            - NVMe driver may batch D events before doorbell write
            - Aggregates across all per-CPU NVMe SQ pairs
            - CQ interrupt coalescing can delay C event timestamps

        Returns (times, qd_total, qd_read, qd_write) — one sample per D/C event.
        """
        changes = []
        for ev in self.events:
            if ev.action == ACTION_ISSUE: changes.append((ev.timestamp-self.t0, +1, ev.is_read))
            elif ev.action == ACTION_COMPLETE: changes.append((ev.timestamp-self.t0, -1, ev.is_read))
        if not changes: return np.array([0.0]), np.array([0]), np.array([0]), np.array([0])
        changes.sort()
        t,qt,qr,qw = [],[],[],[]
        d=dr=dw=0
        for tm,delta,ir in changes:
            d+=delta; dr+=(delta if ir else 0); dw+=(delta if not ir else 0)
            d=max(0,d); dr=max(0,dr); dw=max(0,dw)
            t.append(tm); qt.append(d); qr.append(dr); qw.append(dw)
        return np.array(t), np.array(qt), np.array(qr), np.array(qw)

    def compute_queue_depth_bucketed(self):
        """Average queue depth per time bucket.

        Takes the instantaneous QD samples from compute_queue_depth() and averages
        all samples that fall within each [i×bucket, (i+1)×bucket) window.
        This smooths the high-frequency QD signal for the bucketed bar chart.

        Returns (bucket_times, avg_total, avg_read, avg_write).
        """
        times,qt,qr,qw = self.compute_queue_depth()
        if len(times)==0: return np.array([0]),np.array([0]),np.array([0]),np.array([0])
        n = max(1, int(np.ceil(self.duration/self.time_bucket)))
        bt = np.linspace(0, self.duration, n)
        at,ar,aw = np.zeros(n),np.zeros(n),np.zeros(n)
        for i in range(n):
            mask = (times >= i*self.time_bucket) & (times < (i+1)*self.time_bucket)
            if np.any(mask): at[i]=np.mean(qt[mask]); ar[i]=np.mean(qr[mask]); aw[i]=np.mean(qw[mask])
        return bt, at, ar, aw

    def compute_lba_heatmap(self):
        """Build 2D heatmap of I/O activity: [lba_bins × time_bins].

        Source: Q and D events with sector > 0.
        Binning:
            time_index = floor((timestamp - t0) / duration × n_time_bins)
            lba_index  = floor(sector / (max_sector + 1) × n_lba_bins)

        Produces three heatmaps (all, read-only, write-only) for log-normalized
        inferno colormap visualization. n_time_bins is capped at 200 to keep
        the heatmap readable.

        Returns (heatmap_all, heatmap_read, heatmap_write, max_sector).
        """
        io_ev = [e for e in self.events if e.action in (ACTION_QUEUE,ACTION_ISSUE) and e.sector>0]
        if not io_ev: return np.zeros((1,1)),np.zeros((1,1)),np.zeros((1,1)),np.zeros((1,1))
        sectors = np.array([e.sector for e in io_ev]); mx = sectors.max()
        nt = max(1, min(200, int(self.duration/self.time_bucket)))
        nl = self.lba_bins
        ha,hr,hw = np.zeros((nl,nt)),np.zeros((nl,nt)),np.zeros((nl,nt))
        for ev in io_ev:
            ti = min(int((ev.timestamp-self.t0)/self.duration*nt), nt-1)
            si = min(int(ev.sector/(mx+1)*nl), nl-1)
            ha[si,ti]+=1
            if ev.is_read: hr[si,ti]+=1
            elif ev.is_write: hw[si,ti]+=1
        return ha,hr,hw,mx

    def _accumulate_lba_bins(self, io_ev, extent=True):
        """Accumulate per-bin LBA statistics from Q events.

        extent=False : original behaviour — each request lands entirely in the
                       bin containing its START sector.
        extent=True  : each request is mapped across its full extent
                       [sector, sector + nblocks). Bytes are split proportionally
                       to the sectors falling in each overlapped bin (sum of split
                       bytes == request size, so byte totals are conserved). Each
                       overlapped bin also gets +1 'touch' in io_count / r/w_count.

        Bin width is derived from the furthest sector any request TOUCHES
        (max(sector + nblocks)), not just max start sector, so the last bin
        actually covers the tail of large trailing writes.

        NOTE on counts in extent mode: io_count / read_count / write_count become
        per-bin TOUCH counts. A request spanning N bins adds 1 to each, so summed
        counts can exceed the number of requests. Byte columns remain conserved.

        Returns (arrs_dict, bin_centers_sectors, max_sector_touched).
        """
        nb = self.lba_bins
        keys = ("io_count", "total_bytes", "write_bytes",
                "read_bytes", "write_count", "read_count")
        arrs = {k: np.zeros(nb) for k in keys}
        if not io_ev:
            return arrs, np.array([0.0]), 0
        starts = np.array([e.sector for e in io_ev], dtype=np.float64)
        counts = np.array([e.nblocks for e in io_ev], dtype=np.float64)
        is_w = np.array([e.is_write for e in io_ev])
        sizes = counts * SECTOR_SIZE
        ends = starts + counts                      # exclusive end sector
        # Robust bin range. A few stray sectors far outside the working set
        # (cross-region writes, trace artifacts) would blow up the bin width
        # and collapse all real I/O into bin 0. Scale to the working set by
        # excluding ends that sit far above the median; np.clip below still
        # folds true outliers into the last bin so their bytes are not lost.
        med = np.median(ends)
        inliers = ends[ends <= med * 8] if med > 0 else ends
        mx = float(inliers.max()) if inliers.size else float(ends.max())
        if mx <= 0:
            mx = float(ends.max())
        w = mx / nb                                  # bin width in sectors

        def add(idx, sz, wr):
            np.add.at(arrs["io_count"], idx, 1.0)
            np.add.at(arrs["total_bytes"], idx, sz)
            np.add.at(arrs["write_bytes"], idx, np.where(wr, sz, 0.0))
            np.add.at(arrs["read_bytes"], idx, np.where(~wr, sz, 0.0))
            np.add.at(arrs["write_count"], idx, np.where(wr, 1.0, 0.0))
            np.add.at(arrs["read_count"], idx, np.where(~wr, 1.0, 0.0))

        if not extent:
            idx = np.clip((starts / w).astype(int), 0, nb - 1)
            add(idx, sizes, is_w)
        else:
            start_bin = np.clip((starts / w).astype(int), 0, nb - 1)
            end_bin = np.clip(np.ceil(ends / w).astype(int) - 1, 0, nb - 1)
            single = start_bin == end_bin
            # fast path: requests contained in one bin (the vast majority)
            add(start_bin[single], sizes[single], is_w[single])
            # slow path: requests spanning >1 bin — split by sector overlap
            for i in np.where(~single)[0]:
                s, e = starts[i], ends[i]; wr = is_w[i]
                for b in range(int(start_bin[i]), int(end_bin[i]) + 1):
                    ov = min(e, (b + 1) * w) - max(s, b * w)   # overlap in sectors
                    if ov <= 0:
                        continue
                    byts = ov * SECTOR_SIZE                     # proportional bytes
                    arrs["io_count"][b] += 1.0
                    arrs["total_bytes"][b] += byts
                    if wr:
                        arrs["write_bytes"][b] += byts; arrs["write_count"][b] += 1.0
                    else:
                        arrs["read_bytes"][b] += byts; arrs["read_count"][b] += 1.0

        bin_centers = (np.arange(nb) + 0.5) * w
        return arrs, bin_centers, mx

    def compute_lba_histogram(self):
        """1D LBA access frequency histogram from Q events.

        Divides the LBA range [0, max_sector] into lba_bins equal-width segments
        using np.linspace. Counts Q events per segment, separately for reads and
        writes. The result is used for the bar chart under the heatmap and for
        ranking top hotspot bins.

        Returns (bin_centers_in_sectors, read_hist, write_hist).
        bin_centers are in raw sector units — multiply by SECTOR_SIZE/GB for GB.
        """
        io_ev = [e for e in self.events if e.action==ACTION_QUEUE and e.sector>0]
        if not io_ev: return np.array([0]),np.array([0]),np.array([0])
        sectors = np.array([e.sector for e in io_ev]); mx = sectors.max()
        bins = np.linspace(0, mx, self.lba_bins+1)
        rs = [e.sector for e in io_ev if e.is_read]; ws = [e.sector for e in io_ev if e.is_write]
        hr,_ = np.histogram(rs, bins=bins) if rs else (np.zeros(self.lba_bins), None)
        hw,_ = np.histogram(ws, bins=bins) if ws else (np.zeros(self.lba_bins), None)
        return (bins[:-1]+bins[1:])/2, hr, hw

    def compute_io_sizes(self):
        """Extract I/O sizes from Q (queue) events — the application's original requests.

        Uses Q events (not D) because block layer merging can combine adjacent Q
        requests into a single D dispatch with a different size. Q captures the
        true application I/O pattern, which is what determines IU alignment
        behavior at the individual request level.

        size_bytes = nblocks × SECTOR_SIZE (where SECTOR_SIZE = LBS from --lbs flag)

        Returns (read_sizes, write_sizes, all_sizes) — three lists of bytes values.
        """
        qe = [e for e in self.events if e.action==ACTION_QUEUE and e.nblocks>0]
        return ([e.size_bytes for e in qe if e.is_read],
                [e.size_bytes for e in qe if e.is_write],
                [e.size_bytes for e in qe])

    def compute_throughput(self):
        """Compute read/write throughput in MB/s per time bucket from C events.

        Uses C (complete) events because completion confirms data was actually
        transferred. Each C event's size_bytes is accumulated into the time bucket
        where its completion timestamp falls.

        Formula per bucket:
            MB/s = sum(size_bytes of C events in bucket) / bucket_duration / 1048576

        Throughput is attributed to the COMPLETION time, not submission time.
        This means a large I/O submitted at t=1.0 but completing at t=1.5 shows
        its bytes at t=1.5, which more accurately reflects when bandwidth was
        consumed on the device side.

        Returns (bucket_times, read_mbps, write_mbps).
        """
        ce = [e for e in self.events if e.action==ACTION_COMPLETE]
        if not ce: return np.array([0]),np.array([0]),np.array([0])
        n = max(1, int(np.ceil(self.duration/self.time_bucket)))
        rb,wb = np.zeros(n),np.zeros(n)
        for ev in ce:
            i = min(int((ev.timestamp-self.t0)/self.time_bucket), n-1)
            if ev.is_read: rb[i]+=ev.size_bytes
            else: wb[i]+=ev.size_bytes
        return np.arange(n)*self.time_bucket, rb/self.time_bucket/MB, wb/self.time_bucket/MB

    def compute_iops(self):
        """Compute read/write IOPS per time bucket from C events.

        Counts the number of C (complete) events per time bucket, then divides
        by bucket duration to get IOPS:

            IOPS = count(C events in bucket) / bucket_duration_seconds

        Like throughput, uses completion events so IOPS reflects actual device
        completion rate, not submission rate. Under deep queue depth, submission
        IOPS can spike while completion IOPS stays steady — this metric shows
        the latter, which is the true device throughput in I/O operations.

        Returns (bucket_times, read_iops, write_iops).
        """
        ce = [e for e in self.events if e.action==ACTION_COMPLETE]
        if not ce: return np.array([0]),np.array([0]),np.array([0])
        n = max(1, int(np.ceil(self.duration/self.time_bucket)))
        rc,wc = np.zeros(n),np.zeros(n)
        for ev in ce:
            i = min(int((ev.timestamp-self.t0)/self.time_bucket), n-1)
            if ev.is_read: rc[i]+=1
            else: wc[i]+=1
        return np.arange(n)*self.time_bucket, rc/self.time_bucket, wc/self.time_bucket

    def compute_latency_distributions(self):
        """Collect latency values from completed I/O lifecycles into per-type arrays.

        Iterates self.completed_ios (populated by _compute_latencies). For each
        IORequest, extracts three latency intervals if the required timestamps
        are present and latency > 0:

            q2c (total):    queue_time → complete_time    (application-visible)
            d2c (device):   issue_time → complete_time    (SSD processing time)
            q2d (software): queue_time → issue_time       (block layer overhead)

        Each is split by read/write, producing 6 arrays total.

        These arrays feed the latency histogram (density-normalized, 100 bins),
        CDF chart (sorted values vs percentile rank), and the summary statistics
        (min, p50, p95, p99, max).

        Returns dict: {'q2c_read': np.array, 'q2c_write': np.array,
                        'd2c_read': ..., 'd2c_write': ...,
                        'q2d_read': ..., 'q2d_write': ...}
        Empty arrays for types with no data.
        """
        d = {"q2c_read":[],"q2c_write":[],"d2c_read":[],"d2c_write":[],"q2d_read":[],"q2d_write":[]}
        for req in self.completed_ios:
            for attr, prefix in [(req.q2c_latency_us,"q2c"),(req.d2c_latency_us,"d2c"),(req.q2d_latency_us,"q2d")]:
                if attr is not None and attr > 0:
                    d[f"{prefix}_{'read' if req.is_read else 'write'}"].append(attr)
        return {k: np.array(v) if v else np.array([]) for k,v in d.items()}

    def compute_latency_over_time(self):
        """Compute per-bucket latency percentiles (p50, p99) over time.

        For each completed I/O, the latency used is D→C (device latency) if
        available, falling back to Q→C (total latency). The I/O is placed in
        the time bucket corresponding to its issue_time (or queue_time fallback).

        Within each bucket, np.median gives p50 and np.percentile(99) gives p99,
        computed separately for reads and writes. Buckets with no I/Os get 0.

        The p50-to-p99 band in the time series chart reveals tail latency behavior:
        a narrow band means consistent device response; a wide or spiky p99 band
        indicates intermittent delays (GC, thermal throttling, IU misalignment
        penalties, or NVMe controller congestion).

        Returns (times, p50_read, p99_read, p50_write, p99_write).
        """
        n = max(1, int(np.ceil(self.duration/self.time_bucket)))
        br = [[] for _ in range(n)]; bw = [[] for _ in range(n)]
        for req in self.completed_ios:
            lat = req.d2c_latency_us or req.q2c_latency_us
            if lat is None or lat<=0: continue
            t = req.issue_time or req.queue_time
            if t is None: continue
            i = min(int((t-self.t0)/self.time_bucket), n-1)
            (br if req.is_read else bw)[i].append(lat)
        times = np.arange(n)*self.time_bucket
        return (times,
                np.array([np.median(b) if b else 0 for b in br]),
                np.array([np.percentile(b,99) if b else 0 for b in br]),
                np.array([np.median(b) if b else 0 for b in bw]),
                np.array([np.percentile(b,99) if b else 0 for b in bw]))

    def print_summary(self):
        """Print comprehensive text summary of all analysis metrics.

        Outputs:
            - Trace metadata: duration, event counts by type
            - Throughput: read/write MB/s computed from sum(C event bytes)/duration
            - I/O sizes: min, median, max from Q events
            - Latency percentiles: min/p50/p95/p99/max for each Q2C/D2C/Q2D × R/W
            - Queue depth: max and mean from D/C event tracking
            - IU alignment stats (if --iu-size provided): aligned%, sub-IU%, WAF
            - NPWG alignment stats (if --npwg provided): fully/size-only/unaligned%
            - AWUN safety stats (if --awun provided): safe/unsafe write counts
        """
        print(f"\n{'='*72}\n  BLKTRACE ANALYSIS SUMMARY\n{'='*72}")
        print(f"\n  Duration        : {self.duration:.3f} s")
        print(f"  Total events    : {len(self.events):,}")
        print(f"  Read events     : {len(self.reads):,}")
        print(f"  Write events    : {len(self.writes):,}")
        print(f"  Completed I/Os  : {len(self.completed_ios):,}")
        ce = [e for e in self.events if e.action==ACTION_COMPLETE]
        tbr = sum(e.size_bytes for e in ce if e.is_read)
        tbw = sum(e.size_bytes for e in ce if e.is_write)
        if self.duration > 0:
            print(f"\n  Read throughput  : {tbr/MB/self.duration:.2f} MB/s ({tbr/GB:.2f} GB)")
            print(f"  Write throughput : {tbw/MB/self.duration:.2f} MB/s ({tbw/GB:.2f} GB)")
            print(f"  Total IOPS       : {len(ce)/self.duration:,.0f}")
        rs,ws,als = self.compute_io_sizes()
        if als:
            print(f"\n  I/O size (all)   : min={min(als)/KB:.1f}K  median={np.median(als)/KB:.1f}K  max={max(als)/KB:.1f}K")
        lats = self.compute_latency_distributions()
        for name, arr in lats.items():
            if len(arr) > 0:
                print(f"\n  {name.replace('_',' ').upper()}:")
                print(f"    min={arr.min():.1f}us  p50={np.median(arr):.1f}us  p95={np.percentile(arr,95):.1f}us  p99={np.percentile(arr,99):.1f}us  max={arr.max():.1f}us")
        _,qt,_,_ = self.compute_queue_depth()
        if len(qt)>0: print(f"\n  Queue depth      : max={qt.max()}  mean={qt.mean():.1f}")
        # IU/LBS Summary
        if self.geom.has_iu or self.geom.has_npwg or self.geom.has_awun:
            print(f"\n{'─'*72}\n  {self.geom.summary()}")
            iu_sum = self.compute_iu_summary()
            if "iu" in iu_sum:
                iu = iu_sum["iu"]
                print(f"\n  IU ALIGNMENT (writes):")
                print(f"    Perfectly aligned      : {iu['iu_aligned_writes']:,} ({iu['iu_aligned_write_pct']:.1f}%)")
                print(f"    Sub-IU (RMW triggers)  : {iu['sub_iu_writes']:,} ({iu['sub_iu_pct']:.1f}%)")
                print(f"    IU boundary crossing   : {iu['iu_crossing_writes']:,} ({iu['iu_crossing_write_pct']:.1f}%)")
                print(f"    Alignment WAF          : mean={iu['mean_waf']:.3f}  max={iu['max_waf']:.3f}")
                if iu['misaligned_count']>0:
                    print(f"    Misaligned-only WAF    : mean={iu['misaligned_mean_waf']:.3f} (n={iu['misaligned_count']:,})")
            if "npwg" in iu_sum:
                n = iu_sum["npwg"]
                print(f"\n  NPWG ALIGNMENT (writes):")
                print(f"    Fully aligned          : {n['fully_aligned_writes']:,} ({n['fully_aligned_pct']:.1f}%)")
                print(f"    Size-only aligned      : {n['size_aligned_only']:,} ({n['size_aligned_only_pct']:.1f}%)")
                print(f"    Unaligned              : {n['unaligned_writes']:,} ({n['unaligned_pct']:.1f}%)")
            if "awun" in iu_sum:
                a = iu_sum["awun"]
                print(f"\n  ATOMIC WRITE SAFETY:")
                print(f"    Safe (within AWUN)     : {a['safe_writes']:,} ({a['safe_pct']:.1f}%)")
                print(f"    Unsafe (crosses AWUN)  : {a['unsafe_writes']:,} ({a['unsafe_pct']:.1f}%)")
        print(f"\n{'='*72}")

# ─── Plotting ─────────────────────────────────────────────────────────────────
COLORS = {"read":"#2196F3","write":"#FF5722","total":"#4CAF50","p50":"#2196F3","p99":"#F44336",
          "aligned":"#4CAF50","misaligned":"#FF9800","sub_iu":"#E91E63","unsafe":"#F44336",
          "safe":"#4CAF50","waf":"#9C27B0","bg":"#FAFAFA","grid":"#E0E0E0"}

def setup_ax(ax, title, xlabel, ylabel):
    ax.set_title(title, fontsize=13, fontweight="bold", pad=10)
    ax.set_xlabel(xlabel, fontsize=10); ax.set_ylabel(ylabel, fontsize=10)
    ax.grid(True, alpha=0.3, color=COLORS["grid"]); ax.set_facecolor(COLORS["bg"])

def plot_queue_depth(a, od):
    fig,(ax1,ax2) = plt.subplots(2,1,figsize=(14,8),height_ratios=[2,1])
    fig.suptitle("Queue Depth Analysis", fontsize=15, fontweight="bold")
    t,qt,qr,qw = a.compute_queue_depth()
    if len(t)>10000:
        s=len(t)//5000; i=np.arange(0,len(t),s); t,qt,qr,qw=t[i],qt[i],qr[i],qw[i]
    ax1.fill_between(t,qt,alpha=0.2,color=COLORS["total"])
    ax1.plot(t,qt,lw=0.5,color=COLORS["total"],label="Total")
    ax1.plot(t,qr,lw=0.5,color=COLORS["read"],alpha=0.7,label="Read")
    ax1.plot(t,qw,lw=0.5,color=COLORS["write"],alpha=0.7,label="Write")
    setup_ax(ax1,"Instantaneous Queue Depth","","Queue Depth"); ax1.legend()
    bt,at,ar,aw = a.compute_queue_depth_bucketed()
    ax2.bar(bt,ar,width=a.time_bucket*0.9,color=COLORS["read"],alpha=0.7,label="Read")
    ax2.bar(bt,aw,width=a.time_bucket*0.9,bottom=ar,color=COLORS["write"],alpha=0.7,label="Write")
    setup_ax(ax2,f"Average Queue Depth (bucket={a.time_bucket}s)","Time (s)","Avg QD"); ax2.legend()
    fig.tight_layout(); fig.savefig(os.path.join(od,"01_queue_depth.png"),dpi=150,bbox_inches="tight"); plt.close(fig)
    print("  Saved: 01_queue_depth.png")

def plot_lba_hotspots(a, od):
    fig = plt.figure(figsize=(14,10)); gs = GridSpec(2,2,figure=fig,hspace=0.35,wspace=0.3)
    ha,hr,hw,mx = a.compute_lba_heatmap()
    ax1 = fig.add_subplot(gs[0,:]); 
    if ha.max()>0:
        im = ax1.imshow(ha,aspect="auto",origin="lower",norm=LogNorm(vmin=max(1,ha[ha>0].min()),vmax=ha.max()),cmap="inferno",interpolation="nearest")
        plt.colorbar(im,ax=ax1,label="I/O Count (log)",shrink=0.8)
    gb = mx*SECTOR_SIZE/GB if isinstance(mx,(int,float,np.integer)) else 0
    setup_ax(ax1,f"LBA Access Heatmap (0-{gb:.1f} GB)","Time ->","LBA Range ->")
    bc,hr2,hw2 = a.compute_lba_histogram(); ax2=fig.add_subplot(gs[1,0]); bgb=bc*SECTOR_SIZE/GB
    w = (bgb[1]-bgb[0])*0.9 if len(bgb)>1 else 0.1
    if hr2.sum()>0: ax2.bar(bgb,hr2,width=w,color=COLORS["read"],alpha=0.7,label="Read")
    if hw2.sum()>0: ax2.bar(bgb,hw2,width=w,bottom=hr2,color=COLORS["write"],alpha=0.7,label="Write")
    setup_ax(ax2,"LBA Access Frequency","LBA Offset (GB)","I/O Count"); ax2.legend(fontsize=9)
    ax3=fig.add_subplot(gs[1,1]); ax3.axis("off"); comb=hr2+hw2
    top_idx=np.argsort(comb)[-min(10,len(comb)):][::-1]; td=[]
    for i,idx in enumerate(top_idx):
        if comb[idx]==0: break
        td.append([f"#{i+1}",f"{bgb[idx]:.2f} GB",f"{int(hr2[idx]):,}",f"{int(hw2[idx]):,}",f"{int(comb[idx]):,}"])
    if td:
        t=ax3.table(cellText=td,colLabels=["Rank","LBA Offset","Reads","Writes","Total"],loc="center",cellLoc="center")
        t.auto_set_font_size(False); t.set_fontsize(9); t.scale(1,1.4)
        ax3.set_title("Top LBA Hotspots",fontsize=13,fontweight="bold",pad=10)
    fig.savefig(os.path.join(od,"02_lba_hotspots.png"),dpi=150,bbox_inches="tight"); plt.close(fig)
    print("  Saved: 02_lba_hotspots.png")

def plot_io_sizes(a, od):
    fig,axes = plt.subplots(1,3,figsize=(16,5)); fig.suptitle("I/O Size Distribution",fontsize=15,fontweight="bold")
    rs,ws,als = a.compute_io_sizes()
    if als:
        mxs=max(als); be=[2**i for i in range(9,25) if 2**i<=mxs*2]
        if not be: be=[512,1024,4096,8192,16384,65536,131072,524288,1048576]
        bl = [f"{b//MB}M" if b>=MB else f"{b//KB}K" if b>=KB else f"{b}B" for b in be]
    for ax,(sizes,label,color) in zip(axes,[(als,"All I/O",COLORS["total"]),(rs,"Reads",COLORS["read"]),(ws,"Writes",COLORS["write"])]):
        if not sizes: ax.text(0.5,0.5,"No data",ha="center",va="center",transform=ax.transAxes); setup_ax(ax,label,"I/O Size","Count"); continue
        counts=defaultdict(int)
        for s in sizes:
            placed=False
            for i,b in enumerate(be):
                if s<=b: counts[i]+=1; placed=True; break
            if not placed: counts[len(be)-1]+=1
        h=[counts.get(i,0) for i in range(len(be))]
        ax.bar(range(len(be)),h,color=color,alpha=0.8,edgecolor="white")
        ax.set_xticks(range(len(be))); ax.set_xticklabels(bl,rotation=45,ha="right",fontsize=8)
        setup_ax(ax,label,"I/O Size","Count")
    fig.tight_layout(); fig.savefig(os.path.join(od,"03_io_sizes.png"),dpi=150,bbox_inches="tight"); plt.close(fig)
    print("  Saved: 03_io_sizes.png")

def plot_throughput(a, od):
    fig,(ax1,ax2) = plt.subplots(2,1,figsize=(14,8)); fig.suptitle("Storage Throughput & IOPS",fontsize=15,fontweight="bold")
    bt,rm,wm = a.compute_throughput()
    ax1.fill_between(bt,rm,alpha=0.3,color=COLORS["read"]); ax1.plot(bt,rm,lw=1,color=COLORS["read"],label="Read")
    ax1.fill_between(bt,wm,alpha=0.3,color=COLORS["write"]); ax1.plot(bt,wm,lw=1,color=COLORS["write"],label="Write")
    ax1.plot(bt,rm+wm,lw=1,color=COLORS["total"],ls="--",alpha=0.7,label="Total")
    setup_ax(ax1,f"Throughput (bucket={a.time_bucket}s)","","MB/s"); ax1.legend()
    bt,ri,wi = a.compute_iops()
    ax2.fill_between(bt,ri,alpha=0.3,color=COLORS["read"]); ax2.plot(bt,ri,lw=1,color=COLORS["read"],label="Read IOPS")
    ax2.fill_between(bt,wi,alpha=0.3,color=COLORS["write"]); ax2.plot(bt,wi,lw=1,color=COLORS["write"],label="Write IOPS")
    setup_ax(ax2,f"IOPS (bucket={a.time_bucket}s)","Time (s)","IOPS"); ax2.legend()
    fig.tight_layout(); fig.savefig(os.path.join(od,"04_throughput_iops.png"),dpi=150,bbox_inches="tight"); plt.close(fig)
    print("  Saved: 04_throughput_iops.png")

def plot_latency(a, od):
    lats = a.compute_latency_distributions()
    fig = plt.figure(figsize=(16,12)); gs = GridSpec(3,2,figure=fig,hspace=0.4,wspace=0.3)
    for col,(pfx,ttl) in enumerate([("q2c","Total Latency (Q->C)"),("d2c","Device Latency (D->C)")]):
        ax = fig.add_subplot(gs[0,col]); rd=lats[f"{pfx}_read"]; wd=lats[f"{pfx}_write"]
        if len(rd)>0: ax.hist(rd,bins=100,alpha=0.6,color=COLORS["read"],label=f"Read (n={len(rd):,})",density=True)
        if len(wd)>0: ax.hist(wd,bins=100,alpha=0.6,color=COLORS["write"],label=f"Write (n={len(wd):,})",density=True)
        setup_ax(ax,ttl,"Latency (us)","Density"); ax.legend(fontsize=9)
        ad = np.concatenate([d for d in [rd,wd] if len(d)>0]) if (len(rd)+len(wd))>0 else np.array([0])
        if len(ad)>10: ax.set_xlim(0,np.percentile(ad,99.5))
    for col,(pfx,ttl) in enumerate([("q2c","Q->C Latency CDF"),("d2c","D->C Latency CDF")]):
        ax = fig.add_subplot(gs[1,col])
        for data,label,color in [(lats[f"{pfx}_read"],"Read",COLORS["read"]),(lats[f"{pfx}_write"],"Write",COLORS["write"])]:
            if len(data)>0:
                sd=np.sort(data); cdf=np.arange(1,len(sd)+1)/len(sd)
                ax.plot(sd,cdf*100,lw=1.5,color=color,label=label)
                for pct,ls in [(50,"--"),(99,":")]:
                    v=np.percentile(data,pct); ax.axvline(v,color=color,ls=ls,alpha=0.5,lw=0.8)
                    ax.annotate(f"p{pct}={v:.0f}us",xy=(v,pct),fontsize=7,color=color,alpha=0.8)
        setup_ax(ax,ttl,"Latency (us)","Percentile (%)"); ax.legend(fontsize=9); ax.set_ylim(0,100)
    ax = fig.add_subplot(gs[2,:])
    t,p50r,p99r,p50w,p99w = a.compute_latency_over_time()
    mr=p50r>0; mw=p50w>0
    if mr.any(): ax.plot(t[mr],p50r[mr],lw=1,color=COLORS["read"],label="Read p50"); ax.plot(t[mr],p99r[mr],lw=1,color=COLORS["read"],ls="--",alpha=0.6,label="Read p99")
    if mw.any(): ax.plot(t[mw],p50w[mw],lw=1,color=COLORS["write"],label="Write p50"); ax.plot(t[mw],p99w[mw],lw=1,color=COLORS["write"],ls="--",alpha=0.6,label="Write p99")
    setup_ax(ax,"Latency Over Time (Device)","Time (s)","Latency (us)"); ax.legend(fontsize=9)
    fig.suptitle("Latency Analysis",fontsize=15,fontweight="bold",y=1.01)
    fig.savefig(os.path.join(od,"05_latency.png"),dpi=150,bbox_inches="tight"); plt.close(fig)
    print("  Saved: 05_latency.png")

# ═══ NEW IU/LBS CHARTS ═══════════════════════════════════════════════════════

def plot_iu_alignment(a, od):
    g = a.geom
    if not g.has_iu: return
    iu_sum = a.compute_iu_summary()
    if "iu" not in iu_sum: return
    iu = iu_sum["iu"]
    fig = plt.figure(figsize=(18,10)); gs = GridSpec(2,3,figure=fig,hspace=0.4,wspace=0.35)
    fig.suptitle(f"IU Alignment Analysis  (IU={g.iu_size}B={g.iu_size//KB}K, LBS={g.lbs}B)",fontsize=15,fontweight="bold")
    # Pie
    ax = fig.add_subplot(gs[0,0])
    pv = {f"Aligned\n({iu['iu_aligned_write_pct']:.1f}%)":iu["iu_aligned_writes"],
          f"Misaligned\n({iu['iu_crossing_write_pct']:.1f}%)":iu["iu_crossing_writes"],
          f"Sub-IU (RMW)\n({iu['sub_iu_pct']:.1f}%)":iu["sub_iu_writes"]}
    nz = {k:v for k,v in pv.items() if v>0}
    if nz:
        ax.pie(nz.values(),labels=nz.keys(),colors=[COLORS["aligned"],COLORS["misaligned"],COLORS["sub_iu"]][:len(nz)],
               autopct=lambda p:f"{int(p/100*sum(nz.values())):,}",textprops={"fontsize":9},startangle=90)
    ax.set_title("Write IU Alignment",fontsize=13,fontweight="bold")
    # Quantization
    ax = fig.add_subplot(gs[0,1:])
    labels,rc,wc = a.compute_iu_quantization_histogram()
    if labels:
        x=np.arange(len(labels)); w=0.35
        comb=[r+w2 for r,w2 in zip(rc,wc)]; last_nz=max((i for i,c in enumerate(comb) if c>0),default=0)
        show=min(last_nz+2,len(labels))
        ax.bar(x[:show]-w/2,rc[:show],w,color=COLORS["read"],alpha=0.8,label="Read")
        ax.bar(x[:show]+w/2,wc[:show],w,color=COLORS["write"],alpha=0.8,label="Write")
        ax.set_xticks(x[:show]); ax.set_xticklabels(labels[:show],fontsize=8)
        setup_ax(ax,"I/O Size Quantization by IU Multiples","I/O Size (IU units)","Count"); ax.legend(fontsize=9)
    # Crossings
    ax = fig.add_subplot(gs[1,0])
    results = a.analyze_iu_alignment()
    wc2 = [r.iu_crossings for r in results if not r.is_read]
    if wc2:
        mc=min(max(wc2),20); bins=np.arange(-0.5,mc+1.5,1)
        ax.hist(wc2,bins=bins,color=COLORS["misaligned"],alpha=0.8,edgecolor="white")
        setup_ax(ax,"IU Boundary Crossings per Write","Boundaries Crossed","Count"); ax.set_xticks(range(mc+1))
    # WAF over time
    ax = fig.add_subplot(gs[1,1])
    t,waf,sc = a.compute_waf_over_time(); mask=waf>0
    if mask.any():
        ax.plot(t[mask],waf[mask],lw=1,color=COLORS["waf"],label="WAF")
        ax.axhline(1.0,color=COLORS["aligned"],ls="--",alpha=0.5,label="Ideal (1.0)")
        mw=np.mean(waf[mask]); ax.axhline(mw,color=COLORS["waf"],ls=":",alpha=0.5,label=f"Mean ({mw:.3f})")
        setup_ax(ax,"Alignment-Induced WAF Over Time","Time (s)","WAF"); ax.legend(fontsize=9)
        ax.set_ylim(0.9,min(max(waf[mask])*1.1,3.0))
    # Summary table
    ax = fig.add_subplot(gs[1,2]); ax.axis("off")
    td = [["Total writes",f"{iu_sum['total_writes']:,}"],
          ["IU-aligned",f"{iu['iu_aligned_writes']:,} ({iu['iu_aligned_write_pct']:.1f}%)"],
          ["Sub-IU (RMW)",f"{iu['sub_iu_writes']:,} ({iu['sub_iu_pct']:.1f}%)"],
          ["Boundary-crossing",f"{iu['iu_crossing_writes']:,} ({iu['iu_crossing_write_pct']:.1f}%)"],
          ["Mean WAF (all)",f"{iu['mean_waf']:.4f}"],["Mean WAF (misaligned)",f"{iu['misaligned_mean_waf']:.4f}"],
          ["Max WAF (single I/O)",f"{iu['max_waf']:.2f}"]]
    t=ax.table(cellText=td,colLabels=["Metric","Value"],loc="center",cellLoc="left")
    t.auto_set_font_size(False); t.set_fontsize(10); t.scale(1.2,1.6)
    for (r,c),cell in t.get_celld().items():
        if r==0: cell.set_facecolor("#E0E0E0"); cell.set_text_props(fontweight="bold")
    ax.set_title("IU Alignment Summary",fontsize=13,fontweight="bold",pad=15)
    fig.savefig(os.path.join(od,"06_iu_alignment.png"),dpi=150,bbox_inches="tight"); plt.close(fig)
    print("  Saved: 06_iu_alignment.png")

def plot_npwg_awun_analysis(a, od):
    g = a.geom
    if not g.has_npwg and not g.has_awun: return
    iu_sum = a.compute_iu_summary()
    n_rows = sum(1 for k in ["npwg","awun"] if k in iu_sum)
    if n_rows==0: return
    fig = plt.figure(figsize=(16,5*n_rows+1)); gs = GridSpec(n_rows,3,figure=fig,hspace=0.45,wspace=0.35)
    tp = []
    if g.has_npwg: tp.append(f"NPWG={g.npwg//KB}K")
    if g.has_awun: tp.append(f"AWUN={g.awun//KB}K")
    fig.suptitle(f"NPWG / AWUN Analysis  ({', '.join(tp)})",fontsize=15,fontweight="bold")
    row=0; results=a.analyze_iu_alignment(); writes=[r for r in results if not r.is_read]
    if "npwg" in iu_sum:
        npwg=iu_sum["npwg"]
        ax=fig.add_subplot(gs[row,0])
        pv = {f"Fully aligned\n({npwg['fully_aligned_pct']:.1f}%)":npwg["fully_aligned_writes"],
              f"Size-only\n({npwg['size_aligned_only_pct']:.1f}%)":npwg["size_aligned_only"],
              f"Unaligned\n({npwg['unaligned_pct']:.1f}%)":npwg["unaligned_writes"]}
        nz={k:v for k,v in pv.items() if v>0}
        if nz: ax.pie(nz.values(),labels=nz.keys(),colors=[COLORS["aligned"],"#FFC107",COLORS["misaligned"]][:len(nz)],
                       autopct=lambda p:f"{int(p/100*sum(nz.values())):,}",textprops={"fontsize":9},startangle=90)
        ax.set_title("NPWG Write Alignment",fontsize=13,fontweight="bold")
        ax=fig.add_subplot(gs[row,1])
        nt=[r.npwg_units_touched for r in writes]
        if nt:
            mc=min(max(nt),32); bins=np.arange(0.5,mc+1.5,1)
            ax.hist(nt,bins=bins,color=COLORS["misaligned"],alpha=0.8,edgecolor="white")
            setup_ax(ax,f"NPWG Units Touched per Write\n(1 unit = {g.npwg//KB}K)","NPWG Units","Count")
        ax=fig.add_subplot(gs[row,2])
        al_s=[r.size_bytes/KB for r in writes if r.npwg_aligned and r.npwg_start_aligned]
        un_s=[r.size_bytes/KB for r in writes if not (r.npwg_aligned and r.npwg_start_aligned)]
        if al_s: ax.hist(al_s,bins=50,alpha=0.6,color=COLORS["aligned"],label=f"Aligned (n={len(al_s):,})",density=True)
        if un_s: ax.hist(un_s,bins=50,alpha=0.6,color=COLORS["misaligned"],label=f"Unaligned (n={len(un_s):,})",density=True)
        setup_ax(ax,"Write Size: NPWG Aligned vs Not","Write Size (KB)","Density"); ax.legend(fontsize=8)
        for m in range(1,5): ax.axvline(m*g.npwg/KB,color=COLORS["aligned"],ls=":",alpha=0.3,lw=1)
        row+=1
    if "awun" in iu_sum:
        awun=iu_sum["awun"]
        ax=fig.add_subplot(gs[row,0])
        pv={f"Safe\n({awun['safe_pct']:.1f}%)":awun["safe_writes"],f"Unsafe\n({awun['unsafe_pct']:.1f}%)":awun["unsafe_writes"]}
        nz={k:v for k,v in pv.items() if v>0}
        if nz: ax.pie(nz.values(),labels=nz.keys(),colors=[COLORS["safe"],COLORS["unsafe"]][:len(nz)],
                       autopct=lambda p:f"{int(p/100*sum(nz.values())):,}",textprops={"fontsize":10},startangle=90)
        ax.set_title("Atomic Write Safety (AWUN)",fontsize=13,fontweight="bold")
        ax=fig.add_subplot(gs[row,1])
        ac=[r.awun_crossings for r in writes]
        if ac:
            mc=min(max(ac),16); bins=np.arange(-0.5,mc+1.5,1)
            ax.hist(ac,bins=bins,color=COLORS["unsafe"],alpha=0.8,edgecolor="white")
            setup_ax(ax,f"AWUN Boundary Crossings\n(AWUN={g.awun//KB}K)","Boundaries Crossed","Write Count")
        ax=fig.add_subplot(gs[row,2])
        n=max(1,int(np.ceil(a.duration/a.time_bucket)))
        sc,uc=np.zeros(n),np.zeros(n)
        for r in writes:
            i=min(int((r.timestamp-a.t0)/a.time_bucket),n-1)
            if r.awun_safe: sc[i]+=1
            else: uc[i]+=1
        bt=np.arange(n)*a.time_bucket
        ax.fill_between(bt,sc/a.time_bucket,alpha=0.3,color=COLORS["safe"])
        ax.plot(bt,sc/a.time_bucket,lw=1,color=COLORS["safe"],label="Safe")
        ax.fill_between(bt,uc/a.time_bucket,alpha=0.3,color=COLORS["unsafe"])
        ax.plot(bt,uc/a.time_bucket,lw=1,color=COLORS["unsafe"],label="Unsafe")
        setup_ax(ax,"Atomic-Safe vs Unsafe Write Rate","Time (s)","Writes/s"); ax.legend(fontsize=9)
    fig.savefig(os.path.join(od,"07_npwg_awun.png"),dpi=150,bbox_inches="tight"); plt.close(fig)
    print("  Saved: 07_npwg_awun.png")

def plot_alignment_latency_correlation(a, od):
    g = a.geom
    if not g.has_iu: return
    corr = a.compute_alignment_vs_latency()
    al=corr.get("aligned",np.array([])); ml=corr.get("misaligned",np.array([])); sl=corr.get("sub_iu",np.array([]))
    if len(al)==0 and len(ml)==0: return
    fig,axes = plt.subplots(1,3,figsize=(18,6))
    fig.suptitle(f"IU Alignment <-> Write Latency Correlation  (IU={g.iu_size//KB}K)",fontsize=15,fontweight="bold")
    ax=axes[0]
    if len(al)>0: ax.hist(al,bins=80,alpha=0.6,color=COLORS["aligned"],label=f"Aligned (n={len(al):,})",density=True)
    if len(ml)>0: ax.hist(ml,bins=80,alpha=0.6,color=COLORS["misaligned"],label=f"Misaligned (n={len(ml):,})",density=True)
    setup_ax(ax,"Write Latency: Aligned vs Misaligned","D->C Latency (us)","Density"); ax.legend(fontsize=9)
    ad=np.concatenate([d for d in [al,ml] if len(d)>0])
    if len(ad)>10: ax.set_xlim(0,np.percentile(ad,99.5))
    ax=axes[1]
    for data,label,color in [(al,"Aligned",COLORS["aligned"]),(ml,"Misaligned",COLORS["misaligned"]),(sl,"Sub-IU (RMW)",COLORS["sub_iu"])]:
        if len(data)>0:
            sd=np.sort(data); cdf=np.arange(1,len(sd)+1)/len(sd)
            ax.plot(sd,cdf*100,lw=1.5,color=color,label=label)
    setup_ax(ax,"Latency CDF by Alignment","D->C Latency (us)","Percentile (%)"); ax.legend(fontsize=9); ax.set_ylim(0,100)
    ax=axes[2]; ax.axis("off"); td=[]
    for data,label in [(al,"Aligned"),(ml,"Misaligned"),(sl,"Sub-IU")]:
        if len(data)>0:
            td.append([label,f"{len(data):,}",f"{np.median(data):.0f}",f"{np.percentile(data,95):.0f}",f"{np.percentile(data,99):.0f}",f"{np.max(data):.0f}"])
    if td:
        t=ax.table(cellText=td,colLabels=["Category","Count","p50 (us)","p95 (us)","p99 (us)","Max (us)"],loc="center",cellLoc="center")
        t.auto_set_font_size(False); t.set_fontsize(10); t.scale(1.2,1.8)
        for (r,c),cell in t.get_celld().items():
            if r==0: cell.set_facecolor("#E0E0E0"); cell.set_text_props(fontweight="bold")
    ax.set_title("Latency by Alignment Category",fontsize=13,fontweight="bold",pad=15)
    fig.tight_layout(); fig.savefig(os.path.join(od,"08_alignment_latency.png"),dpi=150,bbox_inches="tight"); plt.close(fig)
    print("  Saved: 08_alignment_latency.png")

def plot_combined_dashboard(a, od):
    has_iu = a.geom.has_iu
    fig = plt.figure(figsize=(20,18 if has_iu else 14))
    nr = 4 if has_iu else 3; gs = GridSpec(nr,3,figure=fig,hspace=0.4,wspace=0.35)
    # Row 0
    ax=fig.add_subplot(gs[0,0]); bt,at2,ar2,aw2=a.compute_queue_depth_bucketed()
    ax.plot(bt,at2,lw=1,color=COLORS["total"]); ax.fill_between(bt,at2,alpha=0.2,color=COLORS["total"])
    setup_ax(ax,"Queue Depth","Time (s)","QD")
    ax=fig.add_subplot(gs[0,1]); bt,rm,wm=a.compute_throughput()
    ax.plot(bt,rm,color=COLORS["read"],lw=1,label="Read"); ax.plot(bt,wm,color=COLORS["write"],lw=1,label="Write")
    setup_ax(ax,"Throughput","Time (s)","MB/s"); ax.legend(fontsize=8)
    ax=fig.add_subplot(gs[0,2]); bt,ri,wi=a.compute_iops()
    ax.plot(bt,ri,color=COLORS["read"],lw=1,label="Read"); ax.plot(bt,wi,color=COLORS["write"],lw=1,label="Write")
    setup_ax(ax,"IOPS","Time (s)","IOPS"); ax.legend(fontsize=8)
    # Row 1
    ax=fig.add_subplot(gs[1,:2]); ha,_,_,mx=a.compute_lba_heatmap()
    if isinstance(ha,np.ndarray) and ha.max()>0:
        im=ax.imshow(ha,aspect="auto",origin="lower",norm=LogNorm(vmin=max(1,ha[ha>0].min()),vmax=ha.max()),cmap="inferno",interpolation="nearest")
        plt.colorbar(im,ax=ax,shrink=0.8)
    setup_ax(ax,"LBA Heatmap","Time ->","LBA ->")
    ax=fig.add_subplot(gs[1,2]); _,_,als=a.compute_io_sizes()
    if als:
        sb={"<=4K":0,"4K-16K":0,"16K-128K":0,"128K-1M":0,">1M":0}
        for s in als:
            if s<=4*KB: sb["<=4K"]+=1
            elif s<=16*KB: sb["4K-16K"]+=1
            elif s<=128*KB: sb["16K-128K"]+=1
            elif s<=MB: sb["128K-1M"]+=1
            else: sb[">1M"]+=1
        nz={k:v for k,v in sb.items() if v>0}
        if nz: ax.pie(nz.values(),labels=nz.keys(),autopct="%1.1f%%",textprops={"fontsize":9})
    ax.set_title("I/O Size Distribution",fontsize=13,fontweight="bold")
    # Row 2
    ax=fig.add_subplot(gs[2,0]); lats=a.compute_latency_distributions()
    for data,label,color in [(lats["d2c_read"],"Read D2C",COLORS["read"]),(lats["d2c_write"],"Write D2C",COLORS["write"])]:
        if len(data)>0:
            sd=np.sort(data); cdf=np.arange(1,len(sd)+1)/len(sd); ax.plot(sd,cdf*100,lw=1.5,color=color,label=label)
    setup_ax(ax,"Latency CDF (D->C)","Latency (us)","Percentile"); ax.legend(fontsize=8); ax.set_ylim(0,100)
    ax=fig.add_subplot(gs[2,1:])
    t2,p50r,p99r,p50w,p99w=a.compute_latency_over_time(); mr=p50r>0; mw=p50w>0
    if mr.any(): ax.plot(t2[mr],p50r[mr],color=COLORS["read"],lw=1,label="Read p50"); ax.fill_between(t2[mr],p50r[mr],p99r[mr],color=COLORS["read"],alpha=0.15)
    if mw.any(): ax.plot(t2[mw],p50w[mw],color=COLORS["write"],lw=1,label="Write p50"); ax.fill_between(t2[mw],p50w[mw],p99w[mw],color=COLORS["write"],alpha=0.15)
    setup_ax(ax,"Latency Over Time (p50->p99)","Time (s)","Latency (us)"); ax.legend(fontsize=8)
    # Row 3: IU
    if has_iu:
        ax=fig.add_subplot(gs[3,0]); tw,waf,_=a.compute_waf_over_time(); mask=waf>0
        if mask.any(): ax.plot(tw[mask],waf[mask],lw=1,color=COLORS["waf"]); ax.axhline(1.0,color=COLORS["aligned"],ls="--",alpha=0.5)
        setup_ax(ax,"Alignment WAF","Time (s)","WAF")
        ax=fig.add_subplot(gs[3,1]); iu_sum=a.compute_iu_summary()
        if "iu" in iu_sum:
            iu=iu_sum["iu"]; vals=[iu["iu_aligned_writes"],max(0,iu_sum["total_writes"]-iu["iu_aligned_writes"]-iu["sub_iu_writes"]),iu["sub_iu_writes"]]
            lbls=["Aligned","Misaligned","Sub-IU"]; cols=[COLORS["aligned"],COLORS["misaligned"],COLORS["sub_iu"]]
            nzi=[i for i,v in enumerate(vals) if v>0]
            if nzi: ax.pie([vals[i] for i in nzi],labels=[lbls[i] for i in nzi],colors=[cols[i] for i in nzi],autopct="%1.1f%%",textprops={"fontsize":9})
        ax.set_title("IU Alignment (Writes)",fontsize=13,fontweight="bold")
        ax=fig.add_subplot(gs[3,2]); corr=a.compute_alignment_vs_latency()
        for data,label,color in [(corr.get("aligned",np.array([])),"Aligned",COLORS["aligned"]),(corr.get("misaligned",np.array([])),"Misaligned",COLORS["misaligned"])]:
            if len(data)>0: sd=np.sort(data); cdf=np.arange(1,len(sd)+1)/len(sd); ax.plot(sd,cdf*100,lw=1.5,color=color,label=label)
        setup_ax(ax,"Latency: Aligned vs Misaligned","D->C Latency (us)","Percentile"); ax.legend(fontsize=8); ax.set_ylim(0,100)
    fig.suptitle("blktrace Analysis Dashboard",fontsize=18,fontweight="bold",y=1.01)
    fig.savefig(os.path.join(od,"00_dashboard.png"),dpi=150,bbox_inches="tight"); plt.close(fig)
    print("  Saved: 00_dashboard.png")

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="blktrace Analyzer with IU/LBS Atomics-Aware SSD Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 blktrace_analyzer.py trace.txt
  python3 blktrace_analyzer.py trace.txt --lbs 512 --iu-size 4096 --npwg 16384 --awun 16384
  python3 blktrace_analyzer.py --show-nvme-commands
""")
    parser.add_argument("trace_file", nargs="?", help="Path to blkparse text output")
    g = parser.add_argument_group("SSD Geometry")
    g.add_argument("--lbs",type=int,default=512,help="Logical Block Size in bytes (default:512)")
    g.add_argument("--iu-size",type=int,default=0,help="Indirection Unit size in bytes")
    g.add_argument("--npwg",type=int,default=0,help="Namespace Preferred Write Granularity bytes")
    g.add_argument("--npwa",type=int,default=0,help="Namespace Preferred Write Alignment bytes")
    g.add_argument("--npdg",type=int,default=0,help="Namespace Preferred Deallocate Granularity bytes")
    g.add_argument("--awun",type=int,default=0,help="Atomic Write Unit Normal bytes")
    g.add_argument("--awupf",type=int,default=0,help="Atomic Write Unit Power Fail bytes")
    g.add_argument("--nand-page",type=int,default=0,help="NAND page size bytes")
    g.add_argument("--device",type=str,default="",help="Device name for labeling")
    g.add_argument("--geometry-json",type=str,default="",help="Load geometry from JSON file")
    parser.add_argument("--time-bucket",type=float,default=0.1,help="Time bucket seconds (default:0.1)")
    parser.add_argument("--lba-bins",type=int,default=256,help="LBA bins for heatmap (default:256)")
    parser.add_argument("--lba-start-only", action="store_true",
                        help="Bin LBA by start sector only (disable full-extent mapping)")
    parser.add_argument("--output-dir",default="./blktrace_results",help="Output directory")
    parser.add_argument("--no-dashboard",action="store_true")
    parser.add_argument("--summary-only",action="store_true")
    parser.add_argument("--show-nvme-commands",action="store_true",help="Show NVMe geometry extraction commands")
    parser.add_argument("--save-geometry",type=str,default="",help="Save geometry to JSON")
    args = parser.parse_args()

    if args.show_nvme_commands:
        print("""
========================================================================
  NVMe SSD Geometry Extraction Commands
========================================================================

Step 1: Identify your device
  lsblk
  nvme list

Step 2: Get namespace details
  sudo nvme id-ns /dev/nvme0n1 -H | grep -E "LBA Format|NPWG|NPWA|NPDG|NAWUN|NAWUPF|lbads|^nsze"

Step 3: Interpret output (NVMe reports 0-based values)
  Actual size = (reported_value + 1) * LBS

  LBA Format  0 : Data Size: 512 bytes   -> --lbs 512
  LBA Format  1 : Data Size: 4096 bytes  -> --lbs 4096
  NPWG  : 3   -> (3+1)*512  = 2048       -> --npwg 2048
  NAWUN : 31  -> (31+1)*512 = 16384      -> --awun 16384

Step 4: For IU (not directly in NVMe spec for most drives)
  Common defaults: 4096 for most modern NVMe SSDs
  Check vendor datasheets:
    Samsung PM9A3/PM9D3:  IU=4096
    Intel P5316/D7-P5620: IU=4096
    Kioxia CM7/CD8:       IU=4096

Step 5: Quick extraction script
  #!/bin/bash
  DEV=/dev/nvme0n1
  LBS=$(sudo nvme id-ns $DEV -H | grep "in use" | grep -oP "Data Size: \K[0-9]+")
  NPWG_RAW=$(sudo nvme id-ns $DEV | grep npwg | awk '{print $NF}')
  NPWG=$(( (NPWG_RAW + 1) * LBS ))
  AWUN_RAW=$(sudo nvme id-ns $DEV | grep nawun | awk '{print $NF}')
  AWUN=$(( (AWUN_RAW + 1) * LBS ))
  echo "--lbs $LBS --iu-size 4096 --npwg $NPWG --awun $AWUN"

Step 6: Run analyzer
  python3 blktrace_analyzer.py trace.txt --lbs 512 --iu-size 4096 \\
      --npwg 16384 --npdg 16384 --awun 16384 --device /dev/nvme0n1
""")
        sys.exit(0)

    if not args.trace_file: parser.error("trace_file is required (or use --show-nvme-commands)")

    geom = SSDGeometry()
    if args.geometry_json:
        with open(args.geometry_json) as f:
            gj = json.load(f)
        for k,v in gj.items():
            if hasattr(geom,k): setattr(geom,k,v)
    else:
        geom.lbs=args.lbs; geom.iu_size=args.iu_size; geom.npwg=args.npwg; geom.npwa=args.npwa
        geom.npdg=args.npdg; geom.awun=args.awun; geom.awupf=args.awupf
        geom.nand_page=args.nand_page; geom.device_name=args.device

    if args.save_geometry:
        with open(args.save_geometry,"w") as f:
            json.dump({k:v for k,v in geom.__dict__.items() if not k.startswith("_")},f,indent=2)
        print(f"  Saved geometry: {args.save_geometry}")

    global SECTOR_SIZE; SECTOR_SIZE = geom.lbs

    print(f"\n{'='*72}\n  blktrace Analyzer (IU/LBS-Aware)\n{'='*72}")
    if geom.has_iu or geom.has_npwg or geom.has_awun:
        print(f"\n  {geom.summary()}")
    print(f"\n  Loading: {args.trace_file}")

    events = load_trace(args.trace_file)
    if not events: print("\n  ERROR: No parseable events found."); sys.exit(1)

    analyzer = BlktraceAnalyzer(events, time_bucket=args.time_bucket,
                                 lba_bins=args.lba_bins, geometry=geom,
				 lba_extent=not args.lba_start_only)
    analyzer.print_summary()
    if args.summary_only: return

    os.makedirs(args.output_dir, exist_ok=True)
    print(f"\n  Generating charts in: {args.output_dir}/\n")

    if not args.no_dashboard: plot_combined_dashboard(analyzer, args.output_dir)
    plot_queue_depth(analyzer, args.output_dir)
    plot_lba_hotspots(analyzer, args.output_dir)
    plot_io_sizes(analyzer, args.output_dir)
    plot_throughput(analyzer, args.output_dir)
    plot_latency(analyzer, args.output_dir)
    if geom.has_iu: plot_iu_alignment(analyzer, args.output_dir)
    if geom.has_npwg or geom.has_awun: plot_npwg_awun_analysis(analyzer, args.output_dir)
    if geom.has_iu: plot_alignment_latency_correlation(analyzer, args.output_dir)

    print(f"\n  All charts saved to: {args.output_dir}/")
    for f in sorted(os.listdir(args.output_dir)):
        if f.endswith(".png"):
            sz = os.path.getsize(os.path.join(args.output_dir,f))/1024
            print(f"    {f} ({sz:.0f} KB)")
    print()

if __name__ == "__main__":
    main()
