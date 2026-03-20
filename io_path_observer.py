#!/usr/bin/env python3
"""
I/O Path Observability Flow with FIO Configuration
====================================================
A tool to trace the full I/O path from syscall → fd → procfs → page monitoring.

Workflow:
  1. Identify the Syscall   – eBPF/strace to catch mmap/open syscalls
  2. Extract FD and Length  – Parse file descriptor and memory length from args
  3. Cross-Reference Procfs – Map FD → address range via /proc/<pid>/maps
  4. Monitor with PageMon   – Watch address ranges for real-time page flushes

Usage:
  # Trace ALL processes named 'fio' (easiest — catches all workers)
  python3 io_path_observer.py --trace --comm fio --duration 15

  # Launch FIO and trace from birth (guaranteed fork capture)
  python3 io_path_observer.py --trace --launch 'fio job.fio' --duration 15

  # Trace a specific PID with auto fork tracking
  python3 io_path_observer.py --trace --pid <PID> --duration 30

  # Generate FIO config and run observability pipeline
  python3 io_path_observer.py --generate-fio
  python3 io_path_observer.py --demo

Requirements:
  - Linux with /proc filesystem
  - bcc/BPF tools (for eBPF tracing)
  - strace (fallback)
  - fio (for workload generation)
  - Root privileges for eBPF and /proc access
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import textwrap
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional


# =============================================================================
# Data Models
# =============================================================================

class SyscallType(Enum):
    MMAP = "mmap"
    OPEN = "open"
    OPENAT = "openat"
    READ = "read"
    WRITE = "write"
    PREAD64 = "pread64"
    PWRITE64 = "pwrite64"
    FSYNC = "fsync"
    FDATASYNC = "fdatasync"
    MSYNC = "msync"


@dataclass
class SyscallEvent:
    """Captured syscall event from eBPF or strace."""
    timestamp: float
    pid: int
    tid: int
    syscall: str
    fd: int = -1
    offset: int = 0
    length: int = 0
    address: int = 0
    flags: str = ""
    return_value: int = 0
    latency_us: float = 0.0
    filename: str = ""
    comm: str = ""  # process name (e.g. "fio")


@dataclass
class ForkEvent:
    """A fork/clone event linking parent → child."""
    timestamp: float
    parent_pid: int
    child_pid: int
    parent_comm: str = ""
    child_comm: str = ""


@dataclass
class MemoryMapping:
    """A memory mapping from /proc/<pid>/maps."""
    start_addr: int
    end_addr: int
    permissions: str
    offset: int
    device: str
    inode: int
    pathname: str

    @property
    def size(self) -> int:
        return self.end_addr - self.start_addr

    @property
    def is_file_backed(self) -> bool:
        return bool(self.pathname) and not self.pathname.startswith("[")


@dataclass
class PageMonEvent:
    """Page-level monitoring event."""
    timestamp: float
    pid: int
    address: int
    page_count: int
    event_type: str  # "dirty", "writeback", "clean"
    mapping_file: str


@dataclass
class IOTraceRecord:
    """Complete I/O trace linking all 4 steps."""
    syscall_event: SyscallEvent
    fd_info: dict
    memory_mapping: Optional[MemoryMapping]
    page_events: list = field(default_factory=list)


# =============================================================================
# Step 0: FIO Configuration Generator
# =============================================================================

class FIOConfigGenerator:
    """Generate FIO job files for various I/O workload patterns."""

    # Predefined workload profiles relevant to storage I/O characterization
    PROFILES = {
        "sequential_read": {
            "description": "Sequential read - baseline throughput measurement",
            "rw": "read",
            "bs": "128k",
            "iodepth": 32,
            "direct": 1,
            "numjobs": 1,
        },
        "sequential_write": {
            "description": "Sequential write - writeback/flush characterization",
            "rw": "write",
            "bs": "128k",
            "iodepth": 32,
            "direct": 1,
            "numjobs": 1,
        },
        "random_read_4k": {
            "description": "Random 4K read - IOPS and latency profiling",
            "rw": "randread",
            "bs": "4k",
            "iodepth": 64,
            "direct": 1,
            "numjobs": 4,
        },
        "random_write_4k": {
            "description": "Random 4K write - write amplification analysis",
            "rw": "randwrite",
            "bs": "4k",
            "iodepth": 64,
            "direct": 1,
            "numjobs": 4,
        },
        "mmap_seq_read": {
            "description": "mmap sequential read - page fault tracing",
            "rw": "read",
            "bs": "4k",
            "iodepth": 1,
            "direct": 0,        # Buffered I/O (uses page cache)
            "ioengine": "mmap",  # mmap engine to generate mmap syscalls
            "numjobs": 1,
        },
        "mmap_rand_write": {
            "description": "mmap random write - dirty page / msync tracing",
            "rw": "randwrite",
            "bs": "4k",
            "iodepth": 1,
            "direct": 0,
            "ioengine": "mmap",
            "numjobs": 1,
        },
        "mixed_rw_buffered": {
            "description": "Mixed buffered R/W - page cache behavior analysis",
            "rw": "randrw",
            "rwmixread": 70,
            "bs": "8k",
            "iodepth": 16,
            "direct": 0,
            "numjobs": 2,
        },
        "sync_heavy_write": {
            "description": "fsync-heavy write - journal/WAL pattern (DB-like)",
            "rw": "write",
            "bs": "16k",
            "iodepth": 1,
            "direct": 0,
            "fsync": 1,          # fsync after every write
            "numjobs": 1,
        },
    }

    def __init__(self, output_dir: str = "./fio_jobs", target_file: str = "/tmp/fio_testfile",
                 file_size: str = "1G", runtime: str = "30"):
        self.output_dir = Path(output_dir)
        self.target_file = target_file
        self.file_size = file_size
        self.runtime = runtime

    def generate_job_file(self, profile_name: str, custom_params: dict = None) -> Path:
        """Generate a single FIO job file for a given profile."""
        if profile_name not in self.PROFILES:
            raise ValueError(f"Unknown profile: {profile_name}. "
                             f"Available: {list(self.PROFILES.keys())}")

        profile = self.PROFILES[profile_name].copy()
        desc = profile.pop("description")
        if custom_params:
            profile.update(custom_params)

        self.output_dir.mkdir(parents=True, exist_ok=True)
        job_path = self.output_dir / f"{profile_name}.fio"

        ioengine = profile.pop("ioengine", None)
        lines = [
            f"# FIO Job: {profile_name}",
            f"# {desc}",
            f"# Generated: {datetime.now().isoformat()}",
            "",
            "[global]",
            f"filename={self.target_file}",
            f"size={self.file_size}",
            f"runtime={self.runtime}",
            "time_based",
            "group_reporting",
            "log_avg_msec=1000",
            f"write_bw_log={profile_name}",
            f"write_lat_log={profile_name}",
            f"write_iops_log={profile_name}",
            "",
            f"[{profile_name}]",
        ]

        if ioengine:
            lines.append(f"ioengine={ioengine}")
        else:
            lines.append("ioengine=libaio")

        for key, value in profile.items():
            lines.append(f"{key}={value}")

        job_path.write_text("\n".join(lines) + "\n")
        return job_path

    def generate_all(self) -> list:
        """Generate FIO job files for all predefined profiles."""
        generated = []
        for name in self.PROFILES:
            path = self.generate_job_file(name)
            generated.append((name, path))
        return generated

    def generate_combined_job(self) -> Path:
        """Generate a single FIO file with multiple job sections for comparison."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        combined_path = self.output_dir / "combined_io_profiles.fio"

        lines = [
            "# Combined FIO Job - All I/O Profiles for Observability Testing",
            f"# Generated: {datetime.now().isoformat()}",
            "# Run profiles individually by name: fio combined_io_profiles.fio --section=<name>",
            "",
            "[global]",
            f"filename={self.target_file}",
            f"size={self.file_size}",
            f"runtime={self.runtime}",
            "time_based",
            "group_reporting",
            "",
        ]

        for name, profile in self.PROFILES.items():
            desc = profile.get("description", "")
            lines.append(f"# --- {desc} ---")
            lines.append(f"[{name}]")
            lines.append("stonewall")  # Run sequentially

            ioengine = profile.get("ioengine", "libaio")
            lines.append(f"ioengine={ioengine}")

            for key, value in profile.items():
                if key in ("description", "ioengine"):
                    continue
                lines.append(f"{key}={value}")
            lines.append("")

        combined_path.write_text("\n".join(lines) + "\n")
        return combined_path

    @staticmethod
    def get_fio_run_command(job_file: str, output_json: bool = True) -> str:
        """Return the shell command to run a FIO job with tracing-friendly options."""
        cmd = f"sudo fio {job_file}"
        if output_json:
            cmd += f" --output-format=json --output={job_file}.results.json"
        return cmd


# =============================================================================
# Step 1: Syscall Identification (eBPF + strace)
# =============================================================================

class SyscallTracer:
    """Capture mmap, open, read, write, fsync syscalls via eBPF or strace."""

    # BPF program source for tracing mmap, open, read, write, fsync syscalls
    # WITH automatic fork/clone child PID tracking via sched:sched_process_fork.
    #
    # Instead of a hardcoded `if (pid != TARGET) return 0;` filter, we use a
    # BPF_HASH(tracked_pids) that is seeded with the initial target PID and
    # auto-expands whenever a tracked process forks a child. This solves the
    # FIO forking problem where child workers perform the actual mmap I/O but
    # the parent-only tracer misses all their syscalls and file names.
    BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/mm.h>

/* ── Tracked PID set ──
 * Key = PID (u32), Value = 1 if tracked.
 * Seeded by userspace with the initial target PID.
 * Auto-expanded by the fork probe when a tracked parent forks.
 * When FILTER_MODE is 0 (no filter), the lookup is skipped entirely.
 */
BPF_HASH(tracked_pids, u32, u8, 1024);

/* Helper macro: check if current pid is tracked.
 * Replaced at compile time by _build_bpf_source():
 *   FILTER_MODE=1 → check tracked_pids hash
 *   FILTER_MODE=0 → allow all (no replacement needed, macro is empty)
 */
FILTER_PID_DEFINE

/* ── Event structures ── */

struct fork_event_t {
    u64 timestamp;
    u32 parent_pid;
    u32 child_pid;
    char parent_comm[16];
    char child_comm[16];
};

struct mmap_event_t {
    u64 timestamp;
    u32 pid;
    u32 tid;
    u64 addr;
    u64 length;
    u32 prot;
    u32 flags;
    s32 fd;
    u64 offset;
    s64 ret;
    char comm[16];
};

struct open_event_t {
    u64 timestamp;
    u32 pid;
    u32 tid;
    s32 fd;
    u32 flags;
    char filename[256];
    char comm[16];
};

struct rw_event_t {
    u64 timestamp;
    u32 pid;
    u32 tid;
    s32 fd;
    u64 count;
    u64 offset;
    s64 ret;
    u8  is_write;
    char comm[16];
};

struct sync_event_t {
    u64 timestamp;
    u32 pid;
    u32 tid;
    s32 fd;
    s64 ret;
    u64 latency_ns;
    char comm[16];
};

BPF_PERF_OUTPUT(fork_events);
BPF_PERF_OUTPUT(mmap_events);
BPF_PERF_OUTPUT(open_events);
BPF_PERF_OUTPUT(rw_events);
BPF_PERF_OUTPUT(sync_events);

BPF_HASH(start_ts, u64, u64);

/* Temporary storage for mmap enter args so exit can emit the full event */
struct mmap_args_t {
    u64 addr;
    u64 length;
    u32 prot;
    u32 flags;
    s32 fd;
    u64 offset;
};
BPF_HASH(mmap_args_map, u64, struct mmap_args_t);

/* ══════════════════════════════════════════════════════════════════════
 * Fork/Clone Tracking
 *
 * sched:sched_process_fork fires for fork(), vfork(), clone(), clone3().
 * When the parent PID is in tracked_pids, auto-add the child PID so
 * all subsequent syscalls from the child are also captured.
 * ══════════════════════════════════════════════════════════════════════ */

TRACEPOINT_PROBE(sched, sched_process_fork) {
    u32 parent_pid = args->parent_pid;
    u32 child_pid  = args->child_pid;

    /* Only track children of already-tracked parents */
    CHECK_PARENT_TRACKED

    /* Auto-register child PID in the tracked set */
    u8 val = 1;
    tracked_pids.update(&child_pid, &val);

    /* Emit fork event to userspace */
    struct fork_event_t event = {};
    event.timestamp  = bpf_ktime_get_ns();
    event.parent_pid = parent_pid;
    event.child_pid  = child_pid;
    bpf_get_current_comm(&event.parent_comm, sizeof(event.parent_comm));
    /* child_comm won't be set yet (still parent's comm at fork time) */
    fork_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * mmap tracing (enter + exit for return address capture)
 * ══════════════════════════════════════════════════════════════════════ */

TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID

    u64 tid = bpf_get_current_pid_tgid();
    struct mmap_args_t margs = {};
    margs.addr   = args->addr;
    margs.length = args->len;
    margs.prot   = args->prot;
    margs.flags  = args->flags;
    margs.fd     = args->fd;
    margs.offset = args->off;
    mmap_args_map.update(&tid, &margs);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_mmap) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID

    u64 tid = bpf_get_current_pid_tgid();
    struct mmap_args_t *margs = mmap_args_map.lookup(&tid);
    if (!margs) return 0;

    struct mmap_event_t event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = pid;
    event.tid = (u32)tid;
    event.addr   = margs->addr;
    event.length = margs->length;
    event.prot   = margs->prot;
    event.flags  = margs->flags;
    event.fd     = margs->fd;
    event.offset = margs->offset;
    event.ret    = args->ret;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    mmap_events.perf_submit(args, &event, sizeof(event));
    mmap_args_map.delete(&tid);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * openat tracing
 * ══════════════════════════════════════════════════════════════════════ */

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID

    struct open_event_t event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = pid;
    event.tid = bpf_get_current_pid_tgid();
    event.flags = args->flags;
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    open_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * read/write tracing
 * ══════════════════════════════════════════════════════════════════════ */

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID

    struct rw_event_t event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = pid;
    event.tid = bpf_get_current_pid_tgid();
    event.fd    = args->fd;
    event.count = args->count;
    event.is_write = 0;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    rw_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID

    struct rw_event_t event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = pid;
    event.tid = bpf_get_current_pid_tgid();
    event.fd    = args->fd;
    event.count = args->count;
    event.is_write = 1;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    rw_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * fsync tracing (enter + exit for latency measurement)
 * ══════════════════════════════════════════════════════════════════════ */

TRACEPOINT_PROBE(syscalls, sys_enter_fsync) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID

    u64 tid = bpf_get_current_pid_tgid();
    u64 ts  = bpf_ktime_get_ns();
    start_ts.update(&tid, &ts);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fsync) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID

    u64 tid = bpf_get_current_pid_tgid();
    u64 *tsp = start_ts.lookup(&tid);
    if (!tsp) return 0;

    struct sync_event_t event = {};
    event.timestamp  = bpf_ktime_get_ns();
    event.pid = pid;
    event.tid = (u32)tid;
    event.ret = args->ret;
    event.latency_ns = event.timestamp - *tsp;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    sync_events.perf_submit(args, &event, sizeof(event));
    start_ts.delete(&tid);
    return 0;
}
"""

    def __init__(self, target_pid: int = None, target_comm: str = None,
                 follow_forks: bool = True):
        self.target_pid = target_pid
        self.target_comm = target_comm  # e.g. "fio" — match all processes by name
        self.follow_forks = follow_forks
        self.events: list[SyscallEvent] = []
        self.fork_events: list[ForkEvent] = []
        self.tracked_pids: set[int] = set()  # All PIDs we're monitoring
        self._bpf = None

        if target_pid:
            self.tracked_pids.add(target_pid)

        # When --comm is used, discover all existing processes with that name
        if target_comm and not target_pid:
            self._discover_pids_by_comm(target_comm)

    def _discover_pids_by_comm(self, comm_name: str):
        """Find all running PIDs whose /proc/<pid>/comm matches comm_name."""
        try:
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                try:
                    with open(f"/proc/{entry}/comm") as f:
                        proc_comm = f.read().strip()
                    if proc_comm == comm_name:
                        pid = int(entry)
                        self.tracked_pids.add(pid)
                        # Also get children of each discovered PID
                        if self.follow_forks:
                            children = self._discover_existing_children(pid)
                            self.tracked_pids.update(children)
                except (OSError, ValueError):
                    pass
        except OSError:
            pass
        if self.tracked_pids:
            print(f"[comm] Found {len(self.tracked_pids)} existing PID(s) "
                  f"with comm='{comm_name}': {sorted(self.tracked_pids)}")

    def get_process_tree(self) -> dict:
        """Return a dict mapping parent_pid → [child_pids] from fork events."""
        tree = {}
        for fe in self.fork_events:
            tree.setdefault(fe.parent_pid, []).append(fe.child_pid)
        return tree

    def get_pid_comm_map(self) -> dict:
        """Return a dict mapping pid → comm name from all captured events."""
        pid_comm = {}
        for ev in self.events:
            if ev.comm and ev.pid not in pid_comm:
                pid_comm[ev.pid] = ev.comm
        for fe in self.fork_events:
            if fe.parent_comm and fe.parent_pid not in pid_comm:
                pid_comm[fe.parent_pid] = fe.parent_comm
            if fe.child_comm and fe.child_pid not in pid_comm:
                pid_comm[fe.child_pid] = fe.child_comm
        return pid_comm

    def _build_bpf_source(self) -> str:
        """
        Compile BPF source with the appropriate filtering mode.

        Three modes:
          --pid:  BPF_HASH(tracked_pids) lookup per syscall (+ fork expansion)
          --comm: bpf_get_current_comm() byte comparison in every probe
                  Matches ALL processes with that name — no PID needed.
                  Also seeds tracked_pids so fork probe emits events.
          neither: no filter, trace all processes on the system.
        """
        src = self.BPF_PROGRAM

        if self.target_comm:
            # ── Comm-based filter mode ──
            # Generate a byte-by-byte comparison of process comm name.
            # This is the standard BCC pattern — BPF verifier is happy with it.
            comm_name = self.target_comm[:15]  # TASK_COMM_LEN is 16 (incl NUL)
            checks = []
            for i, ch in enumerate(comm_name):
                checks.append(f"if (__filt_comm[{i}] != '{ch}') return 0;")
            checks.append(f"if (__filt_comm[{len(comm_name)}] != '\\0') return 0;")
            comm_check = (
                "{ char __filt_comm[16]; "
                "bpf_get_current_comm(&__filt_comm, sizeof(__filt_comm)); "
                + " ".join(checks) + " }"
            )
            # Also auto-register the PID in tracked_pids so fork events work
            comm_filter_with_register = (
                "{ char __filt_comm[16]; "
                "bpf_get_current_comm(&__filt_comm, sizeof(__filt_comm)); "
                + " ".join(checks) +
                " u8 __val = 1; tracked_pids.update(&pid, &__val); }"
            )

            src = src.replace("FILTER_PID_DEFINE", "")
            src = src.replace("FILTER_PID", comm_filter_with_register)
            # Fork probe: check parent comm, not tracked_pids
            fork_comm_check = (
                "{ char __filt_comm[16]; "
                "bpf_get_current_comm(&__filt_comm, sizeof(__filt_comm)); "
                + " ".join(checks) + " }"
            )
            src = src.replace("CHECK_PARENT_TRACKED", fork_comm_check)

        elif self.target_pid:
            # ── PID-based filter mode (existing) ──
            src = src.replace("FILTER_PID_DEFINE", "")
            src = src.replace("FILTER_PID",
                              "{ u8 *is_tracked = tracked_pids.lookup(&pid); "
                              "if (!is_tracked) return 0; }")
            src = src.replace("CHECK_PARENT_TRACKED",
                              "{ u8 *is_tracked = tracked_pids.lookup(&parent_pid); "
                              "if (!is_tracked) return 0; }")
        else:
            # ── No filter: trace all ──
            src = src.replace("FILTER_PID_DEFINE", "")
            src = src.replace("FILTER_PID", "")
            src = src.replace("CHECK_PARENT_TRACKED", "")

        return src

    def _seed_tracked_pids(self):
        """Seed the BPF tracked_pids hash with initial target PIDs."""
        if not self._bpf:
            return
        import ctypes
        tracked = self._bpf["tracked_pids"]

        # Seed all currently-known PIDs (from --pid, --comm discovery, or children)
        for pid in self.tracked_pids:
            tracked[ctypes.c_uint32(pid)] = ctypes.c_uint8(1)

        # When using --pid, also pre-seed existing children
        if self.target_pid and self.follow_forks:
            existing_children = self._discover_existing_children(self.target_pid)
            for child_pid in existing_children:
                tracked[ctypes.c_uint32(child_pid)] = ctypes.c_uint8(1)
                self.tracked_pids.add(child_pid)
            if existing_children:
                print(f"  [fork] Pre-seeded {len(existing_children)} existing child "
                      f"PID(s): {sorted(existing_children)}")

    @staticmethod
    def _discover_existing_children(pid: int) -> set:
        """Scan /proc/<pid>/task/*/children for already-forked child PIDs."""
        children = set()
        task_dir = f"/proc/{pid}/task"
        try:
            for tid in os.listdir(task_dir):
                children_file = os.path.join(task_dir, tid, "children")
                try:
                    with open(children_file) as f:
                        for child_pid_str in f.read().split():
                            child_pid = int(child_pid_str)
                            children.add(child_pid)
                            # Recurse one level for grandchildren
                            children |= SyscallTracer._discover_existing_children(child_pid)
                except (OSError, ValueError):
                    pass
        except OSError:
            pass
        return children

    def start_ebpf(self):
        """Attach eBPF probes with automatic fork/clone child tracking."""
        try:
            from bcc import BPF
        except ImportError:
            print("[WARN] bcc not available – falling back to strace mode.")
            return False

        src = self._build_bpf_source()
        self._bpf = BPF(text=src)

        # Seed the tracked_pids hash before any events fire
        self._seed_tracked_pids()

        # ── Fork event handler ──
        def _handle_fork(cpu, data, size):
            event = self._bpf["fork_events"].event(data)
            child_pid = event.child_pid
            parent_pid = event.parent_pid

            fe = ForkEvent(
                timestamp=event.timestamp / 1e9,
                parent_pid=parent_pid,
                child_pid=child_pid,
                parent_comm=event.parent_comm.decode("utf-8", errors="replace"),
                child_comm=event.child_comm.decode("utf-8", errors="replace"),
            )
            self.fork_events.append(fe)
            self.tracked_pids.add(child_pid)
            print(f"  [fork] Detected: PID {parent_pid} → child PID {child_pid} "
                  f"(now tracking {len(self.tracked_pids)} PIDs)")

        # ── Syscall event handlers (with comm field) ──
        def _handle_mmap(cpu, data, size):
            event = self._bpf["mmap_events"].event(data)
            self.events.append(SyscallEvent(
                timestamp=event.timestamp / 1e9,
                pid=event.pid, tid=event.tid,
                syscall="mmap", fd=event.fd,
                address=event.addr, length=event.length,
                offset=event.offset,
                flags=f"prot={event.prot:#x},flags={event.flags:#x}",
                return_value=event.ret,
                comm=event.comm.decode("utf-8", errors="replace"),
            ))

        def _handle_open(cpu, data, size):
            event = self._bpf["open_events"].event(data)
            self.events.append(SyscallEvent(
                timestamp=event.timestamp / 1e9,
                pid=event.pid, tid=event.tid,
                syscall="openat", fd=event.fd,
                flags=f"{event.flags:#x}",
                filename=event.filename.decode("utf-8", errors="replace"),
                comm=event.comm.decode("utf-8", errors="replace"),
            ))

        def _handle_rw(cpu, data, size):
            event = self._bpf["rw_events"].event(data)
            sc = "write" if event.is_write else "read"
            self.events.append(SyscallEvent(
                timestamp=event.timestamp / 1e9,
                pid=event.pid, tid=event.tid,
                syscall=sc, fd=event.fd,
                length=event.count, offset=event.offset,
                comm=event.comm.decode("utf-8", errors="replace"),
            ))

        def _handle_sync(cpu, data, size):
            event = self._bpf["sync_events"].event(data)
            self.events.append(SyscallEvent(
                timestamp=event.timestamp / 1e9,
                pid=event.pid, tid=event.tid,
                syscall="fsync", fd=event.fd,
                return_value=event.ret,
                latency_us=event.latency_ns / 1000.0,
                comm=event.comm.decode("utf-8", errors="replace"),
            ))

        self._bpf["fork_events"].open_perf_buffer(_handle_fork)
        self._bpf["mmap_events"].open_perf_buffer(_handle_mmap)
        self._bpf["open_events"].open_perf_buffer(_handle_open)
        self._bpf["rw_events"].open_perf_buffer(_handle_rw)
        self._bpf["sync_events"].open_perf_buffer(_handle_sync)

        fork_mode = "on (auto-tracking children)" if self.follow_forks else "off"
        if self.target_comm:
            filter_desc = f"comm='{self.target_comm}' (all matching processes)"
        elif self.target_pid:
            filter_desc = f"PID {self.target_pid}"
        else:
            filter_desc = "none (tracing ALL processes)"
        print(f"[eBPF] Probes attached — filter: {filter_desc}")
        print(f"[eBPF] Fork tracking: {fork_mode}")
        print(f"[eBPF] Initially tracking PIDs: {sorted(self.tracked_pids)}")
        return True

    def poll_ebpf(self, timeout_ms: int = 100):
        """Poll eBPF perf buffers once."""
        if self._bpf:
            self._bpf.perf_buffer_poll(timeout=timeout_ms)

    def stop_ebpf(self):
        """Detach eBPF probes."""
        if self._bpf:
            self._bpf.cleanup()
            self._bpf = None

    # ---- strace fallback ----

    # Matches: [pid NNNNN] timestamp syscall(args) = retval
    # or:      timestamp syscall(args) = retval
    # Captures: (optional_pid, timestamp, syscall, args, return_value)
    STRACE_RE = re.compile(
        r"(?:\[pid\s+(\d+)\]\s+)?(\d+\.\d+)\s+(\w+)\(([^)]*)\)\s+=\s+(-?(?:0x[0-9a-fA-F]+|\d+))"
    )

    def run_strace(self, duration_sec: int = 10) -> list[SyscallEvent]:
        """
        Trace syscalls using strace as a fallback.

        Supports three modes:
          --pid:  Attach to a single PID with -f (follow forks)
          --comm: Discover PIDs by process name, attach to all of them
          neither: Error (strace needs at least one PID)

        Parses [pid NNNNN] prefixes to attribute each syscall to the
        correct process, and detects clone return values for child PIDs.
        """
        # Determine which PIDs to attach to
        attach_pids = []
        if self.target_pid:
            attach_pids = [self.target_pid]
            # Also include pre-discovered children
            if self.follow_forks:
                children = self._discover_existing_children(self.target_pid)
                attach_pids.extend(sorted(children))
        elif self.target_comm:
            # Discover all PIDs with matching comm name
            if not self.tracked_pids:
                self._discover_pids_by_comm(self.target_comm)
            attach_pids = sorted(self.tracked_pids)
        else:
            raise ValueError("strace fallback requires --pid or --comm")

        if not attach_pids:
            print(f"[strace] No PIDs found to attach to"
                  f"{f' (comm={self.target_comm})' if self.target_comm else ''}")
            return []

        io_syscalls = "mmap,open,openat,read,write,pread64,pwrite64,fsync,fdatasync,msync"
        fork_syscalls = "clone,clone3,fork,vfork" if self.follow_forks else ""
        all_syscalls = io_syscalls + ("," + fork_syscalls if fork_syscalls else "")

        # Build strace command: -p PID1 -p PID2 ... (multi-attach)
        cmd = ["sudo", "strace"]
        for pid in attach_pids:
            cmd.extend(["-p", str(pid)])
        cmd.extend([
            "-e", f"trace={all_syscalls}",
            "-ttt",             # Epoch timestamps
            "-T",               # Syscall duration
            "-f",               # Follow forks/threads
            "-o", "/dev/stdout",
        ])

        fork_mode = "on (-f)" if self.follow_forks else "off"
        if self.target_comm:
            print(f"[strace] Attaching to {len(attach_pids)} PID(s) "
                  f"with comm='{self.target_comm}' for {duration_sec}s ...")
        else:
            print(f"[strace] Attaching to PID(s) {attach_pids} "
                  f"for {duration_sec}s ...")
        print(f"[strace] Fork tracking: {fork_mode}")
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
            time.sleep(duration_sec)
            proc.send_signal(signal.SIGINT)
            stdout, _ = proc.communicate(timeout=5)
        except Exception as e:
            print(f"[strace] Error: {e}")
            return []

        events = []
        default_pid = self.target_pid or (attach_pids[0] if attach_pids else 0)
        for line in stdout.splitlines():
            m = self.STRACE_RE.match(line.strip())
            if not m:
                continue
            pid_str, ts, sc, args_str, ret = m.groups()

            # Determine which PID this event belongs to
            event_pid = int(pid_str) if pid_str else default_pid

            # Parse return value (handles decimal and hex 0x... from mmap)
            try:
                ret_val = int(ret, 0)
            except ValueError:
                ret_val = 0

            # Detect fork/clone: child PID is the return value in parent context
            if sc in ("clone", "clone3", "fork", "vfork") and ret_val > 0:
                child_pid = ret_val
                self.tracked_pids.add(child_pid)
                self.fork_events.append(ForkEvent(
                    timestamp=float(ts),
                    parent_pid=event_pid,
                    child_pid=child_pid,
                ))
                print(f"  [fork] Detected via strace: PID {event_pid} → "
                      f"child PID {child_pid} "
                      f"(now tracking {len(self.tracked_pids)} PIDs)")
                continue  # Don't add clone itself as a syscall event

            ev = SyscallEvent(
                timestamp=float(ts),
                pid=event_pid,
                tid=event_pid,
                syscall=sc,
                return_value=ret_val,
            )
            self._parse_strace_args(ev, sc, args_str)
            events.append(ev)
            self.tracked_pids.add(event_pid)

        self.events.extend(events)
        print(f"[strace] Captured {len(events)} I/O events across "
              f"{len(self.tracked_pids)} PIDs")
        if self.fork_events:
            print(f"[strace] Detected {len(self.fork_events)} fork event(s)")
        return events

    @staticmethod
    def _parse_strace_args(event: SyscallEvent, syscall: str, args: str):
        """Best-effort parse of strace argument string."""
        parts = [a.strip() for a in args.split(",")]
        try:
            if syscall in ("open", "openat"):
                # openat(AT_FDCWD, "/path/to/file", O_RDONLY) = 3
                for p in parts:
                    p = p.strip().strip('"')
                    if "/" in p or "." in p:
                        event.filename = p
                        break
            elif syscall == "mmap":
                # mmap(NULL, 1073741824, PROT_READ|PROT_WRITE, MAP_SHARED, 3, 0) = 0x...
                if len(parts) >= 5:
                    event.address = int(parts[0], 0) if parts[0] != "NULL" else 0
                    event.length = int(parts[1])
                    event.fd = int(parts[4])
                    if len(parts) >= 6:
                        event.offset = int(parts[5])
                    # return_value already set to the mapped VA by caller
            elif syscall in ("read", "write"):
                event.fd = int(parts[0]) if parts else -1
                event.length = int(parts[2]) if len(parts) > 2 else 0
            elif syscall in ("pread64", "pwrite64"):
                event.fd = int(parts[0]) if parts else -1
                event.length = int(parts[2]) if len(parts) > 2 else 0
                event.offset = int(parts[3]) if len(parts) > 3 else 0
            elif syscall in ("fsync", "fdatasync"):
                event.fd = int(parts[0]) if parts else -1
            elif syscall == "msync":
                # msync(0x7f..., 4096, MS_SYNC) = 0
                event.address = int(parts[0], 0) if parts else 0
                event.length = int(parts[1]) if len(parts) > 1 else 0
        except (ValueError, IndexError):
            pass


# =============================================================================
# Step 2: FD & Length Extraction
# =============================================================================

class FDExtractor:
    """Extract file descriptor details from /proc/<pid>/fd and /proc/<pid>/fdinfo."""

    def __init__(self, pid: int):
        self.pid = pid

    def get_fd_path(self, fd: int) -> str:
        """Resolve the file path that a file descriptor points to."""
        link = f"/proc/{self.pid}/fd/{fd}"
        try:
            return os.readlink(link)
        except (OSError, PermissionError):
            return f"<unresolved fd={fd}>"

    def get_fd_info(self, fd: int) -> dict:
        """Read /proc/<pid>/fdinfo/<fd> for offset, flags, mnt_id."""
        info = {"fd": fd, "path": self.get_fd_path(fd)}
        fdinfo_path = f"/proc/{self.pid}/fdinfo/{fd}"
        try:
            with open(fdinfo_path) as f:
                for line in f:
                    key, _, val = line.strip().partition(":\t")
                    info[key] = val
        except (OSError, PermissionError):
            info["error"] = "could not read fdinfo"
        return info

    def get_all_fds(self) -> dict:
        """List all open file descriptors for the process."""
        fd_dir = f"/proc/{self.pid}/fd"
        fds = {}
        try:
            for entry in os.listdir(fd_dir):
                if entry.isdigit():
                    fd_num = int(entry)
                    fds[fd_num] = self.get_fd_path(fd_num)
        except (OSError, PermissionError):
            pass
        return fds

    def enrich_event(self, event: SyscallEvent) -> dict:
        """Attach FD metadata to a syscall event (Step 2 output)."""
        if event.fd < 0:
            return {"fd": event.fd, "note": "no valid fd"}
        return self.get_fd_info(event.fd)


# =============================================================================
# Step 3: Procfs Cross-Reference
# =============================================================================

class ProcfsMapper:
    """Cross-reference FDs and addresses with /proc/<pid>/maps and map_files."""

    def __init__(self, pid: int):
        self.pid = pid

    def parse_maps(self) -> list[MemoryMapping]:
        """Parse /proc/<pid>/maps into MemoryMapping objects."""
        mappings = []
        maps_path = f"/proc/{self.pid}/maps"
        try:
            with open(maps_path) as f:
                for line in f:
                    parts = line.strip().split(None, 5)
                    if len(parts) < 5:
                        continue
                    addr_range, perms, offset, dev, inode = parts[:5]
                    pathname = parts[5] if len(parts) > 5 else ""
                    start, end = addr_range.split("-")
                    mappings.append(MemoryMapping(
                        start_addr=int(start, 16),
                        end_addr=int(end, 16),
                        permissions=perms,
                        offset=int(offset, 16),
                        device=dev,
                        inode=int(inode),
                        pathname=pathname.strip(),
                    ))
        except (OSError, PermissionError) as e:
            print(f"[procfs] Cannot read {maps_path}: {e}")
        return mappings

    def find_mapping_for_address(self, addr: int) -> Optional[MemoryMapping]:
        """Find which mapping contains a given virtual address."""
        for m in self.parse_maps():
            if m.start_addr <= addr < m.end_addr:
                return m
        return None

    def find_mappings_for_file(self, filepath: str) -> list[MemoryMapping]:
        """Find all mappings backed by a given file path."""
        return [m for m in self.parse_maps()
                if m.pathname and filepath in m.pathname]

    def list_map_files(self) -> dict:
        """List entries in /proc/<pid>/map_files/ (requires root)."""
        map_files_dir = f"/proc/{self.pid}/map_files"
        entries = {}
        try:
            for entry in os.listdir(map_files_dir):
                link_target = os.readlink(os.path.join(map_files_dir, entry))
                start, end = entry.split("-")
                entries[entry] = {
                    "start": int(start, 16),
                    "end": int(end, 16),
                    "file": link_target,
                }
        except (OSError, PermissionError) as e:
            print(f"[procfs] Cannot read map_files (needs root): {e}")
        return entries

    def cross_reference(self, event: SyscallEvent, fd_info: dict,
                         maps_cache: list = None) -> Optional[MemoryMapping]:
        """
        Step 3: Given a syscall event + FD info, find the relevant mapping.

        Strategy (in priority order):
          1. mmap return_value → direct address lookup
          2. mmap event address field → address lookup (hint addr)
          3. FD path → find all file-backed mappings of that file
          4. event filename → find mappings by open()'d filename
        """
        maps = maps_cache if maps_cache is not None else self.parse_maps()

        # (1) mmap with a valid returned address from sys_exit_mmap
        if event.syscall == "mmap" and event.return_value > 0:
            for m in maps:
                if m.start_addr <= event.return_value < m.end_addr:
                    return m

        # (2) mmap with hint address (less reliable but try)
        if event.syscall == "mmap" and event.address > 0:
            for m in maps:
                if m.start_addr <= event.address < m.end_addr:
                    return m

        # (3) Resolve via FD → file path → matching memory-mapped regions
        filepath = fd_info.get("path", "")
        if filepath and not filepath.startswith("<"):
            # Use basename matching to handle /proc symlink vs maps path differences
            real_path = os.path.realpath(filepath) if os.path.exists(filepath) else filepath
            for m in maps:
                if m.is_file_backed:
                    if (real_path == m.pathname or
                            filepath == m.pathname or
                            os.path.basename(filepath) == os.path.basename(m.pathname)):
                        return m

        # (4) Match by filename from openat() events
        if event.filename:
            for m in maps:
                if m.is_file_backed and event.filename in m.pathname:
                    return m

        return None

    def find_all_file_backed_mappings(self, maps_cache: list = None) -> list[MemoryMapping]:
        """Return all file-backed (non-library, non-vdso) mappings."""
        maps = maps_cache if maps_cache is not None else self.parse_maps()
        skip_prefixes = ("/usr/lib", "/lib", "/usr/share", "[")
        return [m for m in maps if m.is_file_backed
                and not any(m.pathname.startswith(p) for p in skip_prefixes)]

    def find_target_file_mappings(self, target_paths: set,
                                   maps_cache: list = None) -> list[MemoryMapping]:
        """Find all mappings for the specific target file(s) being traced."""
        maps = maps_cache if maps_cache is not None else self.parse_maps()
        results = []
        for m in maps:
            if not m.is_file_backed:
                continue
            for tp in target_paths:
                real_tp = os.path.realpath(tp) if os.path.exists(tp) else tp
                if (m.pathname == tp or m.pathname == real_tp or
                        os.path.basename(m.pathname) == os.path.basename(tp)):
                    results.append(m)
                    break
        return results


# =============================================================================
# Step 4: Page Monitoring
# =============================================================================

class PageMonitor:
    """Monitor page-level activity for specific address ranges."""

    PAGE_SIZE = 4096

    def __init__(self, pid: int):
        self.pid = pid
        self._pagemap_fd = None

    def read_pagemap_entry(self, vaddr: int) -> dict:
        """Read a single pagemap entry for a virtual address."""
        pagemap_path = f"/proc/{self.pid}/pagemap"
        page_index = vaddr // self.PAGE_SIZE
        offset = page_index * 8  # Each entry is 8 bytes

        try:
            with open(pagemap_path, "rb") as f:
                f.seek(offset)
                data = f.read(8)
                if len(data) < 8:
                    return {"error": "short read"}

                entry = int.from_bytes(data, byteorder="little")
                return {
                    "vaddr": hex(vaddr),
                    "present": bool(entry & (1 << 63)),
                    "swapped": bool(entry & (1 << 62)),
                    "file_mapped": bool(entry & (1 << 61)),
                    "dirty": bool(entry & (1 << 55)),  # Soft-dirty
                    "pfn": entry & ((1 << 55) - 1) if entry & (1 << 63) else None,
                }
        except (OSError, PermissionError) as e:
            return {"error": str(e)}

    def scan_range(self, start_addr: int, end_addr: int) -> list[dict]:
        """Scan all pages in an address range."""
        results = []
        for addr in range(start_addr, end_addr, self.PAGE_SIZE):
            entry = self.read_pagemap_entry(addr)
            if entry.get("present") or entry.get("dirty"):
                results.append(entry)
        return results

    def monitor_dirty_pages(self, mapping: MemoryMapping,
                            interval_sec: float = 1.0,
                            duration_sec: float = 10.0) -> list[PageMonEvent]:
        """
        Monitor a mapping for dirty page transitions.

        Uses soft-dirty tracking:
          1. Clear soft-dirty bits via /proc/<pid>/clear_refs
          2. Sleep for interval
          3. Scan pagemap for newly dirtied pages
          4. Repeat
        """
        events = []
        clear_refs = f"/proc/{self.pid}/clear_refs"
        start_time = time.time()
        iteration = 0

        print(f"[PageMon] Monitoring {mapping.pathname or 'anon'} "
              f"[{mapping.start_addr:#x}-{mapping.end_addr:#x}] "
              f"({mapping.size // 1024} KB) for {duration_sec}s ...")

        while (time.time() - start_time) < duration_sec:
            # Clear soft-dirty bits (write "4" to clear_refs)
            try:
                with open(clear_refs, "w") as f:
                    f.write("4")
            except (OSError, PermissionError) as e:
                print(f"[PageMon] Cannot clear soft-dirty (needs root): {e}")
                break

            time.sleep(interval_sec)

            # Scan for newly dirty pages
            dirty_count = 0
            for addr in range(mapping.start_addr, mapping.end_addr, self.PAGE_SIZE):
                entry = self.read_pagemap_entry(addr)
                if entry.get("dirty"):
                    dirty_count += 1

            if dirty_count > 0:
                ev = PageMonEvent(
                    timestamp=time.time(),
                    pid=self.pid,
                    address=mapping.start_addr,
                    page_count=dirty_count,
                    event_type="dirty",
                    mapping_file=mapping.pathname,
                )
                events.append(ev)
                iteration += 1
                print(f"  [{iteration}] {dirty_count} dirty pages "
                      f"({dirty_count * self.PAGE_SIZE // 1024} KB) "
                      f"in {mapping.pathname or 'anon'}")

        print(f"[PageMon] Done – {len(events)} dirty snapshots captured")
        return events

    @staticmethod
    def check_kpageflags(pfn: int) -> dict:
        """Read /proc/kpageflags for a given PFN (requires root)."""
        try:
            with open("/proc/kpageflags", "rb") as f:
                f.seek(pfn * 8)
                data = f.read(8)
                flags = int.from_bytes(data, "little")
                return {
                    "pfn": pfn,
                    "locked": bool(flags & (1 << 0)),
                    "referenced": bool(flags & (1 << 2)),
                    "dirty": bool(flags & (1 << 4)),
                    "lru": bool(flags & (1 << 5)),
                    "active": bool(flags & (1 << 6)),
                    "slab": bool(flags & (1 << 7)),
                    "writeback": bool(flags & (1 << 8)),
                    "mmap": bool(flags & (1 << 11)),
                    "swapbacked": bool(flags & (1 << 13)),
                }
        except (OSError, PermissionError):
            return {"error": "cannot read kpageflags (needs root)"}


# =============================================================================
# Step 4b: PageMon Visualizer (C-accelerated with terminal rendering)
# =============================================================================

class PageMonVisualizer:
    """
    C-accelerated page-level memory visualizer with terminal rendering.

    Uses a compiled C helper (pagemon_viz) for fast bulk pagemap scanning,
    soft-dirty tracking, and structured JSON output. Python renders the
    output as terminal heatmaps, timelines, and region summaries.

    Visualization modes:
      snapshot   – one-shot page state scan (present/dirty/swapped)
      softdirty  – soft-dirty clear+poll cycle with per-page bitmap
      heatmap    – block-level dirty density grid (terminal heatmap)
      timeline   – dirty page rate over time (ASCII sparkline)
      region_all – scan all file-backed regions for a PID
    """

    # Terminal heatmap color palette (ANSI 256-color)
    # Maps dirty density 0-100% to color codes
    HEAT_CHARS = " ░▒▓█"
    HEAT_COLORS = [
        "\033[38;5;236m",   # 0%   — dark gray (cold)
        "\033[38;5;22m",    # ~20% — dark green
        "\033[38;5;28m",    # ~40% — green
        "\033[38;5;178m",   # ~60% — yellow
        "\033[38;5;208m",   # ~80% — orange
        "\033[38;5;196m",   # 100% — red (hot)
    ]
    RESET = "\033[0m"

    # C source file path (compiled on first use)
    C_SOURCE_FILENAME = "pagemon_viz.c"
    C_BINARY_NAME = "pagemon_viz"

    def __init__(self, build_dir: str = "/tmp/io_path_observer"):
        self.build_dir = Path(build_dir)
        self._binary_path = None

    def _find_c_source(self) -> Optional[Path]:
        """Find pagemon_viz.c — check script dir, working dir, build dir."""
        candidates = [
            Path(__file__).parent / self.C_SOURCE_FILENAME,
            Path.cwd() / self.C_SOURCE_FILENAME,
            self.build_dir / self.C_SOURCE_FILENAME,
        ]
        for p in candidates:
            if p.exists():
                return p
        return None

    def _write_embedded_c_source(self) -> Path:
        """Write the embedded C source to build_dir if not found on disk."""
        self.build_dir.mkdir(parents=True, exist_ok=True)
        src_path = self.build_dir / self.C_SOURCE_FILENAME

        # Read from adjacent file if it exists
        adjacent = Path(__file__).parent / self.C_SOURCE_FILENAME
        if adjacent.exists():
            return adjacent

        # Otherwise generate a minimal inline version
        print(f"[pagemon_viz] C source not found — writing to {src_path}")
        print(f"[pagemon_viz] For full version, place {self.C_SOURCE_FILENAME} "
              f"next to {Path(__file__).name}")
        return src_path

    def ensure_compiled(self) -> bool:
        """Compile pagemon_viz.c if needed. Returns True if binary is ready."""
        if self._binary_path and self._binary_path.exists():
            return True

        binary = self.build_dir / self.C_BINARY_NAME
        self.build_dir.mkdir(parents=True, exist_ok=True)

        # Check if already compiled and up-to-date
        src_path = self._find_c_source()
        if not src_path:
            src_path = self._write_embedded_c_source()
            if not src_path or not src_path.exists():
                print("[pagemon_viz] ERROR: Cannot find pagemon_viz.c")
                print(f"  Place it in: {Path(__file__).parent}/")
                return False

        if binary.exists():
            # Check if source is newer than binary
            if src_path.stat().st_mtime <= binary.stat().st_mtime:
                self._binary_path = binary
                return True

        # Compile
        print(f"[pagemon_viz] Compiling {src_path} → {binary} ...")
        result = subprocess.run(
            ["gcc", "-O2", "-Wall", "-o", str(binary), str(src_path), "-lm"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(f"[pagemon_viz] Compilation FAILED:")
            print(result.stderr)
            return False

        print(f"[pagemon_viz] Build OK: {binary}")
        self._binary_path = binary
        return True

    def _run_c_tool(self, pid: int, mode: int, start: int = 0, end: int = 0,
                     interval_ms: int = 1000, count: int = 10,
                     block_kb: int = 0) -> Optional[dict]:
        """Run the C pagemon_viz tool and parse JSON output."""
        if not self.ensure_compiled():
            return None

        cmd = [
            "sudo", str(self._binary_path),
            str(pid), str(mode),
            hex(start), hex(end),
            str(interval_ms), str(count),
            str(block_kb),
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            print("[pagemon_viz] Timeout waiting for C tool")
            return None

        if result.returncode != 0:
            stderr = result.stderr.strip()
            if stderr:
                print(f"[pagemon_viz] {stderr}")
            return None

        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as e:
            print(f"[pagemon_viz] JSON parse error: {e}")
            if result.stdout[:200]:
                print(f"  Raw output: {result.stdout[:200]}...")
            return None

    # ═══════════════════════════════════════════════════════════════════
    # Public visualization methods
    # ═══════════════════════════════════════════════════════════════════

    def snapshot(self, pid: int, start: int, end: int):
        """Mode 0: One-shot page state scan with visual map."""
        print(f"\n  ┌── Page Snapshot: PID {pid} "
              f"[{start:#x}–{end:#x}] ──")

        data = self._run_c_tool(pid, mode=0, start=start, end=end)
        if not data:
            print("  │  (pagemon_viz unavailable — skipping visualization)")
            print("  └──")
            return

        total = data.get("total_pages", 0)
        present = data.get("present", 0)
        dirty = data.get("dirty", 0)
        swapped = data.get("swapped", 0)

        print(f"  │  Total pages:  {total:,} ({total * 4:,} KB)")
        print(f"  │  Present:      {present:,} ({data.get('resident_pct', 0):.1f}%)")
        print(f"  │  Dirty:        {dirty:,} ({data.get('dirty_pct', 0):.1f}%)")
        print(f"  │  Swapped:      {swapped:,}")
        print(f"  │")

        # Render page state map (compact 80-col)
        pages = data.get("pages", "")
        if isinstance(pages, list):
            pages = "".join(str(p) for p in pages)
        if pages:
            self._render_page_map(pages)
        print(f"  └──\n")

    def heatmap(self, pid: int, start: int, end: int,
                interval_ms: int = 500, iterations: int = 10):
        """Mode 2: Block-level dirty density heatmap."""
        size_kb = (end - start) // 1024
        print(f"\n  ┌── Dirty Page Heatmap: PID {pid} ──")
        print(f"  │  Region: {start:#x}–{end:#x} ({size_kb:,} KB)")
        print(f"  │  Polling: {interval_ms}ms × {iterations} iterations")

        data = self._run_c_tool(pid, mode=2, start=start, end=end,
                                 interval_ms=interval_ms, count=iterations)
        if not data:
            print("  │  (pagemon_viz unavailable — skipping visualization)")
            print("  └──")
            return

        cols = data.get("cols", 64)
        block_size_kb = data.get("block_size_kb", 0)
        print(f"  │  Grid: {cols}×N blocks, {block_size_kb} KB/block")

        snapshots = data.get("snapshots", [])
        for snap in snapshots:
            dirty_kb = snap.get("dirty_kb", 0)
            total_dirty = snap.get("total_dirty", 0)
            blocks = snap.get("blocks", [])

            print(f"  │")
            print(f"  │  Iteration {snap['iter']}: "
                  f"{total_dirty} dirty pages ({dirty_kb} KB)")

            self._render_heatmap_grid(blocks, cols)

        # Legend
        print(f"  │")
        print(f"  │  Legend: ", end="")
        for i, ch in enumerate(self.HEAT_CHARS):
            pct = i * 20
            color = self.HEAT_COLORS[min(i, len(self.HEAT_COLORS) - 1)]
            print(f"{color}{ch}{self.RESET}={pct}%  ", end="")
        print()
        print(f"  └──\n")

    def timeline(self, pid: int, start: int, end: int,
                 interval_ms: int = 500, iterations: int = 20):
        """Mode 3: Dirty page rate over time with ASCII sparkline."""
        size_kb = (end - start) // 1024
        print(f"\n  ┌── Dirty Page Timeline: PID {pid} ──")
        print(f"  │  Region: {start:#x}–{end:#x} ({size_kb:,} KB)")
        print(f"  │  Sampling: {interval_ms}ms × {iterations}")

        data = self._run_c_tool(pid, mode=3, start=start, end=end,
                                 interval_ms=interval_ms, count=iterations)
        if not data:
            print("  │  (pagemon_viz unavailable — skipping visualization)")
            print("  └──")
            return

        samples = data.get("samples", [])
        if not samples:
            print("  │  No samples collected")
            print("  └──")
            return

        # Extract dirty counts for sparkline
        dirty_counts = [s.get("dirty", 0) for s in samples]
        rates = [s.get("dirty_rate_kb_s", 0) for s in samples]
        max_dirty = max(dirty_counts) if dirty_counts else 1

        # Table
        print(f"  │")
        print(f"  │  {'#':>4} {'Elapsed':>8} {'Dirty':>8} "
              f"{'KB':>8} {'Rate KB/s':>10} {'Sparkline'}")
        print(f"  │  {'─' * 62}")

        spark_chars = "▁▂▃▄▅▆▇█"
        for s in samples:
            dirty = s.get("dirty", 0)
            elapsed = s.get("elapsed_ms", 0)
            dk = s.get("dirty_kb", 0)
            rate = s.get("dirty_rate_kb_s", 0)
            # Sparkline bar
            bar_len = int(40 * dirty / max_dirty) if max_dirty > 0 else 0
            si = min(len(spark_chars) - 1,
                     int((len(spark_chars) - 1) * dirty / max_dirty)) if max_dirty > 0 else 0
            color = self.HEAT_COLORS[min(si, len(self.HEAT_COLORS) - 1)]
            bar = f"{color}{spark_chars[si] * bar_len}{self.RESET}"
            print(f"  │  {s['iter']:>4} {elapsed:>7}ms {dirty:>8} "
                  f"{dk:>7}K {rate:>9.0f} {bar}")

        # Summary
        avg_dirty = sum(dirty_counts) / len(dirty_counts) if dirty_counts else 0
        avg_rate = sum(rates) / len(rates) if rates else 0
        peak_rate = max(rates) if rates else 0
        print(f"  │")
        print(f"  │  Summary: avg={avg_dirty:.0f} dirty pages/sample, "
              f"avg_rate={avg_rate:.0f} KB/s, peak={peak_rate:.0f} KB/s")
        print(f"  └──\n")

    def region_scan(self, pid: int, interval_ms: int = 1000, iterations: int = 5):
        """Mode 4: Scan all file-backed regions for a PID."""
        print(f"\n  ┌── Region Scan: PID {pid} (all file-backed mappings) ──")

        data = self._run_c_tool(pid, mode=4, interval_ms=interval_ms,
                                 count=iterations)
        if not data:
            print("  │  (pagemon_viz unavailable — skipping visualization)")
            print("  └──")
            return

        regions = data.get("regions", [])
        if not regions:
            print("  │  No file-backed regions found")
            print("  └──")
            return

        print(f"  │  Found {len(regions)} workload region(s):")
        print(f"  │")
        print(f"  │  {'Start':>16}  {'End':>16}  {'Perm':>5}  "
              f"{'Size':>8}  {'Resid%':>6}  {'Dirty%':>6}  {'Path'}")
        print(f"  │  {'─' * 78}")

        for r in regions:
            start = r.get("start", "")
            end = r.get("end", "")
            perms = r.get("perms", "")
            path = r.get("pathname", "")
            size_kb = r.get("size_kb", 0)
            resident_pct = r.get("resident_pct", 0)
            dirty_pct = r.get("dirty_pct", 0)

            # Color-code dirty percentage
            color = self.RESET
            if dirty_pct > 75:
                color = self.HEAT_COLORS[5]
            elif dirty_pct > 50:
                color = self.HEAT_COLORS[4]
            elif dirty_pct > 25:
                color = self.HEAT_COLORS[3]
            elif dirty_pct > 5:
                color = self.HEAT_COLORS[2]

            sz_str = f"{size_kb}K" if size_kb < 1024 else f"{size_kb // 1024}M"
            print(f"  │  {start:>16}  {end:>16}  {perms:>5}  "
                  f"{sz_str:>8}  {resident_pct:>5.1f}%  "
                  f"{color}{dirty_pct:>5.1f}%{self.RESET}  {path}")

        # Tracking data
        tracking = data.get("tracking", [])
        if tracking:
            print(f"  │")
            print(f"  │  Soft-dirty tracking ({len(tracking)} samples, "
                  f"{interval_ms}ms interval):")
            print(f"  │  {'#':>4}  ", end="")
            # Header: abbreviated file names
            paths = set()
            for t in tracking:
                for rdata in t.get("regions", []):
                    paths.add(rdata.get("path", ""))
            path_list = sorted(paths)
            for p in path_list:
                short = os.path.basename(p)[:20]
                print(f"  {short:>20}", end="")
            print()
            print(f"  │  {'─' * (6 + len(path_list) * 22)}")

            for t in tracking:
                print(f"  │  {t['iter']:>4}  ", end="")
                region_data = {rd["path"]: rd for rd in t.get("regions", [])}
                for p in path_list:
                    rd = region_data.get(p, {})
                    dk = rd.get("dirty_kb", 0)
                    if dk > 0:
                        color = self.HEAT_COLORS[min(4, dk // 100)]
                        print(f"  {color}{dk:>18}KB{self.RESET}", end="")
                    else:
                        print(f"  {'—':>20}", end="")
                print()

        print(f"  └──\n")

    def file_unified(self, pid: int, interval_ms: int = 500, iterations: int = 10):
        """Mode 5: Unified file-offset heatmap (coalesced multi-mmap view)."""
        print(f"\n  ┌── Unified File Heatmap: PID {pid} ──")
        print(f"  │  (coalesced multi-mmap: groups VMAs by file, deduplicates overlaps)")

        data = self._run_c_tool(pid, mode=5, interval_ms=interval_ms,
                                 count=iterations)
        if not data:
            print("  │  (pagemon_viz unavailable — skipping visualization)")
            print("  └──")
            return

        files = data.get("files", [])
        if not files:
            print("  │  No file-backed regions found")
            print("  └──")
            return

        for fdata in files:
            pathname = fdata.get("pathname", "<unknown>")
            n_vmas = fdata.get("n_vmas", 0)
            n_coal = fdata.get("n_coalesced", 0)
            fspan_kb = fdata.get("file_span_kb", 0)
            fpages = fdata.get("file_pages", 0)
            block_kb = fdata.get("block_size_kb", 0)
            cols = fdata.get("cols", 64)
            off_range = fdata.get("file_offset_range", ["0x0", "0x0"])
            dedup = fdata.get("overlap_dedup", False)

            print(f"  │")
            print(f"  │  File: {pathname}")
            print(f"  │  VMAs: {n_vmas} → coalesced: {n_coal} span(s)"
                  f"  |  dedup: {'on' if dedup else 'off'}")
            fspan_str = f"{fspan_kb}K" if fspan_kb < 1024 else f"{fspan_kb // 1024}M"
            print(f"  │  File offset: {off_range[0]}–{off_range[1]} "
                  f"({fspan_str}, {fpages:,} pages)")
            print(f"  │  Block size: {block_kb} KB/block, "
                  f"X-axis = file offset (not VA)")

            snapshots = fdata.get("snapshots", [])
            for snap in snapshots:
                dirty_kb = snap.get("dirty_kb", 0)
                total_dirty = snap.get("total_dirty", 0)
                blocks = snap.get("blocks", [])
                print(f"  │")
                print(f"  │  Iteration {snap['iter']}: "
                      f"{total_dirty} dirty ({dirty_kb} KB)")
                self._render_heatmap_grid(blocks, cols)

        print(f"  │")
        print(f"  │  Legend: ", end="")
        for i, ch in enumerate(self.HEAT_CHARS):
            pct = i * 20
            color = self.HEAT_COLORS[min(i, len(self.HEAT_COLORS) - 1)]
            print(f"{color}{ch}{self.RESET}={pct}%  ", end="")
        print()
        print(f"  │  X-axis: file offset (left=start, right=end)")
        print(f"  │  Multi-mmap: all VMAs stitched into one view per file")
        print(f"  └──\n")
    # ═══════════════════════════════════════════════════════════════════

    # ═══════════════════════════════════════════════════════════════════
    # Terminal rendering helpers
    # ═══════════════════════════════════════════════════════════════════

    # Granularity presets: name → block_kb
    GRANULARITY_PRESETS = {
        "page":   4,       # 1 page/block (finest — 4 KB)
        "fine":   64,      # 16 pages/block (64 KB)
        "medium": 256,     # 64 pages/block (256 KB)
        "coarse": 1024,    # 256 pages/block (1 MB)
        "auto":   0,       # C code auto-calculates
    }

    @classmethod
    def resolve_granularity(cls, name_or_kb: str) -> int:
        """Convert granularity name or KB value to block_kb int."""
        if name_or_kb in cls.GRANULARITY_PRESETS:
            return cls.GRANULARITY_PRESETS[name_or_kb]
        try:
            return int(name_or_kb)
        except ValueError:
            return 0

    @classmethod
    def auto_granularity(cls, region_size_kb: int) -> tuple:
        """Choose block_kb based on region size. Returns (block_kb, label)."""
        if region_size_kb <= 256:         # ≤ 256 KB
            return (4, "page (4 KB/block)")
        elif region_size_kb <= 4096:      # ≤ 4 MB
            return (16, "fine (16 KB/block)")
        elif region_size_kb <= 65536:     # ≤ 64 MB
            return (64, "fine (64 KB/block)")
        elif region_size_kb <= 524288:    # ≤ 512 MB
            return (256, "medium (256 KB/block)")
        else:                             # > 512 MB
            return (1024, "coarse (1 MB/block)")

    def zoom_heatmap(self, pid: int, start: int, end: int,
                     interval_ms: int = 500, iterations: int = 5,
                     block_kb: int = 0):
        """
        Two-level visualization: coarse minimap + fine zoom on hottest region.

        1. Coarse overview pass: 1 MB blocks → identify hot zone
        2. Fine detail pass: page-level or 64 KB blocks on the hot zone
        3. Render: minimap (top) with zoom bracket + detail (bottom)
        """
        size_kb = (end - start) // 1024
        print(f"\n  ┌── Zoom Heatmap: PID {pid} ──")
        print(f"  │  Region: {start:#x}–{end:#x} ({size_kb:,} KB)")

        if size_kb < 128:
            # Region too small for zoom — just do fine-grained single pass
            print(f"  │  (small region — single fine-grained pass)")
            self.heatmap(pid, start, end, interval_ms, iterations)
            return

        # ── Pass 1: Coarse overview (1 MB blocks, single iteration) ──
        coarse_kb = 1024 if size_kb > 65536 else 256
        print(f"  │  Pass 1: Overview ({coarse_kb} KB/block)")

        overview = self._run_c_tool(pid, mode=2, start=start, end=end,
                                     interval_ms=interval_ms, count=1,
                                     block_kb=coarse_kb)
        if not overview:
            print("  │  (pagemon_viz unavailable)")
            print("  └──")
            return

        cols = overview.get("cols", 64)
        ppb = overview.get("pages_per_block", 1)
        snaps = overview.get("snapshots", [])
        if not snaps:
            print("  │  No data from overview pass")
            print("  └──")
            return

        blocks = snaps[0].get("blocks", [])
        print(f"  │  Overview ({len(blocks)} blocks):")
        self._render_heatmap_grid(blocks, cols)

        # ── Find hottest contiguous region ──
        if not blocks or max(blocks) == 0:
            print(f"  │  No dirty blocks — nothing to zoom into")
            print(f"  └──\n")
            return

        # Sliding window: find the densest 1/8th of the overview
        window_size = max(4, len(blocks) // 8)
        best_sum = 0
        best_start_idx = 0
        for i in range(len(blocks) - window_size + 1):
            s = sum(blocks[i:i + window_size])
            if s > best_sum:
                best_sum = s
                best_start_idx = i

        # Calculate VA range for the zoom region
        bytes_per_block = ppb * 4096
        zoom_va_start = start + best_start_idx * bytes_per_block
        zoom_va_end = min(end, zoom_va_start + window_size * bytes_per_block)
        zoom_size_kb = (zoom_va_end - zoom_va_start) // 1024

        # Render minimap with zoom bracket
        print(f"  │")
        bracket_start = best_start_idx
        bracket_end = min(best_start_idx + window_size, len(blocks))
        print(f"  │  Zoom target: blocks [{bracket_start}–{bracket_end}] "
              f"= {zoom_va_start:#x}–{zoom_va_end:#x} ({zoom_size_kb:,} KB)")
        print(f"  │  ", end="")
        for i in range(min(len(blocks), cols)):
            if bracket_start <= i < bracket_end:
                print(f"\033[4m\033[38;5;196m▼\033[0m", end="")
            else:
                print(" ", end="")
        print()

        # ── Pass 2: Fine detail on hottest region ──
        detail_kb, detail_label = self.auto_granularity(zoom_size_kb)
        if block_kb > 0:
            detail_kb = block_kb
            detail_label = f"user ({block_kb} KB/block)"

        print(f"  │")
        print(f"  │  Pass 2: Zoom detail ({detail_label})")

        detail = self._run_c_tool(pid, mode=2, start=zoom_va_start,
                                   end=zoom_va_end,
                                   interval_ms=interval_ms, count=iterations,
                                   block_kb=detail_kb)
        if not detail:
            print("  │  (zoom pass failed)")
            print("  └──")
            return

        detail_snaps = detail.get("snapshots", [])
        detail_cols = detail.get("cols", 64)
        for snap in detail_snaps:
            dirty_kb = snap.get("dirty_kb", 0)
            total_dirty = snap.get("total_dirty", 0)
            dblocks = snap.get("blocks", [])
            print(f"  │")
            print(f"  │  Iter {snap['iter']}: {total_dirty} dirty ({dirty_kb} KB)")
            self._render_heatmap_grid(dblocks, detail_cols)

        print(f"  │")
        print(f"  │  Legend: ", end="")
        for i, ch in enumerate(self.HEAT_CHARS):
            color = self.HEAT_COLORS[min(i, len(self.HEAT_COLORS) - 1)]
            print(f"{color}{ch}{self.RESET}={i * 20}%  ", end="")
        print()
        print(f"  └──\n")

    def _render_page_map(self, pages_str: str, width: int = 72):
        """Render a compact page state map with color coding."""
        # P=present D=dirty S=swapped F=file-mapped .=not present
        color_map = {
            '.': "\033[38;5;236m",  # dark gray
            'P': "\033[38;5;34m",   # green
            'D': "\033[38;5;196m",  # red
            'S': "\033[38;5;33m",   # blue
            'F': "\033[38;5;178m",  # yellow
        }
        print(f"  │  Page map (P=present D=dirty S=swapped F=file .=empty):")

        # If too many pages, downsample
        total = len(pages_str)
        display_chars = width * 4  # 4 rows max
        if total > display_chars:
            stride = total // display_chars
            sampled = pages_str[::stride][:display_chars]
        else:
            sampled = pages_str

        for row_start in range(0, len(sampled), width):
            row = sampled[row_start:row_start + width]
            print(f"  │  ", end="")
            for ch in row:
                color = color_map.get(ch, self.RESET)
                print(f"{color}{ch}{self.RESET}", end="")
            print()

    def _render_heatmap_grid(self, blocks: list, cols: int):
        """Render a heatmap grid from block density values (0-100)."""
        for row_start in range(0, len(blocks), cols):
            row = blocks[row_start:row_start + cols]
            print(f"  │  ", end="")
            for density in row:
                # Map 0-100 to character and color
                idx = min(len(self.HEAT_CHARS) - 1, density // 20)
                color = self.HEAT_COLORS[min(idx, len(self.HEAT_COLORS) - 1)]
                print(f"{color}{self.HEAT_CHARS[idx]}{self.RESET}", end="")
            print()


# =============================================================================
# Orchestrator: Full Pipeline
# =============================================================================

class IOPathObserver:
    """
    Orchestrates the 4-step I/O path observability pipeline.

    Filtering modes:
      --pid PID       : Trace a specific process + forked children
      --comm NAME     : Trace ALL processes matching the name (e.g. 'fio')
      --launch CMD    : Start a command, trace it from birth
      (none)          : Trace all processes on the system (very noisy)

    Step 1 → SyscallTracer   : Catch mmap / open / read / write / fsync
                                + auto-detect fork()/clone() child PIDs
    Step 2 → FDExtractor     : Get FD path and metadata (per tracked PID)
    Step 3 → ProcfsMapper    : Cross-reference with /proc/<pid>/maps (per PID)
    Step 4 → PageMonitor     : Watch address ranges for dirty-page flushes
    """

    def __init__(self, pid: int = None, comm: str = None,
                 use_ebpf: bool = True, follow_forks: bool = True,
                 visualize: str = None, viz_interval: int = 500,
                 viz_iterations: int = 10, viz_granularity: str = "auto"):
        self.pid = pid           # May be None for --comm mode
        self.comm = comm         # e.g. "fio"
        self.follow_forks = follow_forks
        self.tracer = SyscallTracer(target_pid=pid, target_comm=comm,
                                     follow_forks=follow_forks)
        self.use_ebpf = use_ebpf
        self.trace_records: list[IOTraceRecord] = []

        # Visualization settings
        self.visualize = visualize          # None, "snapshot", "heatmap", etc.
        self.viz_interval = viz_interval
        self.viz_iterations = viz_iterations
        self.viz_block_kb = PageMonVisualizer.resolve_granularity(viz_granularity)
        self._visualizer = PageMonVisualizer() if visualize else None

        # Per-PID helpers — created dynamically as PIDs are discovered
        self._fd_extractors: dict[int, FDExtractor] = {}
        self._procfs_mappers: dict[int, ProcfsMapper] = {}
        self._page_monitors: dict[int, PageMonitor] = {}

        # Pre-populate for known PIDs
        if pid:
            self._ensure_pid_helpers(pid)
        for p in self.tracer.tracked_pids:
            self._ensure_pid_helpers(p)

    def _ensure_pid_helpers(self, pid: int):
        """Lazily create FDExtractor, ProcfsMapper, PageMonitor for a new PID."""
        if pid not in self._fd_extractors:
            self._fd_extractors[pid] = FDExtractor(pid)
        if pid not in self._procfs_mappers:
            self._procfs_mappers[pid] = ProcfsMapper(pid)
        if pid not in self._page_monitors:
            self._page_monitors[pid] = PageMonitor(pid)

    def run_pipeline(self, trace_duration: int = 10, monitor_duration: float = 5.0):
        """Execute the full 4-step pipeline with automatic fork child tracking."""

        separator = "=" * 72
        print(separator)
        print("  I/O Path Observability Pipeline")
        if self.comm:
            print(f"  Filter: comm='{self.comm}' (all matching processes)"
                  f"  |  Fork tracking: {'ON' if self.follow_forks else 'OFF'}")
        elif self.pid:
            print(f"  Target PID: {self.pid}"
                  f"  |  Fork tracking: {'ON' if self.follow_forks else 'OFF'}")
        else:
            print(f"  Filter: none (all processes)"
                  f"  |  Fork tracking: {'ON' if self.follow_forks else 'OFF'}")
        print(separator)

        # ────────────────────────────────────────────────────────────────
        # Step 1: Capture Syscalls + Detect Forks
        # ────────────────────────────────────────────────────────────────
        print(f"\n{'─' * 72}")
        print("[Step 1] Identifying Syscalls + Fork Detection ...")
        print(f"{'─' * 72}")

        if self.use_ebpf:
            ok = self.tracer.start_ebpf()
            if ok:
                deadline = time.time() + trace_duration
                while time.time() < deadline:
                    self.tracer.poll_ebpf(timeout_ms=200)
                self.tracer.stop_ebpf()
            else:
                self.tracer.run_strace(duration_sec=trace_duration)
        else:
            self.tracer.run_strace(duration_sec=trace_duration)

        events = self.tracer.events
        all_pids = self.tracer.tracked_pids
        fork_events = self.tracer.fork_events

        # In --comm mode, self.pid may be None. Resolve a primary PID from
        # the discovered set: prefer the lowest PID (likely the parent), or
        # the PID with the most events, or any available PID.
        if not self.pid and all_pids:
            self.pid = min(all_pids)
        elif not self.pid and events:
            # Fallback: use the most active PID from captured events
            pid_event_count = {}
            for ev in events:
                pid_event_count[ev.pid] = pid_event_count.get(ev.pid, 0) + 1
            self.pid = max(pid_event_count, key=pid_event_count.get)

        # Ensure per-PID helpers exist for all discovered PIDs
        for pid in all_pids:
            self._ensure_pid_helpers(pid)

        # ── Fork tree display ──
        if fork_events:
            print(f"\n  ┌── Process Fork Tree ──")
            print(f"  │  Parent PID {self.pid}")
            tree = self.tracer.get_process_tree()
            pid_comm = self.tracer.get_pid_comm_map()
            self._print_fork_tree(self.pid, tree, pid_comm, indent=1)
            print(f"  └──")
            print(f"\n  Tracked PIDs ({len(all_pids)}): {sorted(all_pids)}")
        elif len(all_pids) > 1:
            print(f"\n  Tracked PIDs ({len(all_pids)}): {sorted(all_pids)}")
            print(f"  (Pre-existing children discovered via /proc)")
        else:
            print(f"\n  No child processes detected (single-process workload)")

        print(f"\n  Captured {len(events)} syscall events"
              f" across {len(all_pids)} PID(s):")

        if not events:
            print("  [!] No events captured. Possible causes:")
            print("      • Target process is idle or has finished")
            print("      • FIO already forked and children have exited")
            print("      • Wrong PID (check with: pgrep -a fio)")
            if self.pid and not self.comm:
                print(f"\n  Suggested alternatives:")
                print(f"    # Trace by name (catches ALL fio processes):")
                print(f"    sudo python3 io_path_observer.py --trace --comm fio")
                print(f"")
                print(f"    # Or launch FIO through the observer:")
                print(f"    sudo python3 io_path_observer.py --trace \\")
                print(f"         --launch 'fio ./fio_jobs/mmap_rand_write.fio'")
            return

        # ── Per-PID syscall breakdown ──
        pid_sc_counts = {}  # pid → {syscall → count}
        for ev in events:
            pid_sc_counts.setdefault(ev.pid, {})
            pid_sc_counts[ev.pid][ev.syscall] = \
                pid_sc_counts[ev.pid].get(ev.syscall, 0) + 1

        sc_counts = {}
        for ev in events:
            sc_counts[ev.syscall] = sc_counts.get(ev.syscall, 0) + 1

        print(f"\n  {'Syscall':<16} {'Total':>8}", end="")
        # Limit per-PID columns to top 10 most active PIDs
        top_pids = sorted(pid_sc_counts.keys(),
                          key=lambda p: sum(pid_sc_counts[p].values()),
                          reverse=True)[:10]
        if len(all_pids) > 1:
            for pid in top_pids:
                print(f"  {'PID ' + str(pid):>10}", end="")
            if len(all_pids) > 10:
                print(f"  {'(+' + str(len(all_pids) - 10) + ')':>8}", end="")
        print()
        print(f"  {'─' * (30 + (len(top_pids) * 12))}")

        sc_examples = {}
        for ev in events:
            if ev.syscall not in sc_examples:
                sc_examples[ev.syscall] = ev
        for sc, count in sorted(sc_counts.items(), key=lambda x: -x[1]):
            print(f"  {sc:<16} {count:>8}", end="")
            if len(all_pids) > 1:
                for pid in top_pids:
                    c = pid_sc_counts.get(pid, {}).get(sc, 0)
                    print(f"  {c:>10}", end="")
            print()

        # ── Last N events with PID column ──
        show_count = min(20, len(events))
        print(f"\n  Last {show_count} captured events:")
        print(f"  {'#':>4} {'PID':>6} {'Comm':<10} {'Syscall':<12} {'FD':>4} "
              f"{'Length':>10} {'Offset':>10} {'Extra'}")
        print(f"  {'─' * 78}")
        for i, ev in enumerate(events[-show_count:],
                                start=max(0, len(events) - show_count) + 1):
            fd_str = str(ev.fd) if ev.fd >= 0 else "—"
            len_str = str(ev.length) if ev.length > 0 else "—"
            off_str = str(ev.offset) if ev.offset > 0 else "—"
            extra = ev.filename if ev.filename else (
                hex(ev.return_value) if ev.return_value > 0 else (
                    hex(ev.address) if ev.address > 0 else ""))
            if ev.latency_us > 0:
                extra += f" ({ev.latency_us:.0f}µs)"
            comm = ev.comm[:10] if ev.comm else "—"
            print(f"  {i:>4} {ev.pid:>6} {comm:<10} {ev.syscall:<12} "
                  f"{fd_str:>4} {len_str:>10} {off_str:>10} {extra}")

        # ────────────────────────────────────────────────────────────────
        # Filter stale PIDs: FIO workers may have exited during tracing.
        # Only keep PIDs whose /proc/<pid> still exists.
        # ────────────────────────────────────────────────────────────────
        live_pids = set()
        stale_pids = set()
        for pid in all_pids:
            if os.path.exists(f"/proc/{pid}"):
                live_pids.add(pid)
            else:
                stale_pids.add(pid)

        if stale_pids:
            print(f"\n  [!] {len(stale_pids)} PID(s) exited before post-processing "
                  f"(short-lived workers)")
            print(f"      Live: {len(live_pids)} PID(s) — "
                  f"using these for Steps 2–4")

        # Also find PIDs that actually emitted events (most useful subset)
        active_pids = set()
        pid_event_counts = {}
        for ev in events:
            active_pids.add(ev.pid)
            pid_event_counts[ev.pid] = pid_event_counts.get(ev.pid, 0) + 1

        # For Steps 2-4, use live PIDs that are also active
        analysis_pids = live_pids & active_pids
        if not analysis_pids and live_pids:
            analysis_pids = live_pids  # fallback: use all live PIDs
        if not analysis_pids and active_pids:
            # All PIDs exited — use the ones with most events for event analysis
            analysis_pids = active_pids

        print(f"  Analysis PIDs: {len(analysis_pids)} "
              f"(live + active) from {len(all_pids)} tracked")

        # ────────────────────────────────────────────────────────────────
        # Step 2: Extract FD and Length (per PID — live only)
        # ────────────────────────────────────────────────────────────────
        print(f"\n{'─' * 72}")
        print("[Step 2] Extracting FD Metadata & File Paths (all tracked PIDs) ...")
        print(f"{'─' * 72}")

        # Group events by PID for per-process FD resolution
        fd_cache = {}  # (pid, fd) → fd_info
        opened_files = {}  # (pid, fd) → filename
        target_paths = set()

        for pid in sorted(analysis_pids):
            pid_events = [ev for ev in events if ev.pid == pid]
            if not pid_events:
                continue

            # Only read /proc for live PIDs
            if pid not in live_pids:
                continue

            self._ensure_pid_helpers(pid)
            extractor = self._fd_extractors[pid]
            pid_fds = {}
            for ev in pid_events:
                if ev.fd >= 0 and ev.fd not in pid_fds:
                    pid_fds[ev.fd] = extractor.enrich_event(ev)
                if ev.syscall in ("open", "openat") and ev.filename:
                    opened_files[(pid, ev.fd)] = ev.filename

            for fd_num, info in pid_fds.items():
                fd_cache[(pid, fd_num)] = info

            if pid_fds:
                label = "parent" if pid == self.pid else "child"
                print(f"\n  PID {pid} ({label}) — {len(pid_fds)} FDs:")
                print(f"  {'FD':>6}  {'Path':<50}  {'Offset':>10}")
                print(f"  {'─' * 70}")
                for fd_num in sorted(pid_fds.keys()):
                    info = pid_fds[fd_num]
                    path = info.get("path", "<unknown>")
                    offset = info.get("pos", "—")
                    print(f"  {fd_num:>6}  {path:<50}  {offset:>10}")

                    # Collect target file paths
                    if path and not path.startswith("<") and not path.startswith("/dev/"):
                        target_paths.add(path)

        for key, fname in opened_files.items():
            if fname and not fname.startswith("/dev/"):
                target_paths.add(fname)

        if opened_files:
            print(f"\n  Files Opened (from openat syscalls):")
            seen = set()
            for (pid, fd_num), fname in opened_files.items():
                key = (pid, fname)
                if key not in seen:
                    seen.add(key)
                    print(f"    PID {pid:>6}  fd {fd_num:>4} → {fname}")

        # ────────────────────────────────────────────────────────────────
        # Step 3: Cross-Reference Procfs (per PID)
        # ────────────────────────────────────────────────────────────────
        print(f"\n{'─' * 72}")
        print("[Step 3] Cross-referencing /proc/<pid>/maps (all tracked PIDs) ...")
        print(f"{'─' * 72}")

        # Parse maps for live PIDs only, cache per-PID
        all_maps_cache = {}  # pid → list[MemoryMapping]
        for pid in sorted(analysis_pids):
            if pid not in live_pids:
                continue
            self._ensure_pid_helpers(pid)
            mapper = self._procfs_mappers[pid]
            maps = mapper.parse_maps()
            all_maps_cache[pid] = maps
            file_backed = [m for m in maps if m.is_file_backed]
            anon_maps = [m for m in maps if not m.is_file_backed]
            label = "parent" if pid == self.pid else "child"
            print(f"\n  PID {pid} ({label}): {len(maps)} mappings "
                  f"({len(file_backed)} file-backed, {len(anon_maps)} anonymous)")

            # Show workload-relevant file-backed mappings
            skip_prefixes = ("/usr/lib", "/lib", "/usr/share")
            workload_maps = [m for m in file_backed
                             if not any(m.pathname.startswith(p) for p in skip_prefixes)]
            if workload_maps:
                print(f"    Workload Mappings ({len(workload_maps)}):")
                for m in workload_maps[:10]:
                    print(f"      {m.start_addr:#14x}–{m.end_addr:#14x} "
                          f"{m.permissions} {m.size // 1024:>6} KB  {m.pathname}")

        # Cross-reference each syscall event using its own PID's maps
        mappings_found = 0
        records = []
        for ev in events:
            pid_fd_info = fd_cache.get((ev.pid, ev.fd), {"fd": ev.fd})
            mapper = self._procfs_mappers.get(ev.pid)
            maps = all_maps_cache.get(ev.pid, [])
            mapping = None
            if mapper:
                mapping = mapper.cross_reference(ev, pid_fd_info,
                                                  maps_cache=maps)
            if mapping:
                mappings_found += 1
            records.append(IOTraceRecord(
                syscall_event=ev,
                fd_info=pid_fd_info,
                memory_mapping=mapping,
            ))

        print(f"\n  Events matched to address ranges: {mappings_found}/{len(events)}")

        # Per-PID matched regions
        if mappings_found > 0:
            matched_by_pid = {}  # pid → {addr_key → {mapping, syscalls[]}}
            for rec in records:
                if rec.memory_mapping:
                    pid = rec.syscall_event.pid
                    matched_by_pid.setdefault(pid, {})
                    key = (rec.memory_mapping.start_addr, rec.memory_mapping.pathname)
                    if key not in matched_by_pid[pid]:
                        matched_by_pid[pid][key] = {
                            "mapping": rec.memory_mapping,
                            "syscalls": [],
                        }
                    matched_by_pid[pid][key]["syscalls"].append(
                        rec.syscall_event.syscall)

            for pid in sorted(matched_by_pid.keys()):
                regions = matched_by_pid[pid]
                label = "parent" if pid == self.pid else "child"
                print(f"\n  Matched Regions for PID {pid} ({label}) "
                      f"— {len(regions)} region(s):")
                for key, data in regions.items():
                    m = data["mapping"]
                    sc_summary = ", ".join(
                        f"{s}×{c}" for s, c in
                        sorted(dict((s, data["syscalls"].count(s))
                                    for s in set(data["syscalls"])).items(),
                               key=lambda x: -x[1]))
                    print(f"    {m.start_addr:#14x}–{m.end_addr:#14x} "
                          f"{m.permissions} {m.size // 1024:>6} KB "
                          f"{m.pathname}")
                    print(f"      └─ syscalls: {sc_summary}")

        # ────────────────────────────────────────────────────────────────
        # Step 4: Page Monitoring (per PID, with procfs fallback)
        # ────────────────────────────────────────────────────────────────
        print(f"\n{'─' * 72}")
        print("[Step 4] Monitoring Pages (all tracked PIDs) ...")
        print(f"{'─' * 72}")

        # Collect file-backed mappings from Step 3 matches, grouped by PID
        monitored_keys = set()  # (pid, start_addr, end_addr)
        mappings_to_monitor = []  # list of (pid, MemoryMapping)

        for rec in records:
            if rec.memory_mapping and rec.memory_mapping.is_file_backed:
                pid = rec.syscall_event.pid
                key = (pid, rec.memory_mapping.start_addr, rec.memory_mapping.end_addr)
                if key not in monitored_keys:
                    monitored_keys.add(key)
                    mappings_to_monitor.append((pid, rec.memory_mapping))

        # FALLBACK: scan procfs directly for each PID's target file mappings
        if not mappings_to_monitor and target_paths:
            print(f"\n  [fallback] No mappings from syscall matching — "
                  f"scanning /proc/*/maps for {len(analysis_pids)} live PID(s) ...")
            for pid in sorted(analysis_pids):
                if pid not in live_pids:
                    continue
                mapper = self._procfs_mappers.get(pid)
                maps = all_maps_cache.get(pid, [])
                if not mapper:
                    continue
                fallback = mapper.find_target_file_mappings(
                    target_paths, maps_cache=maps)
                if not fallback:
                    fallback = mapper.find_all_file_backed_mappings(
                        maps_cache=maps)
                for m in fallback:
                    key = (pid, m.start_addr, m.end_addr)
                    if key not in monitored_keys:
                        monitored_keys.add(key)
                        mappings_to_monitor.append((pid, m))

            if mappings_to_monitor:
                print(f"  [fallback] Found {len(mappings_to_monitor)} "
                      f"mapping(s) to monitor:")
                for pid, m in mappings_to_monitor:
                    print(f"    PID {pid:>6}: {m.start_addr:#14x}–{m.end_addr:#14x} "
                          f"{m.permissions} {m.size // 1024:>6} KB {m.pathname}")

        # Run page monitoring
        if mappings_to_monitor:
            print(f"\n  Monitoring {len(mappings_to_monitor)} region(s) "
                  f"for {monitor_duration}s each ...\n")

            for pid, m in mappings_to_monitor:
                monitor = self._page_monitors.get(pid)
                if not monitor:
                    continue
                page_events = monitor.monitor_dirty_pages(
                    m,
                    interval_sec=1.0,
                    duration_sec=monitor_duration,
                )
                # Attach page events to matching trace records
                for r in records:
                    if (r.syscall_event.pid == pid and
                            r.memory_mapping and
                            r.memory_mapping.start_addr == m.start_addr):
                        r.page_events = page_events
        else:
            print(f"\n  [!] No file-backed mappings found for page monitoring.")
            print(f"      Possible causes:")
            print(f"        • Workload uses O_DIRECT (bypasses page cache)")
            print(f"        • Target file not opened yet / child exited")
            print(f"        • Try --duration 20 to catch late forks\n")

        # ────────────────────────────────────────────────────────────────
        # Step 4b: C-Accelerated Visualization (if --visualize enabled)
        # ────────────────────────────────────────────────────────────────
        if self._visualizer and self.visualize:
            print(f"\n{'─' * 72}")
            print(f"[Step 4b] C-Accelerated Memory Visualization "
                  f"(mode: {self.visualize}) ...")
            print(f"{'─' * 72}")

            viz_mode = self.visualize.lower()
            viz_targets = []  # list of (pid, start, end, pathname)

            # Collect visualization targets from mapped regions
            if mappings_to_monitor:
                for pid, m in mappings_to_monitor:
                    viz_targets.append((pid, m.start_addr, m.end_addr, m.pathname))
            else:
                # Fallback: just use each tracked PID with auto-detection
                for pid in sorted(all_pids):
                    viz_targets.append((pid, 0, 0, "<auto-detect>"))

            # Deduplicate by (pid, start)
            seen = set()
            unique_targets = []
            for t in viz_targets:
                key = (t[0], t[1])
                if key not in seen:
                    seen.add(key)
                    unique_targets.append(t)

            for pid, start, end, pathname in unique_targets:
                label = pathname or f"PID {pid}"
                print(f"\n  Target: PID {pid} — {label}")

                if viz_mode in ("snapshot", "all"):
                    self._visualizer.snapshot(pid, start, end)

                if viz_mode in ("heatmap", "all"):
                    self._visualizer.heatmap(
                        pid, start, end,
                        interval_ms=self.viz_interval,
                        iterations=self.viz_iterations,
                    )

                if viz_mode in ("zoom", "all"):
                    self._visualizer.zoom_heatmap(
                        pid, start, end,
                        interval_ms=self.viz_interval,
                        iterations=self.viz_iterations,
                        block_kb=self.viz_block_kb,
                    )

                if viz_mode in ("timeline", "all"):
                    self._visualizer.timeline(
                        pid, start, end,
                        interval_ms=self.viz_interval,
                        iterations=self.viz_iterations,
                    )

            # Region-all always scans entire PID
            if viz_mode in ("region_all", "all"):
                viz_live = sorted(live_pids)[:3] if live_pids else sorted(analysis_pids)[:3]
                for pid in viz_live:
                    self._visualizer.region_scan(
                        pid,
                        interval_ms=self.viz_interval,
                        iterations=min(self.viz_iterations, 5),
                    )

            # File-unified: coalesced multi-mmap heatmap per file
            if viz_mode in ("file_unified", "all"):
                viz_live = sorted(live_pids)[:3] if live_pids else sorted(analysis_pids)[:3]
                for pid in viz_live:
                    self._visualizer.file_unified(
                        pid,
                        interval_ms=self.viz_interval,
                        iterations=self.viz_iterations,
                    )

        self.trace_records = records
        self._print_summary()

    @staticmethod
    def _print_fork_tree(pid: int, tree: dict, comm_map: dict, indent: int = 0):
        """Recursively print the process fork tree."""
        children = tree.get(pid, [])
        for child in children:
            prefix = "  │" + "  " * indent
            comm = comm_map.get(child, "?")
            print(f"{prefix}├─ child PID {child} [{comm}]")
            IOPathObserver._print_fork_tree(child, tree, comm_map, indent + 1)

    def _print_summary(self):
        """Print a comprehensive summary of the full trace."""
        print(f"\n{'═' * 72}")
        print("  PIPELINE SUMMARY")
        print(f"{'═' * 72}")

        all_pids = self.tracer.tracked_pids
        fork_events = self.tracer.fork_events

        # ── Process tree summary ──
        if fork_events or len(all_pids) > 1:
            print(f"\n  Process Tree ({len(all_pids)} PIDs tracked, "
                  f"{len(fork_events)} fork(s) detected):")
            tree = self.tracer.get_process_tree()
            comm_map = self.tracer.get_pid_comm_map()
            root_comm = comm_map.get(self.pid, "?")
            print(f"    {self.pid} [{root_comm}] (target)")
            self._print_fork_tree_summary(self.pid, tree, comm_map, indent=2)

            # PIDs not in tree (pre-existing children)
            orphans = all_pids - {self.pid}
            for fe in fork_events:
                orphans.discard(fe.child_pid)
            if orphans:
                for opid in sorted(orphans):
                    print(f"    └─ {opid} [{comm_map.get(opid, '?')}] (pre-existing)")

        # ── Syscall breakdown ──
        sc_counts = {}
        total_bytes_read = 0
        total_bytes_written = 0
        fsync_count = 0
        fsync_latencies = []
        per_pid_stats = {}  # pid → {events, bytes_r, bytes_w}

        for rec in self.trace_records:
            ev = rec.syscall_event
            sc = ev.syscall
            sc_counts[sc] = sc_counts.get(sc, 0) + 1

            # Per-PID stats
            if ev.pid not in per_pid_stats:
                per_pid_stats[ev.pid] = {"events": 0, "bytes_r": 0,
                                          "bytes_w": 0, "syscalls": set()}
            per_pid_stats[ev.pid]["events"] += 1
            per_pid_stats[ev.pid]["syscalls"].add(sc)

            if sc in ("read", "pread64"):
                total_bytes_read += ev.length
                per_pid_stats[ev.pid]["bytes_r"] += ev.length
            elif sc in ("write", "pwrite64"):
                total_bytes_written += ev.length
                per_pid_stats[ev.pid]["bytes_w"] += ev.length
            elif sc in ("fsync", "fdatasync"):
                fsync_count += 1
                if ev.latency_us > 0:
                    fsync_latencies.append(ev.latency_us)

        print(f"\n  ┌── Syscall Distribution ──")
        for sc, count in sorted(sc_counts.items(), key=lambda x: -x[1]):
            bar = "█" * min(40, count // max(1, max(sc_counts.values()) // 40))
            print(f"  │  {sc:<16} {count:>6}  {bar}")
        print(f"  └──")

        # ── Per-PID event breakdown ──
        if len(per_pid_stats) > 1:
            print(f"\n  Per-PID Breakdown:")
            print(f"  {'PID':>8}  {'Role':<8}  {'Events':>8}  "
                  f"{'Read':>10}  {'Write':>10}  {'Syscalls'}")
            print(f"  {'─' * 72}")
            for pid in sorted(per_pid_stats.keys()):
                s = per_pid_stats[pid]
                role = "parent" if pid == self.pid else "child"
                r_str = f"{s['bytes_r'] / (1024*1024):.1f}MB" if s['bytes_r'] else "—"
                w_str = f"{s['bytes_w'] / (1024*1024):.1f}MB" if s['bytes_w'] else "—"
                sc_str = ",".join(sorted(s["syscalls"]))
                print(f"  {pid:>8}  {role:<8}  {s['events']:>8}  "
                      f"{r_str:>10}  {w_str:>10}  {sc_str}")

        # ── I/O volume ──
        if total_bytes_read > 0 or total_bytes_written > 0:
            print(f"\n  I/O Volume (aggregate):")
            if total_bytes_read > 0:
                print(f"    Read:  {total_bytes_read:>12,} bytes "
                      f"({total_bytes_read / (1024*1024):.1f} MB)")
            if total_bytes_written > 0:
                print(f"    Write: {total_bytes_written:>12,} bytes "
                      f"({total_bytes_written / (1024*1024):.1f} MB)")

        # ── fsync latency ──
        if fsync_latencies:
            avg_lat = sum(fsync_latencies) / len(fsync_latencies)
            min_lat = min(fsync_latencies)
            max_lat = max(fsync_latencies)
            print(f"\n  fsync Latency ({len(fsync_latencies)} calls):")
            print(f"    avg={avg_lat:.0f}µs  min={min_lat:.0f}µs  max={max_lat:.0f}µs")

        # ── File breakdown ──
        file_ios = {}
        for rec in self.trace_records:
            path = rec.fd_info.get("path", "<unknown>")
            if path not in file_ios:
                file_ios[path] = {"count": 0, "bytes": 0, "syscalls": set(),
                                   "pids": set()}
            file_ios[path]["count"] += 1
            file_ios[path]["bytes"] += rec.syscall_event.length
            file_ios[path]["syscalls"].add(rec.syscall_event.syscall)
            file_ios[path]["pids"].add(rec.syscall_event.pid)

        print(f"\n  Files Accessed ({len(file_ios)}):")
        print(f"  {'Count':>8}  {'Bytes':>12}  {'PIDs':>6}  "
              f"{'Syscalls':<20}  {'Path'}")
        print(f"  {'─' * 76}")
        for path, info in sorted(file_ios.items(), key=lambda x: -x[1]["count"])[:15]:
            sc_str = ",".join(sorted(info["syscalls"]))
            bytes_str = f"{info['bytes']:,}" if info["bytes"] > 0 else "—"
            pid_count = len(info["pids"])
            print(f"  {info['count']:>8}  {bytes_str:>12}  {pid_count:>6}  "
                  f"{sc_str:<20}  {path}")

        # ── Mapped regions summary ──
        mapped = [r for r in self.trace_records if r.memory_mapping]
        unique_regions = {}
        for r in mapped:
            m = r.memory_mapping
            key = (r.syscall_event.pid, m.start_addr)
            if key not in unique_regions:
                unique_regions[key] = (r.syscall_event.pid, m)

        if unique_regions:
            print(f"\n  Memory-Mapped Regions ({len(unique_regions)} unique):")
            print(f"  {'PID':>8}  {'Start':>16}  {'End':>16}  {'Perm':>5}  "
                  f"{'Size':>10}  {'File'}")
            print(f"  {'─' * 76}")
            for key in sorted(unique_regions.keys()):
                pid, m = unique_regions[key]
                print(f"  {pid:>8}  {m.start_addr:#16x}  {m.end_addr:#16x}  "
                      f"{m.permissions:>5}  {m.size // 1024:>8} KB  {m.pathname}")
        else:
            print(f"\n  Memory-Mapped Regions: none matched")

        # ── Page monitoring stats ──
        total_snapshots = sum(len(r.page_events) for r in self.trace_records)
        if total_snapshots > 0:
            total_pages = sum(pe.page_count
                              for r in self.trace_records for pe in r.page_events)
            print(f"\n  Page Monitor Results:")
            print(f"    Dirty snapshots: {total_snapshots}")
            print(f"    Total dirty pages: {total_pages} "
                  f"({total_pages * 4} KB dirtied)")

            file_dirty = {}
            for r in self.trace_records:
                for pe in r.page_events:
                    f = pe.mapping_file or "<anon>"
                    file_dirty[f] = file_dirty.get(f, 0) + pe.page_count
            if file_dirty:
                print(f"    Per-file dirty pages:")
                for f, count in sorted(file_dirty.items(), key=lambda x: -x[1]):
                    print(f"      {count:>8} pages ({count * 4:>8} KB)  {f}")

        print(f"\n{'═' * 72}\n")

    @staticmethod
    def _print_fork_tree_summary(pid, tree, comm_map, indent=0):
        """Recursively print fork tree for summary section."""
        children = tree.get(pid, [])
        for child in children:
            prefix = "    " + "  " * indent
            comm = comm_map.get(child, "?")
            print(f"{prefix}└─ {child} [{comm}]")
            IOPathObserver._print_fork_tree_summary(child, tree, comm_map, indent + 1)

    def export_json(self, output_path: str):
        """Export full trace data to JSON including fork tree and per-PID stats."""
        # Build process tree
        tree = self.tracer.get_process_tree()
        comm_map = self.tracer.get_pid_comm_map()

        data = {
            "pid": self.pid,
            "timestamp": datetime.now().isoformat(),
            "follow_forks": self.follow_forks,
            "tracked_pids": sorted(self.tracer.tracked_pids),
            "process_tree": {
                "root_pid": self.pid,
                "root_comm": comm_map.get(self.pid, ""),
                "forks": [
                    {
                        "timestamp": fe.timestamp,
                        "parent_pid": fe.parent_pid,
                        "child_pid": fe.child_pid,
                        "parent_comm": fe.parent_comm,
                        "child_comm": fe.child_comm,
                    }
                    for fe in self.tracer.fork_events
                ],
                "children": tree,
            },
            "event_count": len(self.trace_records),
            "events": [],
        }
        for rec in self.trace_records:
            entry = {
                "syscall": {
                    "type": rec.syscall_event.syscall,
                    "pid": rec.syscall_event.pid,
                    "comm": rec.syscall_event.comm,
                    "fd": rec.syscall_event.fd,
                    "length": rec.syscall_event.length,
                    "offset": rec.syscall_event.offset,
                    "timestamp": rec.syscall_event.timestamp,
                    "latency_us": rec.syscall_event.latency_us,
                    "filename": rec.syscall_event.filename,
                },
                "fd_info": rec.fd_info,
                "mapping": None,
                "page_events": len(rec.page_events),
            }
            if rec.memory_mapping:
                m = rec.memory_mapping
                entry["mapping"] = {
                    "start": hex(m.start_addr),
                    "end": hex(m.end_addr),
                    "size_kb": m.size // 1024,
                    "permissions": m.permissions,
                    "file": m.pathname,
                }
            data["events"].append(entry)

        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[export] Trace data written to {output_path}")


# =============================================================================
# Quick Inspection Helpers (usable standalone)
# =============================================================================

def inspect_process(pid: int):
    """Quick-look at a process's I/O state without tracing."""
    print(f"\n{'=' * 60}")
    print(f"  Quick I/O Inspection – PID {pid}")
    print(f"{'=' * 60}")

    # Open FDs
    fd_ext = FDExtractor(pid)
    fds = fd_ext.get_all_fds()
    print(f"\n  Open File Descriptors: {len(fds)}")
    for fd_num, path in sorted(fds.items())[:20]:
        print(f"    fd {fd_num:4d} → {path}")
    if len(fds) > 20:
        print(f"    ... and {len(fds) - 20} more")

    # Memory maps
    mapper = ProcfsMapper(pid)
    maps = mapper.parse_maps()
    file_maps = [m for m in maps if m.is_file_backed]
    anon_maps = [m for m in maps if not m.is_file_backed]
    total_mapped = sum(m.size for m in maps)
    print(f"\n  Memory Mappings: {len(maps)} total "
          f"({len(file_maps)} file-backed, {len(anon_maps)} anonymous)")
    print(f"  Total Mapped: {total_mapped // (1024 * 1024)} MB")

    print("\n  File-Backed Mappings:")
    for m in file_maps[:15]:
        print(f"    {m.start_addr:#14x}-{m.end_addr:#14x}  "
              f"{m.permissions}  {m.size // 1024:>8d} KB  {m.pathname}")

    # map_files (needs root)
    mf = mapper.list_map_files()
    if mf:
        print(f"\n  /proc/{pid}/map_files entries: {len(mf)}")

    print()


# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="I/O Path Observability Tool with FIO Integration and Fork Tracking",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Examples:
          # Trace ALL fio processes by name (catches parent + all workers)
          %(prog)s --trace --comm fio --duration 15

          # Launch FIO and trace from birth (guaranteed to catch forks)
          %(prog)s --trace --launch "fio ./fio_jobs/mmap_rand_write.fio"

          # Trace a specific PID with auto fork tracking
          %(prog)s --trace --pid 12345 --duration 30

          # Trace with strace fallback
          %(prog)s --trace --comm fio --strace --duration 10

          # Trace a specific PID WITHOUT following children
          %(prog)s --trace --pid 12345 --no-follow-forks

          # Generate all FIO job files
          %(prog)s --generate-fio --fio-dir ./fio_jobs

          # Quick inspection of a process
          %(prog)s --inspect --pid 12345

          # Full demo
          %(prog)s --demo
        """),
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--generate-fio", action="store_true",
                      help="Generate FIO job files for I/O workloads")
    mode.add_argument("--trace", action="store_true",
                      help="Run the 4-step observability pipeline on a process")
    mode.add_argument("--inspect", action="store_true",
                      help="Quick-inspect a process's FDs and memory maps")
    mode.add_argument("--demo", action="store_true",
                      help="Run demo: generate FIO configs and print pipeline overview")

    # ── Target selection (at least one of --pid, --comm, --launch for --trace) ──
    parser.add_argument("--pid", type=int,
                        help="Target process ID (use with --trace or --inspect)")
    parser.add_argument("--comm", type=str, metavar="NAME",
                        help="Filter by process name — traces ALL matching PIDs "
                             "(e.g. --comm fio). No need for --pid.")
    parser.add_argument("--launch", type=str, metavar="CMD",
                        help="Launch a command and trace it from birth "
                             "(e.g. --launch 'fio job.fio'). Guarantees fork "
                             "capture from the start.")

    parser.add_argument("--duration", type=int, default=10,
                        help="Tracing duration in seconds (default: 10)")
    parser.add_argument("--monitor-duration", type=float, default=5.0,
                        help="Page monitoring duration per mapping (default: 5.0)")
    parser.add_argument("--strace", action="store_true",
                        help="Force strace instead of eBPF")
    parser.add_argument("--no-follow-forks", action="store_true",
                        help="Disable automatic fork/clone child PID tracking "
                             "(default: follow forks)")
    parser.add_argument("--fio-dir", default="./fio_jobs",
                        help="Output directory for FIO job files")
    parser.add_argument("--fio-size", default="1G",
                        help="FIO test file size (default: 1G)")
    parser.add_argument("--fio-runtime", default="30",
                        help="FIO runtime in seconds (default: 30)")
    parser.add_argument("--fio-target", default="/tmp/fio_testfile",
                        help="FIO target file path")
    parser.add_argument("--output-json", default=None,
                        help="Export trace results to JSON file")
    parser.add_argument("--show-commands", action="store_true",
                        help="Show FIO run commands after generating configs")
    parser.add_argument("--visualize", type=str, metavar="MODE", default=None,
                        help="Enable pagemon C-accelerated visualization. "
                             "Modes: snapshot, heatmap, timeline, region_all, "
                             "file_unified, zoom, all. "
                             "'zoom' does a coarse minimap then fine detail "
                             "on the hottest region.")
    parser.add_argument("--viz-interval", type=int, default=500,
                        help="Visualization polling interval in ms (default: 500)")
    parser.add_argument("--viz-iterations", type=int, default=10,
                        help="Visualization iteration count (default: 10)")
    parser.add_argument("--viz-granularity", type=str, default="auto",
                        metavar="LEVEL",
                        help="Heatmap block granularity. "
                             "Presets: page (4KB), fine (64KB), medium (256KB), "
                             "coarse (1MB), auto. Or a number in KB (e.g. 128). "
                             "(default: auto)")

    args = parser.parse_args()

    # ── Generate FIO Configs ──
    if args.generate_fio:
        gen = FIOConfigGenerator(
            output_dir=args.fio_dir,
            target_file=args.fio_target,
            file_size=args.fio_size,
            runtime=args.fio_runtime,
        )
        print(f"Generating FIO job files in {args.fio_dir}/ ...\n")
        generated = gen.generate_all()
        combined = gen.generate_combined_job()

        for name, path in generated:
            profile = gen.PROFILES[name]
            print(f"  ✓ {path.name:35s}  – {profile['description']}")
        print(f"  ✓ {combined.name:35s}  – All profiles combined")

        if args.show_commands:
            print("\nRun commands:")
            for name, path in generated:
                print(f"  {gen.get_fio_run_command(str(path))}")
            print(f"\n  # Or run all sequentially:")
            print(f"  {gen.get_fio_run_command(str(combined))}")

            print("\n  # Run a single section from combined file:")
            print(f"  sudo fio {combined} --section=mmap_seq_read")

        print(f"\nTo trace FIO with this tool:")
        print(f"  # Option A: trace by process name (easiest, catches all workers)")
        print(f"  sudo fio {args.fio_dir}/mmap_rand_write.fio &")
        print(f"  sudo python3 {sys.argv[0]} --trace --comm fio --duration 15")
        print(f"")
        print(f"  # Option B: launch FIO through the observer (guaranteed fork capture)")
        print(f"  sudo python3 {sys.argv[0]} --trace "
              f"--launch 'fio {args.fio_dir}/mmap_rand_write.fio' --duration 15")
        print(f"")
        print(f"  # Option C: trace by PID (requires knowing the parent PID)")
        print(f"  sudo fio {args.fio_dir}/mmap_seq_read.fio &")
        print(f"  sudo python3 {sys.argv[0]} --trace --pid $(pgrep -x fio | head -1)")

    # ── Trace Pipeline ──
    elif args.trace:
        target_pid = args.pid
        target_comm = args.comm
        launched_proc = None

        # ── --launch mode: start the command, get its PID ──
        if args.launch:
            import shlex
            launch_cmd = shlex.split(args.launch)
            # Prepend sudo if the command doesn't already have it
            if launch_cmd[0] != "sudo":
                launch_cmd = ["sudo"] + launch_cmd

            print(f"[launch] Starting: {' '.join(launch_cmd)}")
            launched_proc = subprocess.Popen(
                launch_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            target_pid = launched_proc.pid
            print(f"[launch] Process started with PID {target_pid}")
            # Give the process a moment to initialize and fork
            time.sleep(1)

        # Validate: at least one target selection method
        if not target_pid and not target_comm:
            parser.error(
                "--trace requires at least one of:\n"
                "  --pid PID       Trace a specific process\n"
                "  --comm NAME     Trace all processes by name (e.g. --comm fio)\n"
                "  --launch CMD    Start and trace a command from birth"
            )

        try:
            observer = IOPathObserver(
                pid=target_pid,
                comm=target_comm,
                use_ebpf=not args.strace,
                follow_forks=not args.no_follow_forks,
                visualize=args.visualize,
                viz_interval=args.viz_interval,
                viz_iterations=args.viz_iterations,
                viz_granularity=args.viz_granularity,
            )
            observer.run_pipeline(
                trace_duration=args.duration,
                monitor_duration=args.monitor_duration,
            )

            if args.output_json:
                observer.export_json(args.output_json)
        finally:
            # Clean up launched process
            if launched_proc:
                print(f"\n[launch] Terminating launched process PID {launched_proc.pid} ...")
                try:
                    launched_proc.terminate()
                    launched_proc.wait(timeout=5)
                except Exception:
                    launched_proc.kill()

    # ── Quick Inspect ──
    elif args.inspect:
        if not args.pid:
            parser.error("--inspect requires --pid")
        inspect_process(args.pid)

    # ── Demo Mode ──
    elif args.demo:
        print("=" * 72)
        print("  I/O Path Observability – Demo Mode")
        print("=" * 72)

        # Generate FIO configs
        gen = FIOConfigGenerator(
            output_dir=args.fio_dir,
            target_file=args.fio_target,
            file_size=args.fio_size,
            runtime=args.fio_runtime,
        )
        print("\n[FIO] Generating workload configurations ...\n")
        generated = gen.generate_all()
        combined = gen.generate_combined_job()
        for name, path in generated:
            desc = gen.PROFILES[name]["description"]
            print(f"  ✓ {name:25s}  {desc}")

        # Print pipeline documentation
        print(textwrap.dedent("""
        ┌─────────────────────────────────────────────────────────────────┐
        │         I/O PATH OBSERVABILITY PIPELINE (Fork-Aware)           │
        ├─────────────────────────────────────────────────────────────────┤
        │                                                                │
        │  ┌──────────────┐   eBPF / strace                             │
        │  │  Step 1      │   Attach to target PID                      │
        │  │  Syscall ID  │──→ Capture: mmap, open, read, write, fsync  │
        │  │  + Fork Det. │   Detect: fork/clone → auto-track children  │
        │  └──────┬───────┘   BPF_HASH(tracked_pids) auto-expands      │
        │         │                                                      │
        │         ▼           PID tracking flow:                         │
        │   ┌─────────────┐   sched:sched_process_fork fires            │
        │   │ Fork Detect │──→ parent_pid in tracked_pids?              │
        │   └──────┬──────┘   YES → add child_pid to tracked_pids      │
        │          │          + scan /proc/<pid>/task/*/children         │
        │          ▼                                                     │
        │  ┌──────────────┐   /proc/<pid>/fd + /proc/<pid>/fdinfo       │
        │  │  Step 2      │   Resolve: fd → file path  (per PID)       │
        │  │  FD Extract  │──→ Read: file offset, flags, mnt_id         │
        │  └──────┬───────┘   Cache: unique FD metadata across PIDs     │
        │         │                                                      │
        │         ▼                                                      │
        │  ┌──────────────┐   /proc/<pid>/maps + map_files (per PID)   │
        │  │  Step 3      │   Parse: virtual address ranges             │
        │  │  Procfs Xref │──→ Match: fd path ↔ mmap region             │
        │  └──────┬───────┘   Children may have DIFFERENT mappings!     │
        │         │                                                      │
        │         ▼                                                      │
        │  ┌──────────────┐   /proc/<pid>/pagemap + clear_refs         │
        │  │  Step 4      │   Clear soft-dirty bits (per PID)          │
        │  │  Page Monitor│──→ Poll: detect newly dirtied pages         │
        │  └──────────────┘   Report: dirty page count per PID          │
        │                                                                │
        └─────────────────────────────────────────────────────────────────┘

        Why fork tracking matters (the FIO problem):
          FIO with numjobs>1 or mmap engine forks child worker processes.
          The PARENT process opens/creates the file, but CHILD processes
          perform the actual mmap and I/O. Without fork tracking:
            • Parent-only tracer misses mmap/read/write in children
            • /proc/<parent>/maps has no file-backed mappings
            • Step 4 page monitoring finds nothing → false "direct I/O"

          Root cause confirmed via: GDB set follow-fork-mode child

        Recommended FIO profiles for fork testing:

          Multi-process (numjobs>1):
            • random_read_4k.fio   → 4 child workers (numjobs=4)
            • random_write_4k.fio  → 4 child workers (numjobs=4)
            • mixed_rw_buffered.fio → 2 child workers (numjobs=2)

          mmap engine (fork + mmap):
            • mmap_seq_read.fio    → child does mmap() + sequential read
            • mmap_rand_write.fio  → child does mmap() + random writes

        Quick-start (three ways to trace):

          # A) By process name (easiest — catches all workers):
          Terminal 1:  sudo fio ./fio_jobs/mmap_rand_write.fio &
          Terminal 2:  sudo python3 io_path_observer.py --trace \\
                         --comm fio --duration 15

          # B) Launch through observer (guaranteed fork capture):
          sudo python3 io_path_observer.py --trace \\
                 --launch 'fio ./fio_jobs/mmap_rand_write.fio' --duration 15

          # C) By PID (traditional):
          Terminal 1:  sudo fio ./fio_jobs/mmap_rand_write.fio &
          Terminal 2:  sudo python3 io_path_observer.py --trace \\
                         --pid $(pgrep -x fio | head -1) --duration 15
        """))


if __name__ == "__main__":
    main()
