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
  # Generate FIO config and run observability pipeline
  python3 io_path_observer.py --generate-fio          # Generate FIO job files
  python3 io_path_observer.py --trace --pid <PID>      # Trace a running FIO process
  python3 io_path_observer.py --demo                   # Run full demo pipeline

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

    # BPF program source for tracing mmap and open syscalls
    BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/mm.h>

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

/* ---------- mmap tracing (enter + exit) ---------- */

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
    event.ret    = args->ret;  /* <-- the returned VA from kernel */
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    mmap_events.perf_submit(args, &event, sizeof(event));
    mmap_args_map.delete(&tid);
    return 0;
}

/* ---------- openat tracing ---------- */

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

/* ---------- read/write tracing ---------- */

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

/* ---------- fsync tracing ---------- */

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

    def __init__(self, target_pid: int = None):
        self.target_pid = target_pid
        self.events: list[SyscallEvent] = []
        self._bpf = None

    def _build_bpf_source(self) -> str:
        """Compile BPF source with optional PID filter."""
        src = self.BPF_PROGRAM
        if self.target_pid:
            src = src.replace("FILTER_PID",
                              f"if (pid != {self.target_pid}) return 0;")
        else:
            src = src.replace("FILTER_PID", "")
        return src

    def start_ebpf(self):
        """Attach eBPF probes (requires root + bcc)."""
        try:
            from bcc import BPF
        except ImportError:
            print("[WARN] bcc not available – falling back to strace mode.")
            return False

        src = self._build_bpf_source()
        self._bpf = BPF(text=src)

        def _handle_mmap(cpu, data, size):
            event = self._bpf["mmap_events"].event(data)
            self.events.append(SyscallEvent(
                timestamp=event.timestamp / 1e9,
                pid=event.pid, tid=event.tid,
                syscall="mmap", fd=event.fd,
                address=event.addr, length=event.length,
                offset=event.offset,
                flags=f"prot={event.prot:#x},flags={event.flags:#x}",
                return_value=event.ret,  # mapped VA from sys_exit_mmap
            ))

        def _handle_open(cpu, data, size):
            event = self._bpf["open_events"].event(data)
            self.events.append(SyscallEvent(
                timestamp=event.timestamp / 1e9,
                pid=event.pid, tid=event.tid,
                syscall="openat", fd=event.fd,
                flags=f"{event.flags:#x}",
                filename=event.filename.decode("utf-8", errors="replace"),
            ))

        def _handle_rw(cpu, data, size):
            event = self._bpf["rw_events"].event(data)
            sc = "write" if event.is_write else "read"
            self.events.append(SyscallEvent(
                timestamp=event.timestamp / 1e9,
                pid=event.pid, tid=event.tid,
                syscall=sc, fd=event.fd,
                length=event.count, offset=event.offset,
            ))

        def _handle_sync(cpu, data, size):
            event = self._bpf["sync_events"].event(data)
            self.events.append(SyscallEvent(
                timestamp=event.timestamp / 1e9,
                pid=event.pid, tid=event.tid,
                syscall="fsync", fd=event.fd,
                return_value=event.ret,
                latency_us=event.latency_ns / 1000.0,
            ))

        self._bpf["mmap_events"].open_perf_buffer(_handle_mmap)
        self._bpf["open_events"].open_perf_buffer(_handle_open)
        self._bpf["rw_events"].open_perf_buffer(_handle_rw)
        self._bpf["sync_events"].open_perf_buffer(_handle_sync)

        print(f"[eBPF] Probes attached"
              f"{f' (filtering PID {self.target_pid})' if self.target_pid else ''}")
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
    STRACE_RE = re.compile(
        r"(?:\[pid\s+\d+\]\s+)?(\d+\.\d+)\s+(\w+)\(([^)]*)\)\s+=\s+(-?(?:0x[0-9a-fA-F]+|\d+))"
    )

    def run_strace(self, duration_sec: int = 10) -> list[SyscallEvent]:
        """Trace syscalls using strace as a fallback (requires target PID)."""
        if not self.target_pid:
            raise ValueError("strace fallback requires --pid")

        syscalls_filter = "mmap,open,openat,read,write,pread64,pwrite64,fsync,fdatasync,msync"
        cmd = [
            "sudo", "strace",
            "-p", str(self.target_pid),
            "-e", f"trace={syscalls_filter}",
            "-ttt",             # Epoch timestamps
            "-T",               # Syscall duration
            "-f",               # Follow threads
            "-o", "/dev/stdout",
        ]

        print(f"[strace] Attaching to PID {self.target_pid} for {duration_sec}s ...")
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
        for line in stdout.splitlines():
            m = self.STRACE_RE.match(line.strip())
            if not m:
                continue
            ts, sc, args_str, ret = m.groups()
            # Parse return value (handles both decimal and hex 0x... from mmap)
            try:
                ret_val = int(ret, 0)  # auto-detect base from prefix
            except ValueError:
                ret_val = 0
            ev = SyscallEvent(
                timestamp=float(ts),
                pid=self.target_pid,
                tid=self.target_pid,
                syscall=sc,
                return_value=ret_val,
            )
            self._parse_strace_args(ev, sc, args_str)
            events.append(ev)

        self.events.extend(events)
        print(f"[strace] Captured {len(events)} events")
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
# Orchestrator: Full Pipeline
# =============================================================================

class IOPathObserver:
    """
    Orchestrates the 4-step I/O path observability pipeline.

    Step 1 → SyscallTracer   : Catch mmap / open / read / write / fsync
    Step 2 → FDExtractor     : Get FD path and metadata
    Step 3 → ProcfsMapper    : Cross-reference with /proc/<pid>/maps
    Step 4 → PageMonitor     : Watch address ranges for dirty-page flushes
    """

    def __init__(self, pid: int, use_ebpf: bool = True):
        self.pid = pid
        self.tracer = SyscallTracer(target_pid=pid)
        self.fd_extractor = FDExtractor(pid)
        self.procfs_mapper = ProcfsMapper(pid)
        self.page_monitor = PageMonitor(pid)
        self.use_ebpf = use_ebpf
        self.trace_records: list[IOTraceRecord] = []

    def run_pipeline(self, trace_duration: int = 10, monitor_duration: float = 5.0):
        """Execute the full 4-step pipeline."""

        separator = "=" * 72
        print(separator)
        print("  I/O Path Observability Pipeline")
        print(f"  Target PID: {self.pid}")
        print(separator)

        # ────────────────────────────────────────────────────────────────
        # Step 1: Capture Syscalls
        # ────────────────────────────────────────────────────────────────
        print(f"\n{'─' * 72}")
        print("[Step 1] Identifying Syscalls (eBPF / strace) ...")
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
        print(f"\n  Captured {len(events)} syscall events:")

        if not events:
            print("  [!] No events captured. Is the target process doing I/O?")
            print("      Verify PID is correct and the process is actively running.")
            return

        # Print captured syscall event list
        sc_counts = {}
        for ev in events:
            sc_counts[ev.syscall] = sc_counts.get(ev.syscall, 0) + 1

        print(f"\n  {'Syscall':<16} {'Count':>8}  {'Example FD':>10}  {'Length/Size':>12}")
        print(f"  {'─' * 52}")
        # Collect one example per syscall type
        sc_examples = {}
        for ev in events:
            if ev.syscall not in sc_examples:
                sc_examples[ev.syscall] = ev
        for sc, count in sorted(sc_counts.items(), key=lambda x: -x[1]):
            ex = sc_examples[sc]
            fd_str = str(ex.fd) if ex.fd >= 0 else "—"
            len_str = str(ex.length) if ex.length > 0 else (
                hex(ex.address) if ex.address > 0 else "—")
            print(f"  {sc:<16} {count:>8}  {fd_str:>10}  {len_str:>12}")

        # Show recent syscall trace (last 20 events for context)
        show_count = min(20, len(events))
        print(f"\n  Last {show_count} captured syscall events:")
        print(f"  {'#':>4} {'Syscall':<12} {'FD':>4} {'Length':>10} "
              f"{'Offset':>10} {'Filename / Address'}")
        print(f"  {'─' * 68}")
        for i, ev in enumerate(events[-show_count:], start=max(0, len(events) - show_count) + 1):
            fd_str = str(ev.fd) if ev.fd >= 0 else "—"
            len_str = str(ev.length) if ev.length > 0 else "—"
            off_str = str(ev.offset) if ev.offset > 0 else "—"
            extra = ev.filename if ev.filename else (
                hex(ev.return_value) if ev.return_value > 0 else (
                    hex(ev.address) if ev.address > 0 else ""))
            if ev.latency_us > 0:
                extra += f" ({ev.latency_us:.0f}µs)"
            print(f"  {i:>4} {ev.syscall:<12} {fd_str:>4} {len_str:>10} "
                  f"{off_str:>10} {extra}")

        # ────────────────────────────────────────────────────────────────
        # Step 2: Extract FD and Length
        # ────────────────────────────────────────────────────────────────
        print(f"\n{'─' * 72}")
        print("[Step 2] Extracting FD Metadata & File Paths ...")
        print(f"{'─' * 72}")

        fd_cache = {}
        for ev in events:
            if ev.fd >= 0 and ev.fd not in fd_cache:
                fd_cache[ev.fd] = self.fd_extractor.enrich_event(ev)

        # Also extract filenames from open/openat events
        opened_files = {}
        for ev in events:
            if ev.syscall in ("open", "openat") and ev.filename:
                opened_files[ev.fd] = ev.filename

        print(f"\n  Unique FDs Resolved: {len(fd_cache)}")
        print(f"\n  {'FD':>6}  {'Path':<50}  {'Offset':>10}")
        print(f"  {'─' * 70}")
        for fd_num in sorted(fd_cache.keys()):
            info = fd_cache[fd_num]
            path = info.get("path", "<unknown>")
            offset = info.get("pos", "—")
            print(f"  {fd_num:>6}  {path:<50}  {offset:>10}")

        if opened_files:
            print(f"\n  Files Accessed (from openat syscalls):")
            seen_files = set()
            for fd_num, fname in opened_files.items():
                if fname not in seen_files:
                    seen_files.add(fname)
                    print(f"    fd {fd_num:>4} → {fname}")

        # Collect all unique target file paths for Step 4 fallback
        target_paths = set()
        for info in fd_cache.values():
            p = info.get("path", "")
            if p and not p.startswith("<") and not p.startswith("/dev/"):
                target_paths.add(p)
        for fname in opened_files.values():
            if fname and not fname.startswith("/dev/"):
                target_paths.add(fname)

        # ────────────────────────────────────────────────────────────────
        # Step 3: Cross-Reference Procfs
        # ────────────────────────────────────────────────────────────────
        print(f"\n{'─' * 72}")
        print(f"[Step 3] Cross-referencing /proc/{self.pid}/maps & map_files ...")
        print(f"{'─' * 72}")

        # Parse maps once and cache for all lookups
        maps_cache = self.procfs_mapper.parse_maps()
        file_backed = [m for m in maps_cache if m.is_file_backed]
        anon_maps = [m for m in maps_cache if not m.is_file_backed]

        print(f"\n  Total mappings: {len(maps_cache)} "
              f"({len(file_backed)} file-backed, {len(anon_maps)} anonymous)")

        # Show all file-backed mappings relevant to the workload (not libc etc.)
        skip_prefixes = ("/usr/lib", "/lib", "/usr/share")
        workload_maps = [m for m in file_backed
                         if not any(m.pathname.startswith(p) for p in skip_prefixes)]
        if workload_maps:
            print(f"\n  Workload File-Backed Mappings ({len(workload_maps)}):")
            print(f"  {'Start Addr':>16}  {'End Addr':>16}  {'Perm':>5} "
                  f"{'Size KB':>8}  {'File'}")
            print(f"  {'─' * 75}")
            for m in workload_maps[:20]:
                print(f"  {m.start_addr:#16x}  {m.end_addr:#16x}  {m.permissions:>5} "
                      f"{m.size // 1024:>8}  {m.pathname}")

        # Cross-reference each syscall event
        mappings_found = 0
        records = []
        for ev in events:
            fd_info = fd_cache.get(ev.fd, {"fd": ev.fd})
            mapping = self.procfs_mapper.cross_reference(ev, fd_info,
                                                          maps_cache=maps_cache)
            if mapping:
                mappings_found += 1
            records.append(IOTraceRecord(
                syscall_event=ev,
                fd_info=fd_info,
                memory_mapping=mapping,
            ))

        print(f"\n  Events matched to address ranges: {mappings_found}/{len(events)}")

        # Show matched mapping details
        if mappings_found > 0:
            matched_regions = {}
            for rec in records:
                if rec.memory_mapping:
                    key = (rec.memory_mapping.start_addr, rec.memory_mapping.pathname)
                    if key not in matched_regions:
                        matched_regions[key] = {
                            "mapping": rec.memory_mapping,
                            "syscalls": [],
                        }
                    matched_regions[key]["syscalls"].append(rec.syscall_event.syscall)

            print(f"\n  Matched Address Regions ({len(matched_regions)} unique):")
            for key, data in matched_regions.items():
                m = data["mapping"]
                sc_summary = ", ".join(f"{s}×{c}" for s, c in
                                       sorted(dict((s, data["syscalls"].count(s))
                                                    for s in set(data["syscalls"])).items(),
                                              key=lambda x: -x[1]))
                print(f"    {m.start_addr:#14x}–{m.end_addr:#14x} "
                      f"{m.permissions} {m.size // 1024:>6} KB "
                      f"{m.pathname}")
                print(f"      └─ syscalls: {sc_summary}")

        # ────────────────────────────────────────────────────────────────
        # Step 4: Page Monitoring (with independent procfs fallback)
        # ────────────────────────────────────────────────────────────────
        print(f"\n{'─' * 72}")
        print("[Step 4] Monitoring Pages (pagemap + soft-dirty tracking) ...")
        print(f"{'─' * 72}")

        # Collect file-backed mappings from Step 3 matches
        monitored_files = set()
        mappings_to_monitor = []

        for rec in records:
            if rec.memory_mapping and rec.memory_mapping.is_file_backed:
                key = (rec.memory_mapping.start_addr, rec.memory_mapping.end_addr)
                if key not in monitored_files:
                    monitored_files.add(key)
                    mappings_to_monitor.append(rec.memory_mapping)

        # FALLBACK: If no mappings from syscall cross-reference, scan procfs
        # directly for the target file's memory-mapped regions.
        # This handles mmap-engine workloads where the mmap happened before
        # tracing started, or when cross_reference couldn't match.
        if not mappings_to_monitor and target_paths:
            print(f"\n  [fallback] No mappings from syscall matching – "
                  f"scanning /proc/{self.pid}/maps directly ...")
            print(f"  [fallback] Looking for target files: "
                  f"{', '.join(target_paths)}")

            fallback_mappings = self.procfs_mapper.find_target_file_mappings(
                target_paths, maps_cache=maps_cache)

            if not fallback_mappings:
                # Also try all non-library file-backed mappings
                fallback_mappings = self.procfs_mapper.find_all_file_backed_mappings(
                    maps_cache=maps_cache)

            for m in fallback_mappings:
                key = (m.start_addr, m.end_addr)
                if key not in monitored_files:
                    monitored_files.add(key)
                    mappings_to_monitor.append(m)

            if mappings_to_monitor:
                print(f"  [fallback] Found {len(mappings_to_monitor)} "
                      f"file-backed mapping(s) to monitor:")
                for m in mappings_to_monitor:
                    print(f"    {m.start_addr:#14x}–{m.end_addr:#14x} "
                          f"{m.permissions} {m.size // 1024:>6} KB "
                          f"{m.pathname}")

        # Now do actual page monitoring
        if mappings_to_monitor:
            print(f"\n  Monitoring {len(mappings_to_monitor)} region(s) "
                  f"for {monitor_duration}s each ...\n")

            all_page_events = {}  # mapping_key → list[PageMonEvent]
            for m in mappings_to_monitor:
                page_events = self.page_monitor.monitor_dirty_pages(
                    m,
                    interval_sec=1.0,
                    duration_sec=monitor_duration,
                )
                mk = (m.start_addr, m.end_addr)
                all_page_events[mk] = page_events

                # Attach page events to matching trace records
                for r in records:
                    if (r.memory_mapping and
                            r.memory_mapping.start_addr == m.start_addr):
                        r.page_events = page_events
        else:
            print(f"\n  [!] No file-backed mappings found for page monitoring.")
            print(f"      Possible causes:")
            print(f"        • Workload uses O_DIRECT (bypasses page cache entirely)")
            print(f"        • Workload hasn't created the target file yet")
            print(f"        • Process finished before maps could be read")
            print(f"      For mmap workloads (ioengine=mmap, direct=0), this")
            print(f"      suggests the file may not be opened yet or needs")
            print(f"      a longer --duration.\n")

        self.trace_records = records
        self._print_summary()

    def _print_summary(self):
        """Print a comprehensive summary of the full trace."""
        print(f"\n{'═' * 72}")
        print("  PIPELINE SUMMARY")
        print(f"{'═' * 72}")

        # ── Syscall breakdown ──
        sc_counts = {}
        total_bytes_read = 0
        total_bytes_written = 0
        fsync_count = 0
        fsync_latencies = []
        for rec in self.trace_records:
            ev = rec.syscall_event
            sc = ev.syscall
            sc_counts[sc] = sc_counts.get(sc, 0) + 1
            if sc in ("read", "pread64"):
                total_bytes_read += ev.length
            elif sc in ("write", "pwrite64"):
                total_bytes_written += ev.length
            elif sc in ("fsync", "fdatasync"):
                fsync_count += 1
                if ev.latency_us > 0:
                    fsync_latencies.append(ev.latency_us)

        print(f"\n  ┌── Syscall Distribution ──")
        for sc, count in sorted(sc_counts.items(), key=lambda x: -x[1]):
            bar = "█" * min(40, count // max(1, max(sc_counts.values()) // 40))
            print(f"  │  {sc:<16} {count:>6}  {bar}")
        print(f"  └──")

        # ── I/O volume ──
        if total_bytes_read > 0 or total_bytes_written > 0:
            print(f"\n  I/O Volume:")
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
                file_ios[path] = {"count": 0, "bytes": 0, "syscalls": set()}
            file_ios[path]["count"] += 1
            file_ios[path]["bytes"] += rec.syscall_event.length
            file_ios[path]["syscalls"].add(rec.syscall_event.syscall)

        print(f"\n  Files Accessed ({len(file_ios)}):")
        print(f"  {'Count':>8}  {'Bytes':>12}  {'Syscalls':<24}  {'Path'}")
        print(f"  {'─' * 72}")
        for path, info in sorted(file_ios.items(), key=lambda x: -x[1]["count"])[:15]:
            sc_str = ",".join(sorted(info["syscalls"]))
            bytes_str = f"{info['bytes']:,}" if info["bytes"] > 0 else "—"
            print(f"  {info['count']:>8}  {bytes_str:>12}  {sc_str:<24}  {path}")

        # ── Mapped regions summary ──
        mapped = [r for r in self.trace_records if r.memory_mapping]
        unique_regions = {}
        for r in mapped:
            m = r.memory_mapping
            key = m.start_addr
            if key not in unique_regions:
                unique_regions[key] = m

        if unique_regions:
            print(f"\n  Memory-Mapped Regions ({len(unique_regions)} unique):")
            print(f"  {'Start':>16}  {'End':>16}  {'Perm':>5}  "
                  f"{'Size':>10}  {'File'}")
            print(f"  {'─' * 72}")
            for addr in sorted(unique_regions.keys()):
                m = unique_regions[addr]
                print(f"  {m.start_addr:#16x}  {m.end_addr:#16x}  "
                      f"{m.permissions:>5}  {m.size // 1024:>8} KB  {m.pathname}")
        else:
            print(f"\n  Memory-Mapped Regions: none matched")
            print(f"    (Workload may use direct I/O, or mmap happened before tracing)")

        # ── Page monitoring stats ──
        total_snapshots = sum(len(r.page_events) for r in self.trace_records)
        if total_snapshots > 0:
            total_pages = sum(pe.page_count
                              for r in self.trace_records for pe in r.page_events)
            print(f"\n  Page Monitor Results:")
            print(f"    Dirty snapshots: {total_snapshots}")
            print(f"    Total dirty pages: {total_pages} "
                  f"({total_pages * 4} KB dirtied)")

            # Per-file breakdown
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

    def export_json(self, output_path: str):
        """Export full trace data to JSON."""
        data = {
            "pid": self.pid,
            "timestamp": datetime.now().isoformat(),
            "event_count": len(self.trace_records),
            "events": [],
        }
        for rec in self.trace_records:
            entry = {
                "syscall": {
                    "type": rec.syscall_event.syscall,
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
        description="I/O Path Observability Tool with FIO Integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Examples:
          # Generate all FIO job files
          %(prog)s --generate-fio --fio-dir ./fio_jobs

          # Generate and show the FIO run commands
          %(prog)s --generate-fio --show-commands

          # Trace a running FIO process (eBPF mode)
          %(prog)s --trace --pid 12345 --duration 30

          # Trace with strace fallback
          %(prog)s --trace --pid 12345 --strace --duration 10

          # Quick inspection of a process
          %(prog)s --inspect --pid 12345

          # Full demo: generate FIO configs + print pipeline info
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

    parser.add_argument("--pid", type=int, help="Target process ID")
    parser.add_argument("--duration", type=int, default=10,
                        help="Tracing duration in seconds (default: 10)")
    parser.add_argument("--monitor-duration", type=float, default=5.0,
                        help="Page monitoring duration per mapping (default: 5.0)")
    parser.add_argument("--strace", action="store_true",
                        help="Force strace instead of eBPF")
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
        print(f"  1. Start FIO:    sudo fio {args.fio_dir}/mmap_seq_read.fio &")
        print(f"  2. Get PID:      pgrep -x fio")
        print(f"  3. Run observer: python3 {sys.argv[0]} --trace --pid <FIO_PID>")

    # ── Trace Pipeline ──
    elif args.trace:
        if not args.pid:
            parser.error("--trace requires --pid")

        observer = IOPathObserver(
            pid=args.pid,
            use_ebpf=not args.strace,
        )
        observer.run_pipeline(
            trace_duration=args.duration,
            monitor_duration=args.monitor_duration,
        )

        if args.output_json:
            observer.export_json(args.output_json)

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
        │               I/O PATH OBSERVABILITY PIPELINE                  │
        ├─────────────────────────────────────────────────────────────────┤
        │                                                                │
        │  ┌──────────────┐   eBPF / strace                             │
        │  │  Step 1      │   Attach to target PID                      │
        │  │  Syscall ID  │──→ Capture: mmap, open, read, write, fsync  │
        │  └──────┬───────┘   Extract: syscall args (fd, len, offset)   │
        │         │                                                      │
        │         ▼                                                      │
        │  ┌──────────────┐   /proc/<pid>/fd + /proc/<pid>/fdinfo       │
        │  │  Step 2      │   Resolve: fd → file path                   │
        │  │  FD Extract  │──→ Read: file offset, flags, mnt_id         │
        │  └──────┬───────┘   Cache: unique FD metadata                 │
        │         │                                                      │
        │         ▼                                                      │
        │  ┌──────────────┐   /proc/<pid>/maps + map_files              │
        │  │  Step 3      │   Parse: virtual address ranges             │
        │  │  Procfs Xref │──→ Match: fd path ↔ mmap region             │
        │  └──────┬───────┘   Output: (start_addr, end_addr, file)      │
        │         │                                                      │
        │         ▼                                                      │
        │  ┌──────────────┐   /proc/<pid>/pagemap + clear_refs          │
        │  │  Step 4      │   Clear soft-dirty bits                     │
        │  │  Page Monitor│──→ Poll: detect newly dirtied pages         │
        │  └──────────────┘   Report: dirty page count per interval     │
        │                                                                │
        └─────────────────────────────────────────────────────────────────┘

        Recommended FIO profiles for each step:

          Step 1 (syscall tracing):
            • mmap_seq_read.fio    → generates mmap() syscalls
            • sync_heavy_write.fio → generates fsync() after every write

          Step 3 (procfs cross-reference):
            • mmap_rand_write.fio  → creates file-backed mappings
            • mixed_rw_buffered.fio → page cache activity

          Step 4 (page monitoring):
            • mmap_rand_write.fio  → dirty pages via memory writes
            • mixed_rw_buffered.fio → page cache writeback patterns

        Quick-start:
          Terminal 1:  sudo fio ./fio_jobs/mmap_rand_write.fio &
          Terminal 2:  sudo python3 io_path_observer.py --trace --pid $(pgrep fio)
        """))


if __name__ == "__main__":
    main()
