#!/usr/bin/env python3
# Copyright 2026 Davidlohr Bueso
# SPDX-License-Identifier: Apache-2.0
"""Run kvspill-derived KV-cache storage-tier workloads safely.

The workload shapes originate in davidlohr/kvspill.  Keep their evidence and
limits visible: some profiles are synthetic stress cases, while the calibrated
restore profile is based on a measured LMCache run.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any


GIB = 1 << 30
MIB = 1 << 20
SYS_BLOCK = Path("/sys/class/block")


@dataclass(frozen=True)
class Job:
    name: str
    rw: str
    bs: int
    iodepth: int
    numjobs: int
    partition_region: bool = False
    group_reporting: bool = True
    mmaphuge: bool = True


@dataclass(frozen=True)
class Profile:
    name: str
    description: str
    evidence_kind: str
    evidence_source: str
    jobs: tuple[Job, ...]


KVSPILL_SOURCE = "https://github.com/davidlohr/kvspill"
KVSPILL_INITIAL = f"{KVSPILL_SOURCE}/blob/a26049bd0f802339156d4f45842c8ae4e2d85bdb/"
CALIBRATED_SOURCE = (
    f"{KVSPILL_SOURCE}/blob/66f21115ed7fcbe8c76e15a9446c3143a0bca8e4/"
    "profiles/lmcache-qwen2.5-1.5b.md"
)


PROFILES: dict[str, Profile] = {
    "restore": Profile(
        "restore",
        "Synthetic concurrent random reads representing resumed sequences",
        "synthetic",
        f"{KVSPILL_INITIAL}workloads/kv-restore.fio",
        (Job("kv_restore", "randread", 2 * MIB, 2, 16),),
    ),
    "restore-calibrated": Profile(
        "restore-calibrated",
        "Measured Qwen2.5-1.5B LMCache whole-object restore shape",
        "measured",
        CALIBRATED_SOURCE,
        (Job("kv_restore_calibrated", "randread", 7_340_032, 1, 4),),
    ),
    "prefix": Profile(
        "prefix",
        "Synthetic sequential reads representing concurrent prefix reloads",
        "synthetic",
        f"{KVSPILL_INITIAL}workloads/kv-prefix.fio",
        (Job("kv_prefix", "read", MIB, 4, 8, True),),
    ),
    "qos-sustain-4k": Profile(
        "qos-sustain-4k",
        "Synthetic co-location test; not observed LMCache 4 KiB I/O",
        "synthetic",
        f"{KVSPILL_INITIAL}workloads/kv-qos.fio",
        (
            Job("qos_sustain_bulk", "randread", 2 * MIB, 8, 4, False, False),
            Job("qos_sustain_4k", "randread", 4096, 16, 2, False, False, False),
        ),
    ),
    "evict": Profile(
        "evict",
        "Synthetic writes representing KV demotion under memory pressure",
        "synthetic",
        f"{KVSPILL_INITIAL}workloads/kv-evict.fio",
        (Job("kv_evict", "write", 2 * MIB, 8, 4, True),),
    ),
}


def _profile_bool(job: dict[str, Any], name: str, default: bool) -> bool:
    value = job.get(name, default)
    if not isinstance(value, bool):
        raise RuntimeError(f"profile job {name} must be true or false")
    return value


def _profile_positive_int(job: dict[str, Any], name: str) -> int:
    value = job.get(name)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise RuntimeError(f"profile job {name} must be a positive integer")
    return value


def load_profile(path: Path) -> Profile:
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"cannot read profile {path}: {error}") from error
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise RuntimeError("profile schema_version must be 1")
    for field in ("name", "description"):
        if not isinstance(data.get(field), str) or not data[field].strip():
            raise RuntimeError(f"profile {field} must be a non-empty string")
    name = data["name"]
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", name):
        raise RuntimeError(
            "profile name must contain lowercase letters, digits, _ or -"
        )
    evidence = data.get("evidence")
    if not isinstance(evidence, dict):
        raise RuntimeError("profile evidence must be an object")
    kind, source = evidence.get("kind"), evidence.get("source")
    if kind not in ("measured", "synthetic"):
        raise RuntimeError("profile evidence kind must be measured or synthetic")
    if not isinstance(source, str) or not source.strip():
        raise RuntimeError("profile evidence source must be a non-empty string")
    raw_jobs = data.get("jobs")
    if not isinstance(raw_jobs, list) or not raw_jobs:
        raise RuntimeError("profile jobs must be a non-empty array")
    jobs = []
    for raw_job in raw_jobs:
        if not isinstance(raw_job, dict):
            raise RuntimeError("each profile job must be an object")
        job_name, rw, block_size = (
            raw_job.get("name"),
            raw_job.get("rw"),
            raw_job.get("bs"),
        )
        if not isinstance(job_name, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_-]*", job_name
        ):
            raise RuntimeError("profile job name is invalid")
        if rw not in ("read", "randread", "write", "randwrite"):
            raise RuntimeError(f"profile job {job_name} has unsupported rw={rw}")
        if isinstance(block_size, str):
            try:
                block_size = parse_size(block_size)
            except argparse.ArgumentTypeError as error:
                raise RuntimeError(f"profile job {job_name}: {error}") from error
        if (
            isinstance(block_size, bool)
            or not isinstance(block_size, int)
            or block_size <= 0
        ):
            raise RuntimeError(f"profile job {job_name} bs must be a positive size")
        jobs.append(
            Job(
                job_name,
                rw,
                block_size,
                _profile_positive_int(raw_job, "iodepth"),
                _profile_positive_int(raw_job, "numjobs"),
                _profile_bool(raw_job, "partition_region", False),
                _profile_bool(raw_job, "group_reporting", True),
                _profile_bool(raw_job, "mmaphuge", True),
            )
        )
    return Profile(name, data["description"], kind, source, tuple(jobs))


def profile_record(
    profile: Profile, jobs: tuple[Job, ...] | None = None
) -> dict[str, Any]:
    selected_jobs = jobs or profile.jobs
    return {
        "name": profile.name,
        "description": profile.description,
        "evidence": {
            "kind": profile.evidence_kind,
            "source": profile.evidence_source,
        },
        "jobs": [
            {
                "name": job.name,
                "rw": job.rw,
                "bs": job.bs,
                "iodepth": job.iodepth,
                "numjobs": job.numjobs,
                "partition_region": job.partition_region,
                "group_reporting": job.group_reporting,
                "mmaphuge": job.mmaphuge,
            }
            for job in selected_jobs
        ],
    }


def parse_size(value: str) -> int:
    match = re.fullmatch(r"([0-9]+)([kKmMgGtT]?[iI]?[bB]?)?", value.strip())
    if not match:
        raise argparse.ArgumentTypeError(f"invalid size: {value}")
    number = int(match.group(1))
    suffix = (match.group(2) or "").lower().rstrip("b")
    powers = {"": 0, "k": 1, "ki": 1, "m": 2, "mi": 2, "g": 3, "gi": 3, "t": 4, "ti": 4}
    return number * (1024 ** powers[suffix])


def _read(path: Path, default: str = "unknown") -> str:
    try:
        return path.read_text().strip()
    except OSError:
        return default


def _run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd, text=True, check=True, **kwargs)


def validate_device(
    device: str, region_bytes: int, allow_signatures: bool = False
) -> tuple[Path, Path]:
    real = Path(os.path.realpath(device))
    try:
        mode = real.stat().st_mode
    except OSError as error:
        raise RuntimeError(f"cannot stat {device}: {error}") from error
    if not stat.S_ISBLK(mode):
        raise RuntimeError(f"not a block device: {device}")

    sysdev = SYS_BLOCK / real.name
    if not sysdev.exists():
        raise RuntimeError(f"no sysfs block entry for {real}")
    if (sysdev / "partition").exists():
        raise RuntimeError("partitions are not valid benchmark targets")
    holders = list((sysdev / "holders").iterdir())
    if holders:
        raise RuntimeError(f"device has holders: {', '.join(p.name for p in holders)}")

    children = subprocess.run(
        ["lsblk", "-nrpo", "NAME,TYPE,MOUNTPOINTS", str(real)],
        text=True,
        capture_output=True,
        check=True,
    ).stdout.splitlines()
    for line in children:
        fields = line.split(None, 2)
        if len(fields) >= 2 and (
            fields[1] == "part" or (len(fields) == 3 and fields[2].strip())
        ):
            raise RuntimeError(f"device has a partition or mount: {line}")
    mounted = subprocess.run(
        ["findmnt", "-rn", "-S", str(real)], capture_output=True, text=True
    )
    if mounted.returncode == 0 and mounted.stdout.strip():
        raise RuntimeError(f"device is mounted: {mounted.stdout.strip()}")

    sectors = int(_read(sysdev / "size", "0"))
    capacity = sectors * 512
    if region_bytes <= 0 or region_bytes > capacity:
        raise RuntimeError(
            f"region {region_bytes} bytes exceeds device capacity {capacity} bytes"
        )
    if not allow_signatures:
        signatures = subprocess.run(
            ["wipefs", "-n", str(real)], capture_output=True, text=True, check=True
        ).stdout.strip()
        if signatures:
            raise RuntimeError(
                "device has signatures; use --allow-signatures only "
                "after independently verifying the target"
            )
    return real, sysdev


def profile_jobs(
    case: str,
    calibrated_bs: int | None = None,
    profiles: dict[str, Profile] | None = None,
) -> tuple[Job, ...]:
    jobs = (profiles or PROFILES)[case].jobs
    if case == "restore-calibrated" and calibrated_bs:
        jobs = (replace(jobs[0], bs=calibrated_bs),)
    return jobs


def fio_config(
    device: Path,
    case: str,
    jobs: tuple[Job, ...],
    region_bytes: int,
    runtime: int,
    ramp_time: int,
    hugepages: bool,
) -> str:
    lines = [
        "[global]",
        f"filename={device}",
        "direct=1",
        "ioengine=io_uring",
        "time_based=1",
        f"runtime={runtime}",
        f"ramp_time={ramp_time}",
        "norandommap=1",
        "randrepeat=0",
        "thread=1",
    ]
    if all(job.group_reporting for job in jobs):
        lines.append("group_reporting=1")
    for job in jobs:
        lines.extend(
            [
                "",
                f"[{job.name}]",
                f"bs={job.bs}",
                f"rw={job.rw}",
                f"iodepth={job.iodepth}",
                f"numjobs={job.numjobs}",
            ]
        )
        if job.partition_region:
            per_job = region_bytes // job.numjobs
            per_job -= per_job % 4096
            if per_job < job.bs:
                raise RuntimeError(f"region is too small for {case}")
            lines.extend([f"size={per_job}", f"offset_increment={per_job}"])
        else:
            lines.append(f"size={region_bytes}")
        if hugepages and job.mmaphuge:
            lines.append("iomem=mmaphuge")
    return "\n".join(lines) + "\n"


def hugepages_needed(jobs: tuple[Job, ...], hugepage_bytes: int) -> int:
    total = sum(
        math.ceil(job.bs / hugepage_bytes) * job.iodepth * job.numjobs
        for job in jobs
        if job.mmaphuge
    )
    return total + max(16, total // 8)


def irq_sum(controller: str, interrupts: Path = Path("/proc/interrupts")) -> int:
    total = 0
    pattern = re.compile(rf"\b{re.escape(controller)}q\d+\b")
    try:
        lines = interrupts.read_text().splitlines()
    except OSError:
        return 0
    for line in lines:
        if not pattern.search(line):
            continue
        for field in line.split()[1:]:
            token = field.rstrip(":")
            if not token.isdigit():
                break
            total += int(token)
    return total


def latency_us(direction: dict[str, Any], percentile: str) -> float:
    for key, divisor in (("clat_ns", 1000.0), ("clat_us", 1.0), ("clat_ms", 0.001)):
        if key in direction:
            values = direction[key].get("percentile", {})
            return float(values.get(percentile, 0.0)) / divisor
    return 0.0


def parse_fio(
    data: dict[str, Any], case: str, rep: int, irqs: int
) -> list[dict[str, Any]]:
    total_gib = (
        sum(
            float(job[direction].get("io_bytes", 0))
            for job in data["jobs"]
            for direction in ("read", "write")
        )
        / GIB
    )
    rows: list[dict[str, Any]] = []
    for job in data["jobs"]:
        for direction in ("read", "write"):
            result = job[direction]
            if not result.get("io_bytes"):
                continue
            rows.append(
                {
                    "case": case,
                    "job": job["jobname"],
                    "dir": direction,
                    "rep": rep,
                    "bw_MiBps": float(result.get("bw_bytes", 0)) / MIB,
                    "iops": float(result.get("iops", 0)),
                    "p50_us": latency_us(result, "50.000000"),
                    "p99_us": latency_us(result, "99.000000"),
                    "usr": float(job.get("usr_cpu", 0)),
                    "sys": float(job.get("sys_cpu", 0)),
                    "irq_per_gib": irqs / total_gib if total_gib else 0.0,
                }
            )
    return rows


def result_line(row: dict[str, Any]) -> str:
    order = (
        "case",
        "job",
        "dir",
        "rep",
        "bw_MiBps",
        "iops",
        "p50_us",
        "p99_us",
        "usr",
        "sys",
        "irq_per_gib",
    )
    values = []
    for key in order:
        value = row[key]
        values.append(
            f"{key}={value:.3f}" if isinstance(value, float) else f"{key}={value}"
        )
    return "RESULT " + " ".join(values)


def gates(device: Path, sysdev: Path, region_bytes: int) -> dict[str, Any]:
    controller = re.sub(r"n\d+$", "", device.name)
    queue = sysdev / "queue"
    pci_path = (sysdev / "device/device").resolve()
    bdf = next(
        (
            part
            for part in reversed(pci_path.parts)
            if re.fullmatch(r"[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]", part)
        ),
        "unknown",
    )
    iommu_group = Path("/sys/bus/pci/devices") / bdf / "iommu_group"
    iommu_type = (
        _read(iommu_group.resolve() / "type") if iommu_group.exists() else "none"
    )
    mdts: int | str = "unavailable"
    if shutil.which("nvme"):
        identify = subprocess.run(
            ["nvme", "id-ctrl", f"/dev/{controller}"], capture_output=True, text=True
        )
        match = re.search(r"^mdts\s*:\s*(\d+)", identify.stdout, re.MULTILINE)
        if identify.returncode == 0 and match:
            mdts = int(match.group(1))
    return {
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "device": str(device),
        "namespace": device.name,
        "controller": controller,
        "region_bytes": region_bytes,
        "serial": _read(sysdev / "device/serial").replace(" ", ""),
        "model": _read(sysdev / "device/model"),
        "firmware": _read(sysdev / "device/firmware_rev"),
        "kernel": os.uname().release,
        "max_hw_sectors_kb": int(_read(queue / "max_hw_sectors_kb", "0")),
        "max_sectors_kb": int(_read(queue / "max_sectors_kb", "0")),
        "logical_block_size": int(_read(queue / "logical_block_size", "0")),
        "physical_block_size": int(_read(queue / "physical_block_size", "0")),
        "scheduler": _read(queue / "scheduler"),
        "nr_requests": int(_read(queue / "nr_requests", "0")),
        "nvme_mdts": mdts,
        "pci_bdf": bdf,
        "iommu_group_type": iommu_type,
        "nr_hugepages": int(_read(Path("/proc/sys/vm/nr_hugepages"), "0")),
        "fio_version": subprocess.run(
            ["fio", "--version"], capture_output=True, text=True, check=True
        ).stdout.strip(),
    }


class Tuning:
    def __init__(self, sysdev: Path, max_sectors_kb: int | None, hugepages: int | None):
        self.paths: list[tuple[Path, str]] = []
        self.requested = (
            (sysdev / "queue/max_sectors_kb", max_sectors_kb),
            (Path("/proc/sys/vm/nr_hugepages"), hugepages),
        )

    def __enter__(self) -> "Tuning":
        try:
            for path, value in self.requested:
                if value is None:
                    continue
                old = path.read_text().strip()
                self.paths.append((path, old))
                if path == Path("/proc/sys/vm/nr_hugepages"):
                    value = max(value, int(old))
                path.write_text(f"{value}\n")
        except Exception:
            self.restore()
            raise
        return self

    def restore(self) -> None:
        for path, old in reversed(self.paths):
            try:
                path.write_text(f"{old}\n")
            except OSError as error:
                print(f"WARNING: failed to restore {path}: {error}", file=sys.stderr)
        self.paths.clear()

    def __exit__(self, *_: object) -> None:
        self.restore()


def precondition(device: Path, region_bytes: int, output: Path) -> None:
    _run(
        [
            "fio",
            "--name=kvio-precondition",
            f"--filename={device}",
            "--rw=write",
            "--bs=1M",
            "--iodepth=32",
            "--direct=1",
            f"--size={region_bytes}",
            "--ioengine=io_uring",
            "--group_reporting=1",
            f"--output={output}",
        ]
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run kvspill-derived KV-cache storage workloads. WARNING: "
        "the selected raw block device is overwritten."
    )
    parser.add_argument("device", nargs="?")
    parser.add_argument(
        "--cases",
        help="comma-separated cases (default: built-ins, or supplied profiles)",
    )
    parser.add_argument(
        "--profile",
        action="append",
        default=[],
        type=Path,
        help="JSON sustained-workload profile; repeat for multiple profiles",
    )
    parser.add_argument(
        "--list-profiles", action="store_true", help="show profile evidence and exit"
    )
    parser.add_argument(
        "--size",
        type=parse_size,
        default=100 * GIB,
        help="device region, e.g. 8GiB (default: 100GiB)",
    )
    parser.add_argument("--runtime", type=int, default=20)
    parser.add_argument("--ramp-time", type=int, default=3)
    parser.add_argument("--reps", type=int, default=3)
    parser.add_argument(
        "--calibrated-block-size",
        type=parse_size,
        help="whole KV-object size (default: 7340032 bytes)",
    )
    parser.add_argument("--max-sectors-kb", type=int)
    parser.add_argument("--no-hugepages", action="store_true")
    parser.add_argument("--skip-precondition", action="store_true")
    parser.add_argument("--allow-signatures", action="store_true")
    parser.add_argument(
        "--yes-really-use-device",
        action="store_true",
        help="required acknowledgement that DEVICE is overwritten",
    )
    parser.add_argument("--output-dir", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    profiles = dict(PROFILES)
    custom_names = []
    try:
        for path in args.profile:
            profile = load_profile(path)
            if profile.name in profiles:
                raise RuntimeError(f"duplicate profile name: {profile.name}")
            profiles[profile.name] = profile
            custom_names.append(profile.name)
    except RuntimeError as error:
        raise SystemExit(f"invalid profile: {error}") from error
    if args.list_profiles:
        for profile in profiles.values():
            print(f"{profile.name} [{profile.evidence_kind}]")
            print(f"  {profile.description}")
            print(f"  source: {profile.evidence_source}")
            for job in profile.jobs:
                print(
                    f"  job: {job.name} rw={job.rw} bs={job.bs} "
                    f"iodepth={job.iodepth} numjobs={job.numjobs}"
                )
        return 0
    if args.device is None:
        raise SystemExit("DEVICE is required unless --list-profiles is used")
    if os.geteuid() != 0:
        raise SystemExit("kvio bench must run as root")
    if not args.yes_really_use_device:
        raise SystemExit("refusing destructive run without --yes-really-use-device")
    if args.runtime <= 0 or args.ramp_time < 0 or args.reps <= 0:
        raise SystemExit("runtime/reps must be positive and ramp-time non-negative")
    cases = args.cases.split(",") if args.cases else custom_names or list(PROFILES)
    unknown = set(cases) - set(profiles)
    if unknown:
        raise SystemExit(f"unknown cases: {', '.join(sorted(unknown))}")
    for command in ("fio", "lsblk", "findmnt", "wipefs"):
        if not shutil.which(command):
            raise SystemExit(f"required command is missing: {command}")

    try:
        device, sysdev = validate_device(args.device, args.size, args.allow_signatures)
    except (RuntimeError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"refusing device: {error}") from error

    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    outdir = args.output_dir or Path(f"kvio-bench-{device.name}-{stamp}")
    outdir.mkdir(parents=True, exist_ok=False)
    gate = gates(device, sysdev, args.size)
    (outdir / "gates.json").write_text(json.dumps(gate, indent=2) + "\n")
    run = {
        "cases": cases,
        "region_bytes": args.size,
        "runtime": args.runtime,
        "ramp_time": args.ramp_time,
        "repetitions": args.reps,
        "calibrated_block_size": args.calibrated_block_size or 7_340_032,
        "profiles": [
            profile_record(
                profiles[case], profile_jobs(case, args.calibrated_block_size, profiles)
            )
            for case in cases
        ],
        "requested_max_sectors_kb": args.max_sectors_kb,
        "hugepages": not args.no_hugepages,
        "precondition": not args.skip_precondition,
    }
    (outdir / "run.json").write_text(json.dumps(run, indent=2) + "\n")
    print("GATE", json.dumps(gate, sort_keys=True))

    all_jobs = tuple(
        job
        for case in cases
        for job in profile_jobs(case, args.calibrated_block_size, profiles)
    )
    hugepages = None
    if not args.no_hugepages:
        hugepage_kib = (
            int(
                _read(Path("/proc/meminfo"), "").split("Hugepagesize:", 1)[1].split()[0]
            )
            if "Hugepagesize:" in _read(Path("/proc/meminfo"), "")
            else 2048
        )
        hugepages = hugepages_needed(all_jobs, hugepage_kib * 1024)

    interrupted = False
    old_handlers: dict[int, Any] = {}

    def stop(_signum: int, _frame: object) -> None:
        nonlocal interrupted
        interrupted = True
        raise KeyboardInterrupt

    for sig in (signal.SIGINT, signal.SIGTERM):
        old_handlers[sig] = signal.signal(sig, stop)
    results_path = outdir / "results.jsonl"
    log_path = outdir / "results.log"
    controller = gate["controller"]
    try:
        with Tuning(sysdev, args.max_sectors_kb, hugepages):
            if not args.skip_precondition:
                precondition(device, args.size, outdir / "precondition.txt")
            for rep in range(1, args.reps + 1):
                for case in cases:
                    jobs = profile_jobs(case, args.calibrated_block_size, profiles)
                    config = fio_config(
                        device,
                        case,
                        jobs,
                        args.size,
                        args.runtime,
                        args.ramp_time,
                        not args.no_hugepages,
                    )
                    jobfile = outdir / f"{case}.fio"
                    if not jobfile.exists():
                        jobfile.write_text(config)
                    json_path = outdir / f"{case}-r{rep}.json"
                    before = irq_sum(controller)
                    _run(
                        [
                            "fio",
                            "--output-format=json",
                            f"--output={json_path}",
                            str(jobfile),
                        ]
                    )
                    delta = max(0, irq_sum(controller) - before)
                    rows = parse_fio(
                        json.loads(json_path.read_text()), case, rep, delta
                    )
                    with (
                        results_path.open("a") as structured,
                        log_path.open("a") as log,
                    ):
                        for row in rows:
                            structured.write(json.dumps(row, sort_keys=True) + "\n")
                            line = result_line(row)
                            log.write(line + "\n")
                            print(line)
    except KeyboardInterrupt:
        return 130
    finally:
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)
    if interrupted:
        return 130
    print(f"KVIO_BENCH_DONE device={device} output={outdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
