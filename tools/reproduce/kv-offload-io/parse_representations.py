#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Turn a sweep_representations.sh output tree into one CSV row per cell.

Each row joins three witnesses of the same cell and reports where they
disagree:

* the representation manifest's derived object bytes (what was intended);
* the engine's target-run manifest (what the engine says it did, with its
  measured aggregate rates and failure counts);
* the driver-level NVMe capture bracketing the timed phases (what the
  device was actually asked to do: commands, bytes, command-size histogram,
  completion status and latency).

The check that matters for the plan's gate is the last column pair: the
bytes the device wrote and read during the timed phases, against the bytes
the intent said it would move.  A representation is only as small on the
drive as the capture says it is.

    python3 parse_representations.py OUTROOT > cells.csv
"""
from __future__ import annotations

import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path

PHASE = re.compile(r"@@@ PHASE (store|load) pass=(\d+) start_ns=(\d+) end_ns=(\d+)")


def timed_windows(replay_log, warmup):
    """Return {phase: [(start, end), ...]} for the passes that were timed."""
    windows = {"store": [], "load": []}
    for line in replay_log.read_text(errors="replace").splitlines():
        match = PHASE.search(line)
        if match and int(match.group(2)) >= warmup:
            windows[match.group(1)].append((int(match.group(3)), int(match.group(4))))
    return windows


def capture_stats(jsonl, windows):
    """Per phase: commands, bytes, size histogram, status, latency."""
    stats = {phase: {"cmds": 0, "bytes": 0, "sizes": Counter(), "bad_status": 0,
                     "lat_ns": []} for phase in windows}
    pending = {}
    drops = None
    opname = {"store": "write", "load": "read"}
    with open(jsonl, encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            try:
                rec = json.loads(raw)
            except json.JSONDecodeError:
                continue
            kind = rec.get("event_type")
            if kind == "drops":
                drops = rec.get("dropped")
            elif kind == "nvme_cmd":
                ts = rec["ts"]
                for phase, spans in windows.items():
                    if rec.get("op_name") != opname[phase]:
                        continue
                    if any(start <= ts <= end for start, end in spans):
                        stat = stats[phase]
                        stat["cmds"] += 1
                        stat["bytes"] += rec["bytes"]
                        stat["sizes"][rec["bytes"]] += 1
                        pending[(rec["hwq"], rec["cid"])] = phase
                        break
            elif kind == "nvme_cmp":
                phase = pending.pop((rec["hwq"], rec["cid"]), None)
                if phase is None:
                    continue
                if rec.get("status", 0):
                    stats[phase]["bad_status"] += 1
                stats[phase]["lat_ns"].append(rec["lat_ns"])
    return stats, drops, len(pending)


def pct(values, q):
    if not values:
        return ""
    values = sorted(values)
    return values[min(len(values) - 1, int(q * len(values)))]


def main(argv):
    if len(argv) != 2:
        sys.exit(__doc__)
    root = Path(argv[1])
    sets = {}
    for manifest in root.glob("sets/s*/representation-set.json"):
        sets[manifest.parent.name] = json.loads(manifest.read_text())
    out = csv.writer(sys.stdout)
    out.writerow([
        "representation", "streams", "command_bytes", "dmabuf", "replica",
        "status", "intent_payload_bytes", "extent_bytes", "host_retained_bytes",
        "ops_per_phase", "store_failures", "load_failures",
        "engine_store_MBps", "engine_load_MBps",
        "timed_logical_bytes_per_phase",
        "dev_write_cmds", "dev_write_bytes", "dev_write_sizes",
        "dev_read_cmds", "dev_read_bytes", "dev_read_sizes",
        "dev_read_lat_p50_us", "dev_read_lat_p99_us", "dev_write_lat_p99_us",
        "dev_bad_status", "dev_unpaired", "capture_drops",
        "write_bytes_vs_logical", "read_bytes_vs_logical",
    ])
    for status_file in sorted(root.glob("*/s*/c*/r*/status.txt")):
        cell = status_file.parent
        rep = cell.parents[2].name
        streams = int(cell.parents[1].name[1:])
        size_kind = cell.parents[0].name[1:]
        command_bytes, kind = size_kind.split("-", 1)
        replica = int(cell.name[1:])
        manifest = sets.get(f"s{streams}", {})
        entry = manifest.get("representations", {}).get(rep, {})
        payload = entry.get("stored", {}).get("payload_bytes", "")
        extent = entry.get("storage", {}).get("physical_extent_bytes", "")
        retained = entry.get("host", {}).get("h2d_bytes_per_restore", "")
        warmup = manifest.get("schedule", {}).get("warmup", 0)
        iters = manifest.get("schedule", {}).get("iters", 1)
        chunks = manifest.get("schedule", {}).get("num_chunks", 0)
        objects = manifest.get("schedule", {}).get("objects_per_chunk", 1)
        run = {}
        try:
            run = json.loads((cell / "target-run.json").read_text())
        except (OSError, json.JSONDecodeError):
            pass
        outcomes = run.get("outcomes", {})
        rates = outcomes.get("aggregate_MBps", {})
        logical_per_phase = (payload * chunks * objects * streams * iters
                             if isinstance(payload, int) else "")
        row = [rep, streams, command_bytes, kind, replica,
               (cell / "status.txt").read_text().strip(),
               payload, extent, retained,
               outcomes.get("operations_per_phase", ""),
               outcomes.get("store_failures", ""), outcomes.get("load_failures", ""),
               f"{rates['store']:.1f}" if "store" in rates else "",
               f"{rates['load']:.1f}" if "load" in rates else "",
               logical_per_phase]
        jsonl = cell / "device.jsonl"
        if jsonl.exists() and (cell / "replay.log").exists():
            windows = timed_windows(cell / "replay.log", warmup)
            stats, drops, unpaired = capture_stats(jsonl, windows)
            w, r = stats["store"], stats["load"]
            sizes = lambda s: " ".join(f"{k}x{v}" for k, v in sorted(s["sizes"].items()))
            row += [w["cmds"], w["bytes"], sizes(w), r["cmds"], r["bytes"], sizes(r),
                    f"{pct(r['lat_ns'], .5) / 1e3:.1f}" if r["lat_ns"] else "",
                    f"{pct(r['lat_ns'], .99) / 1e3:.1f}" if r["lat_ns"] else "",
                    f"{pct(w['lat_ns'], .99) / 1e3:.1f}" if w["lat_ns"] else "",
                    w["bad_status"] + r["bad_status"], unpaired, drops,
                    (f"{w['bytes'] / logical_per_phase:.4f}"
                     if logical_per_phase else ""),
                    (f"{r['bytes'] / logical_per_phase:.4f}"
                     if logical_per_phase else "")]
        else:
            row += [""] * 14
        out.writerow(row)


if __name__ == "__main__":
    main(sys.argv)
