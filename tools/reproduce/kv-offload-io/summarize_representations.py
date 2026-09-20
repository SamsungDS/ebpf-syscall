#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Collapse parse_representations.py rows into one line per cell kind.

Replicas of the same (representation, streams, command size, exporter) are
averaged, with the spread shown, so a difference between representations
can be read against the run-to-run noise instead of against one lucky run.
The device-side columns are kept next to the engine-side ones on purpose:
the engine's aggregate rate is what the tool measured, the command count
and size histogram are what the drive was asked for, and the bytes ratio is
whether the two agree with the intent.

    python3 summarize_representations.py cells.csv [--pad LABEL] > table.md
"""
from __future__ import annotations

import argparse
import csv
import statistics
import sys
from collections import defaultdict


def fnum(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def mean_spread(values):
    values = [v for v in values if v is not None]
    if not values:
        return "", ""
    mean = statistics.fmean(values)
    spread = (max(values) - min(values)) / 2 if len(values) > 1 else 0.0
    return mean, spread


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv")
    parser.add_argument("--pad", default="", help="label for the padding arm")
    parser.add_argument("--markdown", action="store_true", default=True)
    args = parser.parse_args(argv)

    groups = defaultdict(list)
    with open(args.csv, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            key = (row["representation"], int(row["streams"]),
                   int(row["command_bytes"]), row["dmabuf"])
            groups[key].append(row)

    order = {"bf16_kv": 0, "k16_v8": 1, "v8_only": 2}
    print("| rep | streams | cmd | exporter | n | ok | store MB/s | load MB/s | "
          "dev write cmds | dev read cmds | read sizes | read p99 us | "
          "write/intent | read/intent | bad status | drops |")
    print("|---|---:|---:|---|---:|---|---:|---:|---:|---:|---|---:|---:|---:|---:|---:|")
    for key in sorted(groups, key=lambda k: (order.get(k[0], 9), k[1], k[2], k[3])):
        rows = groups[key]
        ok = all(r["status"] == "replay_status=0" and r["store_failures"] == "0"
                 and r["load_failures"] == "0" for r in rows)
        store, store_s = mean_spread([fnum(r["engine_store_MBps"]) for r in rows])
        load, load_s = mean_spread([fnum(r["engine_load_MBps"]) for r in rows])
        wcmds, _ = mean_spread([fnum(r["dev_write_cmds"]) for r in rows])
        rcmds, _ = mean_spread([fnum(r["dev_read_cmds"]) for r in rows])
        p99, p99_s = mean_spread([fnum(r["dev_read_lat_p99_us"]) for r in rows])
        wr, _ = mean_spread([fnum(r["write_bytes_vs_logical"]) for r in rows])
        rr, _ = mean_spread([fnum(r["read_bytes_vs_logical"]) for r in rows])
        bad = sum(int(r["dev_bad_status"] or 0) for r in rows)
        drops = sum(int(r["capture_drops"] or 0) for r in rows)
        sizes = sorted({r["dev_read_sizes"] for r in rows if r["dev_read_sizes"]})
        rep, streams, cmd, kind = key
        cmd_label = f"{cmd // 1024} KiB" if cmd < 1 << 20 else f"{cmd >> 20} MiB"
        fmt = lambda m, s: (f"{m:,.0f} ± {s:,.0f}" if m != "" else "")
        print(f"| {rep} | {streams} | {cmd_label} | {kind} | {len(rows)} | "
              f"{'yes' if ok else 'NO'} | {fmt(store, store_s)} | {fmt(load, load_s)} | "
              f"{wcmds:,.0f} | {rcmds:,.0f} | {'; '.join(sizes)[:40]} | "
              f"{fmt(p99, p99_s)} | {wr:.4f} | {rr:.4f} | {bad} | {drops} |"
              if wcmds != "" else
              f"| {rep} | {streams} | {cmd_label} | {kind} | {len(rows)} | "
              f"{'yes' if ok else 'NO'} | {fmt(store, store_s)} | {fmt(load, load_s)} | "
              f"| | | | | | | |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
