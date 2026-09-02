#!/usr/bin/env python3
# Copyright 2026 Davidlohr Bueso
# SPDX-License-Identifier: Apache-2.0
"""Compare median metrics from two kvio bench logs."""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path
from typing import Any


KEY_FIELDS = {"case", "job", "dir", "rep"}
METRICS = ("bw_MiBps", "iops", "p50_us", "p99_us", "sys", "irq_per_gib")


def load(path: Path) -> dict[tuple[str, str, str], dict[str, list[float]]]:
    grouped: dict[tuple[str, str, str], dict[str, list[float]]] = {}
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        if line.startswith("RESULT "):
            row: dict[str, Any] = dict(
                field.split("=", 1) for field in line.split()[1:]
            )
        else:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
        if "case" not in row:
            continue
        key = (str(row["case"]), str(row.get("job", "-")), str(row.get("dir", "read")))
        metrics = grouped.setdefault(key, {})
        for name, value in row.items():
            if name not in KEY_FIELDS:
                try:
                    metrics.setdefault(name, []).append(float(value))
                except (TypeError, ValueError):
                    pass
    return grouped


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare two kvio bench logs")
    parser.add_argument("a", type=Path)
    parser.add_argument("b", type=Path)
    args = parser.parse_args(argv)
    a, b = load(args.a), load(args.b)
    print(f"{'case/job metric':42s} {'A':>12s} {'B':>12s} {'delta':>9s}")
    for key in sorted(set(a) | set(b)):
        label = f"{key[0]}/{key[1]}" + (" (w)" if key[2] == "write" else "")
        for metric in METRICS:
            av = a.get(key, {}).get(metric)
            bv = b.get(key, {}).get(metric)
            if not av or not bv:
                continue
            ma, mb = statistics.median(av), statistics.median(bv)
            delta = "n/a" if ma == 0 else f"{(mb - ma) / ma:+.1%}"
            print(f"{label + ' ' + metric:42s} {ma:12.1f} {mb:12.1f} {delta:>9s}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
