#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare a source NVMe capture with one or more replay captures.

The referee reports ordered operation, offset, length, and complete tuple
equality separately.  Latency and issue-timing errors are measurements, not
part of the stream-equivalence claim.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter


class ComparisonError(ValueError):
    pass


def load(path):
    commands, latencies = [], []
    lba_bytes = None
    drops = None
    seen_seq = set()
    with open(path, encoding="utf-8") as source:
        for source_seq, line in enumerate(source):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ComparisonError(
                    f"{path}:{source_seq + 1}: invalid JSON") from error
            if not isinstance(record, dict):
                raise ComparisonError(
                    f"{path}:{source_seq + 1}: expected a JSON object")
            event_type = record.get("event_type")
            if event_type == "capture_meta" and record.get("lba_bytes") is not None:
                candidate = int(record["lba_bytes"])
                if lba_bytes is not None and lba_bytes != candidate:
                    raise ComparisonError(f"{path}: conflicting LBA sizes")
                lba_bytes = candidate
            elif event_type == "drops":
                candidate = int(record.get("dropped", 0))
                if drops is not None and drops != candidate:
                    raise ComparisonError(f"{path}: conflicting drop counts")
                drops = candidate
            elif event_type == "nvme_cmd":
                operation = record["op_name"]
                if operation not in ("read", "write", "flush"):
                    raise ComparisonError(
                        f"{path}:{source_seq + 1}: unsupported NVMe command "
                        f"{operation!r}")
                sequence = int(record.get("seq", source_seq))
                if sequence in seen_seq:
                    raise ComparisonError(
                        f"{path}: duplicate command sequence {sequence}")
                seen_seq.add(sequence)
                timestamp = int(record["ts"])
                slba = 0 if operation == "flush" else int(record["slba"])
                length = 0 if operation == "flush" else int(record["bytes"])
                if sequence < 0 or timestamp < 0 or slba < 0 or length < 0:
                    raise ComparisonError(
                        f"{path}:{source_seq + 1}: negative command field")
                if operation != "flush" and length == 0:
                    raise ComparisonError(
                        f"{path}:{source_seq + 1}: zero command length")
                commands.append({
                    "seq": sequence,
                    "source_seq": source_seq,
                    "ts": timestamp,
                    "op": "datasync" if operation == "flush" else operation,
                    "slba": slba,
                    "bytes": length,
                })
            elif event_type == "nvme_cmp":
                latencies.append(int(record["lat_ns"]) / 1e3)
    commands.sort(key=lambda command: (
        command["ts"], command["seq"], command["source_seq"]))
    latencies.sort()
    return {"commands": commands, "latencies_us": latencies,
            "lba_bytes": lba_bytes, "drops": drops}


def _percentile(values, fraction):
    if not values:
        return 0.0
    values = sorted(values)
    return values[min(len(values) - 1, int(len(values) * fraction))]


def stats(capture):
    commands = capture["commands"]
    latencies = capture["latencies_us"]
    count = len(commands)
    total_bytes = sum(command["bytes"] for command in commands)
    writes = sum(command["op"] == "write" for command in commands)
    sizes = Counter(command["bytes"] for command in commands)
    top = ", ".join(
        f"{size // 1024}K:{number * 100 // count}%"
        for size, number in sizes.most_common(3)
    ) if count else ""
    duration = ((commands[-1]["ts"] - commands[0]["ts"]) / 1e9
                if commands else 0.0)
    return {
        "cmds": count, "writes": writes, "MB": total_bytes / 1e6,
        "avgKB": total_bytes / count / 1024 if count else 0.0,
        "sizes": top, "dur_s": duration,
        "p50us": _percentile(latencies, 0.50),
        "p99us": _percentile(latencies, 0.99),
    }


def exact_comparison(source, replay, lba_bytes):
    left = source["commands"]
    right = replay["commands"]
    source_tuples = [(c["op"], c["slba"] * lba_bytes, c["bytes"]) for c in left]
    replay_tuples = [(c["op"], c["slba"] * lba_bytes, c["bytes"]) for c in right]
    count_equal = len(left) == len(right)
    result = {
        "source_capture_complete": source.get("drops") == 0,
        "replay_capture_complete": replay.get("drops") == 0,
        "command_count_equal": count_equal,
        "operation_sequence_equal": count_equal and
            [c[0] for c in source_tuples] == [c[0] for c in replay_tuples],
        "offset_sequence_equal": count_equal and
            [c[1] for c in source_tuples] == [c[1] for c in replay_tuples],
        "length_sequence_equal": count_equal and
            [c[2] for c in source_tuples] == [c[2] for c in replay_tuples],
        "tuple_sequence_equal": source_tuples == replay_tuples,
    }
    result["device_stream_equal"] = (
        result["source_capture_complete"]
        and result["replay_capture_complete"]
        and result["tuple_sequence_equal"]
    )
    if count_equal and left:
        left_t0, right_t0 = left[0]["ts"], right[0]["ts"]
        errors = [abs((a["ts"] - left_t0) - (b["ts"] - right_t0)) / 1000
                  for a, b in zip(left, right)]
        result.update({
            "timing_error_p50_us": _percentile(errors, 0.50),
            "timing_error_p99_us": _percentile(errors, 0.99),
            "timing_error_max_us": max(errors),
        })
    return result


def report(name, paths, lba_override=None):
    captures = {label: load(path) for label, path in paths}
    source = captures["capture"]
    lba_bytes = lba_override or source["lba_bytes"]
    if lba_bytes is None:
        raise SystemExit("source capture has no lba_bytes metadata; pass --lba-bytes")
    if lba_bytes <= 0 or lba_bytes & (lba_bytes - 1):
        raise SystemExit("lba_bytes must be a positive power of two")
    for label, capture in captures.items():
        if capture["lba_bytes"] not in (None, lba_bytes):
            raise SystemExit(
                f"{label}: capture LBA {capture['lba_bytes']} disagrees with {lba_bytes}")

    summaries = {label: stats(capture) for label, capture in captures.items()}
    print(f"\n##### {name}")
    print(f"{'':16s}" + "".join(f"{label:>16s}" for label in summaries))
    for field, fmt in (("cmds", "d"), ("writes", "d"), ("MB", ".0f"),
                       ("avgKB", ".1f"), ("dur_s", ".1f"),
                       ("p50us", ".0f"), ("p99us", ".0f")):
        print(f"{field:16s}" + "".join(
            f"{format(summary[field], fmt):>16s}" for summary in summaries.values()))
    for label, capture in captures.items():
        print(f"  sizes[{label}]: {summaries[label]['sizes']}")
        if capture["drops"] not in (None, 0):
            print(f"  warning[{label}]: capture reports {capture['drops']} dropped events")
        if label == "capture":
            continue
        exact = exact_comparison(source, capture, lba_bytes)
        print(f"  exact[{label}]: " + ", ".join(
            f"{key}={value}" for key, value in exact.items()))


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("spec", nargs="+",
                        help="NAME:CAPTURE:REPLAY_A[:REPLAY_B...] (legacy interface)")
    parser.add_argument("--lba-bytes", type=int,
                        help="required for legacy captures without capture_meta")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        for specification in args.spec:
            fields = specification.split(":")
            if len(fields) < 3:
                raise SystemExit("spec must be NAME:CAPTURE:REPLAY_A[:REPLAY_B...]")
            name, capture_path, *replays = fields
            paths = [("capture", capture_path)]
            paths.extend((f"replay-{index + 1}", path)
                         for index, path in enumerate(replays))
            report(name, paths, args.lba_bytes)
    except (ComparisonError, OSError, KeyError, TypeError, ValueError) as error:
        raise SystemExit(f"kvio compare: {error}") from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
