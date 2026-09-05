#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare a source NVMe capture with one or more replay captures.

The referee reports ordered operation, offset, length, and complete tuple
equality separately.  Latency and issue-timing errors are measurements, not
part of the stream-equivalence claim.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from collections import Counter
from pathlib import Path

from capture_format import CaptureFormatError, load_records, validate_envelope


class ComparisonError(ValueError):
    pass


BUNDLE_ARTIFACTS = {
    "README.txt",
    "certificate.json",
    "commands.iolog",
    "replay-block.fio",
    "replay-uring-cmd.fio",
    "workload.json",
}


def _int_field(path, line_number, record, field, *, minimum=0):
    value = record.get(field)
    if type(value) is not int or value < minimum:
        raise ComparisonError(
            f"{path}:{line_number}: {field} must be an integer >= {minimum}")
    return value


def _pair_completions(events, commands):
    pending = {}
    orphan_completions = 0
    ambiguous_reuse = 0
    invalid_latency = 0
    missing_command_keys = 0
    paired = 0

    for _, _, event_type, value in sorted(events):
        if event_type == "command":
            if value["hwq"] is None or value["cid"] is None:
                missing_command_keys += 1
                continue
            key = (value["hwq"], value["cid"])
            if key in pending:
                ambiguous_reuse += 1
                pending[key]["pairing_ambiguous"] = True
                value["pairing_ambiguous"] = True
            pending[key] = value
            continue

        key = (value["hwq"], value["cid"])
        command = pending.pop(key, None)
        if command is None:
            orphan_completions += 1
            continue
        derived_latency = value["ts"] - command["ts"]
        if derived_latency < 0 or derived_latency != value["lat_ns"]:
            invalid_latency += 1
            continue
        command["completion"] = value
        paired += 1

    unmatched = sum(
        command.get("completion") is None and
        command["hwq"] is not None and command["cid"] is not None
        for command in commands)
    complete = (
        paired == len(commands)
        and orphan_completions == 0
        and ambiguous_reuse == 0
        and invalid_latency == 0
        and missing_command_keys == 0
        and unmatched == 0
    )
    return {
        "complete": complete,
        "paired": paired,
        "unmatched_commands": unmatched,
        "orphan_completions": orphan_completions,
        "ambiguous_key_reuse": ambiguous_reuse,
        "invalid_latency": invalid_latency,
        "commands_without_pairing_key": missing_command_keys,
    }


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _load_json(path):
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ComparisonError(f"{path}: duplicate JSON key")
            result[key] = value
        return result

    try:
        with open(path, encoding="utf-8") as source:
            value = json.load(source, object_pairs_hook=unique_object)
    except json.JSONDecodeError as error:
        raise ComparisonError(f"{path}: invalid JSON") from error
    if not isinstance(value, dict):
        raise ComparisonError(f"{path}: expected a JSON object")
    return value


def _verify_bundle(bundle):
    root = Path(bundle)
    if root.is_symlink() or not root.is_dir():
        raise ComparisonError("runtime bundle must be a real directory")
    expected = BUNDLE_ARTIFACTS | {"SHA256SUMS"}
    if {path.name for path in root.iterdir()} != expected:
        raise ComparisonError("runtime bundle inventory is not schema v1")
    for name in expected:
        mode = os.lstat(root / name).st_mode
        if not stat.S_ISREG(mode):
            raise ComparisonError(f"runtime bundle {name} is not a regular file")

    checksums = {}
    for line in (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        fields = line.split("  ", 1)
        if (
            len(fields) != 2
            or len(fields[0]) != 64
            or any(character not in "0123456789abcdef" for character in fields[0])
            or fields[1] in checksums
        ):
            raise ComparisonError("runtime bundle has an invalid checksum list")
        checksums[fields[1]] = fields[0]
    if set(checksums) != BUNDLE_ARTIFACTS:
        raise ComparisonError("runtime bundle checksum inventory is incomplete")
    for name, expected_digest in checksums.items():
        if _sha256_file(root / name) != expected_digest:
            raise ComparisonError(f"runtime bundle checksum failed for {name}")
    return root, _load_json(root / "certificate.json"), _load_json(
        root / "workload.json")


def _atomic_write(path, content):
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    temporary = f".{path.name}.tmp-{os.getpid()}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = None
    try:
        descriptor = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            descriptor = None
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(
            temporary,
            path.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except OSError:
            pass
        raise ComparisonError(f"cannot update runtime bundle {path.name}") from error
    finally:
        os.close(directory_fd)


def _latency_distribution(capture):
    values = capture["latencies_us"]
    return {
        "sample_count": len(values),
        "p50_us": _percentile(values, 0.50) if values else None,
        "p99_us": _percentile(values, 0.99) if values else None,
    }


def _completion_status(capture):
    completed = [
        command.get("completion")
        for command in capture["commands"]
        if command.get("completion") is not None
    ]
    errors = sum(completion["status"] != 0 for completion in completed)
    return {
        "error_count": errors,
        "all_commands_succeeded": (
            bool(capture["commands"])
            and capture.get("completion_pairing", {}).get("complete", False)
            and errors == 0
        ),
    }


def _normalized_commands(capture, lba_bytes):
    commands = capture["commands"]
    if not commands:
        return []
    first_timestamp = commands[0]["ts"]
    return [
        {
            "seq": index,
            "at_ns": command["ts"] - first_timestamp,
            "op": command["op"],
            "offset_bytes": command["slba"] * lba_bytes,
            "length_bytes": command["bytes"],
        }
        for index, command in enumerate(commands)
    ]


def update_runtime_bundle(
    bundle, source_path, replay_path, source, replay, comparison, lba_bytes
):
    root, certificate, workload = _verify_bundle(bundle)
    if certificate.get("schema_version") != 1:
        raise ComparisonError("runtime bundle has an unsupported certificate")
    if certificate.get("source_trace_sha256") != _sha256_file(source_path):
        raise ComparisonError("source capture does not match the runtime bundle")
    if certificate.get("lba_bytes") != lba_bytes:
        raise ComparisonError("comparison LBA size does not match the runtime bundle")
    if workload != {
        "schema_version": 1,
        "commands": _normalized_commands(source, lba_bytes),
    }:
        raise ComparisonError("source capture does not match the normalized workload")

    runtime = {
        "schema_version": 1,
        "replay_capture_sha256": _sha256_file(replay_path),
        "source_command_count": len(source["commands"]),
        "replay_command_count": len(replay["commands"]),
        "source_capture_complete": comparison["source_capture_complete"],
        "replay_capture_complete": comparison["replay_capture_complete"],
        "command_count_equal": comparison["command_count_equal"],
        "operation_sequence_equal": comparison["operation_sequence_equal"],
        "offset_sequence_equal": comparison["offset_sequence_equal"],
        "length_sequence_equal": comparison["length_sequence_equal"],
        "tuple_sequence_equal": comparison["tuple_sequence_equal"],
        "device_stream_equal": comparison["device_stream_equal"],
        "timing_error_us": {
            "p50": comparison["timing_error_p50_us"],
            "p99": comparison["timing_error_p99_us"],
            "max": comparison["timing_error_max_us"],
        },
        "completion_latency_us": {
            "source": _latency_distribution(source),
            "replay": _latency_distribution(replay),
        },
        "completion_status": {
            "source": {
                "error_count": comparison[
                    "source_completion_error_count"],
                "all_commands_succeeded": comparison[
                    "source_all_commands_succeeded"],
            },
            "replay": {
                "error_count": comparison[
                    "replay_completion_error_count"],
                "all_commands_succeeded": comparison[
                    "replay_all_commands_succeeded"],
            },
        },
        "completion_pairing": {
            "source_complete": comparison[
                "source_completion_pairing_complete"],
            "replay_complete": comparison[
                "replay_completion_pairing_complete"],
            "per_command_compared": comparison[
                "per_command_completion_latency_compared"],
            "absolute_error_p50_us": comparison[
                "completion_latency_error_p50_us"],
            "absolute_error_p99_us": comparison[
                "completion_latency_error_p99_us"],
            "absolute_error_max_us": comparison[
                "completion_latency_error_max_us"],
        },
    }
    certificate["runtime_device_validation"] = runtime
    certificate_text = json.dumps(
        certificate, indent=2, sort_keys=True, allow_nan=False) + "\n"
    _atomic_write(root / "certificate.json", certificate_text)
    sums = [
        f"{_sha256_file(root / name)}  {name}"
        for name in sorted(BUNDLE_ARTIFACTS)
    ]
    _atomic_write(root / "SHA256SUMS", "\n".join(sums) + "\n")
    return runtime


def load(path, allow_legacy_capture=False):
    commands, events = [], []
    lba_bytes = None
    seen_seq = set()
    try:
        records = load_records(path)
        envelope = validate_envelope(
            path, records, allow_legacy=allow_legacy_capture)
    except CaptureFormatError as error:
        raise ComparisonError(str(error)) from error
    for source_seq, (line_number, record) in enumerate(records):
        event_type = record.get("event_type")
        if event_type == "capture_meta" and record.get("lba_bytes") is not None:
            candidate = int(record["lba_bytes"])
            if lba_bytes is not None and lba_bytes != candidate:
                raise ComparisonError(f"{path}: conflicting LBA sizes")
            lba_bytes = candidate
        elif event_type == "nvme_cmd":
            operation = record["op_name"]
            if operation not in ("read", "write", "flush"):
                raise ComparisonError(
                    f"{path}:{line_number}: unsupported NVMe command "
                    f"{operation!r}")
            sequence = int(record.get("seq", source_seq))
            if sequence in seen_seq:
                raise ComparisonError(
                    f"{path}: duplicate command sequence {sequence}")
            seen_seq.add(sequence)
            timestamp = _int_field(path, line_number, record, "ts")
            slba = 0 if operation == "flush" else _int_field(
                path, line_number, record, "slba")
            length = 0 if operation == "flush" else _int_field(
                path, line_number, record, "bytes")
            hwq = record.get("hwq")
            cid = record.get("cid")
            if hwq is not None:
                hwq = _int_field(path, line_number, record, "hwq")
            if cid is not None:
                cid = _int_field(path, line_number, record, "cid")
            if (hwq is None) != (cid is None):
                raise ComparisonError(
                    f"{path}:{line_number}: command must carry both hwq and cid")
            if sequence < 0:
                raise ComparisonError(f"{path}:{line_number}: negative command seq")
            if operation != "flush" and length == 0:
                raise ComparisonError(
                    f"{path}:{line_number}: zero command length")
            command = {
                "seq": sequence,
                "source_seq": source_seq,
                "ts": timestamp,
                "op": "datasync" if operation == "flush" else operation,
                "slba": slba,
                "bytes": length,
                "hwq": hwq,
                "cid": cid,
                "completion": None,
                "pairing_ambiguous": False,
            }
            commands.append(command)
            events.append((timestamp, source_seq, "command", command))
        elif event_type == "nvme_cmp":
            completion = {
                "ts": _int_field(path, line_number, record, "ts"),
                "lat_ns": _int_field(path, line_number, record, "lat_ns"),
                "hwq": _int_field(path, line_number, record, "hwq"),
                "cid": _int_field(path, line_number, record, "cid"),
                "status": _int_field(path, line_number, record, "status"),
            }
            events.append((completion["ts"], source_seq, "completion", completion))
    pairing = _pair_completions(events, commands)
    commands.sort(key=lambda command: (
        command["ts"], command["seq"], command["source_seq"]))
    latencies = sorted(
        command["completion"]["lat_ns"] / 1e3
        for command in commands if command["completion"] is not None)
    return {"commands": commands, "latencies_us": latencies,
            "lba_bytes": lba_bytes, "drops": envelope.drops,
            "capture_scope": envelope.scope, "completion_pairing": pairing}


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
    source_status = _completion_status(source)
    replay_status = _completion_status(replay)
    source_tuples = [(c["op"], c["slba"] * lba_bytes, c["bytes"]) for c in left]
    replay_tuples = [(c["op"], c["slba"] * lba_bytes, c["bytes"]) for c in right]
    count_equal = len(left) == len(right)
    source_pairing_complete = source.get(
        "completion_pairing", {}).get("complete", False)
    replay_pairing_complete = replay.get(
        "completion_pairing", {}).get("complete", False)
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
        "source_completion_pairing_complete": source_pairing_complete,
        "replay_completion_pairing_complete": replay_pairing_complete,
        "source_completion_error_count": source_status["error_count"],
        "replay_completion_error_count": replay_status["error_count"],
        "source_all_commands_succeeded": source_status[
            "all_commands_succeeded"],
        "replay_all_commands_succeeded": replay_status[
            "all_commands_succeeded"],
        "per_command_completion_latency_compared": False,
        "completion_latency_error_p50_us": None,
        "completion_latency_error_p99_us": None,
        "completion_latency_error_max_us": None,
        "timing_error_p50_us": None,
        "timing_error_p99_us": None,
        "timing_error_max_us": None,
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
    if (
        result["tuple_sequence_equal"]
        and source_pairing_complete
        and replay_pairing_complete
        and left
    ):
        latency_errors = [
            abs(a["completion"]["lat_ns"] - b["completion"]["lat_ns"]) / 1000
            for a, b in zip(left, right)
        ]
        result.update({
            "per_command_completion_latency_compared": True,
            "completion_latency_error_p50_us": _percentile(
                latency_errors, 0.50),
            "completion_latency_error_p99_us": _percentile(
                latency_errors, 0.99),
            "completion_latency_error_max_us": max(latency_errors),
        })
    return result


def report(name, paths, lba_override=None, allow_legacy_capture=False):
    captures = {
        label: load(path, allow_legacy_capture) for label, path in paths
    }
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
    comparisons = {}
    for label, capture in captures.items():
        print(f"  sizes[{label}]: {summaries[label]['sizes']}")
        if capture["drops"] not in (None, 0):
            print(f"  warning[{label}]: capture reports {capture['drops']} dropped events")
        if label == "capture":
            continue
        exact = exact_comparison(source, capture, lba_bytes)
        comparisons[label] = exact
        print(f"  exact[{label}]: " + ", ".join(
            f"{key}={value}" for key, value in exact.items()))
    return {
        "captures": captures,
        "summaries": summaries,
        "comparisons": comparisons,
        "lba_bytes": lba_bytes,
    }


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("spec", nargs="+",
                        help="NAME:CAPTURE:REPLAY_A[:REPLAY_B...] (legacy interface)")
    parser.add_argument("--lba-bytes", type=int,
                        help="required for legacy captures without capture_meta")
    parser.add_argument(
        "--allow-legacy-capture", action="store_true",
        help="accept unversioned captures without v1 scope guarantees")
    parser.add_argument(
        "--update-bundle",
        help="write one replay comparison into a matching fio bundle")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        reports = []
        for specification in args.spec:
            fields = specification.split(":")
            if len(fields) < 3:
                raise SystemExit("spec must be NAME:CAPTURE:REPLAY_A[:REPLAY_B...]")
            name, capture_path, *replays = fields
            paths = [("capture", capture_path)]
            paths.extend((f"replay-{index + 1}", path)
                         for index, path in enumerate(replays))
            reports.append((
                capture_path,
                replays,
                report(
                    name, paths, args.lba_bytes, args.allow_legacy_capture),
            ))
        if args.update_bundle:
            if len(reports) != 1 or len(reports[0][1]) != 1:
                raise ComparisonError(
                    "--update-bundle requires exactly one spec and one replay")
            source_path, replay_paths, result = reports[0]
            runtime = update_runtime_bundle(
                args.update_bundle,
                source_path,
                replay_paths[0],
                result["captures"]["capture"],
                result["captures"]["replay-1"],
                result["comparisons"]["replay-1"],
                result["lba_bytes"],
            )
            print(
                f"updated runtime_device_validation in {args.update_bundle}: "
                f"device_stream_equal={runtime['device_stream_equal']}")
    except (ComparisonError, OSError, KeyError, TypeError, ValueError) as error:
        raise SystemExit(f"kvio compare: {error}") from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
