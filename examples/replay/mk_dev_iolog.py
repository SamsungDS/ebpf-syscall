#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Convert an NVMe capture to a validated fio version-3 replay artifact.

The converter preserves the ordered operation/offset/length stream. Source
timestamps are monotonic nanoseconds; fio v3 timestamps are relative
microseconds, so conversion loses at most 999 ns. A portable bundle also
contains block and NVMe-passthrough fio wrappers, the normalized workload, and
a translation certificate. It does not claim performance equivalence or that
the kernel/controller will execute the requested stream unchanged; re-record
the replay to establish device conformance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


V3_HEADER = "fio version 3 iolog"
SUPPORTED = {"read", "write", "flush"}


class CaptureError(ValueError):
    pass


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def load_capture(path: str, requested_lba: int | None = None,
                 allow_drops: bool = False, allow_unsupported: bool = False):
    rows = []
    metadata_lba = None
    drops = None
    unsupported = []
    seen_seq = set()
    with open(path, encoding="utf-8") as source:
        for source_seq, line in enumerate(source):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise CaptureError(f"{path}:{source_seq + 1}: invalid JSON") from error
            event_type = record.get("event_type")
            if event_type == "capture_meta" and record.get("lba_bytes") is not None:
                candidate = int(record["lba_bytes"])
                if metadata_lba is not None and metadata_lba != candidate:
                    raise CaptureError("capture contains conflicting LBA sizes")
                metadata_lba = candidate
            elif event_type == "drops":
                drops = int(record.get("dropped", 0))
            elif event_type == "nvme_cmd":
                operation = record.get("op_name")
                if operation not in SUPPORTED:
                    unsupported.append((source_seq + 1, operation))
                    continue
                seq = int(record.get("seq", source_seq))
                timestamp_ns = int(record["ts"])
                slba = int(record.get("slba", 0))
                length_bytes = 0 if operation == "flush" else int(record["bytes"])
                if seq in seen_seq:
                    raise CaptureError(f"capture contains duplicate command seq {seq}")
                if seq < 0 or timestamp_ns < 0 or slba < 0:
                    raise CaptureError(f"{path}:{source_seq + 1}: negative command field")
                if operation != "flush" and length_bytes <= 0:
                    raise CaptureError(f"{path}:{source_seq + 1}: non-positive command length")
                seen_seq.add(seq)
                rows.append({
                    "seq": seq,
                    "source_seq": source_seq,
                    "timestamp_ns": timestamp_ns,
                    "op": "datasync" if operation == "flush" else operation,
                    "slba": slba,
                    "length_bytes": length_bytes,
                })
    if drops is None:
        raise CaptureError("capture has no final drops record; it may be incomplete")
    if drops and not allow_drops:
        raise CaptureError(f"capture reports {drops} dropped events; use --allow-drops to override")
    if unsupported and not allow_unsupported:
        line, operation = unsupported[0]
        raise CaptureError(
            f"capture contains {len(unsupported)} unsupported commands "
            f"(first at line {line}: {operation!r}); use --allow-unsupported to omit them"
        )
    lba_bytes = requested_lba if requested_lba is not None else metadata_lba
    if lba_bytes is None:
        raise CaptureError("capture does not record lba_bytes; pass --lba-bytes explicitly")
    if lba_bytes <= 0 or lba_bytes & (lba_bytes - 1):
        raise CaptureError("lba_bytes must be a positive power of two")
    if metadata_lba is not None and requested_lba is not None and metadata_lba != requested_lba:
        raise CaptureError(
            f"--lba-bytes {requested_lba} disagrees with capture metadata {metadata_lba}"
        )
    if not rows:
        raise CaptureError("capture contains no supported NVMe commands")
    rows.sort(key=lambda row: (row["timestamp_ns"], row["seq"], row["source_seq"]))
    for row in rows:
        row["offset_bytes"] = row.pop("slba") * lba_bytes
        if row["op"] != "datasync" and row["length_bytes"] % lba_bytes:
            raise CaptureError(
                f"command length {row['length_bytes']} is not aligned to LBA {lba_bytes}")
        if row["offset_bytes"] > (1 << 64) - 1 - row["length_bytes"]:
            raise CaptureError("command byte range overflows an unsigned 64-bit offset")
    return rows, {
        "lba_bytes": lba_bytes, "drops": drops,
        "unsupported_commands_omitted": len(unsupported),
    }


def emit_iolog(rows: list[dict], filename: str) -> str:
    t0 = rows[0]["timestamp_ns"]
    lines = [V3_HEADER, f"0 {filename} add", f"0 {filename} open"]
    for row in rows:
        timestamp_us = (row["timestamp_ns"] - t0) // 1000
        if row["op"] == "datasync":
            lines.append(f"{timestamp_us} {filename} datasync")
        else:
            lines.append(
                f"{timestamp_us} {filename} {row['op']} "
                f"{row['offset_bytes']} {row['length_bytes']}"
            )
    end_us = (rows[-1]["timestamp_ns"] - t0) // 1000
    lines.append(f"{end_us} {filename} close")
    return "\n".join(lines) + "\n"


def parse_iolog(text: str) -> list[tuple[int, str, int, int]]:
    lines = text.splitlines()
    if not lines or lines[0] != V3_HEADER:
        raise CaptureError("emitted artifact has an invalid fio v3 header")
    commands = []
    for line in lines[1:]:
        fields = line.split()
        if len(fields) == 3 and fields[2] in ("add", "open", "close"):
            continue
        if len(fields) == 3 and fields[2] in ("sync", "datasync"):
            commands.append((int(fields[0]), fields[2], 0, 0))
            continue
        if len(fields) == 5 and fields[2] in ("read", "write", "trim"):
            commands.append((int(fields[0]), fields[2], int(fields[3]), int(fields[4])))
            continue
        raise CaptureError(f"emitted artifact contains an invalid line: {line}")
    return commands


def translation_certificate(rows: list[dict], iolog: str, capture_path: str,
                            capture_meta: dict) -> tuple[dict, list[dict]]:
    t0 = rows[0]["timestamp_ns"]
    normalized = [{
        "seq": index,
        "at_ns": row["timestamp_ns"] - t0,
        "op": row["op"],
        "offset_bytes": row["offset_bytes"],
        "length_bytes": row["length_bytes"],
    } for index, row in enumerate(rows)]
    reparsed = parse_iolog(iolog)
    expected = [
        (command["at_ns"] // 1000, command["op"], command["offset_bytes"],
         command["length_bytes"])
        for command in normalized
    ]
    equal = reparsed == expected
    stream_bytes = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
    certificate = {
        "schema_version": 1,
        "source": "measured NVMe command capture",
        "equivalence_level": (
            "partial-stream-translation"
            if capture_meta["drops"] or capture_meta["unsupported_commands_omitted"]
            else "stream-translation"
        ),
        "source_command_count": len(rows),
        "emitted_command_count": len(reparsed),
        "operation_offset_length_sequence_equal": equal,
        "source_trace_sha256": _sha256_file(capture_path),
        "normalized_stream_sha256": _sha256_bytes(stream_bytes),
        "emitted_iolog_sha256": _sha256_bytes(iolog.encode()),
        "timestamp_input_unit": "nanoseconds",
        "timestamp_output_unit": "microseconds",
        "maximum_timestamp_quantization_error_ns": max(
            command["at_ns"] % 1000 for command in normalized
        ),
        "lba_bytes": capture_meta["lba_bytes"],
        "capture_drops": capture_meta["drops"],
        "unsupported_commands_omitted": capture_meta["unsupported_commands_omitted"],
        "performance_equivalence_claimed": False,
        "runtime_device_validation": None,
    }
    if not equal:
        raise CaptureError("internal translation validation failed")
    return certificate, normalized


def _fio_wrapper(ioengine: str) -> str:
    command_type = "cmd_type=nvme\n" if ioengine == "io_uring_cmd" else ""
    return (
        "; generated by kvio; set KVIO_TARGET to an empty replay target\n"
        "[global]\n"
        f"ioengine={ioengine}\n"
        f"{command_type}"
        "direct=1\n"
        "iodepth=16\n"
        "read_iolog=commands.iolog\n"
        "replay_redirect=${KVIO_TARGET}\n"
        "group_reporting=1\n\n"
        "[kvio-replay]\n"
    )


def write_bundle(directory: str, iolog: str,
                 certificate: dict, normalized: list[dict]) -> None:
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=False)
    artifacts = {
        "commands.iolog": iolog,
        "replay-block.fio": _fio_wrapper("io_uring"),
        "replay-uring-cmd.fio": _fio_wrapper("io_uring_cmd"),
        "workload.json": json.dumps({
            "schema_version": 1, "commands": normalized,
        }, indent=2, sort_keys=True) + "\n",
        "certificate.json": json.dumps(certificate, indent=2, sort_keys=True) + "\n",
        "README.txt": (
            "This bundle preserves the captured operation/offset/length sequence and\n"
            "quantizes relative timestamps from nanoseconds to fio microseconds.\n"
            "Set KVIO_TARGET to an empty raw target, then run one replay jobfile.\n"
            "The block job may be merged or split again by Linux. The uring-cmd job\n"
            "targets NVMe passthrough. Re-record either run before claiming that the\n"
            "device received the same stream. Performance equivalence is not claimed.\n"
            "Run `kvio fio-certify .` for an independent Rust validation.\n"
        ),
    }
    for name, content in artifacts.items():
        (target / name).write_text(content, encoding="utf-8")
    sums = []
    for name in sorted(artifacts):
        sums.append(f"{_sha256_file(target / name)}  {name}")
    (target / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", help="nvme_tp_monitor JSONL capture")
    parser.add_argument("device", help="filename recorded in the iolog")
    parser.add_argument("-o", "--output", help="write the iolog here (default: stdout)")
    parser.add_argument("--lba-bytes", type=int,
                        help="required for legacy captures without capture_meta")
    parser.add_argument("--allow-drops", action="store_true")
    parser.add_argument("--allow-unsupported", action="store_true")
    parser.add_argument("--bundle-dir", help="write a certified portable fio bundle")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rows, meta = load_capture(
            args.capture, args.lba_bytes, args.allow_drops, args.allow_unsupported)
        iolog = emit_iolog(rows, args.device)
        certificate, normalized = translation_certificate(rows, iolog, args.capture, meta)
        if args.bundle_dir:
            write_bundle(args.bundle_dir, iolog, certificate, normalized)
        if args.output:
            Path(args.output).write_text(iolog, encoding="utf-8")
        elif not args.bundle_dir:
            print(iolog, end="")
        if args.bundle_dir:
            print(f"wrote certified fio replay bundle: {args.bundle_dir}")
        return 0
    except (CaptureError, OSError) as error:
        raise SystemExit(f"kvio iolog: {error}") from error


if __name__ == "__main__":
    raise SystemExit(main())
