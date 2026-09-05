#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build and verify bounded kvio result candidates without source traces."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path


MAX_JSON_BYTES = 64 * 1024
RESULT_SCHEMA = "kvio-bank-local-result-v1"
MANIFEST_SCHEMA = "kvio-release-manifest-v1"
PROFILE = "bank-local-results-v1"
EXPECTED_FILES = {"manifest.json", "result.json"}

QUESTIONS = {
    "restore-tail-latency",
    "restore-throughput",
    "same-device-interference",
    "write-tail-latency",
}
METRICS = {
    "p99-completion-latency",
    "p99-probe-latency",
    "throughput",
}
OUTCOMES = {
    "candidate-higher",
    "candidate-lower",
    "inconclusive",
    "no-material-change",
}
RATIO_BANDS = {
    "below-0.80",
    "0.80-to-0.90",
    "0.90-to-0.95",
    "0.95-to-1.05",
    "1.05-to-1.10",
    "1.10-to-1.20",
    "above-1.20",
    "not-reported",
}
REPEAT_BANDS = {"5-to-9", "10-to-19", "20-or-more"}
WORKLOAD_EVIDENCE = {
    "measured-capture",
    "trace-derived",
    "calibrated",
    "synthetic",
}
TARGET_CLASSES = {"local-nvme", "network-block", "other-storage"}
RUNTIME_EVIDENCE = {
    "fio-result-only",
    "not-measured",
    "re-recorded-device-stream",
}
DISCLOSURES = {
    "aggregate-comparison",
    "coarse-ratio-band",
    "storage-class",
    "workload-class",
}
QUESTION_METRICS = {
    "restore-tail-latency": "p99-completion-latency",
    "restore-throughput": "throughput",
    "same-device-interference": "p99-probe-latency",
    "write-tail-latency": "p99-completion-latency",
}
LOWER_BANDS = {"below-0.80", "0.80-to-0.90", "0.90-to-0.95"}
HIGHER_BANDS = {"1.05-to-1.10", "1.10-to-1.20", "above-1.20"}


class ReleaseError(ValueError):
    """Report a stable error code without echoing candidate contents."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code


class _DuplicateKeyError(ValueError):
    pass


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError
        result[key] = value
    return result


def _decode_json(raw: bytes, code: str) -> dict:
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except UnicodeDecodeError as error:
        raise ReleaseError(code, "JSON file is not valid UTF-8") from error
    except _DuplicateKeyError as error:
        raise ReleaseError(code, "JSON object contains a duplicate key") from error
    except json.JSONDecodeError as error:
        raise ReleaseError(code, "invalid JSON") from error
    if not isinstance(document, dict):
        raise ReleaseError(code, "top-level JSON value must be an object")
    return document


def _read_bytes(path: Path, code: str) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as source:
            details = os.fstat(source.fileno())
            if not stat.S_ISREG(details.st_mode):
                raise ReleaseError(code, "expected a regular JSON file")
            if details.st_size > MAX_JSON_BYTES:
                raise ReleaseError(code, "JSON file exceeds the 64 KiB format limit")
            raw = source.read(MAX_JSON_BYTES + 1)
    except ReleaseError:
        raise
    except OSError as error:
        raise ReleaseError(code, "cannot read a regular JSON file") from error
    if len(raw) > MAX_JSON_BYTES:
        raise ReleaseError(code, "JSON file exceeds the 64 KiB format limit")
    return raw


def _read_bytes_at(directory_fd: int, name: str, code: str) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
        with os.fdopen(descriptor, "rb") as source:
            details = os.fstat(source.fileno())
            if not stat.S_ISREG(details.st_mode):
                raise ReleaseError(code, "expected a regular JSON file")
            if details.st_size > MAX_JSON_BYTES:
                raise ReleaseError(code, "JSON file exceeds the 64 KiB format limit")
            raw = source.read(MAX_JSON_BYTES + 1)
    except ReleaseError:
        raise
    except OSError as error:
        raise ReleaseError(code, "cannot read a regular JSON file") from error
    if len(raw) > MAX_JSON_BYTES:
        raise ReleaseError(code, "JSON file exceeds the 64 KiB format limit")
    return raw


def _read_json(path: Path, code: str) -> dict:
    return _decode_json(_read_bytes(path, code), code)


def _require_fields(document: dict, expected: set[str], code: str) -> None:
    if set(document) != expected:
        raise ReleaseError(code, "object fields do not match the closed grammar")


def _require_enum(value, allowed: set[str], code: str) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise ReleaseError(code, "value is not in the supported enumeration")


def validate_result(result: dict) -> None:
    _require_fields(
        result,
        {
            "schema",
            "status",
            "profile",
            "question",
            "comparison",
            "conditions",
            "residual_disclosures",
        },
        "E_RESULT_FIELDS",
    )
    if result["schema"] != RESULT_SCHEMA:
        raise ReleaseError("E_RESULT_SCHEMA", "unsupported result schema")
    if result["status"] != "draft":
        raise ReleaseError(
            "E_RESULT_STATUS",
            "v1 builds draft candidates; authorization is external",
        )
    if result["profile"] != PROFILE:
        raise ReleaseError("E_RESULT_PROFILE", "unsupported release profile")
    _require_enum(result["question"], QUESTIONS, "E_RESULT_QUESTION")

    comparison = result["comparison"]
    if not isinstance(comparison, dict):
        raise ReleaseError("E_COMPARISON_TYPE", "comparison must be an object")
    _require_fields(
        comparison,
        {"metric", "outcome", "ratio_band", "repeat_count_band"},
        "E_COMPARISON_FIELDS",
    )
    _require_enum(comparison["metric"], METRICS, "E_COMPARISON_METRIC")
    _require_enum(comparison["outcome"], OUTCOMES, "E_COMPARISON_OUTCOME")
    _require_enum(comparison["ratio_band"], RATIO_BANDS, "E_COMPARISON_RATIO_BAND")
    _require_enum(
        comparison["repeat_count_band"], REPEAT_BANDS, "E_COMPARISON_REPEAT_BAND"
    )
    if comparison["metric"] != QUESTION_METRICS[result["question"]]:
        raise ReleaseError(
            "E_COMPARISON_QUESTION", "metric does not match the question"
        )
    outcome = comparison["outcome"]
    ratio_band = comparison["ratio_band"]
    valid_outcome = (
        outcome == "candidate-lower"
        and ratio_band in LOWER_BANDS
        or outcome == "candidate-higher"
        and ratio_band in HIGHER_BANDS
        or outcome == "no-material-change"
        and ratio_band == "0.95-to-1.05"
        or outcome == "inconclusive"
        and ratio_band == "not-reported"
    )
    if not valid_outcome:
        raise ReleaseError("E_COMPARISON_CONFLICT", "outcome and ratio band disagree")

    conditions = result["conditions"]
    if not isinstance(conditions, dict):
        raise ReleaseError("E_CONDITIONS_TYPE", "conditions must be an object")
    _require_fields(
        conditions,
        {"workload_evidence", "offered_load", "target_class", "runtime_evidence"},
        "E_CONDITIONS_FIELDS",
    )
    _require_enum(
        conditions["workload_evidence"], WORKLOAD_EVIDENCE, "E_CONDITIONS_WORKLOAD"
    )
    if conditions["offered_load"] != "fixed":
        raise ReleaseError(
            "E_CONDITIONS_LOAD", "v1 requires a fixed offered-load comparison"
        )
    _require_enum(conditions["target_class"], TARGET_CLASSES, "E_CONDITIONS_TARGET")
    _require_enum(
        conditions["runtime_evidence"], RUNTIME_EVIDENCE, "E_CONDITIONS_RUNTIME"
    )

    disclosures = result["residual_disclosures"]
    if not isinstance(disclosures, list) or not disclosures:
        raise ReleaseError(
            "E_DISCLOSURES_TYPE", "residual disclosures must be a non-empty list"
        )
    if any(
        not isinstance(value, str) or value not in DISCLOSURES for value in disclosures
    ):
        raise ReleaseError("E_DISCLOSURES_VALUE", "unsupported residual disclosure")
    if disclosures != sorted(DISCLOSURES):
        raise ReleaseError(
            "E_DISCLOSURES_SET",
            "v1 requires its complete, sorted residual-disclosure set",
        )


def _json_bytes(document: dict) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_new(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def build_candidate(input_path: str, output_path: str) -> dict:
    source = Path(input_path)
    target = Path(output_path)
    result = _read_json(source, "E_INPUT")
    validate_result(result)
    parent = target.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ReleaseError("E_OUTPUT_PARENT", "output parent must be a directory")

    result_bytes = _json_bytes(result)
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "profile": PROFILE,
        "files": [
            {
                "name": "result.json",
                "bytes": len(result_bytes),
                "sha256": _sha256(result_bytes),
            }
        ],
    }
    manifest_bytes = _json_bytes(manifest)

    try:
        target.mkdir(mode=0o700)
    except FileExistsError as error:
        raise ReleaseError("E_OUTPUT_EXISTS", "output path already exists") from error
    except OSError as error:
        raise ReleaseError(
            "E_OUTPUT_CREATE", "cannot create output directory"
        ) from error
    try:
        _write_new(target / "result.json", result_bytes)
        _write_new(target / "manifest.json", manifest_bytes)
    except OSError as error:
        raise ReleaseError(
            "E_OUTPUT_WRITE", "candidate output is incomplete; do not use it"
        ) from error
    return verify_candidate(str(target))


def _validate_manifest(manifest: dict, result_bytes: bytes) -> None:
    _require_fields(manifest, {"schema", "profile", "files"}, "E_MANIFEST_FIELDS")
    if manifest["schema"] != MANIFEST_SCHEMA:
        raise ReleaseError("E_MANIFEST_SCHEMA", "unsupported manifest schema")
    if manifest["profile"] != PROFILE:
        raise ReleaseError("E_MANIFEST_PROFILE", "profile does not match v1")
    files = manifest["files"]
    if not isinstance(files, list) or len(files) != 1:
        raise ReleaseError("E_MANIFEST_FILES", "manifest must name one payload")
    entry = files[0]
    if not isinstance(entry, dict):
        raise ReleaseError("E_MANIFEST_ENTRY", "file entry must be an object")
    _require_fields(entry, {"name", "bytes", "sha256"}, "E_MANIFEST_ENTRY")
    if entry["name"] != "result.json":
        raise ReleaseError("E_MANIFEST_NAME", "unsupported payload name")
    if type(entry["bytes"]) is not int or entry["bytes"] != len(result_bytes):
        raise ReleaseError("E_MANIFEST_SIZE", "payload size does not match")
    digest = entry["sha256"]
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ReleaseError("E_MANIFEST_DIGEST", "invalid payload digest")
    if digest != _sha256(result_bytes):
        raise ReleaseError("E_MANIFEST_HASH", "payload digest does not match")


def verify_candidate(bundle_path: str) -> dict:
    bundle = Path(bundle_path)
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        directory_fd = os.open(bundle, flags)
    except OSError as error:
        raise ReleaseError(
            "E_BUNDLE_TYPE", "bundle must be a real directory"
        ) from error
    try:
        try:
            names_list = os.listdir(directory_fd)
            names = set(names_list)
        except OSError as error:
            raise ReleaseError("E_BUNDLE_READ", "cannot inspect bundle") from error
        if names != EXPECTED_FILES or len(names_list) != len(EXPECTED_FILES):
            raise ReleaseError(
                "E_BUNDLE_INVENTORY", "bundle inventory does not match the profile"
            )
        for name in names:
            try:
                details = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as error:
                raise ReleaseError(
                    "E_BUNDLE_FILE_TYPE", "cannot inspect bundle entry"
                ) from error
            if not stat.S_ISREG(details.st_mode):
                raise ReleaseError(
                    "E_BUNDLE_FILE_TYPE", "bundle entries must be regular files"
                )
        result_bytes = _read_bytes_at(directory_fd, "result.json", "E_RESULT")
        manifest_bytes = _read_bytes_at(directory_fd, "manifest.json", "E_MANIFEST")
    finally:
        os.close(directory_fd)

    result = _decode_json(result_bytes, "E_RESULT")
    manifest = _decode_json(manifest_bytes, "E_MANIFEST")
    validate_result(result)
    _validate_manifest(manifest, result_bytes)
    return {
        "profile": PROFILE,
        "bundle_conformance": "pass",
        "internal_evidence": "not_checked",
        "release_authorization": "not_checked",
        "export_allowed": False,
        "residual_disclosures": result["residual_disclosures"],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser(
        "release-build", help="build a bounded, unsigned result candidate"
    )
    build.add_argument("input", help="strict bank-local result JSON")
    build.add_argument("output", help="new output directory")
    subparsers.add_parser(
        "release-example", help="print the canonical bank-local result draft"
    )
    verify = subparsers.add_parser(
        "release-verify", help="check candidate format and manifest only"
    )
    verify.add_argument("bundle", help="candidate directory")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "release-example":
            example = _read_json(
                Path(__file__).with_name("bank-local-result.example.json"),
                "E_EXAMPLE",
            )
            validate_result(example)
            print(_json_bytes(example).decode("utf-8"), end="")
            return 0
        if args.command == "release-build":
            verdict = build_candidate(args.input, args.output)
        else:
            verdict = verify_candidate(args.bundle)
    except ReleaseError as error:
        raise SystemExit(f"kvio {args.command}: {error}") from error
    print(json.dumps(verdict, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
