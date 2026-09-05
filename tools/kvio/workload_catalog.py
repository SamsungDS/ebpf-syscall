#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate and list kvio's evidence-labeled workload sources."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


CATALOG = Path(__file__).with_name("workload_catalog.json")
EVIDENCE_LABELS = {"trace-derived", "measured"}
CAPTURE_METHODS = {
    "application-jsonl",
    "sanitized-application-jsonl",
    "semantic-jsonl",
    "nvme-jsonl",
}
TIMING_EVIDENCE = {"recorded", "derived", "not-recorded"}
SESSION_EVIDENCE = {"recorded", "pseudonymous", "removed", "not-recorded"}
CONTENT_EVIDENCE = {
    "prompt-content",
    "observed-prefix-accounting",
    "opaque-object",
    "not-recorded",
}
PRIVACY_TRANSFORMS = {"none", "source-sanitized", "kvio-sanitized"}
PROMPT_CONTENT = {"retained", "removed", "not-applicable"}


class CatalogError(ValueError):
    pass


def _exact_object(value, fields, where):
    if not isinstance(value, dict):
        raise CatalogError(f"{where} must be an object")
    unknown = set(value) - set(fields)
    missing = set(fields) - set(value)
    if unknown:
        raise CatalogError(f"{where} has unknown fields: {sorted(unknown)}")
    if missing:
        raise CatalogError(f"{where} is missing fields: {sorted(missing)}")


def _string(value, where):
    if not isinstance(value, str) or not value:
        raise CatalogError(f"{where} must be a non-empty string")


def _choice(value, choices, where):
    _string(value, where)
    if value not in choices:
        raise CatalogError(f"{where} has unsupported value {value!r}")


def _sha256(value, where, *, optional=False):
    if optional and value is None:
        return
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CatalogError(f"{where} must be a lowercase SHA-256 digest")


def _string_list(value, where):
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
        or len(set(value)) != len(value)
    ):
        raise CatalogError(f"{where} must contain unique non-empty strings")


def validate_catalog(catalog):
    _exact_object(catalog, {"schema_version", "workloads"}, "catalog")
    if catalog["schema_version"] != 1:
        raise CatalogError("unsupported workload catalog schema")
    entries = catalog["workloads"]
    if not isinstance(entries, list) or not entries:
        raise CatalogError("catalog workloads must be a non-empty list")

    identifiers = set()
    for index, entry in enumerate(entries):
        where = f"workloads[{index}]"
        _exact_object(entry, {
            "id", "title", "workload_class", "evidence_label", "source",
            "capture", "hardware_geometry", "privacy", "contribution_lanes",
        }, where)
        for field in ("id", "title", "workload_class"):
            _string(entry[field], f"{where}.{field}")
        if entry["id"] in identifiers:
            raise CatalogError(f"duplicate workload id {entry['id']!r}")
        identifiers.add(entry["id"])
        _choice(entry["evidence_label"], EVIDENCE_LABELS,
                f"{where}.evidence_label")

        source = entry["source"]
        _exact_object(source, {
            "url", "revision", "license", "artifact_sha256",
        }, f"{where}.source")
        for field in ("url", "revision", "license"):
            _string(source[field], f"{where}.source.{field}")
        if not source["url"].startswith("https://"):
            raise CatalogError(f"{where}.source.url must use HTTPS")
        _sha256(source["artifact_sha256"],
                f"{where}.source.artifact_sha256", optional=True)

        capture = entry["capture"]
        _exact_object(capture, {
            "method", "format", "timing", "session_identity",
            "content_identity",
        }, f"{where}.capture")
        _choice(capture["method"], CAPTURE_METHODS, f"{where}.capture.method")
        _string(capture["format"], f"{where}.capture.format")
        _choice(capture["timing"], TIMING_EVIDENCE,
                f"{where}.capture.timing")
        _choice(capture["session_identity"], SESSION_EVIDENCE,
                f"{where}.capture.session_identity")
        _choice(capture["content_identity"], CONTENT_EVIDENCE,
                f"{where}.capture.content_identity")

        hardware = entry["hardware_geometry"]
        hardware_fields = {
            "available", "device_model", "logical_block_bytes",
            "max_transfer_bytes", "kernel", "capture_tool",
        }
        _exact_object(hardware, hardware_fields, f"{where}.hardware_geometry")
        if type(hardware["available"]) is not bool:
            raise CatalogError(f"{where}.hardware_geometry.available must be boolean")
        details = hardware_fields - {"available"}
        if not hardware["available"] and any(hardware[field] is not None
                                             for field in details):
            raise CatalogError(
                f"{where}.hardware_geometry unavailable details must be null")
        if hardware["available"]:
            for field in ("device_model", "kernel", "capture_tool"):
                _string(hardware[field], f"{where}.hardware_geometry.{field}")
            for field in ("logical_block_bytes", "max_transfer_bytes"):
                if type(hardware[field]) is not int or hardware[field] <= 0:
                    raise CatalogError(
                        f"{where}.hardware_geometry.{field} must be positive")
        if hardware["available"] != (entry["evidence_label"] == "measured"):
            raise CatalogError(
                f"{where} measured evidence and hardware geometry disagree")

        privacy = entry["privacy"]
        _exact_object(privacy, {
            "transformation", "prompt_content", "residual_disclosure",
        }, f"{where}.privacy")
        _choice(privacy["transformation"], PRIVACY_TRANSFORMS,
                f"{where}.privacy.transformation")
        _choice(privacy["prompt_content"], PROMPT_CONTENT,
                f"{where}.privacy.prompt_content")
        _string_list(privacy["residual_disclosure"],
                     f"{where}.privacy.residual_disclosure")
        _string_list(entry["contribution_lanes"],
                     f"{where}.contribution_lanes")
    return catalog


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CatalogError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_catalog(path=CATALOG):
    try:
        with open(path, encoding="utf-8") as source:
            catalog = json.load(source, object_pairs_hook=_unique_object)
    except json.JSONDecodeError as error:
        raise CatalogError(f"{path}: invalid JSON") from error
    return validate_catalog(catalog)


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", default=str(CATALOG))
    parser.add_argument("--json", action="store_true", help="print validated JSON")
    parser.add_argument("--check", action="store_true", help="validate without listing")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        catalog = load_catalog(args.catalog)
    except (CatalogError, OSError) as error:
        raise SystemExit(f"kvio catalog: {error}") from error
    if args.check:
        print(f"valid workload catalog: {len(catalog['workloads'])} entries")
    elif args.json:
        print(json.dumps(catalog, indent=2, sort_keys=True))
    else:
        for entry in catalog["workloads"]:
            hardware = ("recorded" if entry["hardware_geometry"]["available"]
                        else "not-recorded")
            print(
                f"{entry['id']}: {entry['evidence_label']}; "
                f"{entry['capture']['method']}; hardware={hardware}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
