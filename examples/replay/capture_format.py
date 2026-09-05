#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Strict envelope checks shared by kvio's NVMe capture consumers."""
from __future__ import annotations

import json
from dataclasses import dataclass


CAPTURE_SCHEMA_VERSION = 1
KNOWN_EVENT_TYPES = {
    "capture_meta", "clock_anchor", "nvme_cmd", "nvme_cmp", "drops",
}


class CaptureFormatError(ValueError):
    pass


class _DuplicateKeyError(ValueError):
    pass


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(key)
        result[key] = value
    return result


def load_records(path: str) -> list[tuple[int, dict]]:
    records = []
    with open(path, encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line, object_pairs_hook=_unique_object)
            except _DuplicateKeyError as error:
                raise CaptureFormatError(
                    f"{path}:{line_number}: duplicate JSON key {str(error)!r}"
                ) from error
            except json.JSONDecodeError as error:
                raise CaptureFormatError(
                    f"{path}:{line_number}: invalid JSON"
                ) from error
            if not isinstance(record, dict):
                raise CaptureFormatError(
                    f"{path}:{line_number}: expected a JSON object"
                )
            records.append((line_number, record))
    if not records:
        raise CaptureFormatError(f"{path}: capture is empty")
    return records


@dataclass(frozen=True)
class CaptureEnvelope:
    metadata: dict | None
    drops: int
    legacy: bool
    scope: tuple[str, int] | None


def validate_envelope(path: str, records: list[tuple[int, dict]], *,
                      allow_legacy: bool = False) -> CaptureEnvelope:
    metadata_records = [
        (line, record) for line, record in records
        if record.get("event_type") == "capture_meta"
    ]
    drop_records = [
        (line, record) for line, record in records
        if record.get("event_type") == "drops"
    ]

    if len(metadata_records) > 1:
        raise CaptureFormatError(f"{path}: multiple capture_meta records")
    if metadata_records and metadata_records[0] != records[0]:
        raise CaptureFormatError(f"{path}: capture_meta must be the first record")
    if len(drop_records) != 1:
        if not drop_records:
            raise CaptureFormatError(
                f"{path}: capture has no final drops record; it may be incomplete"
            )
        raise CaptureFormatError(f"{path}: multiple drops records")
    if drop_records[0] != records[-1]:
        raise CaptureFormatError(f"{path}: drops record must be the final record")

    metadata = metadata_records[0][1] if metadata_records else None
    version = metadata.get("schema_version") if metadata is not None else None
    legacy = version is None
    if legacy and not allow_legacy:
        raise CaptureFormatError(
            f"{path}: capture uses the legacy unversioned format; "
            "pass --allow-legacy-capture to inspect it"
        )
    if not legacy and (type(version) is not int or
                       version != CAPTURE_SCHEMA_VERSION):
        raise CaptureFormatError(
            f"{path}: unsupported capture schema_version {version!r}"
        )

    drops = drop_records[0][1].get("dropped")
    if type(drops) is not int or drops < 0:
        raise CaptureFormatError(f"{path}: drops must be a non-negative integer")

    scope = None
    if not legacy:
        if metadata.get("emitter") != "nvme_tp_monitor":
            raise CaptureFormatError(
                f"{path}: schema v1 requires emitter nvme_tp_monitor"
            )
        if metadata.get("disk_filter") is not True:
            raise CaptureFormatError(
                f"{path}: schema v1 replay requires a --disk scoped capture"
            )
        lba_bytes = metadata.get("lba_bytes")
        if (type(lba_bytes) is not int or lba_bytes <= 0 or
                lba_bytes & (lba_bytes - 1)):
            raise CaptureFormatError(
                f"{path}: schema v1 capture_meta has invalid lba_bytes"
            )
        selected_disk = metadata.get("disk")
        if not isinstance(selected_disk, str) or not selected_disk:
            raise CaptureFormatError(
                f"{path}: schema v1 capture_meta has no selected disk"
            )

        scopes = set()
        for line_number, record in records:
            event_type = record.get("event_type")
            if event_type not in KNOWN_EVENT_TYPES:
                raise CaptureFormatError(
                    f"{path}:{line_number}: unknown event_type {event_type!r}"
                )
            if event_type != "nvme_cmd":
                continue
            disk = record.get("disk")
            nsid = record.get("nsid")
            if not isinstance(disk, str) or not disk:
                raise CaptureFormatError(
                    f"{path}:{line_number}: nvme_cmd has no disk identity"
                )
            if type(nsid) is not int or nsid <= 0:
                raise CaptureFormatError(
                    f"{path}:{line_number}: nvme_cmd has invalid nsid"
                )
            if disk != selected_disk:
                raise CaptureFormatError(
                    f"{path}:{line_number}: command disk {disk!r} disagrees "
                    f"with capture scope {selected_disk!r}"
                )
            scopes.add((disk, nsid))
        if len(scopes) > 1:
            raise CaptureFormatError(
                f"{path}: capture spans multiple device/namespace identities"
            )
        if scopes:
            scope = next(iter(scopes))

    return CaptureEnvelope(metadata, drops, legacy, scope)
