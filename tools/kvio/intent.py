#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Versioned, device-independent KV-offload intent and target lowering.

An intent records the logical objects an application means to store or load.
It deliberately does *not* record a source device, DMA exporter, physical slot
offset, MDTS, or already-split NVMe commands. Those are properties of one
realization of the intent, captured separately with ``kvio record``.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


SCHEMA = "kvio.intent.v1"
PLAN_SCHEMA = "kvio.intent-plan.v1"


class IntentError(ValueError):
    """Raised when an intent is not a valid v1 contract."""


def _positive(value, where):
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise IntentError(f"{where} must be a positive integer")
    return value


def _nonnegative(value, where):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise IntentError(f"{where} must be a non-negative integer")
    return value


def build_kv_offload_intent(*, model, geometry, dtype, chunk_tokens,
                            payload_bytes, ranks_per_chunk, num_chunks,
                            streams, iters, warmup, store_metadata_bytes):
    """Build the intent for ``run_kv_offload_io.py`` without a storage device.

    The canonical array order is serialization only. Operations in different
    streams of one phase may execute in parallel; the phase barrier is explicit
    in ``execution``.
    """
    for value, name in ((chunk_tokens, "chunk_tokens"),
                        (payload_bytes, "payload_bytes"),
                        (ranks_per_chunk, "ranks_per_chunk"),
                        (num_chunks, "num_chunks"), (streams, "streams"),
                        (iters, "iters")):
        _positive(value, name)
    _nonnegative(store_metadata_bytes, "store_metadata_bytes")
    if not isinstance(warmup, int) or isinstance(warmup, bool) or warmup < 0:
        raise IntentError("warmup must be a non-negative integer")

    operations = []
    sequence = 0
    for pass_index in range(warmup + iters):
        for phase in ("store", "load"):
            for stream in range(streams):
                for chunk_index in range(num_chunks):
                    for kv_rank in range(ranks_per_chunk):
                        logical_object = (
                            f"pass={pass_index}/stream={stream}/"
                            f"chunk={chunk_index}/rank={kv_rank}")
                        operations.append({
                            "sequence": sequence,
                            "pass": pass_index,
                            "phase": phase,
                            "stream": stream,
                            "stream_sequence": chunk_index * ranks_per_chunk + kv_rank,
                            "logical_object": logical_object,
                            "chunk_index": chunk_index,
                            "kv_rank": kv_rank,
                            "payload_bytes": payload_bytes,
                            "timed": pass_index >= warmup,
                        })
                        sequence += 1

    intent = {
        "schema": SCHEMA,
        "kind": "kv-offload",
        "evidence": {
            "logical_operations": "derived-from-model-geometry",
            "timing": "not-recorded",
            "device_io": "not-recorded",
        },
        "model": {
            "name": model,
            "dtype": dtype,
            "chunk_tokens": chunk_tokens,
            "geometry": geometry,
        },
        "object": {
            "payload_bytes": payload_bytes,
            # raw_block emits this fixed object header before every store. It
            # is a storage-protocol property, not a source device property.
            "store_metadata_bytes": store_metadata_bytes,
            "ranks_per_chunk": ranks_per_chunk,
        },
        "execution": {
            "num_chunks": num_chunks,
            "streams": streams,
            "iters": iters,
            "warmup": warmup,
            "phase_order": ["store", "load"],
            "cross_stream_order": "unordered-within-phase",
        },
        "operations": operations,
    }
    validate_intent(intent)
    return intent


def validate_intent(intent):
    """Validate the closed fields and invariants of ``kvio.intent.v1``."""
    if not isinstance(intent, dict):
        raise IntentError("intent root must be an object")
    if intent.get("schema") != SCHEMA:
        raise IntentError(f"unsupported intent schema: {intent.get('schema')!r}")
    if intent.get("kind") != "kv-offload":
        raise IntentError("intent kind must be 'kv-offload'")
    evidence = intent.get("evidence")
    if not isinstance(evidence, dict) or evidence != {
            "logical_operations": "derived-from-model-geometry",
            "timing": "not-recorded", "device_io": "not-recorded"}:
        raise IntentError("intent evidence must preserve the v1 modeled boundary")

    model = intent.get("model")
    if not isinstance(model, dict) or not isinstance(model.get("name"), str) or not model["name"]:
        raise IntentError("model.name must be a non-empty string")
    if not isinstance(model.get("dtype"), str) or not model["dtype"]:
        raise IntentError("model.dtype must be a non-empty string")
    _positive(model.get("chunk_tokens"), "model.chunk_tokens")
    if not isinstance(model.get("geometry"), dict):
        raise IntentError("model.geometry must be an object")

    obj = intent.get("object")
    if not isinstance(obj, dict):
        raise IntentError("object must be an object")
    payload = _positive(obj.get("payload_bytes"), "object.payload_bytes")
    _nonnegative(obj.get("store_metadata_bytes"), "object.store_metadata_bytes")
    ranks = _positive(obj.get("ranks_per_chunk"), "object.ranks_per_chunk")
    execution = intent.get("execution")
    if not isinstance(execution, dict):
        raise IntentError("execution must be an object")
    chunks = _positive(execution.get("num_chunks"), "execution.num_chunks")
    streams = _positive(execution.get("streams"), "execution.streams")
    iters = _positive(execution.get("iters"), "execution.iters")
    warmup = execution.get("warmup")
    if not isinstance(warmup, int) or isinstance(warmup, bool) or warmup < 0:
        raise IntentError("execution.warmup must be a non-negative integer")
    if execution.get("phase_order") != ["store", "load"]:
        raise IntentError("execution.phase_order must be ['store', 'load']")
    if execution.get("cross_stream_order") != "unordered-within-phase":
        raise IntentError("execution.cross_stream_order must preserve v1 partial ordering")

    operations = intent.get("operations")
    expected = (warmup + iters) * 2 * streams * chunks * ranks
    if not isinstance(operations, list) or len(operations) != expected:
        raise IntentError(f"operations must contain exactly {expected} entries")
    for sequence, operation in enumerate(operations):
        where = f"operations[{sequence}]"
        if not isinstance(operation, dict) or operation.get("sequence") != sequence:
            raise IntentError(f"{where}.sequence must be canonical")
        if operation.get("phase") not in ("store", "load"):
            raise IntentError(f"{where}.phase must be store or load")
        pass_index = operation.get("pass")
        if not isinstance(pass_index, int) or not 0 <= pass_index < warmup + iters:
            raise IntentError(f"{where}.pass is out of range")
        stream = operation.get("stream")
        if not isinstance(stream, int) or not 0 <= stream < streams:
            raise IntentError(f"{where}.stream is out of range")
        chunk_index = operation.get("chunk_index")
        rank = operation.get("kv_rank")
        if not isinstance(chunk_index, int) or not 0 <= chunk_index < chunks:
            raise IntentError(f"{where}.chunk_index is out of range")
        if not isinstance(rank, int) or not 0 <= rank < ranks:
            raise IntentError(f"{where}.kv_rank is out of range")
        if operation.get("stream_sequence") != chunk_index * ranks + rank:
            raise IntentError(f"{where}.stream_sequence disagrees with object identity")
        expected_object = f"pass={pass_index}/stream={stream}/chunk={chunk_index}/rank={rank}"
        if operation.get("logical_object") != expected_object:
            raise IntentError(f"{where}.logical_object is not canonical")
        if operation.get("payload_bytes") != payload:
            raise IntentError(f"{where}.payload_bytes disagrees with object payload")
        if operation.get("timed") is not (pass_index >= warmup):
            raise IntentError(f"{where}.timed disagrees with execution.warmup")


def lower_intent(intent, *, mdts_bytes, dma_ceiling_bytes=None,
                 software_limit_bytes=None):
    """Lower logical operations into object-relative target command fragments."""
    validate_intent(intent)
    limits = {"mdts_bytes": _positive(mdts_bytes, "mdts_bytes")}
    if dma_ceiling_bytes is not None:
        limits["dma_ceiling_bytes"] = _positive(dma_ceiling_bytes, "dma_ceiling_bytes")
    if software_limit_bytes is not None:
        limits["software_limit_bytes"] = _positive(software_limit_bytes,
                                                     "software_limit_bytes")
    effective = min(limits.values())
    commands = []
    for operation in intent["operations"]:
        components = []
        if operation["phase"] == "store" and intent["object"]["store_metadata_bytes"]:
            components.append(("metadata", intent["object"]["store_metadata_bytes"]))
        components.append(("payload", operation["payload_bytes"]))
        command_index = 0
        for component, remaining in components:
            offset = 0
            while remaining:
                size = min(remaining, effective)
                commands.append({
                    "logical_sequence": operation["sequence"],
                    "logical_object": operation["logical_object"],
                    "op": operation["phase"],
                    "component": component,
                    "command_index": command_index,
                    "component_offset_bytes": offset,
                    "bytes": size,
                })
                remaining -= size
                offset += size
                command_index += 1
    encoded = json.dumps(intent, sort_keys=True, separators=(",", ":")).encode()
    return {
        "schema": PLAN_SCHEMA,
        "intent_sha256": hashlib.sha256(encoded).hexdigest(),
        "evidence": "modeled-target-command-plan-not-device-measurement",
        "target_limits": limits,
        "effective_command_bytes": effective,
        "summary": {
            "logical_operations": len(intent["operations"]),
            "logical_bytes": sum(op["payload_bytes"] for op in intent["operations"]),
            "commands": len(commands),
        },
        "commands": commands,
    }


def _load(path):
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise IntentError(f"cannot read intent {path}: {error}") from error
    validate_intent(value)
    return value


def _write(value, path):
    output = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if path == "-":
        print(output, end="")
    else:
        Path(path).write_text(output, encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("validate", help="validate a kvio.intent.v1 file")
    check.add_argument("intent")
    plan = sub.add_parser("plan", help="model command splitting for a target")
    plan.add_argument("intent")
    plan.add_argument("--mdts-bytes", type=int, required=True)
    plan.add_argument("--dma-ceiling-bytes", type=int)
    plan.add_argument("--software-limit-bytes", type=int)
    plan.add_argument("--out", default="-", help="output JSON path, or - for stdout")
    args = parser.parse_args(argv)
    try:
        intent = _load(args.intent)
        if args.command == "validate":
            print(f"valid {SCHEMA}: {len(intent['operations'])} logical operations")
            return 0
        result = lower_intent(intent, mdts_bytes=args.mdts_bytes,
                              dma_ceiling_bytes=args.dma_ceiling_bytes,
                              software_limit_bytes=args.software_limit_bytes)
        _write(result, args.out)
        return 0
    except IntentError as error:
        parser.error(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
