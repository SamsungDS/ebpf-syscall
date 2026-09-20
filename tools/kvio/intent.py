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
import os
import subprocess
import sys
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
        expected_pass = sequence // (2 * streams * chunks * ranks)
        within_pass = sequence % (2 * streams * chunks * ranks)
        expected_phase = (
            "store" if within_pass < streams * chunks * ranks else "load"
        )
        within_phase = within_pass % (streams * chunks * ranks)
        expected_stream = within_phase // (chunks * ranks)
        within_stream = within_phase % (chunks * ranks)
        expected_chunk = within_stream // ranks
        expected_rank = within_stream % ranks
        if operation.get("phase") != expected_phase:
            raise IntentError(
                f"{where}.phase is not in the v1 execution order"
            )
        pass_index = operation.get("pass")
        if pass_index != expected_pass:
            raise IntentError(f"{where}.pass is not in the v1 execution order")
        stream = operation.get("stream")
        if stream != expected_stream:
            raise IntentError(
                f"{where}.stream is not in the v1 execution order"
            )
        chunk_index = operation.get("chunk_index")
        rank = operation.get("kv_rank")
        if chunk_index != expected_chunk:
            raise IntentError(
                f"{where}.chunk_index is not in the v1 execution order"
            )
        if rank != expected_rank:
            raise IntentError(
                f"{where}.kv_rank is not in the v1 execution order"
            )
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
    return {
        "schema": PLAN_SCHEMA,
        "intent_sha256": intent_sha256(intent),
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


def intent_sha256(intent):
    """Return the canonical digest binding plans and runs to an intent."""
    validate_intent(intent)
    encoded = json.dumps(
        intent, sort_keys=True, separators=(",", ":")
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def validate_target_plan(plan, intent):
    """Reject a modeled plan that does not exactly lower ``intent``."""
    if not isinstance(plan, dict) or plan.get("schema") != PLAN_SCHEMA:
        raise IntentError("target plan must use kvio.intent-plan.v1")
    if plan.get("evidence") != (
        "modeled-target-command-plan-not-device-measurement"
    ):
        raise IntentError(
            "target plan must preserve the modeled evidence label"
        )
    if plan.get("intent_sha256") != intent_sha256(intent):
        raise IntentError("target plan does not bind to this intent")
    limits = plan.get("target_limits")
    if not isinstance(limits, dict) or set(limits) - {
            "mdts_bytes", "dma_ceiling_bytes", "software_limit_bytes"}:
        raise IntentError("target plan has invalid target limits")
    expected = lower_intent(
        intent, mdts_bytes=limits.get("mdts_bytes"),
        dma_ceiling_bytes=limits.get("dma_ceiling_bytes"),
        software_limit_bytes=limits.get("software_limit_bytes"))
    if plan != expected:
        raise IntentError(
            "target plan is not the exact lowering of this intent"
        )


def load_intent(path):
    """Load and validate an intent from a local file."""
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


def _engine_env():
    """Return an environment that resolves kvio's vendored engine first."""
    env = dict(os.environ)
    if env.get("KVIO_USE_SYSTEM_LMCACHE") == "1":
        return env
    here = Path(__file__).resolve().parent
    prepend = [str(here / "vendor" / "lmcache"), str(here / "build"), str(here)]
    old = env.get("PYTHONPATH")
    env["PYTHONPATH"] = os.pathsep.join(prepend + ([old] if old else []))
    return env


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
    replay = sub.add_parser(
        "replay",
        help="execute a validated intent with target-side realization options",
    )
    replay.add_argument("intent")
    replay.add_argument("--device", required=True)
    replay.add_argument("--engine", choices=["posix", "io_uring", "uring_cmd"],
                        required=True)
    replay.add_argument("--mdts-bytes", type=int, required=True)
    replay.add_argument("--dma-ceiling-bytes", type=int)
    replay.add_argument("--software-limit-bytes", type=int)
    replay.add_argument("--dmabuf")
    replay.add_argument("--hugepage", action="store_true")
    replay.add_argument("--odirect", action="store_true")
    replay.add_argument("--capacity-gb", type=int, default=8)
    replay.add_argument("--block-align", type=int,
                        help="target namespace physical block size in bytes")
    replay.add_argument("--ring-depth", type=int, default=0)
    replay.add_argument("--load-parallelism", type=int, default=0)
    replay.add_argument(
        "--phase-gate-dir",
        help="after warmup, create READY here and wait for GO before timing",
    )
    replay.add_argument("--phase-gate-timeout-seconds", type=float)
    replay.add_argument("--phase-gate-close", action="store_true")
    replay.add_argument("--phase-rapl-out")
    replay.add_argument("--allow-io-errors", action="store_true")
    replay.add_argument(
        "--advertised-mdts-bytes",
        type=int,
        help="controller MDTS in bytes; 0 means no controller limit",
    )
    replay.add_argument("--record")
    replay.add_argument("--trace")
    replay.add_argument("--target-plan", required=True)
    replay.add_argument("--target-manifest", required=True)
    args = parser.parse_args(argv)
    try:
        intent = load_intent(args.intent)
        if args.command == "validate":
            print(f"valid {SCHEMA}: {len(intent['operations'])} logical operations")
            return 0
        if args.command == "plan":
            result = lower_intent(
                intent,
                mdts_bytes=args.mdts_bytes,
                dma_ceiling_bytes=args.dma_ceiling_bytes,
                software_limit_bytes=args.software_limit_bytes,
            )
            _write(result, args.out)
            return 0
        if args.advertised_mdts_bytes is not None:
            _nonnegative(args.advertised_mdts_bytes, "advertised_mdts_bytes")
        if args.dmabuf and args.engine != "io_uring":
            raise IntentError("dma-buf replay requires --engine io_uring")
        if args.dmabuf and not args.odirect:
            raise IntentError("dma-buf replay requires --odirect")
        if args.dmabuf and args.dma_ceiling_bytes is None:
            raise IntentError("dma-buf replay requires --dma-ceiling-bytes")
        for path in (args.target_plan, args.target_manifest):
            if Path(path).exists():
                raise IntentError(
                    f"refusing to overwrite existing artifact: {path}"
                )
        result = lower_intent(intent, mdts_bytes=args.mdts_bytes,
                              dma_ceiling_bytes=args.dma_ceiling_bytes,
                              software_limit_bytes=args.software_limit_bytes)
        _write(result, args.target_plan)
        runner = Path(__file__).with_name("run_kv_offload_io.py")
        command = [sys.executable, str(runner), "--intent", args.intent,
                   "--device", args.device, "--engine", args.engine,
                   "--mdts-bytes", str(args.mdts_bytes),
                   "--target-plan", args.target_plan,
                   "--target-manifest", args.target_manifest,
                   "--capacity-gb", str(args.capacity_gb),
                   "--ring-depth", str(args.ring_depth),
                   "--load-parallelism", str(args.load_parallelism)]
        option_values = (
            ("--dma-ceiling-bytes", args.dma_ceiling_bytes),
            ("--software-limit-bytes", args.software_limit_bytes),
            ("--advertised-mdts-bytes", args.advertised_mdts_bytes),
            ("--dmabuf", args.dmabuf),
            ("--record", args.record),
            ("--trace", args.trace),
            ("--phase-gate-dir", args.phase_gate_dir),
            ("--phase-gate-timeout-seconds",
             args.phase_gate_timeout_seconds),
            ("--phase-rapl-out", args.phase_rapl_out),
            ("--block-align", args.block_align),
        )
        for option, value in option_values:
            if value is not None:
                command.extend((option, str(value)))
        for option, enabled in (("--hugepage", args.hugepage),
                                ("--odirect", args.odirect),
                                ("--phase-gate-close", args.phase_gate_close),
                                ("--allow-io-errors", args.allow_io_errors)):
            if enabled:
                command.append(option)
        return subprocess.run(command, env=_engine_env(), check=False).returncode
    except IntentError as error:
        parser.error(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
