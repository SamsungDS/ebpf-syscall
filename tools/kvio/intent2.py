#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""``kvio.intent.v2``: an object workload captured before target layout.

``kvio.intent.v1`` describes a workload kvio itself generates: one object
size, a canonical pass/phase/stream/chunk/rank order, timing not recorded.
Its validator keeps that closed, and it stays closed.  This module holds
the normalized form a *captured* workload needs and that v1 lacks:

* objects with an opaque stable identity, a version that changes on
  overwrite, and a representation (codec, encoded size, components) that
  may differ from object to object;
* operations with their own identity (a repeated load of one object is two
  operations), a store/load/release verb, an optional object-relative
  range, the stream and batch they belonged to, explicit dependencies, and
  the outcome the source observed;
* the initial live set, so a load of something never stored in the record
  is a miss and not an error;
* provenance that says how the operations were obtained (generated,
  observed at the engine's object boundary, or a request record), how the
  object mapping was established (declared, verified, heuristic), whether
  the capture was complete, and which timing model applies;
* a timing sidecar that is part of the hashed bundle whenever the timing
  model is ``captured``, so a file cannot advertise paced replay just
  because its object list parses.

Nothing here carries a source device, slot offset, command ceiling or
already-split command: those belong to one realization of the workload,
recorded separately.  A validated v1 file is normalized into this form by
:func:`normalize_v1` through an explicit adapter that carries its phase
and stream semantics forward as dependencies, marks its timing absent and
its workload generated; it is not called a subset of v2 and its digest
stays a v1 digest.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

SCHEMA = "kvio.intent.v2"
KIND = "object-workload"

CAPTURE_LEVELS = ("generated", "A1", "request")
MAPPING_METHODS = ("declared", "verified", "heuristic")
COMPLETENESS = ("complete", "partial")
TIMING_MODELS = ("absent", "captured", "synthetic")
OPS = ("store", "load", "release")
OUTCOMES = ("success", "miss", "already_present", "rejected", "short",
            "cancelled", "error")
TIERS = ("storage", "ram", "unknown")


class Intent2Error(ValueError):
    """Raised when a record is not a valid v2 contract for its own claims."""


def _int(value, where, *, minimum=0):
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise Intent2Error(f"{where} must be an integer >= {minimum}")
    return value


def _str(value, where):
    if not isinstance(value, str) or not value:
        raise Intent2Error(f"{where} must be a non-empty string")
    return value


def _enum(value, allowed, where):
    if value not in allowed:
        raise Intent2Error(f"{where} must be one of {allowed}, not {value!r}")
    return value


def canonical_json(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256_of(value) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


# --------------------------------------------------------------- building
def new_intent(*, capture_level, mapping_method, timing_model, engine,
               completeness="complete", notes=None, source=None):
    return {
        "schema": SCHEMA,
        "kind": KIND,
        "provenance": {
            "capture_level": capture_level,
            "mapping_method": mapping_method,
            "completeness": {"status": completeness, "notes": list(notes or [])},
            "timing_model": timing_model,
            "source": dict(source or {}),
        },
        "engine": {"name": engine.get("name", "unknown"),
                   "revision": engine.get("revision", "unknown"),
                   "layout": dict(engine.get("layout", {}))},
        "representations": {},
        "objects": {},
        "initial_state": {"live": []},
        "operations": [],
        "health": {},
        "timing": {"sidecar": None, "sidecar_sha256": None},
    }


def add_representation(intent, rep_id, *, codec, encoded_bytes, logical_bytes=None,
                       components=None):
    intent["representations"][rep_id] = {
        "codec": codec, "encoded_bytes": encoded_bytes, "logical_bytes": logical_bytes,
        "components": list(components or [{"role": "payload", "offset": 0,
                                           "length": encoded_bytes}]),
    }
    return rep_id


def add_object_version(intent, object_id, version, *, representation):
    rep = intent["representations"][representation]
    entry = intent["objects"].setdefault(object_id, {"versions": {}})
    entry["versions"][str(version)] = {"representation": representation,
                                       "bytes": rep["encoded_bytes"]}


def add_operation(intent, *, op_id, op, object_id, version, stream, deps=(),
                  range=None, batch_id=None, release_ns=None, declared_delay_ns=None,
                  source_outcome=None, requested_bytes=None):
    if requested_bytes is None:
        if range is not None:
            requested_bytes = range["length"]
        elif op == "release":
            requested_bytes = 0
        else:
            requested_bytes = intent["objects"][object_id]["versions"][str(version)]["bytes"]
    operation = {
        "op_id": op_id, "seq": len(intent["operations"]), "op": op,
        "object_id": object_id, "version": version, "range": range,
        "stream": stream, "batch_id": batch_id, "deps": list(deps),
        "release_ns": release_ns, "declared_delay_ns": declared_delay_ns,
        "requested_bytes": requested_bytes, "source_outcome": source_outcome,
    }
    intent["operations"].append(operation)
    return operation


# ------------------------------------------------------------- validating
def validate_intent2(intent):
    """Reject a record that cannot support the replay its provenance claims."""
    if not isinstance(intent, dict) or intent.get("schema") != SCHEMA:
        raise Intent2Error(f"unsupported schema: {intent.get('schema') if isinstance(intent, dict) else intent!r}")
    if intent.get("kind") != KIND:
        raise Intent2Error(f"kind must be {KIND!r}")
    prov = intent.get("provenance")
    if not isinstance(prov, dict):
        raise Intent2Error("provenance must be an object")
    _enum(prov.get("capture_level"), CAPTURE_LEVELS, "provenance.capture_level")
    _enum(prov.get("mapping_method"), MAPPING_METHODS, "provenance.mapping_method")
    comp = prov.get("completeness")
    if not isinstance(comp, dict):
        raise Intent2Error("provenance.completeness must be an object")
    _enum(comp.get("status"), COMPLETENESS, "provenance.completeness.status")
    timing_model = _enum(prov.get("timing_model"), TIMING_MODELS, "provenance.timing_model")
    if prov["capture_level"] == "A1" and prov["mapping_method"] == "heuristic":
        raise Intent2Error("an engine-boundary capture cannot have a heuristic object mapping")
    if prov["capture_level"] == "generated" and timing_model == "captured":
        raise Intent2Error("a generated workload has no captured timing")

    engine = intent.get("engine")
    if not isinstance(engine, dict):
        raise Intent2Error("engine must be an object")
    _str(engine.get("name"), "engine.name")
    _str(engine.get("revision"), "engine.revision")
    if not isinstance(engine.get("layout"), dict):
        raise Intent2Error("engine.layout must be an object")

    reps = intent.get("representations")
    if not isinstance(reps, dict) or not reps:
        raise Intent2Error("representations must be a non-empty object")
    for rep_id, rep in reps.items():
        where = f"representations[{rep_id}]"
        _str(rep_id, "representation id")
        _str(rep.get("codec"), f"{where}.codec")
        size = _int(rep.get("encoded_bytes"), f"{where}.encoded_bytes", minimum=1)
        if rep.get("logical_bytes") is not None:
            _int(rep["logical_bytes"], f"{where}.logical_bytes", minimum=0)
        comps = rep.get("components")
        if not isinstance(comps, list) or not comps:
            raise Intent2Error(f"{where}.components must be a non-empty list")
        covered = 0
        for c in comps:
            _str(c.get("role"), f"{where}.components.role")
            off = _int(c.get("offset"), f"{where}.components.offset")
            ln = _int(c.get("length"), f"{where}.components.length", minimum=1)
            if off != covered:
                raise Intent2Error(f"{where}.components must tile the object without gaps")
            covered += ln
        if covered != size:
            raise Intent2Error(f"{where}.components cover {covered} bytes, not {size}")

    objects = intent.get("objects")
    if not isinstance(objects, dict):
        raise Intent2Error("objects must be an object")
    for object_id, obj in objects.items():
        _str(object_id, "object id")
        versions = obj.get("versions") if isinstance(obj, dict) else None
        if not isinstance(versions, dict) or not versions:
            raise Intent2Error(f"objects[{object_id}].versions must be non-empty")
        for v, ver in versions.items():
            if not v.isdigit():
                raise Intent2Error(f"objects[{object_id}] version {v!r} must be an integer")
            rep = ver.get("representation") if isinstance(ver, dict) else None
            if rep not in reps:
                raise Intent2Error(f"objects[{object_id}].versions[{v}] names an unknown representation")
            if ver.get("bytes") != reps[rep]["encoded_bytes"]:
                raise Intent2Error(f"objects[{object_id}].versions[{v}].bytes disagrees with its representation")

    live = intent.get("initial_state", {}).get("live")
    if not isinstance(live, list):
        raise Intent2Error("initial_state.live must be a list")
    live_set = set()
    for item in live:
        oid = item.get("object_id")
        ver = item.get("version")
        if oid not in objects or str(ver) not in objects[oid]["versions"]:
            raise Intent2Error(f"initial_state names unknown object {oid!r} version {ver!r}")
        _enum(item.get("tier", "storage"), TIERS, "initial_state.tier")
        live_set.add((oid, str(ver)))

    ops = intent.get("operations")
    if not isinstance(ops, list):
        raise Intent2Error("operations must be a list")
    seen_ids = {}
    stored = set(live_set)          # (object_id, version) visible so far, in seq order
    released = set()
    for seq, op in enumerate(ops):
        where = f"operations[{seq}]"
        if not isinstance(op, dict) or op.get("seq") != seq:
            raise Intent2Error(f"{where}.seq must equal its position")
        op_id = _str(op.get("op_id"), f"{where}.op_id")
        if op_id in seen_ids:
            raise Intent2Error(f"{where}.op_id {op_id!r} is not unique")
        seen_ids[op_id] = seq
        verb = _enum(op.get("op"), OPS, f"{where}.op")
        oid = op.get("object_id")
        ver = op.get("version")
        if oid not in objects or str(ver) not in objects[oid]["versions"]:
            raise Intent2Error(f"{where} names unknown object {oid!r} version {ver!r}")
        size = objects[oid]["versions"][str(ver)]["bytes"]
        rng = op.get("range")
        if rng is not None:
            off = _int(rng.get("offset"), f"{where}.range.offset")
            ln = _int(rng.get("length"), f"{where}.range.length", minimum=1)
            if off + ln > size:
                raise Intent2Error(f"{where}.range exceeds the object")
            if verb != "load":
                raise Intent2Error(f"{where}: only loads take a range")
        _int(op.get("requested_bytes"), f"{where}.requested_bytes")
        if op.get("stream") is None:
            raise Intent2Error(f"{where}.stream is required")
        deps = op.get("deps")
        if not isinstance(deps, list):
            raise Intent2Error(f"{where}.deps must be a list")
        for d in deps:
            if d not in seen_ids or seen_ids[d] >= seq:
                raise Intent2Error(f"{where} depends on {d!r}, which is not an earlier operation")
        if op.get("source_outcome") is not None:
            _enum(op["source_outcome"], OUTCOMES, f"{where}.source_outcome")
        if op.get("release_ns") is not None:
            _int(op["release_ns"], f"{where}.release_ns")
            if timing_model == "absent":
                raise Intent2Error(f"{where} carries release_ns but the timing model is absent")
        elif timing_model == "captured":
            raise Intent2Error(f"{where} lacks release_ns under a captured timing model")
        if op.get("declared_delay_ns") is not None:
            _int(op["declared_delay_ns"], f"{where}.declared_delay_ns")
        key = (oid, str(ver))
        if verb == "store":
            stored.add(key)
            released.discard(key)
        elif verb == "load":
            if key not in stored and op.get("source_outcome") not in ("miss", "cancelled", "error", "rejected"):
                raise Intent2Error(f"{where} loads {oid!r} v{ver} before any store or initial state; "
                                   "declare source_outcome=miss if that is what happened")
        elif verb == "release":
            released.add(key)
            stored.discard(key)

    timing = intent.get("timing")
    if not isinstance(timing, dict):
        raise Intent2Error("timing must be an object")
    if timing_model == "captured":
        if not timing.get("sidecar") or not timing.get("sidecar_sha256"):
            raise Intent2Error("a captured timing model requires a timing sidecar bound by digest")
    if not isinstance(intent.get("health"), dict):
        raise Intent2Error("health must be an object")
    return intent


def intent2_sha256(intent):
    validate_intent2(intent)
    return sha256_of(intent)


def bundle_sha256(intent, sidecar_bytes=None, target=None):
    """Digest of the whole bundle: intent, its timing sidecar, the target."""
    validate_intent2(intent)
    h = hashlib.sha256()
    h.update(canonical_json(intent))
    if intent["provenance"]["timing_model"] == "captured":
        if sidecar_bytes is None:
            raise Intent2Error("bundle digest needs the timing sidecar bytes")
        if hashlib.sha256(sidecar_bytes).hexdigest() != intent["timing"]["sidecar_sha256"]:
            raise Intent2Error("timing sidecar does not match the digest the intent binds")
        h.update(sidecar_bytes)
    if target is not None:
        h.update(canonical_json(target))
    return h.hexdigest()


# ----------------------------------------------------------- v1 adapter
def normalize_v1(intent_v1):
    """Carry a validated v1 record into the v2 form, semantics intact.

    v1's partial order is: within one stream of one phase, operations run
    in sequence; every load of a pass waits for every store of that pass;
    every store of the next pass waits for every load of this one.  Those
    become explicit dependencies.  Timing is absent and the workload is
    generated; nothing is upgraded to observed evidence.
    """
    from intent import intent_sha256, validate_intent  # v1 stays its own module
    validate_intent(intent_v1)
    v2 = new_intent(capture_level="generated", mapping_method="declared",
                    timing_model="absent",
                    engine={"name": "lmcache-raw_block", "revision": "vendored",
                            "layout": {"store_metadata_bytes": intent_v1["object"]["store_metadata_bytes"],
                                       "ranks_per_chunk": intent_v1["object"]["ranks_per_chunk"]}},
                    source={"schema": "kvio.intent.v1", "sha256": intent_sha256(intent_v1),
                            "model": intent_v1["model"], "execution": intent_v1["execution"]})
    payload = intent_v1["object"]["payload_bytes"]
    rep = add_representation(v2, "v1-payload", codec="opaque", encoded_bytes=payload)
    streams = intent_v1["execution"]["streams"]
    prev_in_stream = {}
    stores_of_pass = {}
    loads_of_pass = {}
    for op1 in intent_v1["operations"]:
        oid = op1["logical_object"]
        if oid not in v2["objects"]:
            add_object_version(v2, oid, 1, representation=rep)
        p, phase, s = op1["pass"], op1["phase"], op1["stream"]
        deps = []
        key = (p, phase, s)
        if key in prev_in_stream:
            deps.append(prev_in_stream[key])
        if phase == "load":
            deps.extend(stores_of_pass.get(p, []))
        elif p > 0:
            deps.extend(loads_of_pass.get(p - 1, []))
        op_id = f"v1/{op1['sequence']}"
        add_operation(v2, op_id=op_id, op=phase, object_id=oid, version=1,
                      stream=f"s{s}", batch_id=f"pass{p}/{phase}/s{s}",
                      deps=sorted(set(deps), key=lambda d: int(d.split("/")[1])))
        prev_in_stream[key] = op_id
        (stores_of_pass if phase == "store" else loads_of_pass).setdefault(p, []).append(op_id)
    v2["health"] = {"source": "generated", "emitted": len(v2["operations"]), "dropped": 0}
    v2["provenance"]["completeness"]["notes"].append(
        f"{streams} streams; phase barriers and per-stream order carried as dependencies")
    validate_intent2(v2)
    return v2


# ------------------------------------------------------------------ cli
def load_intent2(path):
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise Intent2Error(f"cannot read {path}: {error}") from error
    validate_intent2(value)
    return value


def _write(value, path):
    output = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if path == "-":
        print(output, end="")
    else:
        Path(path).write_text(output, encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    v = sub.add_parser("validate", help="validate a kvio.intent.v2 file")
    v.add_argument("intent")
    v.add_argument("--sidecar", help="timing sidecar to bind into the bundle digest")
    n = sub.add_parser("normalize-v1", help="carry a v1 intent into v2 form")
    n.add_argument("intent_v1")
    n.add_argument("--out", default="-")
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            intent = load_intent2(args.intent)
            sidecar = Path(args.sidecar).read_bytes() if args.sidecar else None
            print(json.dumps({"schema": SCHEMA, "operations": len(intent["operations"]),
                              "objects": len(intent["objects"]),
                              "provenance": intent["provenance"],
                              "intent_sha256": intent2_sha256(intent),
                              "bundle_sha256": bundle_sha256(intent, sidecar)
                              if (sidecar is not None or intent["provenance"]["timing_model"] != "captured") else None},
                             indent=2))
        elif args.command == "normalize-v1":
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            v1 = json.loads(Path(args.intent_v1).read_text(encoding="utf-8"))
            _write(normalize_v1(v1), args.out)
    except Intent2Error as error:
        print(f"kvio intent2: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.exit(main())
