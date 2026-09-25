#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""``kvio.workload.v3``: one envelope, typed operations per API family.

``kvio.intent.v2`` describes an object workload: store, load and release
of an opaque object.  A file system has open handles, directory entries,
renames and directory listings; an object store has keys, ranged reads,
paginated listings and multipart uploads.  Flattening those into
store/load/release would erase what a replay must preserve, so this
envelope keeps them as typed operations under one scheduling contract.

What the envelope fixes, and the executor relies on:

* **api_family** per operation (``object``, ``posix``, ``s3``) with a typed
  ``call`` whose fields are validated per family; a target that cannot
  realize a required call fails preflight before any mutation;
* **identities**: an opaque node id plus incarnation for a file or key
  (a rename keeps the node, a recreation under the same name is a new
  incarnation), synthetic names for directory entries, opaque handle ids
  that replay rebinds to real descriptors; source names never appear;
* **dependencies with provenance**: each edge says whether it is program
  order, a synchronization the application performed, or overlap that was
  merely observed.  No edge is invented from shared identity; two
  operations on one node with no edge may run concurrently, and the
  expected outcome set says which results the race may produce;
* **release-time provenance**: whether recorded release times are the
  application's observed API submissions, independently measured
  arrivals, or declared delays, because those answer different questions;
* **initial state**: the namespace graph (nodes, entries, handles) or the
  live object set that must exist before the first operation;
* **content profile**: a named profile the generator realizes; payload
  never travels in the record.

A validated v2 record is carried into this form by :func:`from_intent2`,
which keeps its operations in the ``object`` family, keeps its
dependencies (labelled ``program`` for stream order and ``identity`` for
the v2 same-object rule, which this format does not apply to new
workloads) and marks the source schema.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

SCHEMA = "kvio.workload.v3"
FAMILIES = ("object", "posix", "s3")
CAPTURE_LEVELS = ("generated", "A1", "api", "request")
MAPPING_METHODS = ("declared", "verified", "heuristic")
COMPLETENESS = ("complete", "partial")
TIMING_MODELS = ("absent", "captured", "synthetic")
RELEASE_PROVENANCE = ("none", "observed_submission", "measured_arrival", "declared")
DEP_KINDS = ("program", "sync", "observed", "identity")
OUTCOMES = ("success", "miss", "already_present", "rejected", "short", "cancelled",
            "error", "eof", "exists", "not_empty", "denied", "timeout", "unknown")

# Calls per family and the fields each must carry.  ``handle`` fields name
# an opaque handle id; ``node`` fields an opaque node id; ``path`` a
# synthetic path under the generated root.
CALLS = {
    "object": {
        "store": ("node", "size"), "load": ("node",), "release": ("node",),
        "exists": ("node",),
    },
    "posix": {
        "open": ("path", "flags", "handle"), "close": ("handle",),
        "pread": ("handle", "offset", "length"), "pwrite": ("handle", "offset", "length"),
        "read": ("handle", "length"), "write": ("handle", "length"),
        "fstat": ("handle",), "stat": ("path",), "readdir": ("path",),
        "rename": ("path", "new_path"), "unlink": ("path",),
        "mkdir": ("path",), "rmdir": ("path",), "truncate": ("path", "size"),
        "ftruncate": ("handle", "size"), "fsync": ("handle",), "fdatasync": ("handle",),
    },
    "s3": {
        "put": ("key", "size"), "get": ("key",), "head": ("key",),
        "list": ("prefix",), "delete": ("key",),
        "mpu_create": ("key", "upload"), "mpu_part": ("key", "upload", "part", "size"),
        "mpu_complete": ("key", "upload"), "mpu_abort": ("key", "upload"),
    },
}
OPEN_FLAGS = ("rd", "wr", "rdwr", "creat", "excl", "trunc", "append", "direct", "sync")


class Workload3Error(ValueError):
    pass


def canonical_json(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256_of(value) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _int(v, where, minimum=0):
    if not isinstance(v, int) or isinstance(v, bool) or v < minimum:
        raise Workload3Error(f"{where} must be an integer >= {minimum}")
    return v


def _str(v, where):
    if not isinstance(v, str) or not v:
        raise Workload3Error(f"{where} must be a non-empty string")
    return v


def _enum(v, allowed, where):
    if v not in allowed:
        raise Workload3Error(f"{where} must be one of {allowed}, not {v!r}")
    return v


# --------------------------------------------------------------- building
def new_workload(*, capture_level, mapping_method, timing_model, release_provenance,
                 engine, completeness="complete", notes=None, source=None,
                 content_profile="incompressible"):
    return {
        "schema": SCHEMA,
        "provenance": {
            "capture_level": capture_level, "mapping_method": mapping_method,
            "completeness": {"status": completeness, "notes": list(notes or [])},
            "timing_model": timing_model, "release_provenance": release_provenance,
            "source": dict(source or {}),
        },
        "engine": {"family": engine.get("family", "unknown"), "name": engine.get("name", "unknown"),
                   "revision": engine.get("revision", "unknown"), "config": dict(engine.get("config", {}))},
        "content_profile": content_profile,
        "namespace": {"nodes": {}, "entries": [], "handles": {}},
        "objects": {},
        "operations": [],
        "health": {},
        "timing": {"sidecar": None, "sidecar_sha256": None},
    }


def add_node(wl, node_id, *, kind, incarnation=1, size=0, tier="storage"):
    wl["namespace"]["nodes"][node_id] = {"kind": kind, "incarnation": incarnation,
                                         "size": size, "tier": tier}


def add_entry(wl, path, node_id):
    wl["namespace"]["entries"].append({"path": path, "node": node_id})


def add_op(wl, *, op_id, family, call, stream, deps=(), release_ns=None, declared_delay_ns=None,
           expected=None, attempt=1, batch_id=None, **fields):
    if family not in CALLS or call not in CALLS[family]:
        raise Workload3Error(f"unknown call {family}.{call}")
    op = {"op_id": op_id, "seq": len(wl["operations"]), "family": family, "call": call,
          "args": dict(fields), "stream": stream, "batch_id": batch_id, "attempt": attempt,
          "deps": [d if isinstance(d, dict) else {"op": d, "kind": "program"} for d in deps],
          "release_ns": release_ns, "declared_delay_ns": declared_delay_ns,
          "expected": dict(expected or {})}
    wl["operations"].append(op)
    return op


# ------------------------------------------------------------- validating
def required_capabilities(wl):
    return sorted({f"{o['family']}.{o['call']}" for o in wl["operations"]})


def validate_workload(wl):
    if not isinstance(wl, dict) or wl.get("schema") != SCHEMA:
        raise Workload3Error(f"unsupported schema {wl.get('schema') if isinstance(wl, dict) else wl!r}")
    prov = wl.get("provenance")
    if not isinstance(prov, dict):
        raise Workload3Error("provenance must be an object")
    _enum(prov.get("capture_level"), CAPTURE_LEVELS, "provenance.capture_level")
    _enum(prov.get("mapping_method"), MAPPING_METHODS, "provenance.mapping_method")
    comp = prov.get("completeness")
    if not isinstance(comp, dict):
        raise Workload3Error("provenance.completeness must be an object")
    _enum(comp.get("status"), COMPLETENESS, "provenance.completeness.status")
    timing = _enum(prov.get("timing_model"), TIMING_MODELS, "provenance.timing_model")
    relp = _enum(prov.get("release_provenance"), RELEASE_PROVENANCE, "provenance.release_provenance")
    if timing == "captured" and relp == "none":
        raise Workload3Error("captured timing must say what its release times are")
    if timing == "absent" and relp != "none":
        raise Workload3Error("absent timing cannot claim release provenance")
    if prov["capture_level"] in ("A1", "api") and prov["mapping_method"] == "heuristic":
        raise Workload3Error("an API-boundary capture cannot have a heuristic mapping")
    eng = wl.get("engine")
    if not isinstance(eng, dict):
        raise Workload3Error("engine must be an object")
    for f in ("family", "name", "revision"):
        _str(eng.get(f), f"engine.{f}")
    _str(wl.get("content_profile"), "content_profile")

    ns = wl.get("namespace")
    if not isinstance(ns, dict) or not isinstance(ns.get("nodes"), dict) \
            or not isinstance(ns.get("entries"), list) or not isinstance(ns.get("handles"), dict):
        raise Workload3Error("namespace must have nodes, entries and handles")
    for nid, node in ns["nodes"].items():
        _str(nid, "node id")
        _enum(node.get("kind"), ("file", "dir", "object"), f"nodes[{nid}].kind")
        _int(node.get("incarnation", 1), f"nodes[{nid}].incarnation", 1)
        _int(node.get("size", 0), f"nodes[{nid}].size")
    paths = set()
    for e in ns["entries"]:
        p = _str(e.get("path"), "entry.path")
        if p.startswith("/") or ".." in p.split("/"):
            raise Workload3Error(f"entry path {p!r} must be relative and traversal-free")
        if e.get("node") not in ns["nodes"]:
            raise Workload3Error(f"entry {p!r} names unknown node")
        if p in paths:
            raise Workload3Error(f"entry {p!r} listed twice")
        paths.add(p)
    for hid, h in ns["handles"].items():
        if h.get("node") not in ns["nodes"]:
            raise Workload3Error(f"handle {hid!r} names unknown node")

    ops = wl.get("operations")
    if not isinstance(ops, list):
        raise Workload3Error("operations must be a list")
    seen = {}
    open_handles = set(ns["handles"])
    for seq, op in enumerate(ops):
        where = f"operations[{seq}]"
        if not isinstance(op, dict) or op.get("seq") != seq:
            raise Workload3Error(f"{where}.seq must equal its position")
        oid = _str(op.get("op_id"), f"{where}.op_id")
        if oid in seen:
            raise Workload3Error(f"{where}.op_id {oid!r} not unique")
        seen[oid] = seq
        fam = _enum(op.get("family"), FAMILIES, f"{where}.family")
        call = _enum(op.get("call"), tuple(CALLS[fam]), f"{where}.call")
        args = op.get("args")
        if not isinstance(args, dict):
            raise Workload3Error(f"{where}.args must be an object")
        for f in CALLS[fam][call]:
            if f not in args:
                raise Workload3Error(f"{where} ({fam}.{call}) lacks {f}")
        for f in ("size", "offset", "length", "part"):
            if f in args:
                _int(args[f], f"{where}.args.{f}")
        if "path" in args and (args["path"].startswith("/") or ".." in args["path"].split("/")):
            raise Workload3Error(f"{where}.args.path must be relative and traversal-free")
        if "new_path" in args and (args["new_path"].startswith("/") or ".." in args["new_path"].split("/")):
            raise Workload3Error(f"{where}.args.new_path must be relative and traversal-free")
        if "flags" in args:
            for fl in args["flags"]:
                _enum(fl, OPEN_FLAGS, f"{where}.args.flags")
        if "node" in args and args["node"] not in ns["nodes"] and args["node"] not in wl.get("objects", {}):
            raise Workload3Error(f"{where} names unknown node {args['node']!r}")
        if fam == "posix":
            if call == "open":
                if args["handle"] in open_handles:
                    raise Workload3Error(f"{where} reopens live handle {args['handle']!r}")
                open_handles.add(args["handle"])
            elif "handle" in args:
                if args["handle"] not in open_handles:
                    raise Workload3Error(f"{where} uses handle {args['handle']!r} that is not open")
                if call == "close":
                    open_handles.discard(args["handle"])
        if op.get("stream") is None:
            raise Workload3Error(f"{where}.stream required")
        _int(op.get("attempt", 1), f"{where}.attempt", 1)
        deps = op.get("deps")
        if not isinstance(deps, list):
            raise Workload3Error(f"{where}.deps must be a list")
        for d in deps:
            if not isinstance(d, dict) or d.get("op") not in seen or seen[d["op"]] >= seq:
                raise Workload3Error(f"{where} depends on something that is not an earlier operation")
            _enum(d.get("kind"), DEP_KINDS, f"{where}.deps.kind")
        if op.get("release_ns") is not None:
            _int(op["release_ns"], f"{where}.release_ns")
            if timing == "absent":
                raise Workload3Error(f"{where} carries release_ns under absent timing")
        elif timing == "captured":
            raise Workload3Error(f"{where} lacks release_ns under captured timing")
        exp = op.get("expected", {})
        if not isinstance(exp, dict):
            raise Workload3Error(f"{where}.expected must be an object")
        if "outcome" in exp:
            _enum(exp["outcome"], OUTCOMES, f"{where}.expected.outcome")
        if "outcomes" in exp:
            for x in exp["outcomes"]:
                _enum(x, OUTCOMES, f"{where}.expected.outcomes")
    if timing == "captured":
        t = wl.get("timing", {})
        if not t.get("sidecar") or not t.get("sidecar_sha256"):
            raise Workload3Error("captured timing requires a bound timing sidecar")
    if not isinstance(wl.get("health"), dict):
        raise Workload3Error("health must be an object")
    return wl


def workload_sha256(wl):
    validate_workload(wl)
    return sha256_of(wl)


def bundle_sha256(wl, sidecar_bytes=None, target=None):
    validate_workload(wl)
    h = hashlib.sha256(canonical_json(wl))
    if wl["provenance"]["timing_model"] == "captured":
        if sidecar_bytes is None:
            raise Workload3Error("bundle digest needs the timing sidecar bytes")
        if hashlib.sha256(sidecar_bytes).hexdigest() != wl["timing"]["sidecar_sha256"]:
            raise Workload3Error("timing sidecar does not match the digest the workload binds")
        h.update(sidecar_bytes)
    if target is not None:
        h.update(canonical_json(target))
    return h.hexdigest()


# ---------------------------------------------------------- v2 adapter
def from_intent2(intent):
    """Carry a validated ``kvio.intent.v2`` record into the v3 envelope.

    Object operations stay object operations.  v2's dependencies come
    through labelled ``program``; the normalizer's same-object ordering,
    where the v2 record says it applied it, is labelled ``identity`` so a
    reader knows those edges were a rule of the old format, not observed
    synchronization.  Nothing is upgraded.
    """
    import intent2
    intent2.validate_intent2(intent)
    p = intent["provenance"]
    identity_rule = any("ordered by identity" in n for n in p["completeness"]["notes"])
    wl = new_workload(capture_level=p["capture_level"], mapping_method=p["mapping_method"],
                      timing_model=p["timing_model"],
                      release_provenance="observed_submission" if p["timing_model"] == "captured" else "none",
                      engine={"family": "object", "name": intent["engine"]["name"],
                              "revision": intent["engine"]["revision"], "config": intent["engine"].get("layout", {})},
                      completeness=p["completeness"]["status"], notes=p["completeness"]["notes"],
                      source={"schema": intent["schema"], "sha256": intent2.intent2_sha256(intent)})
    for oid, obj in intent["objects"].items():
        for ver, v in obj["versions"].items():
            add_node(wl, f"{oid}@{ver}", kind="object", incarnation=int(ver), size=v["bytes"])
    for item in intent["initial_state"]["live"]:
        add_entry(wl, f"live/{item['object_id']}@{item['version']}", f"{item['object_id']}@{item['version']}")
    by_id = {o["op_id"]: o for o in intent["operations"]}
    for o in intent["operations"]:
        node = f"{o['object_id']}@{o['version']}"
        deps = []
        for d in o["deps"]:
            same = by_id[d]["object_id"] == o["object_id"]
            kind = "identity" if (identity_rule and same and by_id[d]["stream"] != o["stream"]) else "program"
            deps.append({"op": d, "kind": kind})
        fields = {"node": node}
        if o["op"] == "store":
            fields["size"] = o["requested_bytes"]
        elif o["op"] == "load" and o.get("range"):
            fields["offset"], fields["length"] = o["range"]["offset"], o["range"]["length"]
        exp = {"outcome": o["source_outcome"]} if o.get("source_outcome") else {}
        add_op(wl, op_id=o["op_id"], family="object", call=o["op"], stream=o["stream"], deps=deps,
               release_ns=o.get("release_ns"), declared_delay_ns=o.get("declared_delay_ns"),
               expected=exp, batch_id=o.get("batch_id"), **fields)
    wl["health"] = dict(intent["health"])
    wl["timing"] = dict(intent["timing"])
    validate_workload(wl)
    return wl


def load_workload(path):
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise Workload3Error(f"cannot read {path}: {error}") from error
    if value.get("schema") == "kvio.intent.v2":
        return from_intent2(value)
    validate_workload(value)
    return value


def main(argv=None):
    import argparse, sys
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate"); v.add_argument("workload"); v.add_argument("--sidecar")
    c = sub.add_parser("from-v2"); c.add_argument("intent"); c.add_argument("--out", default="-")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "validate":
            wl = load_workload(args.workload)
            side = Path(args.sidecar).read_bytes() if args.sidecar else None
            print(json.dumps({"schema": SCHEMA, "operations": len(wl["operations"]),
                              "required_capabilities": required_capabilities(wl),
                              "provenance": wl["provenance"], "workload_sha256": workload_sha256(wl),
                              "bundle_sha256": bundle_sha256(wl, side)
                              if (side is not None or wl["provenance"]["timing_model"] != "captured") else None},
                             indent=2))
        else:
            import intent2
            wl = from_intent2(json.loads(Path(args.intent).read_text()))
            out = json.dumps(wl, indent=2, sort_keys=True) + "\n"
            print(out, end="") if args.out == "-" else Path(args.out).write_text(out)
    except Workload3Error as error:
        print(f"kvio workload3: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.exit(main())
