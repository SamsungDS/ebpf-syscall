#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""``kvio.capture-events.v1``: object operations as an engine performs them.

A storage engine decides which objects to store, load and release before
it lays them out, pads them or splits them into commands.  This is the
event contract an engine adapter emits at that boundary, the recorder that
buffers it without blocking the engine, and the normalizer that turns a
finished capture into a ``kvio.intent.v2`` record.

The contract is transport-independent.  The recorder here keeps records
in a bounded queue drained by a background thread to JSON lines; when the
queue is full the record is dropped and counted, never blocked on.  A
capture without a start marker, or whose end marker never came, or with
operations left open, or with drops, normalizes with
``completeness.status = partial`` and says why.  Payload bytes never pass
through here; an adapter hands over lengths and identities only.

Events (one JSON object per line, ``ev`` names the kind):

  ``start``        clock domain, engine, adapter, run id, producer
  ``object_state`` the live objects when capture began
  ``op_begin``     op_id, producer_seq, op, object_id, version, representation,
                   stream, batch_id, range, requested_bytes, deps, ts_ns;
                   a batch carries ``items`` with per-item identities
  ``op_end``       op_id, ts_ns, outcome, completed_bytes; per-item outcomes
  ``marker``       free-form, timestamped
  ``end``          health counters as the recorder saw them
"""
from __future__ import annotations

import hashlib
import json
import os
import queue
import threading
import time
from pathlib import Path

import intent2

SCHEMA = "kvio.capture-events.v1"
OUTCOMES = intent2.OUTCOMES


class CaptureError(ValueError):
    pass


class Recorder:
    """Opt-in, bounded, asynchronous event sink for an engine adapter."""

    def __init__(self, path, *, engine, adapter, run_id=None, producer="engine",
                 capacity=1 << 16, clock=time.monotonic_ns, enabled=True):
        self.path = Path(path)
        self.enabled = enabled
        self.engine = dict(engine)
        self.adapter = dict(adapter)
        self.run_id = run_id or hashlib.sha256(f"{os.getpid()}:{clock()}".encode()).hexdigest()[:16]
        self.producer = producer
        self.clock = clock
        self._q: queue.Queue = queue.Queue(maxsize=capacity)
        self._seq = 0
        self._lock = threading.Lock()
        self.emitted = 0
        self.dropped = 0
        self.errors = 0
        self._open: set = set()
        self._closed = False
        if not enabled:
            return
        self._fh = self.path.open("w", encoding="utf-8")
        self._writer = threading.Thread(target=self._drain, name="kvio-capture", daemon=True)
        self._writer.start()
        self._put({"ev": "start", "schema": SCHEMA, "run_id": self.run_id,
                   "clock": {"domain": "CLOCK_MONOTONIC", "unit": "ns"},
                   "engine": self.engine, "adapter": self.adapter,
                   "producer": self.producer, "ts_ns": self.clock()})

    # ------------------------------------------------------------ plumbing
    def _next_seq(self):
        with self._lock:
            self._seq += 1
            return self._seq

    def _put(self, record):
        if not self.enabled or self._closed:
            return
        if "producer_seq" not in record:      # not setdefault: its default would burn a number
            record["producer_seq"] = self._next_seq()
        try:
            self._q.put_nowait(record)
            self.emitted += 1
        except queue.Full:
            self.dropped += 1

    def _drain(self):
        # Flush every record: a serving process is usually stopped with a
        # signal, and a capture that stops at the last flushed line is worth
        # more than one that lost its tail in a buffer.
        while True:
            record = self._q.get()
            if record is None:
                break
            try:
                self._fh.write(json.dumps(record, sort_keys=True) + "\n")
                self._fh.flush()
            except (OSError, TypeError, ValueError):
                self.errors += 1

    # -------------------------------------------------------------- events
    def object_state(self, live):
        """``live``: iterable of (object_id, version, representation, bytes, tier)."""
        self._put({"ev": "object_state", "ts_ns": self.clock(),
                   "live": [{"object_id": o, "version": v, "representation": r,
                             "bytes": b, "tier": t} for o, v, r, b, t in live]})

    def begin(self, *, op, object_id=None, version=None, representation=None,
              stream, batch_id=None, range=None, requested_bytes=None, deps=(),
              items=None, op_id=None):
        """Record the start of one operation or one batch; returns its op_id."""
        if not self.enabled:
            return op_id or f"disabled-{self._next_seq()}"
        seq = self._next_seq()
        op_id = op_id or f"{self.producer}-{seq}"
        rec = {"ev": "op_begin", "op_id": op_id, "ts_ns": self.clock(), "op": op,
               "stream": stream, "batch_id": batch_id, "deps": list(deps),
               "producer_seq": seq}
        if items is not None:
            rec["items"] = [dict(it) for it in items]
        else:
            rec.update({"object_id": object_id, "version": version,
                        "representation": representation, "range": range,
                        "requested_bytes": requested_bytes})
        with self._lock:
            self._open.add(op_id)
        self._put(rec)
        return op_id

    def end(self, op_id, *, outcome=None, completed_bytes=None, items=None):
        if not self.enabled:
            return
        rec = {"ev": "op_end", "op_id": op_id, "ts_ns": self.clock()}
        if items is not None:
            rec["items"] = [dict(it) for it in items]
        else:
            rec.update({"outcome": outcome, "completed_bytes": completed_bytes})
        with self._lock:
            self._open.discard(op_id)
        self._put(rec)

    def marker(self, name, **fields):
        rec = {"ev": "marker", "name": name, "ts_ns": self.clock()}
        rec.update(fields)
        self._put(rec)

    def health(self):
        return {"emitted": self.emitted, "dropped": self.dropped, "errors": self.errors,
                "open_operations": sorted(self._open), "queue_capacity": self._q.maxsize}

    def close(self):
        if not self.enabled or self._closed:
            return self.health()
        self._put({"ev": "end", "ts_ns": self.clock(), "health": self.health()})
        self._closed = True
        self._q.put(None)
        self._writer.join()
        self._fh.close()
        return self.health()


# ----------------------------------------------------------- normalizing
def read_events(path):
    events = []
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise CaptureError(f"{path}:{n}: {error}") from error
    return events


def _rep_id(representation, size):
    if isinstance(representation, dict):
        codec = representation.get("codec", "opaque")
        size = int(representation.get("encoded_bytes", size))
        return f"{codec}:{size}", codec, size
    return f"opaque:{size}", "opaque", int(size)


def normalize_capture(events, *, sidecar_path=None):
    """Turn a finished capture into a ``kvio.intent.v2`` record plus a timing sidecar.

    Returns ``(intent, sidecar_lines)``.  The sidecar holds, per operation,
    the source's begin and end timestamps and outcome; the intent carries
    ``release_ns`` (the begin timestamp) so paced replay is possible, and
    its ``timing.sidecar_sha256`` binds the sidecar.
    """
    if not events or events[0].get("ev") != "start":
        raise CaptureError("capture must begin with a start event")
    start = events[0]
    if start.get("schema") != SCHEMA:
        raise CaptureError(f"unsupported capture schema {start.get('schema')!r}")
    notes = []
    ended = None
    begins = {}
    ends = {}
    initial = []
    seqs = []
    for ev in events[1:]:
        kind = ev.get("ev")
        if "producer_seq" in ev:
            seqs.append(ev["producer_seq"])
        if kind == "object_state":
            initial.extend(ev.get("live", []))
        elif kind == "op_begin":
            if ev["op_id"] in begins:
                raise CaptureError(f"op_id {ev['op_id']!r} begun twice")
            begins[ev["op_id"]] = ev
        elif kind == "op_end":
            if ev["op_id"] in ends:
                raise CaptureError(f"op_id {ev['op_id']!r} ended twice")
            ends[ev["op_id"]] = ev
        elif kind == "end":
            ended = ev
        elif kind == "marker":
            pass
        else:
            raise CaptureError(f"unknown event kind {kind!r}")
    seqs_sorted = sorted(seqs)
    gaps = sum(1 for a, b in zip(seqs_sorted, seqs_sorted[1:]) if b != a + 1)
    if ended is None:
        notes.append("no end marker: the recorder did not drain")
    health = dict(ended.get("health", {})) if ended else {}
    health.update({"begins": len(begins), "ends": len(ends), "sequence_gaps": gaps})
    unmatched_ends = sorted(set(ends) - set(begins))
    open_ops = sorted(set(begins) - set(ends))
    if unmatched_ends:
        notes.append(f"{len(unmatched_ends)} end events without a begin")
    if open_ops:
        notes.append(f"{len(open_ops)} operations never ended")
    if health.get("dropped"):
        notes.append(f"{health['dropped']} events dropped by the recorder")
    if gaps:
        notes.append(f"{gaps} producer sequence gaps")
    complete = not (notes or unmatched_ends or open_ops)

    intent = intent2.new_intent(capture_level="A1", mapping_method="declared",
                                timing_model="captured",
                                completeness="complete" if complete else "partial",
                                notes=notes, engine=start.get("engine", {}),
                                source={"schema": SCHEMA, "run_id": start.get("run_id"),
                                        "adapter": start.get("adapter", {}),
                                        "clock": start.get("clock", {})})
    versions = {}   # object_id -> current version
    for item in initial:
        rep_id, codec, size = _rep_id(item.get("representation"), item.get("bytes"))
        if rep_id not in intent["representations"]:
            intent2.add_representation(intent, rep_id, codec=codec, encoded_bytes=size)
        ver = int(item.get("version", 1))
        intent2.add_object_version(intent, item["object_id"], ver, representation=rep_id)
        versions[item["object_id"]] = ver
        intent["initial_state"]["live"].append({"object_id": item["object_id"], "version": ver,
                                                "tier": item.get("tier", "storage")})
    sidecar = []
    ordered = sorted(begins.values(), key=lambda e: (e["ts_ns"], e["producer_seq"]))
    # Operations on one object are ordered by identity: a version is defined
    # by its store, a load of that version follows it, a release ends it. That
    # dependency is added here, per object, and said so in the provenance.
    last_on_object = {}
    order_note = "same-object operations ordered by identity; stream order as the adapter declared it"
    # A dependency may name a batch; it means every item of that batch.
    expanded = {}
    for b in ordered:
        if "items" in b:
            expanded[b["op_id"]] = [f"{b['op_id']}/{i}" for i in range(len(b["items"]))]
        else:
            expanded[b["op_id"]] = [b["op_id"]]

    def expand_deps(deps):
        out = []
        for d in deps:
            out.extend(expanded.get(d, [d]))
        return out

    for b in ordered:
        e = ends.get(b["op_id"])
        items = b.get("items")
        if items is None:
            items = [{"object_id": b.get("object_id"), "version": b.get("version"),
                      "representation": b.get("representation"), "range": b.get("range"),
                      "requested_bytes": b.get("requested_bytes")}]
            item_ends = [e] if e else [None]
        else:
            item_ends = (e.get("items") if e else None) or [None] * len(items)
            if len(item_ends) != len(items):
                raise CaptureError(f"batch {b['op_id']!r} ended with {len(item_ends)} items, began with {len(items)}")
        for i, (it, ie) in enumerate(zip(items, item_ends)):
            oid = it["object_id"]
            verb = b["op"]
            size = it.get("requested_bytes")
            if verb == "store":
                rep_id, codec, size = _rep_id(it.get("representation"), size)
                if rep_id not in intent["representations"]:
                    intent2.add_representation(intent, rep_id, codec=codec, encoded_bytes=size)
                outcome = (ie or {}).get("outcome")
                if it.get("version") is not None:
                    ver = int(it["version"])
                elif outcome == "already_present":
                    ver = versions.get(oid, 1)
                else:
                    ver = versions.get(oid, 0) + 1
                if str(ver) not in intent["objects"].get(oid, {}).get("versions", {}):
                    intent2.add_object_version(intent, oid, ver, representation=rep_id)
                versions[oid] = ver
            else:
                ver = int(it["version"]) if it.get("version") is not None else versions.get(oid, 1)
                if oid not in intent["objects"]:
                    # A load or release of something never stored here: the
                    # object must still be describable; it is a miss unless the
                    # source says otherwise.
                    rep_id, codec, size = _rep_id(it.get("representation"), size or 1)
                    if rep_id not in intent["representations"]:
                        intent2.add_representation(intent, rep_id, codec=codec, encoded_bytes=size)
                    intent2.add_object_version(intent, oid, ver, representation=rep_id)
            op_id = b["op_id"] if len(items) == 1 and "items" not in b else f"{b['op_id']}/{i}"
            outcome = (ie or {}).get("outcome")
            if e is None:
                outcome = outcome or "error"
            deps = expand_deps(b.get("deps", []))
            if oid in last_on_object and last_on_object[oid] not in deps:
                deps.append(last_on_object[oid])
            last_on_object[oid] = op_id
            op = intent2.add_operation(
                intent, op_id=op_id, op=verb, object_id=oid, version=ver,
                stream=b.get("stream"), batch_id=b.get("batch_id") or (b["op_id"] if "items" in b else None),
                deps=deps, range=it.get("range"),
                release_ns=int(b["ts_ns"]), source_outcome=outcome,
                requested_bytes=it.get("requested_bytes"))
            sidecar.append({"op_id": op_id, "begin_ns": b["ts_ns"],
                            "end_ns": e["ts_ns"] if e else None,
                            "outcome": outcome,
                            "completed_bytes": (ie or {}).get("completed_bytes")})
    sidecar_bytes = "".join(json.dumps(s, sort_keys=True) + "\n" for s in sidecar).encode()
    intent["provenance"]["completeness"]["notes"].append(order_note)
    intent["timing"] = {"sidecar": sidecar_path or "timing.jsonl",
                        "sidecar_sha256": hashlib.sha256(sidecar_bytes).hexdigest()}
    intent["health"] = health
    intent2.validate_intent2(intent)
    return intent, sidecar_bytes


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("capture", help="capture events JSONL")
    ap.add_argument("--out", required=True, help="directory for intent.json and timing.jsonl")
    args = ap.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    try:
        intent, sidecar = normalize_capture(read_events(args.capture), sidecar_path="timing.jsonl")
    except (CaptureError, intent2.Intent2Error) as error:
        print(f"kvio capture: {error}", file=sys.stderr)
        return 2
    (out / "timing.jsonl").write_bytes(sidecar)
    (out / "intent.json").write_text(json.dumps(intent, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"operations": len(intent["operations"]), "objects": len(intent["objects"]),
                      "completeness": intent["provenance"]["completeness"],
                      "bundle_sha256": intent2.bundle_sha256(intent, sidecar)}, indent=2))
    return 0


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.exit(main())
