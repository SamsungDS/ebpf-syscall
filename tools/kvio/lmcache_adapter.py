#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Record LMCache raw_block object operations as ``kvio.capture-events.v1``.

The object-level decisions of LMCache's raw_block engine live in the
Python core: ``put_many`` decides which keys get a slot, ``load_many_into``
which keys are read, ``delete_many`` which slots are recycled.  Below them
the Rust engine sees bytes and offsets, which is already past the point
where an object's identity and size were decided.  This adapter wraps a
``RawBlockCore`` and records, around each of those three calls, the batch
it was asked for and the per-item outcome it returned, without touching
payloads and without editing the vendored engine.

What the engine's result can and cannot say is recorded honestly:
``put_many`` returns ``True`` both for a fresh store and for a key that was
already indexed (no device I/O), so presence is checked before the call to
tell ``already_present`` from ``success``; it returns ``False`` for "no
free slot", "write failed" and "another store of the key was in flight"
alike, which this adapter reports as ``error`` with that limitation named
in the capture's adapter record.  ``load_many_into`` returns ``False`` for
a missing key and for a failed read alike; presence before the call
separates ``miss`` from ``error``.  ``delete_many`` returns whether an
entry was removed: ``success`` or ``miss``.

The recorded object identity is a digest of the encoded raw_block key,
because a serving LMCache's key carries the model's name as the
deployment spelled it, which can be a path.  The real key is kept in a
private mapping next to the capture (``<capture>.keys.json``), written by
the recorder's owner when it closes.  The representation is the payload
length with an opaque codec; whatever the payload encodes (a codec
header, K and V planes) is not visible at this boundary and is not
invented here.
"""
from __future__ import annotations

import hashlib
import json
import time

import capture_events

ADAPTER = {"name": "kvio-lmcache-raw_block-wrapper", "revision": "1",
           "stream_order": "each batch depends on the previous batch recorded on the same stream (the caller's call order)",
           "outcome_limits": ["put_many False covers no-slot, write-failure and inflight alike (reported as error)",
                              "load_many_into False covers miss and read-failure; presence is checked before the call",
                              "payload representation is opaque: length only"]}


def _payload_len(memory_obj):
    try:
        return int(memory_obj.get_size())
    except Exception:
        return len(memory_obj.byte_array)


class RecordingRawBlockCore:
    """A ``RawBlockCore`` whose object operations are recorded.

    Composition, not inheritance: every attribute not wrapped here is
    forwarded to the core unchanged, so callers that already hold a core
    can wrap it after construction.
    """

    def __init__(self, core, recorder: capture_events.Recorder, *, stream="main"):
        self._core = core
        self._rec = recorder
        self._stream = stream
        self._batch = 0
        self._keys = {}          # digest -> encoded key, private
        self._last = {}          # stream -> op_id of the last batch on it

    def __getattr__(self, name):
        return getattr(self._core, name)

    def set_stream(self, stream):
        self._stream = stream

    def record_initial_state(self):
        """Objects already indexed when capture begins are the initial live set."""
        live = []
        for encoded in self._core.snapshot_indexed_keys():
            meta = self._core.get_metadata_many([encoded])[0]
            size = int(getattr(meta, "size", 0) or 0)
            live.append((self.oid(encoded), 1, {"codec": "raw_block-opaque", "encoded_bytes": size}, size, "storage"))
        self._rec.object_state(live)
        return len(live)

    def oid(self, encoded):
        """Opaque object identity for a raw_block key; the mapping stays private."""
        d = "k" + hashlib.sha256(encoded.encode()).hexdigest()[:20]
        self._keys[d] = encoded
        return d

    def write_key_mapping(self, path=None):
        path = path or (str(self._rec.path) + ".keys.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self._keys, f, indent=0, sort_keys=True)
        return path

    def _next_batch(self):
        self._batch += 1
        return f"{self._stream}/b{self._batch}"

    def _begin(self, **fields):
        prev = self._last.get(self._stream)
        op = self._rec.begin(stream=self._stream, batch_id=self._next_batch(),
                             deps=[prev] if prev else [], **fields)
        self._last[self._stream] = op
        return op

    def put_many(self, keys, objs, placement_ids=None):
        encoded = [k.encoded for k in keys]
        present = self._core.exists_many(encoded) if hasattr(self._core, "exists_many") else [False] * len(keys)
        items = [{"object_id": self.oid(e), "requested_bytes": _payload_len(o),
                  "representation": {"codec": "raw_block-opaque", "encoded_bytes": _payload_len(o)}}
                 for e, o in zip(encoded, objs)]
        op = self._begin(op="store", items=items)
        try:
            result = self._core.put_many(keys, objs, placement_ids)
        except Exception:
            self._rec.end(op, items=[{"outcome": "error", "completed_bytes": 0} for _ in items])
            raise
        outcomes = []
        for ok, was, it in zip(result.results, present, items):
            if ok and was:
                outcomes.append({"outcome": "already_present", "completed_bytes": 0})
            elif ok:
                outcomes.append({"outcome": "success", "completed_bytes": it["requested_bytes"]})
            else:
                outcomes.append({"outcome": "error", "completed_bytes": 0})
        self._rec.end(op, items=outcomes)
        return result

    def load_many_into(self, encoded_keys, objs):
        present = self._core.exists_many(list(encoded_keys))
        items = [{"object_id": self.oid(e), "requested_bytes": _payload_len(o)} for e, o in zip(encoded_keys, objs)]
        op = self._begin(op="load", items=items)
        try:
            results = self._core.load_many_into(encoded_keys, objs)
        except Exception:
            self._rec.end(op, items=[{"outcome": "error", "completed_bytes": 0} for _ in items])
            raise
        outcomes = []
        for ok, was, it in zip(results, present, items):
            if ok:
                outcomes.append({"outcome": "success", "completed_bytes": it["requested_bytes"]})
            elif not was:
                outcomes.append({"outcome": "miss", "completed_bytes": 0})
            else:
                outcomes.append({"outcome": "error", "completed_bytes": 0})
        self._rec.end(op, items=outcomes)
        return results

    def delete_many(self, encoded_keys, *, force=False):
        items = [{"object_id": self.oid(e), "requested_bytes": 0} for e in encoded_keys]
        op = self._begin(op="release", items=items)
        try:
            results = self._core.delete_many(encoded_keys, force=force)
        except Exception:
            self._rec.end(op, items=[{"outcome": "error", "completed_bytes": 0} for _ in items])
            raise
        self._rec.end(op, items=[{"outcome": "success" if ok else "miss", "completed_bytes": 0}
                                 for ok in results])
        return results


def open_recorder(path, *, core, run_id=None, enabled=True, engine_revision=None):
    """A recorder whose engine record names the vendored raw_block revision."""
    import os
    rev = engine_revision
    if rev is None:
        prov = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor", "lmcache", "PROVENANCE.md")
        try:
            for line in open(prov, encoding="utf-8"):
                if line.startswith("- synced_commit:"):
                    rev = line.split(":", 1)[1].strip()
                    break
        except OSError:
            pass
    engine = {"name": "lmcache-raw_block", "revision": rev or "unknown",
              "io_engine": getattr(core, "io_engine", None),
              "layout": {"header_bytes": getattr(core, "header_bytes", None),
                         "slot_bytes": getattr(core, "slot_bytes", None),
                         "block_align": getattr(core, "block_align", None)}}
    return capture_events.Recorder(path, engine=engine, adapter=ADAPTER, run_id=run_id,
                                   producer="lmcache", enabled=enabled, clock=time.monotonic_ns)
