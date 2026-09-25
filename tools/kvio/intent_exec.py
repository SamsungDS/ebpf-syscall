#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute a ``kvio.intent.v2`` object workload against a storage backend.

The executor owns scheduling and bookkeeping; a backend owns the storage
path.  The executor releases an operation only when its dependencies have
completed on *this* target (plus any declared delay), never at the time
the source happened to complete it, so a faster drive is allowed to finish
earlier and a slower one shows up as backlog rather than as a quietly
reduced offered load.  It never serializes independent work globally and
never creates a thread per operation.

Three timing profiles, named so their permitted conclusions stay apart:

  ``offered``     release each operation at its recorded ``release_ns``
                  (relative to the first), subject to real prerequisites and
                  the worker budget; report scheduler lag and backlog.
  ``dependency``  release successors after actual target completion of
                  their prerequisites plus a declared compute delay; keep
                  independent work concurrent.
  ``saturation``  run eligible independent work as fast as the worker
                  budget permits.

For a dependent operation the eligible time is
``max(external_release, max(prerequisite_completion + declared_delay))``;
admission (the worker budget) can delay submission further, and release,
eligible, submit, complete and consumer-wait are reported separately.

Two execution modes share one scheduler: ``simulated`` advances a virtual
clock over a discrete-event heap and asks the backend for a service time
(the deterministic fake backend used by the contract tests), ``real`` runs
a bounded pool of worker threads on the monotonic clock against a backend
that touches storage.  The content model is deterministic synthetic bytes
keyed by object, version and range: it exercises correctness, not any
content-sensitive controller behaviour, and the ledger says so.
"""
from __future__ import annotations

import hashlib
import heapq
import json
import statistics
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

import content_profile
import intent2
import workload3

PROFILES = ("offered", "dependency", "saturation")


# --------------------------------------------------------------- content
def synthetic_bytes(object_id, version, offset, length):
    """Deterministic content for (object, version, range); never all zeros."""
    out = bytearray()
    block = 0
    first = offset // 64
    last = (offset + length - 1) // 64
    for block in range(first, last + 1):
        seed = f"{object_id}:{version}:{block}".encode()
        out += hashlib.blake2b(seed, digest_size=64).digest()
    start = offset - first * 64
    return bytes(out[start:start + length])


@dataclass
class Outcome:
    status: str
    completed_bytes: int = 0
    detail: str = ""


# --------------------------------------------------------------- backend
def initial_objects(intent):
    """(identity, version, size) of every object live before the first
    operation, from a v2 intent's initial state or a v3 namespace."""
    if intent.get("schema") == workload3.SCHEMA:
        nodes = intent["namespace"]["nodes"]
        return [(e["node"], 0, nodes[e["node"]].get("size", 0)) for e in intent["namespace"]["entries"]
                if nodes[e["node"]]["kind"] == "object"]
    return [(i["object_id"], i["version"], intent["objects"][i["object_id"]]["versions"][str(i["version"])]["bytes"])
            for i in intent["initial_state"]["live"]]


class Backend:
    """What a target must provide.  Payloads are memoryviews; no engine
    metadata, layout or command shaping is decided here."""

    profile = None

    def payload(self, identity, version, offset, length):
        """Initial-state content: the executor's own profile if one was set."""
        return content_profile.content(self.profile or "incompressible", identity, offset, length) \
            if self.profile else synthetic_bytes(identity, version, offset, length)

    def initialize(self, intent):
        """Materialize the initial live set; called before any operation."""

    def store(self, object_id, version, payload: memoryview) -> Outcome:
        raise NotImplementedError

    def load(self, object_id, version, offset, length, dst: memoryview, *,
             object_bytes=None, op_id=None) -> Outcome:
        raise NotImplementedError

    def release(self, object_id, version) -> Outcome:
        raise NotImplementedError

    def close(self):
        pass


class FakeBackend(Backend):
    """A deterministic in-memory target for contract tests.

    Service times come from ``latency`` (a callable of the operation or a
    constant), so completion order can differ from submission order;
    ``fail`` marks operations that must fail with a given status; content
    is checked on every load.  Records every call in order.
    """

    def __init__(self, *, latency_ns=1000, fail=None, verify=True):
        self.latency_ns = latency_ns
        self.fail = fail or {}
        self.verify = verify
        self.objects = {}          # (object_id, version) -> bytes
        self.calls = []
        self.lock = threading.Lock()

    def service_ns(self, op):
        if callable(self.latency_ns):
            return int(self.latency_ns(op))
        return int(self.latency_ns)

    def initialize(self, intent):
        for oid, ver, size in initial_objects(intent):
            self.objects[(oid, ver)] = self.payload(oid, ver, 0, size)

    def _forced(self, op_id):
        return self.fail.get(op_id)

    def store(self, object_id, version, payload, op_id=None):
        with self.lock:
            self.calls.append(("store", object_id, version, op_id))
            forced = self._forced(op_id)
            if forced:
                return Outcome(forced, 0, "injected")
            if (object_id, version) in self.objects:
                return Outcome("already_present", 0)
            self.objects[(object_id, version)] = bytes(payload)
            return Outcome("success", len(payload))

    def load(self, object_id, version, offset, length, dst, object_bytes=None, op_id=None):
        with self.lock:
            self.calls.append(("load", object_id, version, op_id))
            forced = self._forced(op_id)
            if forced:
                return Outcome(forced, 0, "injected")
            data = self.objects.get((object_id, version))
            if data is None:
                return Outcome("miss", 0)
            chunk = data[offset:offset + length]
            dst[:len(chunk)] = chunk
            if self.verify and chunk != self.payload(object_id, version, offset, len(chunk)):
                return Outcome("error", len(chunk), "content mismatch")
            if len(chunk) < length:
                return Outcome("short", len(chunk))
            return Outcome("success", len(chunk))

    def release(self, object_id, version, op_id=None):
        with self.lock:
            self.calls.append(("release", object_id, version, op_id))
            forced = self._forced(op_id)
            if forced:
                return Outcome(forced, 0, "injected")
            if self.objects.pop((object_id, version), None) is None:
                return Outcome("miss", 0)
            return Outcome("success", 0)


class RawBlockBackend(Backend):
    """LMCache's vendored raw_block engine as a target, on a CPU.

    ``provenance_modules`` names what the fidelity manifest must show as
    actually loaded: the label "vendored" is not evidence, the path is.

    The core lays out slots, writes its own headers and pads to its
    alignment; nothing about that is decided here.  Object ids are encoded
    raw_block keys.  A ranged load reads the whole object through the
    engine (it has no ranged read) and copies the range out, which the
    ledger's completed bytes reflect.  Optionally wrapped in the recording
    adapter so a replay produces its own capture for comparison.
    """

    provenance_modules = ("lmcache", "lmcache.v1.storage_backend.raw_block.core", "lmcache_rust_raw_block_io")

    def doctor(self):
        return "ok (vendored core and Rust module import)"

    def describe(self):
        c = self.core
        return {"device": getattr(c, "device_path", None), "io_engine": getattr(c, "io_engine", None),
                "slot_bytes": getattr(c, "slot_bytes", None), "block_align": getattr(c, "block_align", None),
                "header_bytes": getattr(c, "header_bytes", None)}

    def __init__(self, core, *, record_to=None, profile="incompressible"):
        self.core = core
        self.profile = content_profile.parse_profile(profile) if isinstance(profile, str) else profile
        self.recorder = None
        if record_to is not None:
            import lmcache_adapter
            self.recorder = lmcache_adapter.open_recorder(record_to, core=core)
            self.core = lmcache_adapter.RecordingRawBlockCore(core, self.recorder)
        from lmcache.v1.storage_backend.raw_block.key_codec import (  # noqa: E402
            RawBlockKeySpec, slot_identity_from_encoded_key)
        namespace = getattr(core, "key_namespace", "object")
        self._spec = lambda oid: RawBlockKeySpec(
            encoded=oid, slot_identity=slot_identity_from_encoded_key(oid, namespace))
        self.lock = threading.Lock()

    @staticmethod
    def _memory_obj(payload):
        import torch
        from lmcache.v1.memory_management import MemoryFormat, MemoryObjMetadata, TensorMemoryObj
        data = bytearray(payload)
        raw = torch.frombuffer(data, dtype=torch.uint8) if data else torch.empty(0, dtype=torch.uint8)
        meta = MemoryObjMetadata(shape=torch.Size([len(data)]), dtype=torch.uint8, address=0,
                                 phy_size=len(data), fmt=MemoryFormat.BINARY, ref_count=1)
        obj = TensorMemoryObj(raw, meta, parent_allocator=None)
        return obj, data

    def initialize(self, intent):
        for oid, ver, size in initial_objects(intent):
            obj, _ = self._memory_obj(self.payload(oid, ver, 0, size))
            self.core.put_many([self._spec(oid)], [obj])

    def store(self, object_id, version, payload, op_id=None):
        obj, _ = self._memory_obj(payload)
        present = self.core.exists_many([object_id])[0]
        result = self.core.put_many([self._spec(object_id)], [obj])
        if result.results[0]:
            return Outcome("already_present" if present else "success", 0 if present else len(payload))
        return Outcome("error", 0, "put_many returned False")

    def load(self, object_id, version, offset, length, dst, object_bytes=None, op_id=None):
        # Always ask the engine, so a miss is the engine's answer (and shows in
        # the replay's own capture), never this backend's guess.
        present = self.core.exists_many([object_id])[0]
        size = object_bytes if object_bytes is not None else offset + length
        if present:
            meta = self.core.get_metadata_many([object_id])[0]
            size = int(getattr(meta, "size", 0) or size)
        obj, data = self._memory_obj(bytes(size))
        ok = self.core.load_many_into([object_id], [obj])[0]
        if not ok:
            return Outcome("miss" if not present else "error", 0,
                           "" if not present else "load_many_into returned False")
        chunk = bytes(data[offset:offset + length])
        dst[:len(chunk)] = chunk
        if chunk != self.payload(object_id, version, offset, len(chunk)):
            return Outcome("error", len(chunk), "content mismatch")
        return Outcome("success" if len(chunk) == length else "short", len(chunk))

    def release(self, object_id, version, op_id=None):
        ok = self.core.delete_many([object_id])[0]
        return Outcome("success" if ok else "miss", 0)

    def close(self):
        if self.recorder is not None:
            self.recorder.close()
        try:
            self.core.close()
        except Exception:
            pass


def vendored_lmcache_revision():
    prov = Path(__file__).resolve().parent / "vendor" / "lmcache" / "PROVENANCE.md"
    try:
        for line in prov.read_text(encoding="utf-8").splitlines():
            if line.startswith("- synced_commit:"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return "unknown"


def raw_block_from_config(cfg):
    """A RawBlockBackend from a registry config; ``probe`` only checks imports."""
    if cfg.get("probe"):
        import lmcache.v1.storage_backend.raw_block.core  # noqa: F401
        import lmcache_rust_raw_block_io  # noqa: F401
        b = RawBlockBackend.__new__(RawBlockBackend)
        return b
    largest = cfg.get("slot_bytes") or 4 * 1024 * 1024
    core = open_raw_block_core(cfg["device"], capacity_bytes=cfg.get("capacity_bytes", 256 * 1024 * 1024),
                               slot_bytes=largest, io_engine=cfg.get("provider", "posix") if cfg.get("provider") != "uring_cmd" else "io_uring",
                               odirect=cfg.get("odirect", False),
                               max_data_transfer_size=cfg.get("max_data_transfer_size", 0))
    return RawBlockBackend(core, record_to=cfg.get("record_to"), profile=cfg.get("content_profile", "incompressible"))


def open_raw_block_core(device, *, capacity_bytes, slot_bytes, block_align=4096,
                        header_bytes=4096, io_engine="posix", odirect=False,
                        max_data_transfer_size=0):
    """A writer core over a file or device, the way the runner builds one."""
    from lmcache.v1.storage_backend.raw_block.core import RawBlockCore, RawBlockCoreConfig
    cfg = RawBlockCoreConfig(
        device_path=str(device), capacity_bytes=capacity_bytes, block_align=block_align,
        header_bytes=header_bytes, slot_bytes=slot_bytes, use_odirect=odirect,
        enable_zero_copy=False, meta_total_bytes=1 * 1024 * 1024, meta_magic=b"LMCIDX01",
        meta_version=1, meta_checkpoint_interval_sec=60, meta_idle_quiet_ms=0,
        meta_enable_periodic=False, meta_verify_on_load=False,
        max_data_transfer_size=max_data_transfer_size, load_checkpoint_on_init=False,
        io_engine=io_engine)
    return RawBlockCore(cfg, key_namespace="object")


# ---------------------------------------------------------------- ledger
@dataclass
class Row:
    op_id: str
    op: str
    object_id: str
    version: int
    requested_bytes: int
    release_ns: int
    family: str = "object"
    eligible_ns: int | None = None
    submit_ns: int | None = None
    complete_ns: int | None = None
    outcome: str | None = None
    completed_bytes: int = 0
    detail: str = ""
    source_outcome: str | None = None
    deps: list = field(default_factory=list)


def _pct(values, q):
    if not values:
        return None
    values = sorted(values)
    return values[min(len(values) - 1, int(q * len(values)))]


def summarize(rows, profile, mode, content_model="synthetic-blake2b-64"):
    by_outcome = {}
    bytes_by = {}
    for r in rows:
        by_outcome[r.outcome] = by_outcome.get(r.outcome, 0) + 1
        bytes_by[r.op] = bytes_by.get(r.op, 0) + r.completed_bytes
    done = [r for r in rows if r.complete_ns is not None]
    lag = [r.submit_ns - r.eligible_ns for r in done]
    wait = [r.complete_ns - r.release_ns for r in done]
    svc = [r.complete_ns - r.submit_ns for r in done]
    diverged = [r.op_id for r in rows if r.source_outcome is not None and r.outcome != r.source_outcome]
    return {
        "profile": profile, "mode": mode, "content_model": content_model,
        "operations": len(rows), "completed": len(done),
        "outcomes": by_outcome, "completed_bytes_by_op": bytes_by,
        "scheduler_lag_ns": {"p50": _pct(lag, .5), "p95": _pct(lag, .95), "max": max(lag) if lag else None},
        "release_to_complete_ns": {"p50": _pct(wait, .5), "p95": _pct(wait, .95), "max": max(wait) if wait else None},
        "submit_to_complete_ns": {"p50": _pct(svc, .5), "p95": _pct(svc, .95)},
        "wall_ns": (max(r.complete_ns for r in done) - min(r.release_ns for r in rows)) if done else 0,
        "diverged_from_source": diverged,
    }


# -------------------------------------------------------------- executor
class Executor:
    """Schedules a v2 intent or a v3 workload over one backend.

    For a v2 intent the backend is an object store (store/load/release).
    For a v3 workload each operation is a typed call; object-family calls
    go to the same store/load/release methods with the node as the content
    identity, and every other family goes to ``backend.perform(op)``.
    """

    def __init__(self, intent, backend, *, profile="dependency", mode="simulated",
                 workers=8, declared_delay_ns=0, cancelled_skip=True, content="incompressible"):
        self.v3 = isinstance(intent, dict) and intent.get("schema") == workload3.SCHEMA
        if self.v3:
            workload3.validate_workload(intent)
        else:
            intent2.validate_intent2(intent)
        self.content = content_profile.parse_profile(content) if isinstance(content, str) else content
        if self.v3 and getattr(backend, "profile", None) is None:
            backend.profile = self.content       # v3 payloads come from the named profile
        if profile not in PROFILES:
            raise ValueError(f"profile must be one of {PROFILES}")
        if profile == "offered" and intent["provenance"]["timing_model"] == "absent":
            raise ValueError("offered-load replay needs recorded release times")
        if mode not in ("simulated", "real"):
            raise ValueError("mode must be simulated or real")
        self.intent = intent
        self.backend = backend
        self.profile = profile
        self.mode = mode
        self.workers = max(1, workers)
        self.declared_delay_ns = declared_delay_ns
        self.cancelled_skip = cancelled_skip
        self.rows = {}
        self.order = []
        self.buffers = {}

    # ------------------------------------------------------------ setup
    def _prepare(self):
        ops = self.intent["operations"]
        base = min((o["release_ns"] for o in ops if o.get("release_ns") is not None), default=0)
        for o in ops:
            rel = (o["release_ns"] - base) if (self.profile == "offered" and o.get("release_ns") is not None) else 0
            if self.v3:
                a = o["args"]
                row = Row(op_id=o["op_id"], op=o["call"], family=o["family"],
                          object_id=a.get("node") or a.get("path") or a.get("key") or a.get("handle") or "",
                          version=0, requested_bytes=a.get("length") or a.get("size") or 0,
                          release_ns=rel, source_outcome=o.get("expected", {}).get("outcome"),
                          deps=[d["op"] for d in o["deps"]])
            else:
                row = Row(op_id=o["op_id"], op=o["op"], object_id=o["object_id"],
                          version=o["version"], requested_bytes=o["requested_bytes"],
                          release_ns=rel, source_outcome=o.get("source_outcome"),
                          deps=list(o["deps"]))
            self.rows[o["op_id"]] = row
            self.order.append(o["op_id"])
        self.by_id = {o["op_id"]: o for o in ops}
        self.dependents = {}
        for o in ops:
            for d in self.rows[o["op_id"]].deps:
                self.dependents.setdefault(d, []).append(o["op_id"])
        self.remaining_deps = {o["op_id"]: len(self.rows[o["op_id"]].deps) for o in ops}
        self.backend.initialize(self.intent)

    def _eligible_time(self, op_id, now):
        o = self.by_id[op_id]
        r = self.rows[op_id]
        t = r.release_ns if self.profile == "offered" else 0
        delay = o.get("declared_delay_ns")
        delay = self.declared_delay_ns if delay is None else delay
        for d in r.deps:
            t = max(t, self.rows[d].complete_ns + delay)
        return t

    def _perform_v3(self, op):
        exp = op.get("expected", {})
        if self.cancelled_skip and exp.get("outcome") == "cancelled":
            return Outcome("cancelled", 0, "source cancelled; not submitted")
        if op["family"] == "object":
            a = op["args"]
            node = a["node"]
            size = a.get("size") or self.intent["namespace"]["nodes"].get(node, {}).get("size", 0)
            if op["call"] == "store":
                payload = memoryview(self.backend.payload(node, 0, 0, size))
                return self.backend.store(node, 0, payload, op_id=op["op_id"])
            if op["call"] == "load":
                off, ln = a.get("offset", 0), a.get("length", size)
                dst = memoryview(bytearray(ln))
                return self.backend.load(node, 0, off, ln, dst, object_bytes=size, op_id=op["op_id"])
            if op["call"] == "release":
                return self.backend.release(node, 0, op_id=op["op_id"])
            if op["call"] == "exists":
                return self.backend.exists(node, op_id=op["op_id"]) if hasattr(self.backend, "exists") \
                    else Outcome("error", 0, "backend has no exists")
        res = self.backend.perform(op)
        detail = res.meta.get("detail", "") if getattr(res, "meta", None) else ""
        return Outcome(res.outcome, getattr(res, "bytes", 0), detail)

    def _perform(self, op_id):
        o = self.by_id[op_id]
        r = self.rows[op_id]
        if self.v3:
            return self._perform_v3(o)
        if self.cancelled_skip and o.get("source_outcome") == "cancelled":
            return Outcome("cancelled", 0, "source cancelled; not submitted")
        size = self.intent["objects"][o["object_id"]]["versions"][str(o["version"])]["bytes"]
        if o["op"] == "store":
            # The backend verifies loads against its own payload(); store the same.
            payload = memoryview(self.backend.payload(o["object_id"], o["version"], 0, size))
            return self.backend.store(o["object_id"], o["version"], payload, op_id=op_id)
        if o["op"] == "load":
            rng = o.get("range") or {"offset": 0, "length": size}
            dst = memoryview(bytearray(rng["length"]))
            return self.backend.load(o["object_id"], o["version"], rng["offset"], rng["length"], dst,
                                     object_bytes=size, op_id=op_id)
        return self.backend.release(o["object_id"], o["version"], op_id=op_id)

    # --------------------------------------------------------- simulated
    def _run_simulated(self):
        now = 0
        pending = []      # (eligible_ns, seq, op_id)
        completions = []  # (complete_ns, seq, op_id, outcome)
        running = 0
        seq = 0
        ready_at = {}
        for op_id in self.order:
            if self.remaining_deps[op_id] == 0:
                t = self._eligible_time(op_id, now)
                heapq.heappush(pending, (t, seq, op_id)); seq += 1
        while pending or completions:
            # Submit everything eligible now while the worker budget allows.
            while pending and running < self.workers and pending[0][0] <= now:
                t, _, op_id = heapq.heappop(pending)
                r = self.rows[op_id]
                r.eligible_ns = t
                r.submit_ns = now
                outcome = self._perform(op_id)
                service = 0 if outcome.status == "cancelled" and outcome.detail.startswith("source") \
                    else self.backend.service_ns(self.by_id[op_id])
                heapq.heappush(completions, (now + service, seq, op_id, outcome)); seq += 1
                running += 1
            # Advance to the next event: a completion, or a pending release.
            next_t = None
            if completions:
                next_t = completions[0][0]
            if pending and running < self.workers:
                next_t = pending[0][0] if next_t is None else min(next_t, pending[0][0])
            if next_t is None:
                break
            now = max(now, next_t)
            while completions and completions[0][0] <= now:
                t, _, op_id, outcome = heapq.heappop(completions)
                running -= 1
                r = self.rows[op_id]
                r.complete_ns = t
                r.outcome = outcome.status
                r.completed_bytes = outcome.completed_bytes
                r.detail = outcome.detail
                for dep in self.dependents.get(op_id, []):
                    self.remaining_deps[dep] -= 1
                    if self.remaining_deps[dep] == 0:
                        heapq.heappush(pending, (self._eligible_time(dep, now), seq, dep)); seq += 1
        return now

    # --------------------------------------------------------------- real
    def _run_real(self):
        clock = time.monotonic_ns
        t0 = clock()
        lock = threading.Condition()
        pending = []
        done_q = deque()
        running = [0]
        seq = [0]
        finished = [0]
        total = len(self.order)

        def worker():
            while True:
                with lock:
                    while True:
                        if finished[0] >= total:
                            return
                        now = clock() - t0
                        if pending and pending[0][0] <= now and running[0] < self.workers:
                            t, _, op_id = heapq.heappop(pending)
                            running[0] += 1
                            break
                        timeout = None
                        if pending and running[0] < self.workers:
                            timeout = max(0.0, (pending[0][0] - now) / 1e9)
                        lock.wait(timeout=timeout if timeout is not None else 0.05)
                r = self.rows[op_id]
                r.eligible_ns = t
                r.submit_ns = clock() - t0
                try:
                    outcome = self._perform(op_id)
                except Exception as error:      # a backend bug must not hang the run
                    outcome = Outcome("error", 0, f"{type(error).__name__}: {error}")
                r.complete_ns = clock() - t0
                r.outcome, r.completed_bytes, r.detail = outcome.status, outcome.completed_bytes, outcome.detail
                with lock:
                    running[0] -= 1
                    finished[0] += 1
                    for dep in self.dependents.get(op_id, []):
                        self.remaining_deps[dep] -= 1
                        if self.remaining_deps[dep] == 0:
                            heapq.heappush(pending, (self._eligible_time(dep, r.complete_ns), seq[0], dep)); seq[0] += 1
                    lock.notify_all()

        with lock:
            for op_id in self.order:
                if self.remaining_deps[op_id] == 0:
                    heapq.heappush(pending, (self._eligible_time(op_id, 0), seq[0], op_id)); seq[0] += 1
        threads = [threading.Thread(target=worker, name=f"kvio-exec-{i}", daemon=True)
                   for i in range(self.workers)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        return clock() - t0

    def run(self):
        self._prepare()
        wall = self._run_simulated() if self.mode == "simulated" else self._run_real()
        try:
            self.backend.close()
        finally:
            pass
        rows = [self.rows[i] for i in self.order]
        unfinished = [r.op_id for r in rows if r.complete_ns is None]
        result = summarize(rows, self.profile, self.mode, content_model=self.content["name"])
        result["diverged_from_source"] = [d["op_id"] for d in compare_outcomes(rows, self.intent)]
        result["unfinished"] = unfinished
        result["wall_ns"] = wall
        return rows, result


# --------------------------------------------------------------- checks
def check_dependencies(rows, intent, declared_delay_ns=0):
    """Every operation was submitted only after its prerequisites completed."""
    by = {r.op_id: r for r in rows}
    violations = []
    for o in intent["operations"]:
        r = by[o["op_id"]]
        if r.submit_ns is None:
            continue
        delay = o.get("declared_delay_ns")
        delay = declared_delay_ns if delay is None else delay
        for d in r.deps:
            p = by[d]
            if p.complete_ns is None or r.submit_ns < p.complete_ns + delay:
                violations.append((o["op_id"], d))
    return violations


def compare_outcomes(rows, intent=None):
    """Where the target's outcome differs from what the source saw, say so.

    A v3 operation may declare a *set* of permitted outcomes for a race the
    application intentionally ran; any member of the set is agreement."""
    permitted = {}
    if intent is not None and intent.get("schema") == workload3.SCHEMA:
        for o in intent["operations"]:
            if o.get("expected", {}).get("outcomes"):
                permitted[o["op_id"]] = set(o["expected"]["outcomes"])
    out = []
    for r in rows:
        if r.op_id in permitted:
            if r.outcome not in permitted[r.op_id]:
                out.append({"op_id": r.op_id, "source": sorted(permitted[r.op_id]), "target": r.outcome, "detail": r.detail})
        elif r.source_outcome is not None and r.outcome != r.source_outcome:
            out.append({"op_id": r.op_id, "source": r.source_outcome, "target": r.outcome, "detail": r.detail})
    return out


def rows_to_jsonl(rows):
    return "".join(json.dumps(r.__dict__, sort_keys=True) + "\n" for r in rows)


def load_any(path):
    """A v2 intent stays v2 (its executor path is unchanged); a v3 workload is v3."""
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if value.get("schema") == workload3.SCHEMA:
        workload3.validate_workload(value)
        return value
    intent2.validate_intent2(value)
    return value


def main(argv=None):
    import argparse
    import sys
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("intent", help="a kvio.intent.v2 or kvio.workload.v3 file")
    ap.add_argument("--backend", choices=("fake", "raw_block"), default="fake",
                    help="v2 intents: the object target (kept for the existing command lines)")
    ap.add_argument("--engine-name", help="v3 workloads: a registered engine (see `kvio engines`)")
    ap.add_argument("--provider", help="the engine's storage provider")
    ap.add_argument("--root", help="posix engines: the generated root directory")
    ap.add_argument("--content-profile", default="incompressible",
                    help="zeros | incompressible | mixed:zero=F,pattern=F,dup_classes=N")
    ap.add_argument("--manifest", help="write the fidelity manifest here")
    ap.add_argument("--device", help="raw_block: a file or block device to lay slots on")
    ap.add_argument("--capacity-bytes", type=int, default=256 * 1024 * 1024)
    ap.add_argument("--slot-bytes", type=int, default=0,
                    help="raw_block slot size; default: the largest object rounded up to 4 KiB")
    ap.add_argument("--io-engine", choices=("posix", "io_uring"), default="posix")
    ap.add_argument("--odirect", action="store_true")
    ap.add_argument("--max-data-transfer-size", type=int, default=0,
                    help="raw_block: the engine's per-command ceiling in bytes (0: the engine's own resolution)")
    ap.add_argument("--record-to", help="raw_block: also record the replay's own object operations here")
    ap.add_argument("--profile", choices=PROFILES, default="dependency")
    ap.add_argument("--mode", choices=("simulated", "real"), default="simulated")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--declared-delay-ns", type=int, default=0)
    ap.add_argument("--out", help="directory for ledger.jsonl and summary.json")
    args = ap.parse_args(argv)
    intent = load_any(args.intent)
    spec = None
    if intent.get("schema") == workload3.SCHEMA:
        import engines
        name = args.engine_name or {"object": "fake", "posix": "fake-fs", "s3": "fake-s3"}[
            intent["operations"][0]["family"] if intent["operations"] else "object"]
        spec = engines.preflight(intent, name, args.provider)
        cfg = {"provider": args.provider, "root": args.root, "device": args.device,
               "capacity_bytes": args.capacity_bytes, "slot_bytes": args.slot_bytes or None,
               "odirect": args.odirect, "max_data_transfer_size": args.max_data_transfer_size,
               "record_to": args.record_to, "content_profile": args.content_profile}
        backend = spec.make(cfg)
        if hasattr(backend, "profile"):
            backend.profile = content_profile.parse_profile(args.content_profile)
    elif args.backend == "fake":
        backend = FakeBackend()
    else:
        if not args.device:
            ap.error("--backend raw_block needs --device")
        largest = max(v["bytes"] for o in intent["objects"].values() for v in o["versions"].values())
        slot = args.slot_bytes or ((largest + 4095) // 4096) * 4096
        core = open_raw_block_core(args.device, capacity_bytes=args.capacity_bytes, slot_bytes=slot,
                                   io_engine=args.io_engine, odirect=args.odirect,
                                   max_data_transfer_size=args.max_data_transfer_size)
        backend = RawBlockBackend(core, record_to=args.record_to)
    ex = Executor(intent, backend, profile=args.profile, mode=args.mode,
                  workers=args.workers, declared_delay_ns=args.declared_delay_ns,
                  content=args.content_profile)
    rows, result = ex.run()
    result["dependency_violations"] = check_dependencies(rows, intent, args.declared_delay_ns)
    result["intent_sha256"] = workload3.workload_sha256(intent) if spec else intent2.intent2_sha256(intent)
    if spec is not None:
        import engines
        man = engines.fidelity_manifest(intent, spec, args.provider, cfg, timing_profile=args.profile,
                                        content_profile=args.content_profile, backend=backend)
        if hasattr(backend, "final_state"):
            man["final_state"] = backend.final_state()
        result["fidelity_manifest"] = man
        if args.manifest:
            Path(args.manifest).write_text(json.dumps(man, indent=2, sort_keys=True) + "\n")
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "ledger.jsonl").write_text(rows_to_jsonl(rows))
        (out / "summary.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not result["dependency_violations"] and not result["unfinished"] else 1


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.exit(main())
