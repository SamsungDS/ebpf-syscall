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

import intent2

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
class Backend:
    """What a target must provide.  Payloads are memoryviews; no engine
    metadata, layout or command shaping is decided here."""

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
        for item in intent["initial_state"]["live"]:
            size = intent["objects"][item["object_id"]]["versions"][str(item["version"])]["bytes"]
            self.objects[(item["object_id"], item["version"])] = synthetic_bytes(
                item["object_id"], item["version"], 0, size)

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
            if self.verify and chunk != synthetic_bytes(object_id, version, offset, len(chunk)):
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


# ---------------------------------------------------------------- ledger
@dataclass
class Row:
    op_id: str
    op: str
    object_id: str
    version: int
    requested_bytes: int
    release_ns: int
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
    def __init__(self, intent, backend, *, profile="dependency", mode="simulated",
                 workers=8, declared_delay_ns=0, cancelled_skip=True):
        intent2.validate_intent2(intent)
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
            self.rows[o["op_id"]] = Row(op_id=o["op_id"], op=o["op"], object_id=o["object_id"],
                                        version=o["version"], requested_bytes=o["requested_bytes"],
                                        release_ns=rel, source_outcome=o.get("source_outcome"),
                                        deps=list(o["deps"]))
            self.order.append(o["op_id"])
        self.by_id = {o["op_id"]: o for o in ops}
        self.dependents = {}
        for o in ops:
            for d in o["deps"]:
                self.dependents.setdefault(d, []).append(o["op_id"])
        self.remaining_deps = {o["op_id"]: len(o["deps"]) for o in ops}
        self.backend.initialize(self.intent)

    def _eligible_time(self, op_id, now):
        o = self.by_id[op_id]
        r = self.rows[op_id]
        t = r.release_ns if self.profile == "offered" else 0
        delay = o.get("declared_delay_ns")
        delay = self.declared_delay_ns if delay is None else delay
        for d in o["deps"]:
            t = max(t, self.rows[d].complete_ns + delay)
        return t

    def _perform(self, op_id):
        o = self.by_id[op_id]
        r = self.rows[op_id]
        if self.cancelled_skip and o.get("source_outcome") == "cancelled":
            return Outcome("cancelled", 0, "source cancelled; not submitted")
        size = self.intent["objects"][o["object_id"]]["versions"][str(o["version"])]["bytes"]
        if o["op"] == "store":
            payload = memoryview(synthetic_bytes(o["object_id"], o["version"], 0, size))
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
                outcome = self._perform(op_id)
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
        result = summarize(rows, self.profile, self.mode)
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
        for d in o["deps"]:
            p = by[d]
            if p.complete_ns is None or r.submit_ns < p.complete_ns + delay:
                violations.append((o["op_id"], d))
    return violations


def compare_outcomes(rows):
    """Where the target's outcome differs from the source's, say so."""
    return [{"op_id": r.op_id, "source": r.source_outcome, "target": r.outcome, "detail": r.detail}
            for r in rows if r.source_outcome is not None and r.outcome != r.source_outcome]


def rows_to_jsonl(rows):
    return "".join(json.dumps(r.__dict__, sort_keys=True) + "\n" for r in rows)


def main(argv=None):
    import argparse
    import sys
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("intent")
    ap.add_argument("--backend", choices=("fake",), default="fake")
    ap.add_argument("--profile", choices=PROFILES, default="dependency")
    ap.add_argument("--mode", choices=("simulated", "real"), default="simulated")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--declared-delay-ns", type=int, default=0)
    ap.add_argument("--out", help="directory for ledger.jsonl and summary.json")
    args = ap.parse_args(argv)
    intent = intent2.load_intent2(args.intent)
    backend = FakeBackend()
    ex = Executor(intent, backend, profile=args.profile, mode=args.mode,
                  workers=args.workers, declared_delay_ns=args.declared_delay_ns)
    rows, result = ex.run()
    result["dependency_violations"] = check_dependencies(rows, intent, args.declared_delay_ns)
    result["intent_sha256"] = intent2.intent2_sha256(intent)
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
