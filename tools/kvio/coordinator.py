#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run one workload from many clients: shard, start together, merge honestly.

A single executor preserves timing and dependencies on one host.  System
dynamics, the queueing a shared file system or object service shows when
several clients press on it at once, need several clients, and the
question they answer is different: not "can this target serve the
recorded demand" but "how does serving it degrade as clients are added".

The coordinator shards a ``kvio.workload.v3`` by stream across N clients,
each of which drives its own engine locally; the coordinator carries only
launch, ready, start, drain and failure messages, never data operations.
Cross-shard dependencies are refused with the edges named, because a
prerequisite on another client needs an explicit acknowledgement and that
relay is not implemented; timestamps are never used as a synchronization
primitive.  Every client keeps its own monotonic clock; the coordinator
measures each client's offset with repeated round trips and records the
offset, its uncertainty (half the smallest round trip) and the drift seen
across the run, and never adjusts a system clock.  A missing client, a
duplicate shard or a client that fails makes the run partial, never a
silent at-least-once replay.

The merged ledger keeps every per-client row with a ``client`` column and
the client's own timestamps; the coordinator-domain timestamps are added
beside them.  Percentiles are computed from pooled samples; a client's p99
is never averaged into a pooled p99.

    python3 coordinator.py serve --workload wl.json --clients 2 --bind 0.0.0.0:39020 \\
        --profile offered --out run/
    python3 coordinator.py client --coordinator host:39020 --client-id c1 \\
        --engine-name s3-sdk --provider endpoint --target-config s3.json
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import statistics
import struct
import sys
import threading
import time
from pathlib import Path

import content_profile
import engines
import intent_exec
import workload3

RUN_SCHEMA = "kvio.distributed-run.v1"
PROBES = 25


class CrossShardError(ValueError):
    pass


# --------------------------------------------------------------- framing
def send(sock, obj):
    data = json.dumps(obj, sort_keys=True).encode()
    sock.sendall(struct.pack("!I", len(data)) + data)


def recv(sock):
    head = _recv_exact(sock, 4)
    if head is None:
        return None
    (n,) = struct.unpack("!I", head)
    body = _recv_exact(sock, n)
    return None if body is None else json.loads(body.decode())


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


# -------------------------------------------------------------- sharding
def shard_workload(wl, clients, *, assignment=None):
    """Split a workload by stream; each shard is a valid workload of its own."""
    streams = []
    for o in wl["operations"]:
        if o["stream"] not in streams:
            streams.append(o["stream"])
    if assignment is None:
        assignment = {s: clients[i % len(clients)] for i, s in enumerate(streams)}
    unknown = set(assignment) - set(streams)
    if unknown:
        raise ValueError(f"assignment names streams not in the workload: {sorted(unknown)}")
    owner = {o["op_id"]: assignment[o["stream"]] for o in wl["operations"]}
    cross = [(o["op_id"], d["op"], owner[o["op_id"]], owner[d["op"]])
             for o in wl["operations"] for d in o["deps"] if owner[d["op"]] != owner[o["op_id"]]]
    if cross:
        raise CrossShardError("cross-shard dependencies need an acknowledgement relay this "
                              f"coordinator does not implement: {cross[:8]}{' ...' if len(cross) > 8 else ''}")
    shards = {}
    for c in clients:
        s = json.loads(json.dumps(wl))            # the shard is a copy; the source is never renumbered
        s["operations"] = [o for o in s["operations"] if owner[o["op_id"]] == c]
        for i, o in enumerate(s["operations"]):
            o["seq"] = i
        s["provenance"]["completeness"]["notes"] = list(s["provenance"]["completeness"]["notes"]) + \
            [f"shard for client {c}: streams {sorted(k for k, v in assignment.items() if v == c)}"]
        workload3.validate_workload(s)
        shards[c] = s
    return shards, assignment


# ------------------------------------------------------------ coordinator
class Coordinator:
    def __init__(self, workload, clients, *, bind, profile, out, target_public=None,
                 content="incompressible", assignment=None, timeout_s=3600):
        self.wl = workload
        self.clients = list(clients)
        self.bind = bind
        self.profile = profile
        self.out = Path(out)
        self.out.mkdir(parents=True, exist_ok=True)
        self.content = content
        self.timeout_s = timeout_s
        self.shards, self.assignment = shard_workload(workload, self.clients, assignment=assignment)
        self.run_id = f"run-{int(time.time())}-{os.getpid()}"
        self.manifest = {
            "schema": RUN_SCHEMA, "run_id": self.run_id,
            "workload_sha256": workload3.workload_sha256(workload),
            "clients": {c: {"streams": sorted(k for k, v in self.assignment.items() if v == c),
                            "operations": len(self.shards[c]["operations"])} for c in self.clients},
            "timing_profile": profile, "content_profile": content,
            "target": dict(target_public or {}),
            "coordinator": {"host": platform.node(), "python": sys.version.split()[0],
                            "clock": "CLOCK_MONOTONIC per host; offsets measured, never applied to system clocks"},
            "cross_shard_dependencies": "refused",
        }
        self.conns = {}
        self.hello = {}
        self.clock = {}
        self.results = {}
        self.failures = {}
        self.lock = threading.Lock()

    def _probe_clock(self, c, sock):
        samples = []
        for _ in range(PROBES):
            t0 = time.monotonic_ns()
            send(sock, {"msg": "ping", "t0": t0})
            r = recv(sock)
            t1 = time.monotonic_ns()
            if r is None or r.get("msg") != "pong":
                raise RuntimeError(f"client {c}: bad pong")
            rtt = t1 - t0
            # client clock minus coordinator clock, assuming symmetric delay
            offset = r["t_client"] - (t0 + rtt // 2)
            samples.append((rtt, offset))
        best = min(samples)
        return {"offset_ns": best[1], "uncertainty_ns": best[0] // 2, "min_rtt_ns": best[0],
                "median_rtt_ns": int(statistics.median(s[0] for s in samples)), "probes": PROBES}

    def _serve_client(self, sock, addr):
        hello = recv(sock)
        if not hello or hello.get("msg") != "hello":
            sock.close(); return
        c = hello["client"]
        with self.lock:
            if c not in self.shards:
                send(sock, {"msg": "reject", "reason": f"unknown client {c}"}); sock.close(); return
            if c in self.conns:
                send(sock, {"msg": "reject", "reason": f"duplicate client {c}"})
                self.failures[c] = "duplicate shard claim"; sock.close(); return
            self.conns[c] = sock
            self.hello[c] = hello
        send(sock, {"msg": "shard", "run_id": self.run_id, "client": c, "workload": self.shards[c],
                    "profile": self.profile, "content": self.content})
        r = recv(sock)
        if not r or r.get("msg") != "ready":
            with self.lock:
                self.failures[c] = f"not ready: {r}"
            return
        with self.lock:
            self.clock[c] = self._probe_clock(c, sock)
            self.hello[c]["ready"] = r
            self.ready_count = getattr(self, "ready_count", 0) + 1
            self.ready_event.set() if self.ready_count == len(self.clients) else None

    def _accept_loop(self, srv):
        """Accept until the run ends, so a late or duplicate client is rejected
        by name and recorded rather than refused at the socket."""
        while not self.finished.is_set():
            try:
                sock, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._serve_client, args=(sock, addr), daemon=True).start()

    def run(self):
        host, port = self.bind.rsplit(":", 1)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, int(port))); srv.listen(len(self.clients) + 4)
        srv.settimeout(0.2)
        self.ready_event = threading.Event()
        self.finished = threading.Event()
        self.bound_port = srv.getsockname()[1]
        threading.Thread(target=self._accept_loop, args=(srv,), daemon=True).start()
        self.ready_event.wait(self.timeout_s)
        status = "complete"
        missing = [c for c in self.clients if c not in self.conns]
        if missing or self.failures or not self.ready_event.is_set():
            status = "partial"
            self.manifest["failures"] = dict(self.failures, **{c: "never connected" for c in missing})
            for c, sock in self.conns.items():
                try:
                    send(sock, {"msg": "abort", "reason": "not all clients ready"})
                except OSError:
                    pass
            self.finished.set(); srv.close()
            self._write(status, [])
            return status
        # Everyone is ready: start together.
        start_ns = time.monotonic_ns()
        self.manifest["start_coordinator_ns"] = start_ns
        for c, sock in self.conns.items():
            send(sock, {"msg": "start", "coordinator_ns": start_ns})
        for c, sock in self.conns.items():
            r = recv(sock)
            if not r or r.get("msg") != "done":
                self.failures[c] = f"no result: {r}"; status = "partial"; continue
            self.results[c] = r
            end_probe = self._probe_clock(c, sock) if r.get("keep_open") else None
            if end_probe:
                self.clock[c]["end_offset_ns"] = end_probe["offset_ns"]
                self.clock[c]["drift_ns"] = end_probe["offset_ns"] - self.clock[c]["offset_ns"]
            try:
                send(sock, {"msg": "bye"})
            except OSError:
                pass
        if self.failures:                 # a duplicate claim arrived during the run
            status = "partial"
            self.manifest["failures"] = dict(self.failures)
        self.finished.set(); srv.close()
        rows = self._merge()
        self._write(status, rows)
        return status

    def _merge(self):
        rows = []
        for c, r in self.results.items():
            off = self.clock[c]["offset_ns"]
            t0 = r["start_client_ns"]
            for row in r["rows"]:
                row = dict(row); row["client"] = c
                for k in ("release_ns", "eligible_ns", "submit_ns", "complete_ns"):
                    if row.get(k) is not None:
                        row[f"coord_{k}"] = row[k] + t0 - off - self.manifest["start_coordinator_ns"]
                rows.append(row)
        return rows

    def _write(self, status, rows):
        self.manifest["status"] = status
        self.manifest["clocks"] = self.clock
        self.manifest["client_hello"] = self.hello
        with open(self.out / "merged-ledger.jsonl", "w") as f:
            for r in rows:
                f.write(json.dumps(r, sort_keys=True) + "\n")
        summary = {"status": status, "run_id": self.run_id, "clients": {}, "pooled": None}
        for c, r in self.results.items():
            summary["clients"][c] = r["summary"]
            (self.out / f"client-{c}").mkdir(exist_ok=True)
            (self.out / f"client-{c}" / "ledger.jsonl").write_text(
                "".join(json.dumps(x, sort_keys=True) + "\n" for x in r["rows"]))
            (self.out / f"client-{c}" / "summary.json").write_text(json.dumps(r["summary"], indent=2, sort_keys=True) + "\n")
            if r.get("manifest"):
                (self.out / f"client-{c}" / "fidelity-manifest.json").write_text(json.dumps(r["manifest"], indent=2, sort_keys=True) + "\n")
        if rows:
            summary["pooled"] = pooled_metrics(rows)
        self.manifest["summary"] = summary
        (self.out / "run-manifest.json").write_text(json.dumps(self.manifest, indent=2, sort_keys=True) + "\n")
        (self.out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")


def pooled_metrics(rows):
    """Pooled samples, never averaged per-client quantiles."""
    done = [r for r in rows if r.get("complete_ns") is not None]
    def pct(v, q):
        if not v:
            return None
        v = sorted(v); return v[min(len(v) - 1, int(q * len(v)))]
    rtc = [r["complete_ns"] - r["release_ns"] for r in done]
    stc = [r["complete_ns"] - r["submit_ns"] for r in done]
    lag = [r["submit_ns"] - r["eligible_ns"] for r in done]
    outcomes = {}
    for r in rows:
        outcomes[r.get("outcome")] = outcomes.get(r.get("outcome"), 0) + 1
    span = (max(r["coord_complete_ns"] for r in done) - min(r["coord_release_ns"] for r in done)) if done else 0
    return {"operations": len(rows), "completed": len(done), "outcomes": outcomes,
            "release_to_complete_ns": {"p50": pct(rtc, .5), "p95": pct(rtc, .95), "p99": pct(rtc, .99)},
            "submit_to_complete_ns": {"p50": pct(stc, .5), "p95": pct(stc, .95), "p99": pct(stc, .99)},
            "scheduler_lag_ns": {"p50": pct(lag, .5), "p95": pct(lag, .95), "max": max(lag) if lag else None},
            "completed_bytes": sum(r.get("completed_bytes", 0) for r in done),
            "span_ns_coordinator_domain": span,
            "throughput_ops_per_s": (len(done) / (span / 1e9)) if span else None}


# ----------------------------------------------------------------- client
def run_client(coordinator, client_id, *, engine_name, provider, target_config, workers=8,
               declared_delay_ns=0, keep_open=True):
    host, port = coordinator.rsplit(":", 1)
    sock = socket.create_connection((host, int(port)), timeout=600)
    sock.settimeout(None)
    send(sock, {"msg": "hello", "client": client_id, "host": platform.node(), "pid": os.getpid(),
                "python": sys.version.split()[0]})
    r = recv(sock)
    if not r or r.get("msg") != "shard":
        raise RuntimeError(f"coordinator refused: {r}")
    wl = r["workload"]
    workload3.validate_workload(wl)
    spec = engines.preflight(wl, engine_name, provider)
    cfg = dict(target_config or {})
    cfg["provider"] = provider
    cfg.setdefault("content_profile", r["content"])
    backend = spec.make(cfg)
    if hasattr(backend, "profile"):
        backend.profile = content_profile.parse_profile(r["content"])
    ex = intent_exec.Executor(wl, backend, profile=r["profile"], mode="real", workers=workers,
                              declared_delay_ns=declared_delay_ns, content=r["content"])
    send(sock, {"msg": "ready", "engine": engine_name, "provider": provider,
                "operations": len(wl["operations"])})
    # Clock probes, then wait for the start.
    while True:
        m = recv(sock)
        if m is None:
            raise RuntimeError("coordinator went away before start")
        if m["msg"] == "ping":
            send(sock, {"msg": "pong", "t0": m["t0"], "t_client": time.monotonic_ns()})
        elif m["msg"] == "start":
            break
        elif m["msg"] == "abort":
            backend.close()
            return {"status": "aborted", "reason": m.get("reason")}
    start_client_ns = time.monotonic_ns()
    rows, result = ex.run()
    result["dependency_violations"] = intent_exec.check_dependencies(rows, wl, declared_delay_ns)
    public_cfg = {k: v for k, v in cfg.items() if k not in ("access_key", "secret_key", "token")}
    man = engines.fidelity_manifest(wl, spec, provider, public_cfg, timing_profile=r["profile"],
                                    content_profile=r["content"], backend=backend)
    if hasattr(backend, "final_state"):
        man["final_state"] = backend.final_state()
    send(sock, {"msg": "done", "client": client_id, "start_client_ns": start_client_ns,
                "rows": [x.__dict__ for x in rows], "summary": result, "manifest": man, "keep_open": keep_open})
    if keep_open:
        while True:
            m = recv(sock)
            if m is None or m["msg"] == "bye":
                break
            if m["msg"] == "ping":
                send(sock, {"msg": "pong", "t0": m["t0"], "t_client": time.monotonic_ns()})
    backend.close()
    return {"status": "done", "summary": result}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--workload", required=True)
    s.add_argument("--clients", required=True, help="count, or comma-separated client ids")
    s.add_argument("--bind", default="127.0.0.1:39020")
    s.add_argument("--profile", choices=intent_exec.PROFILES, default="dependency")
    s.add_argument("--content-profile", default="incompressible")
    s.add_argument("--assign", help="JSON {stream: client} to override round-robin")
    s.add_argument("--timeout", type=int, default=3600)
    s.add_argument("--out", required=True)
    c = sub.add_parser("client")
    c.add_argument("--coordinator", required=True)
    c.add_argument("--client-id", required=True)
    c.add_argument("--engine-name", required=True)
    c.add_argument("--provider")
    c.add_argument("--target-config", help="JSON file with the engine's local configuration")
    c.add_argument("--workers", type=int, default=8)
    c.add_argument("--declared-delay-ns", type=int, default=0)
    args = ap.parse_args(argv)
    if args.cmd == "serve":
        wl = intent_exec.load_any(args.workload)
        if wl.get("schema") != workload3.SCHEMA:
            wl = workload3.from_intent2(wl)
        ids = [f"c{i}" for i in range(int(args.clients))] if args.clients.isdigit() else args.clients.split(",")
        assignment = json.loads(args.assign) if args.assign else None
        try:
            coord = Coordinator(wl, ids, bind=args.bind, profile=args.profile, out=args.out,
                                content=args.content_profile, assignment=assignment, timeout_s=args.timeout)
        except CrossShardError as error:
            print(f"kvio coordinator: {error}", file=sys.stderr); return 2
        print(json.dumps({"run_id": coord.run_id, "bind": args.bind, "shards": coord.manifest["clients"]}), flush=True)
        status = coord.run()
        print(json.dumps({"status": status, "out": str(coord.out)}))
        return 0 if status == "complete" else 1
    cfg = json.loads(Path(args.target_config).read_text()) if args.target_config else {}
    res = run_client(args.coordinator, args.client_id, engine_name=args.engine_name, provider=args.provider,
                     target_config=cfg, workers=args.workers, declared_delay_ns=args.declared_delay_ns)
    print(json.dumps({"client": args.client_id, "status": res["status"],
                      "outcomes": res.get("summary", {}).get("outcomes")}))
    return 0 if res["status"] == "done" else 1


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.exit(main())
