#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Convert kvio traces into a Perfetto trace (.pftrace, native TrackEvent).

Inputs are the two kvio JSONL trace layers:
  * the LMCache semantic trace (LMCACHE_KVIO_TRACE): one record per KV object
    store/load with trace_id, key, bytes, slot_offset and an op-END timestamp
    (time.monotonic() seconds);
  * the eBPF nvme_uring_cmd_monitor trace: one record per NVMe passthrough
    command submission (event_type=nvme_cmd) with user_data, slba, data_len
    and a bpf_ktime_get_ns() timestamp.

Both timestamps are the SAME CLOCK_MONOTONIC on one host/boot, so no offset
estimation is done (or needed): semantic events are placed at ts*1e9 on the
eBPF nanosecond timeline.  The join key is trace_id = user_data >> 32;
trace_id 0 is untagged traffic (metadata IO, foreign passthrough users).

Output mapping (one process group per --label / --merge arm):
  Process "LMCache <label>"   object spans on auto-assigned lanes
                              (span = first device cmd .. semantic op-end),
                              per-object args: trace_id, op, rank + fmt
                              (parsed from the key; NOTE: MP-server captures
                              record rank 0 for every object and encode the
                              shard identity in the key's second/fmt field —
                              group by debug.fmt for per-shard queries),
                              chunk sha, bytes, slot_offset, n_cmds,
                              op_latency_ms; + objects-in-flight counter.
  Process "NVMe <dev> <label>" one slice per command on writes/reads/other/
                              untagged tracks (nominal durations; real
                              durations are used automatically when
                              event_type=nvme_cmp completion records are
                              present, and overlapping commands then spread
                              onto per-role lanes), args: slba, data_len,
                              trace_id, role=header|payload; + cmds/ms,
                              MB/s and slba-over-time counters.
  Flow arrows link each object span to its first and last device command.

Merge mode overlays multiple captures (A/B arms, real-vs-replay) as separate
process groups; every arm is rebased to t=0 by default because separate runs
occupy unrelated CLOCK_MONOTONIC windows.  --no-rebase keeps true absolute
CLOCK_MONOTONIC nanoseconds (same-boot captures only).

The converter tolerates a truncated final line (live or wedged captures may
be converted mid-flight) and prints a kvio_validate-style self-check whose
numbers must line up with kvio_validate.py on the same capture.

Requires: pip install perfetto  (ships the TrackEvent proto builder).
View: drag the .pftrace onto https://ui.perfetto.dev (processing is local).
Query: python -c "from perfetto.trace_processor import TraceProcessor; ..."
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
from collections import defaultdict

NOMINAL_DUR_NS = 8000          # per-command slice length until completions exist
LANE_GAP_FRACTION = 0.9        # cap nominal dur at this fraction of the gap
SEQ = 1                        # single-writer trusted_packet_sequence_id


# ---------------------------------------------------------------- loading

def load_jsonl(path):
    """Tolerant JSONL reader: skips malformed lines (a live or killed capture
    typically has one truncated tail line) and reports what it skipped."""
    rows, skipped = [], 0
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                skipped += 1
    return rows, skipped


def classify(rows):
    """Split rows into (semantic, nvme_cmd, nvme_cmp, anchors, meta, other)."""
    sem, cmd, cmp_, anchors, meta, other = [], [], [], [], [], 0
    for r in rows:
        et = r.get("event_type")
        if et == "nvme_cmd":
            cmd.append(r)
        elif et == "nvme_cmp":          # P2 completion records
            cmp_.append(r)
        elif et == "clock_anchor":      # P2 wall-clock anchors
            anchors.append(r)
        elif et == "kvio_meta":         # P3 self-describing header line
            meta.append(r)
        elif et is None and "op" in r and "trace_id" in r:
            sem.append(r)
        else:
            other += 1
    return sem, cmd, cmp_, anchors, meta, other


# ---------------------------------------------------------------- helpers

def uid(*parts):
    """Deterministic 63-bit track uuid / flow id from a name path."""
    h = hashlib.md5("/".join(str(p) for p in parts).encode()).digest()
    return int.from_bytes(h[:8], "big") & 0x7FFFFFFFFFFFFFFF


def parse_key(key):
    """LMCache raw-block keys look like model@fmt@rank@sha256.  Returns
    (rank, sha, fmt).  CAVEAT (verified on the TP2/TP4 MP captures): the
    rank field is 0 for every object in MP-server captures; the per-shard
    identity is carried by distinct values of the fmt field instead — so fmt
    is surfaced as its own arg for per-shard grouping."""
    parts = str(key).split("@")
    rank = int(parts[2]) if len(parts) >= 4 and parts[2].isdigit() else None
    sha = parts[3][:12] if len(parts) >= 4 else None
    fmt = parts[1] if len(parts) >= 4 else None
    return rank, sha, fmt


def assign_lanes(spans):
    """Greedy interval-graph coloring: spans overlapping in time land on
    different lanes.  Strict inequality so spans touching at one ns never
    share a lane (a shared boundary would garble begin/end pairing).
    Deterministic."""
    lane_free = []                                   # end ts per lane
    out = []
    for begin, end, item in sorted(spans, key=lambda s: (s[0], s[1])):
        for i, free_at in enumerate(lane_free):
            if free_at < begin:
                lane_free[i] = end
                out.append((i, item))
                break
        else:
            lane_free.append(end)
            out.append((len(lane_free) - 1, item))
    return out, len(lane_free)


def parse_trace_id_range(spec):
    if spec is None:
        return None
    a, _, b = spec.partition("-")
    lo = int(a)
    hi = int(b) if b else lo
    return (lo, hi)


def pair_completions(cmds_ts, cmps_ts):
    """Consuming merge-join: assign each completion (ts-sorted) to the LATEST
    not-yet-paired submission with cmd_ts <= cmp_ts.  Under an -EAGAIN
    re-issue (two submissions, one completion) the re-issue gets the
    completion and the failed first attempt falls back to nominal duration.
    Each completion serves at most one submission.  Returns {cmd_index: dur}.
    O(n log n)."""
    out = {}
    cmd_ix = sorted(range(len(cmds_ts)), key=lambda i: cmds_ts[i])
    unpaired = []                                     # stack of cmd indices
    ci = 0
    for cts in sorted(cmps_ts):
        while ci < len(cmd_ix) and cmds_ts[cmd_ix[ci]] <= cts:
            unpaired.append(cmd_ix[ci])
            ci += 1
        if unpaired:
            i = unpaired.pop()                        # latest eligible
            out[i] = cts - cmds_ts[i]
    return out


# ---------------------------------------------------------------- capture

class Capture:
    """One (label, semantic?, ebpf?) arm, joined."""

    def __init__(self, label, sem_path, ebpf_path, serving_path, args):
        self.label = label
        self.stats = {"sem_file": sem_path or "-", "ebpf_file": ebpf_path or "-",
                      "serving_file": serving_path or "-",
                      "sem_skipped": 0, "ebpf_skipped": 0, "other_lines": 0,
                      "dup_trace_id": 0, "clock_anomalies": 0}
        self.warnings = []
        sem, cmds = [], []
        self.cmps, self.anchors = [], []
        self.kmeta = None
        if sem_path:
            rows, sk = load_jsonl(sem_path)
            s, c, p, a, m, o = classify(rows)
            sem = s
            if m:
                self.kmeta = m[0]
            self.stats["sem_skipped"] = sk
            self.stats["other_lines"] += o + len(c)
        if ebpf_path:
            rows, sk = load_jsonl(ebpf_path)
            s, c, p, a, m, o = classify(rows)
            cmds, self.cmps, self.anchors = c, p, a
            if m and self.kmeta is None:
                self.kmeta = m[0]
            self.stats["ebpf_skipped"] = sk
            self.stats["other_lines"] += o + len(s)
        # serving-layer request spans: any JSONL whose records carry
        # ts_start + ts (monotonic seconds) and an op/name — the E6 driver
        # emits {"op":"recompute"|"load_ttft",...} so both arms of the
        # crossover render side by side above the device activity.
        self.serving = []
        if serving_path:
            rows, sk = load_jsonl(serving_path)
            self.serving = [r for r in rows
                            if "ts" in r and "ts_start" in r]
            self.stats["serving_skipped"] = sk + (len(rows) - len(self.serving))
        self.stats["serving_spans"] = len(self.serving)
        self.stats["sem_records"] = len(sem)
        self.stats["nvme_cmd_lines"] = len(cmds)
        self.stats["nvme_cmp_lines"] = len(self.cmps)

        # --- join ------------------------------------------------------
        # A trace_id can legitimately repeat only if two RawBlockCore
        # instances share one trace file (P3 adds an instance field); keep
        # every occurrence and segment its commands by op-end time below.
        self.sem_occs = defaultdict(list)             # tid -> [records]
        for r in sem:
            tid = int(r["trace_id"])
            if self.sem_occs[tid]:
                self.stats["dup_trace_id"] += 1
            self.sem_occs[tid].append(r)
        for occs in self.sem_occs.values():
            occs.sort(key=lambda r: float(r["ts"]))
        insts = {r.get("instance") for rs in self.sem_occs.values() for r in rs}
        insts.discard(None)
        if len(insts) > 1:
            self.warnings.append(
                f"{len(insts)} producer instances share this trace file — "
                "device-command attribution across instances is ambiguous "
                "(same trace_id space)")
        for c in cmds:
            c["tid"] = int(c.get("user_data", 0)) >> 32
        self.cmds = cmds
        self.cmds_by_tid = defaultdict(list)
        for c in cmds:
            self.cmds_by_tid[c["tid"]].append(c)

        # completion pairing (consuming merge-join per user_data)
        self.dur_by_id = {}
        if self.cmps:
            cmd_by_ud, cmp_by_ud = defaultdict(list), defaultdict(list)
            for c in cmds:
                cmd_by_ud[int(c.get("user_data", 0))].append(c)
            for p in self.cmps:
                cmp_by_ud[int(p.get("user_data", 0))].append(int(p["ts"]))
            for ud, cl in cmd_by_ud.items():
                pend = cmp_by_ud.get(ud)
                if not pend:
                    continue
                durs = pair_completions([int(c["ts"]) for c in cl], pend)
                for i, dur in durs.items():
                    self.dur_by_id[id(cl[i])] = dur

        # --- filters ---------------------------------------------------
        tr = parse_trace_id_range(args.trace_id)
        if tr:
            lo, hi = tr
            self.cmds = [c for c in self.cmds if lo <= c["tid"] <= hi]
            self.sem_occs = defaultdict(list, {
                t: rs for t, rs in self.sem_occs.items() if lo <= t <= hi})
            self.cmds_by_tid = defaultdict(list)
            for c in self.cmds:
                self.cmds_by_tid[c["tid"]].append(c)

        # --- occurrence segmentation (raw ns, clock-shared) ------------
        # occ_of[id(cmd)] = index into sem_occs[tid]; cmds after the last
        # op-end belong to the last occurrence.
        self.occ_of = {}
        for tid, occs in self.sem_occs.items():
            cl = sorted(self.cmds_by_tid.get(tid, []), key=lambda c: int(c["ts"]))
            ends = [int(float(r["ts"]) * 1e9) for r in occs]
            j = 0
            for c in cl:
                while j < len(ends) - 1 and int(c["ts"]) > ends[j]:
                    j += 1
                self.occ_of[id(c)] = j

        # --- lba-size inference (header classification sanity) ---------
        # The capture-time --lba-size is not recorded in the JSONL; a wrong
        # value silently classifies every store command as payload.  Test
        # the flag value plus the common candidates and keep the best.
        self.lba_bytes = args.lba_bytes
        cand = []
        for v in (args.lba_bytes, 4096, 512):
            if v not in cand:
                cand.append(v)
        score = {v: 0 for v in cand}
        sampled = 0
        for tid, occs in self.sem_occs.items():
            for oi, r in enumerate(occs):
                if r.get("op") != "store":
                    continue
                slot = int(r.get("slot_offset", -1))
                slbas = [int(c.get("slba", 0)) for c in self.cmds_by_tid.get(tid, [])
                         if self.occ_of.get(id(c)) == oi]
                if not slbas:
                    continue
                for v in cand:
                    if any(s * v == slot for s in slbas):
                        score[v] += 1
                sampled += 1
                if sampled >= 50:
                    break
            if sampled >= 50:
                break
        if sampled:
            best = max(cand, key=lambda v: score[v])
            if score[best] == 0:
                self.warnings.append(
                    "header classification: no store command matches "
                    "slot_offset under any candidate LBA size — headers "
                    "will read as payload")
            elif best != args.lba_bytes:
                self.warnings.append(
                    f"--lba-bytes {args.lba_bytes} matches no headers; "
                    f"inferred lba_bytes={best} (matched {score[best]}/{sampled} "
                    "sampled stores) and using it")
                self.lba_bytes = best

        # --- rebase ----------------------------------------------------
        ts_candidates = [int(c["ts"]) for c in self.cmds]
        for occs in self.sem_occs.values():
            ts_candidates += [int(float(r["ts"]) * 1e9) for r in occs]
        ts_candidates += [int(float(r["ts_start"]) * 1e9) for r in self.serving]
        self.base_ns = min(ts_candidates) if ts_candidates else 0


# ---------------------------------------------------------------- emission

def emit(captures, args, out_file):
    from perfetto.trace_builder.proto_builder import StreamingTraceProtoBuilder
    from perfetto.protos.perfetto.trace.perfetto_trace_pb2 import TrackEvent

    b = StreamingTraceProtoBuilder(out_file)
    emitted = defaultdict(int)
    T = TrackEvent

    def track(uuid, name=None, parent=None, pid=None, pname=None, unit=None,
              order=None):
        p = b.create_packet()
        d = p.track_descriptor
        d.uuid = uuid
        if parent is not None:
            d.parent_uuid = parent
        if name is not None:
            d.name = name
        if pid is not None:
            d.process.pid = pid
            d.process.process_name = pname
            # children carry sibling_order_rank; without EXPLICIT ordering the
            # UI falls back to uuid order, which differs per label and makes
            # A/B arms' collapsed summaries render different tracks first.
            d.child_ordering = d.EXPLICIT
        if unit is not None:
            d.counter.unit_name = unit
        if order is not None:
            d.sibling_order_rank = order
        b.write_packet(p)

    def build_event(spec):
        """Construct the TracePacket for one buffered event spec.  Specs are
        small tuples so the whole trace is never held as protobufs in RAM
        (the 70B capture is ~700k packets)."""
        ts, typ, uuid_, name, flows, tflows, counter, counter_d, args_ = spec
        p = b.create_packet()
        p.timestamp = max(0, ts)
        p.trusted_packet_sequence_id = SEQ
        te = p.track_event
        te.type = typ
        te.track_uuid = uuid_
        if name is not None:
            te.name = name
        for fl in flows:
            te.flow_ids.append(fl)
        for fl in tflows:
            te.terminating_flow_ids.append(fl)
        if counter is not None:
            te.counter_value = int(counter)
        if counter_d is not None:
            te.double_counter_value = float(counter_d)
        for k, v in (args_ or {}).items():
            if v is None:
                continue
            a = te.debug_annotations.add()
            a.name = k
            if isinstance(v, bool):
                a.bool_value = v
            elif isinstance(v, int):
                if v < 0:
                    a.int_value = v
                else:
                    a.uint_value = v
            elif isinstance(v, float):
                a.double_value = v
            else:
                a.string_value = str(v)
        return p

    def ev(ts, typ, uuid_, name=None, flows=(), tflows=(), counter=None,
           counter_d=None, args_=None):
        return (ts, typ, uuid_, name, flows, tflows, counter, counter_d, args_)

    # (ts, order, spec, span_lo, span_hi): span keeps a slice's begin/end
    # pair together under --time-range (kept iff the span overlaps).
    events = []

    def add_point(ts, order, spec):
        events.append((ts, order, spec, ts, ts))

    def add_span(ts0, ts1, spec_begin, spec_end, order0=2, order1=3):
        events.append((ts0, order0, spec_begin, ts0, ts1))
        events.append((ts1, order1, spec_end, ts0, ts1))

    for li, cap in enumerate(captures):
        L = cap.label
        # rebase: per-capture base by default; --no-rebase keeps absolute
        # CLOCK_MONOTONIC ns (same-boot captures only).
        base = 0 if args.no_rebase else cap.base_ns
        rel = lambda ts_ns: int(ts_ns) - base  # noqa: E731
        stats = cap.stats

        # ---- fixed track descriptors ---------------------------------
        lm_proc = uid(L, "lmcache", "proc")
        nv_proc = uid(L, "nvme", "proc")
        track(lm_proc, pid=1000 + 3 * li, pname=f"LMCache {L}")
        track(nv_proc, pid=1001 + 3 * li, pname=f"NVMe {args.device} {L}")
        meta_trk = uid(L, "lmcache", "meta")
        track(meta_trk, name="capture info", parent=lm_proc, order=0)
        obj_ctr = uid(L, "lmcache", "inflight")
        track(obj_ctr, name="objects in flight", parent=lm_proc, unit="objects", order=1)
        ctr_cmds = uid(L, "nvme", "cmds_ms")
        track(ctr_cmds, name="cmds/ms", parent=nv_proc, unit="cmds", order=90)
        ctr_mbs = uid(L, "nvme", "mb_s")
        track(ctr_mbs, name="MB/s", parent=nv_proc, unit="MB/s", order=91)
        ctr_slba = {}
        if not args.no_slba_counter:
            for op in ("write", "read"):
                ctr_slba[op] = uid(L, "nvme", "slba", op)
                track(ctr_slba[op], name=f"slba ({op}s)", parent=nv_proc,
                      unit="LBA", order=92 if op == "write" else 93)

        cinfo = {"label": L, "base_ns": cap.base_ns,
                 "applied_base_ns": base,
                 "rebased": not args.no_rebase,
                 "sem_file": stats["sem_file"],
                 "ebpf_file": stats["ebpf_file"],
                 "lba_bytes": cap.lba_bytes,
                 "anchors": len(cap.anchors)}
        if cap.kmeta:
            for k in ("kvio_schema", "hostname", "device_path", "io_engine",
                      "block_align", "header_bytes", "max_data_transfer_size"):
                if cap.kmeta.get(k) is not None:
                    cinfo[k] = cap.kmeta[k]
        add_point(0, 0, ev(0, T.TYPE_INSTANT, meta_trk, "capture_info",
                           args_=cinfo))

        # ---- serving request spans -----------------------------------
        if cap.serving:
            sv_proc = uid(L, "serving", "proc")
            track(sv_proc, pid=1002 + 3 * li, pname=f"Serving {L}")
            sv_spans = []
            for r in cap.serving:
                b_ = rel(int(float(r["ts_start"]) * 1e9))
                e_ = rel(int(float(r["ts"]) * 1e9))
                if e_ <= b_:
                    e_ = b_ + 1
                sv_spans.append((b_, e_, r))
            sv_laned, sv_n = assign_lanes(sv_spans)
            sv_uuid = {}
            for lane in range(sv_n):
                sv_uuid[lane] = uid(L, "serving", "lane", lane)
                track(sv_uuid[lane], name=f"requests.{lane:03d}", parent=sv_proc, order=10 + lane)
            for lane, r in sv_laned:
                b_ = rel(int(float(r["ts_start"]) * 1e9))
                e_ = rel(int(float(r["ts"]) * 1e9))
                if e_ <= b_:
                    e_ = b_ + 1
                nm = r.get("op") or r.get("name") or "request"
                add_span(b_, e_,
                         ev(b_, T.TYPE_SLICE_BEGIN, sv_uuid[lane], str(nm),
                            args_={"op": r.get("op"),
                                   "tokens": r.get("tokens"),
                                   "request_id": r.get("request_id"),
                                   "ms": (e_ - b_) / 1e6}),
                         ev(e_, T.TYPE_SLICE_END, sv_uuid[lane]))
                emitted["serving_spans"] += 1

        # ---- object spans (one per semantic occurrence) --------------
        spans, instants = [], []
        for tid, occs in cap.sem_occs.items():
            for oi, r in enumerate(occs):
                end_ns = rel(int(float(r["ts"]) * 1e9))
                # schema-2 op-start: the true leading edge (includes Python
                # pre-submit time the device stream cannot see); legacy
                # captures fall back to the first device command.
                t0 = r.get("ts_start")
                start_ns = rel(int(float(t0) * 1e9)) if t0 is not None else None
                cmds = [c for c in cap.cmds_by_tid.get(tid, [])
                        if cap.occ_of.get(id(c)) == oi]
                if cmds:
                    first_cmd = rel(min(int(c["ts"]) for c in cmds))
                    max_cmd = rel(max(int(c["ts"]) for c in cmds))
                    begin_ns = (min(start_ns, first_cmd)
                                if start_ns is not None else first_cmd)
                    if end_ns < max_cmd:        # same clock: must not happen
                        stats["clock_anomalies"] += 1
                        end_ns = max_cmd
                    spans.append((begin_ns, end_ns, (tid, oi, r, cmds)))
                elif start_ns is not None and end_ns > start_ns:
                    spans.append((start_ns, end_ns, (tid, oi, r, cmds)))
                else:
                    instants.append((end_ns, tid, oi, r))

        laned, nlanes = assign_lanes(spans)
        lane_uuid = {}
        if nlanes:
            obj_grp = uid(L, "lmcache", "objgroup")
            track(obj_grp, name="objects", parent=lm_proc, order=10)
            for lane in range(nlanes):
                lane_uuid[lane] = uid(L, "lmcache", "lane", lane)
                track(lane_uuid[lane], name=f"objects.{lane:03d}", parent=obj_grp,
                      order=lane)

        flow_of = {}                                  # (tid, oi) -> flow id
        span_ix = {id(it): (b_, e_) for b_, e_, it in spans}
        for lane, item in laned:
            tid, oi, r, cmds = item
            begin_ns, end_ns = span_ix[id(item)]
            rank, sha, fmt = parse_key(r.get("key", ""))
            fid = uid(L, "flow", tid, oi)
            flow_of[(tid, oi)] = fid
            nbytes = int(r.get("bytes", 0))
            name = f"{r.get('op')} {r.get('part', 'kv')} {nbytes / 1048576:.1f}MiB"
            if r.get("error"):
                name += " FAILED"
            a = {"trace_id": tid, "op": r.get("op"),
                 "part": r.get("part"), "bytes": nbytes,
                 "slot_offset": int(r.get("slot_offset", 0)),
                 "rank": rank, "fmt": fmt, "chunk": sha, "n_cmds": len(cmds),
                 "op_latency_ms": (end_ns - begin_ns) / 1e6,
                 "error": r.get("error"), "instance": r.get("instance"),
                 "producer_pid": r.get("pid"),
                 "key": str(r.get("key", ""))[-24:]}
            if len(cap.sem_occs[tid]) > 1:
                a["occurrence"] = oi
            add_span(begin_ns, end_ns,
                     ev(begin_ns, T.TYPE_SLICE_BEGIN, lane_uuid[lane], name,
                        flows=(fid,), args_=a),
                     ev(end_ns, T.TYPE_SLICE_END, lane_uuid[lane]))
            emitted["object_spans"] += 1

        for end_ns, tid, oi, r in instants:           # no device cmds seen
            add_point(end_ns, 2, ev(
                end_ns, T.TYPE_INSTANT, meta_trk,
                f"{r.get('op')} (no device cmds)",
                args_={"trace_id": tid, "no_device_cmds": True}))
            emitted["object_instants"] += 1

        # objects-in-flight counter
        deltas = []
        for b_, e_, _ in spans:
            deltas.append((b_, 1))
            deltas.append((e_, -1))
        cur = 0
        for ts, d in sorted(deltas):
            cur += d
            add_point(ts, 1, ev(ts, T.TYPE_COUNTER, obj_ctr, counter=cur))

        # ---- device command slices -----------------------------------
        per_role = defaultdict(list)
        for c in cap.cmds:
            if c["tid"] == 0:
                role = "untagged"
            elif c.get("op_name") == "write":
                role = "writes"
            elif c.get("op_name") == "read":
                role = "reads"
            else:
                role = "other"
            per_role[role].append(c)

        first_last = {}
        for (tid, oi), fid in flow_of.items():
            cl = [c for c in cap.cmds_by_tid.get(tid, [])
                  if cap.occ_of.get(id(c)) == oi]
            if cl:
                cl.sort(key=lambda c: int(c["ts"]))
                first_last[(tid, oi)] = (id(cl[0]), id(cl[-1]))

        untagged_bytes = tagged_bytes = header_cmds = 0
        for role, cl in per_role.items():
            cl.sort(key=lambda c: int(c["ts"]))
            # durations first (real when completions exist, else nominal
            # capped to the same-role gap)
            entries = []
            for i, c in enumerate(cl):
                ts = rel(int(c["ts"]))
                real = cap.dur_by_id.get(id(c))
                if real is not None:
                    dur = max(1, real)
                else:
                    dur = args.nominal_dur_ns
                    if i + 1 < len(cl):
                        gap = rel(int(cl[i + 1]["ts"])) - ts
                        dur = max(1, min(dur, int(gap * LANE_GAP_FRACTION)))
                entries.append((ts, dur, real is not None, c))
            # real durations can overlap (QD>1): spread onto lanes so no
            # track ever holds two overlapping sync slices.
            if any(e[2] for e in entries):
                laned_cmds, ncl = assign_lanes(
                    [(ts, ts + dur, (ts, dur, is_r, c))
                     for ts, dur, is_r, c in entries])
            else:
                laned_cmds = [(0, e) for e in entries]
                ncl = 1
            # one expandable group per role; zero-padded lane names so the
            # UI's lexicographic sort equals numeric order (10 < 2 as strings
            # otherwise), identical layout in every arm.
            role_rank = {"writes": 10, "reads": 40, "other": 70, "untagged": 80}
            role_uuid = {}
            if ncl == 1:
                role_uuid[0] = uid(L, "nvme", role, "lane", 0)
                track(role_uuid[0], name=role, parent=nv_proc,
                      order=role_rank.get(role, 85))
            else:
                grp = uid(L, "nvme", role, "group")
                track(grp, name=role, parent=nv_proc,
                      order=role_rank.get(role, 85))
                for lane in range(ncl):
                    role_uuid[lane] = uid(L, "nvme", role, "lane", lane)
                    track(role_uuid[lane], name=f"{role}.{lane:03d}", parent=grp,
                          order=lane)

            for lane, (ts, dur, is_real, c) in laned_cmds:
                dlen = int(c.get("data_len", 0))
                tid = c["tid"]
                if tid == 0:
                    untagged_bytes += dlen
                else:
                    tagged_bytes += dlen
                oi = cap.occ_of.get(id(c))
                crole = None
                if oi is not None:
                    sem_r = cap.sem_occs[tid][oi]
                    if sem_r.get("op") == "store":
                        if int(c.get("slba", 0)) * cap.lba_bytes == \
                                int(sem_r.get("slot_offset", -1)):
                            crole = "header"
                            header_cmds += 1
                        else:
                            crole = "payload"
                flows, tflows = (), ()
                fid = flow_of.get((tid, oi))
                fl = first_last.get((tid, oi))
                if fid is not None and fl is not None:
                    fst, lst = fl
                    if id(c) == fst and id(c) != lst:
                        flows = (fid,)
                    elif id(c) == lst:
                        tflows = (fid,)
                add_span(ts, ts + dur,
                         ev(ts, T.TYPE_SLICE_BEGIN, role_uuid[lane],
                            c.get("op_name", "cmd"), flows=flows,
                            tflows=tflows,
                            args_={"slba": int(c.get("slba", 0)),
                                   "data_len": dlen,
                                   "trace_id": tid or None, "role": crole,
                                   "real_dur": is_real}),
                         ev(ts + dur, T.TYPE_SLICE_END, role_uuid[lane]),
                         order0=4, order1=5)
                emitted["cmd_slices"] += 1
                if not args.no_slba_counter and c.get("op_name") in ctr_slba:
                    add_point(ts, 1, ev(ts, T.TYPE_COUNTER,
                                        ctr_slba[c["op_name"]],
                                        counter=int(c.get("slba", 0))))

        stats["untagged_cmds"] = len(per_role.get("untagged", []))
        stats["untagged_bytes"] = untagged_bytes
        stats["tagged_bytes"] = tagged_bytes
        stats["header_cmds"] = header_cmds
        stats["lanes"] = nlanes
        n_store_spans = sum(1 for _, _, it in spans if it[2].get("op") == "store")
        if n_store_spans and header_cmds == 0:
            cap.warnings.append(
                "0 header commands classified across "
                f"{n_store_spans} stores — check --lba-bytes")

        # ---- rate counters -------------------------------------------
        def bucket_counter(track_uuid, bucket_ns, value_fn, scale=None):
            buckets = defaultdict(int)
            for c in cap.cmds:
                buckets[rel(int(c["ts"])) // bucket_ns] += value_fn(c)
            prev = None
            for kb in sorted(buckets):
                ts = kb * bucket_ns
                if prev is not None and kb > prev + 1:
                    z = (prev + 1) * bucket_ns
                    add_point(z, 1, ev(z, T.TYPE_COUNTER, track_uuid,
                                       counter=0 if scale is None else None,
                                       counter_d=None if scale is None else 0.0))
                v = buckets[kb]
                add_point(ts, 1, ev(ts, T.TYPE_COUNTER, track_uuid,
                                    counter=v if scale is None else None,
                                    counter_d=None if scale is None
                                    else v * scale))
                prev = kb
            if prev is not None:
                z = (prev + 1) * bucket_ns
                add_point(z, 1, ev(z, T.TYPE_COUNTER, track_uuid,
                                   counter=0 if scale is None else None,
                                   counter_d=None if scale is None else 0.0))

        bucket_counter(ctr_cmds, 1_000_000, lambda c: 1)                # cmds/ms
        # MB/s: bytes per 10 ms bucket -> MB/s = bytes * 100 / 1e6; emitted
        # as a double counter so sub-1 MB/s traffic stays visible.
        bucket_counter(ctr_mbs, 10_000_000,
                       lambda c: int(c.get("data_len", 0)), scale=1e-4)

    # ---- write, sorted & deterministic --------------------------------
    lo_ns = hi_ns = None
    if args.time_range:
        a, _, bb = args.time_range.partition(",")
        lo_ns, hi_ns = int(float(a) * 1e9), int(float(bb) * 1e9)
    n_written = 0
    for ts, order, spec, s_lo, s_hi in sorted(events, key=lambda e: (e[0], e[1])):
        if lo_ns is not None and (s_hi < lo_ns or s_lo > hi_ns):
            continue
        b.write_packet(build_event(spec))
        n_written += 1
    return emitted, n_written


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sem", help="LMCache semantic JSONL")
    ap.add_argument("--ebpf", help="eBPF nvme_uring_cmd_monitor JSONL")
    ap.add_argument("--serving", help="serving-layer request-span JSONL "
                    "(records with op, ts_start, ts in monotonic seconds; "
                    "e.g. recompute vs load TTFT spans from a benchmark driver)")
    ap.add_argument("--label", default="capture", help="label for the single capture")
    ap.add_argument("--merge", action="append", default=[],
                    metavar="LABEL=SEM,EBPF[,SERVING]",
                    help="add an arm: label=sem.jsonl,ebpf.jsonl[,serving.jsonl] "
                         "(repeatable; use '-' to omit a component)")
    ap.add_argument("-o", "--out", required=True,
                    help="output .pftrace (.gz suffix gzips)")
    ap.add_argument("--no-rebase", action="store_true",
                    help="keep absolute CLOCK_MONOTONIC timestamps "
                         "(same-boot arms only)")
    ap.add_argument("--lba-bytes", type=int, default=4096,
                    help="capture-time --lba-size of the tracer (auto-inferred "
                         "from store headers when the flag value matches none)")
    ap.add_argument("--nominal-dur-ns", type=int, default=NOMINAL_DUR_NS)
    ap.add_argument("--time-range", metavar="START_S,END_S",
                    help="keep only events in this window (seconds, post-rebase)")
    ap.add_argument("--trace-id", metavar="A[-B]",
                    help="keep only this trace_id (range)")
    ap.add_argument("--no-slba-counter", action="store_true")
    ap.add_argument("--device", default="ng", help="device label (old captures "
                    "record no device id)")
    args = ap.parse_args()

    arms = []
    if args.merge:
        for spec in args.merge:
            label, _, files = spec.partition("=")
            parts = (files.split(",") + ["", ""])[:3]
            arms.append(tuple([label] + [None if p in ("", "-") else p
                                         for p in parts]))
    else:
        arms.append((args.label, args.sem, args.ebpf, args.serving))
    if not any(s or e or v for _, s, e, v in arms):
        ap.error("need --sem/--ebpf/--serving or --merge")

    try:
        import perfetto  # noqa: F401
    except ImportError:
        sys.exit("pip install perfetto  (required for .pftrace emission); "
                 "for a zero-dependency fallback see the archived JSON spike "
                 "converter in the kvio evidence bundle")

    captures = [Capture(label, s, e, v, args) for label, s, e, v in arms]

    opener = gzip.open if args.out.endswith(".gz") else open
    with opener(args.out, "wb") as f:
        emitted, n_written = emit(captures, args, f)

    # ---- self-check report (numbers must match kvio_validate) ----------
    print(f"=== kvio2perfetto: wrote {args.out} ({n_written} event packets) ===")
    ok = True
    for cap in captures:
        s = cap.stats
        ops = defaultdict(int)
        for occs in cap.sem_occs.values():
            for r in occs:
                ops[r.get("op")] += 1
        print(f"[{cap.label}]")
        print(f"  semantic: {s['sem_records']} records"
              f" ({', '.join(f'{k} {v}' for k, v in sorted(ops.items())) or '-'})"
              f", {s['sem_skipped']} malformed skipped"
              f", dup trace_id {s['dup_trace_id']}")
        print(f"  device  : {s['nvme_cmd_lines']} nvme_cmd lines"
              f" ({s['ebpf_skipped']} malformed skipped,"
              f" {s['nvme_cmp_lines']} completions,"
              f" {s['other_lines']} other)")
        print(f"  tagged bytes {s.get('tagged_bytes', 0)}"
              f" | untagged {s.get('untagged_cmds', 0)} cmds"
              f" / {s.get('untagged_bytes', 0)} bytes"
              f" | header cmds {s.get('header_cmds', 0)}"
              f" | lanes {s.get('lanes', 0)}"
              f" | clock anomalies {s['clock_anomalies']}")
        for w in cap.warnings:
            print(f"  WARNING: {w}")
            ok = False
        if s["clock_anomalies"]:
            print("  WARNING: semantic op-end earlier than last device command "
                  "— should be impossible on one host/boot; check inputs.")
            ok = False
        if s["dup_trace_id"]:
            print(f"  WARNING: {s['dup_trace_id']} duplicate trace_id(s) — "
                  "multiple producer instances sharing one trace file? "
                  "Spans were segmented by op-end time; treat with care.")
    print(f"  emitted: {emitted.get('object_spans', 0)} object spans, "
          f"{emitted.get('object_instants', 0)} object instants, "
          f"{emitted.get('cmd_slices', 0)} command slices, "
          f"{emitted.get('serving_spans', 0)} serving spans")
    total_sem = sum(s["sem_records"] - s["sem_skipped"] * 0
                    for s in (c.stats for c in captures))
    total_sem = sum(len(rs) for c in captures for rs in c.sem_occs.values())
    total_cmd = sum(len(c.cmds) for c in captures)
    if not args.time_range and not args.trace_id:
        if emitted.get("object_spans", 0) + emitted.get("object_instants", 0) \
                != total_sem:
            print("  SELF-CHECK FAIL: object count mismatch"); ok = False
        if emitted.get("cmd_slices", 0) != total_cmd:
            print("  SELF-CHECK FAIL: command count mismatch"); ok = False
        if ok:
            print("  self-check OK: input == emitted per category")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
