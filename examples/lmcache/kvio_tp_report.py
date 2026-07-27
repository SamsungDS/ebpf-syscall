#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""kvio metrics report over a converted Perfetto trace (P4 SQL pack).

Loads a kvio2perfetto .pftrace with the trace_processor Python API and prints
the canned kvio analyses — per capture label (A/B arms report side by side):

  * QD1 detector — per-object submission-gap analysis: the failure mode where
    128 KiB commands are issued one-at-a-time (the bug class that cost 4-15x
    TTFT) shows as median inter-command gap >> device service time;
  * per-command latency percentiles (real durations, when the tracer captured
    completions) and achieved-QD timeline (%time at QD<=1);
  * per-object spans: device window, end-to-end (schema-2 ts_start..ts), and
    the Python pre-submit cost between them;
  * inferred batches — submission clusters split on a gap threshold: batch
    size and inter-batch gap distributions (contrasts stock vs batched arms
    with no producer-side events);
  * TP all-rank-ready barrier — per chunk, max-min object end across shards
    (grouped by the key fmt field; see kvio2perfetto notes);
  * space axis — slot/LBA reuse and write sequentiality; header-write share;
  * throughput + untagged share; failed ops;
  * A/B: when the trace holds multiple labels, per-object PAIRED diffs
    matched on the object key.

Usage:
  kvio_tp_report.py trace.pftrace [--batch-gap-us 50] [--json out.json]

Requires: pip install perfetto (same dependency as kvio2perfetto.py).
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else 0.0


def fmt_us(ns):
    return f"{ns / 1e3:.1f}us"


def fmt_ms(ns):
    return f"{ns / 1e6:.2f}ms"


def load_trace(path):
    from perfetto.trace_processor import TraceProcessor
    tp = TraceProcessor(trace=path)

    def rows(q):
        out = []
        for r in tp.query(q):
            out.append({k: getattr(r, k) for k in r.__dict__
                        if not k.startswith("_")})
        return out

    # Every kvio track is a proto custom track parented (directly) to a
    # process track, so process_track carries the track name and upid.
    cmds = rows("""
        select pr.name proc, pt.name track, s.ts, s.dur, s.name op,
               extract_arg(s.arg_set_id,'debug.trace_id') tid,
               extract_arg(s.arg_set_id,'debug.slba') slba,
               extract_arg(s.arg_set_id,'debug.data_len') dlen,
               extract_arg(s.arg_set_id,'debug.role') role,
               extract_arg(s.arg_set_id,'debug.real_dur') real
        from slice s
        join process_track pt on s.track_id = pt.id
        join process pr on pt.upid = pr.upid
        where pt.name like 'writes%' or pt.name like 'reads%'
           or pt.name like 'other%' or pt.name like 'untagged%'""")
    objs = rows("""
        select pr.name proc, s.ts, s.dur, s.name,
               extract_arg(s.arg_set_id,'debug.trace_id') tid,
               extract_arg(s.arg_set_id,'debug.op') op,
               extract_arg(s.arg_set_id,'debug.bytes') bytes,
               extract_arg(s.arg_set_id,'debug.n_cmds') n_cmds,
               extract_arg(s.arg_set_id,'debug.rank') rank,
               extract_arg(s.arg_set_id,'debug.fmt') fmt,
               extract_arg(s.arg_set_id,'debug.chunk') chunk,
               extract_arg(s.arg_set_id,'debug.key') key,
               extract_arg(s.arg_set_id,'debug.error') error,
               extract_arg(s.arg_set_id,'debug.slot_offset') slot
        from slice s
        join process_track pt on s.track_id = pt.id
        join process pr on pt.upid = pr.upid
        where pt.name like 'objects%'""")
    info = rows("""
        select pr.name proc,
               extract_arg(s.arg_set_id,'debug.label') label,
               extract_arg(s.arg_set_id,'debug.kvio_schema') schema,
               extract_arg(s.arg_set_id,'debug.hostname') hostname,
               extract_arg(s.arg_set_id,'debug.device_path') device,
               extract_arg(s.arg_set_id,'debug.lba_bytes') lba_bytes,
               extract_arg(s.arg_set_id,'debug.header_bytes') header_bytes
        from slice s
        join process_track pt on s.track_id = pt.id
        join process pr on pt.upid = pr.upid
        where s.name = 'capture_info'""")
    serving = rows("""
        select pr.name proc, pt.name track, s.ts, s.dur, s.name,
               extract_arg(s.arg_set_id,'debug.op') op,
               extract_arg(s.arg_set_id,'debug.tokens') tokens
        from slice s
        join process_track pt on s.track_id = pt.id
        join process pr on pt.upid = pr.upid
        where pr.name like 'Serving%'""")
    tp.close()
    return cmds, objs, info, serving


def label_of(proc):
    # process names are "LMCache <label>" / "NVMe <dev> <label>" / "Serving <label>"
    if proc.startswith("LMCache "):
        return proc[len("LMCache "):]
    if proc.startswith("Serving "):
        return proc[len("Serving "):]
    if proc.startswith("NVMe "):
        return proc.split(" ", 2)[-1]
    return proc


def analyze_label(label, cmds, objs, info, serving, batch_gap_ns):
    R = {"label": label}
    out = [f"===== [{label}] ====="]
    if info:
        i = info[0]
        out.append(f"  capture : schema={i.get('schema')} host={i.get('hostname')} "
                   f"dev={i.get('device')} lba={i.get('lba_bytes')}")
        R["info"] = {k: i.get(k) for k in ("schema", "hostname", "device",
                                           "lba_bytes", "header_bytes")}
    lba = (info[0].get("lba_bytes") if info else None) or 4096
    hdr = (info[0].get("header_bytes") if info else None) or 131072

    # ---- commands -----------------------------------------------------
    tagged = [c for c in cmds if c["tid"]]
    untagged = [c for c in cmds if not c["tid"]]
    # transports with no user_data channel (GDS, NIXL, plain block IO via the
    # nvme-tracepoint monitor) are 100% untagged: per-command analyses fall
    # back to ALL commands; only the per-object analyses need the tags.
    pool = tagged if tagged else cmds
    total_bytes = sum(c["dlen"] or 0 for c in pool)
    wall = (max((c["ts"] + c["dur"]) for c in cmds) - min(c["ts"] for c in cmds)) \
        if cmds else 0
    n_real = sum(1 for c in cmds if c["real"])
    out.append(f"  commands: {len(cmds)} ({len(tagged)} tagged / "
               f"{len(untagged)} untagged), {total_bytes / 1e9:.2f} GB tagged, "
               f"wall {wall / 1e9:.2f}s, real-duration coverage "
               f"{100 * n_real / max(1, len(cmds)):.0f}%")
    R["commands"] = {"n": len(cmds), "tagged": len(tagged),
                     "untagged": len(untagged), "tagged_bytes": total_bytes,
                     "wall_ns": wall, "real_cover": n_real / max(1, len(cmds))}

    if n_real:
        for opname in ("write", "read"):
            ls = [c["dur"] for c in pool if c["op"] == opname and c["real"]]
            if ls:
                out.append(f"  {opname:5s} latency: p50 {fmt_us(pct(ls, .5))}  "
                           f"p95 {fmt_us(pct(ls, .95))}  p99 {fmt_us(pct(ls, .99))}"
                           f"  max {fmt_us(max(ls))}  (n={len(ls)})")
                R[f"lat_{opname}"] = {"p50": pct(ls, .5), "p99": pct(ls, .99)}

    # ---- QD1 detector: per-object submission gaps ---------------------
    by_tid = defaultdict(list)
    for c in tagged:
        by_tid[c["tid"]].append(c)
    gaps_by_op = defaultdict(list)
    for tid, cl in by_tid.items():
        cl.sort(key=lambda c: c["ts"])
        if len(cl) < 4:
            continue
        opn = "load" if cl[0]["op"] == "read" else "store"
        for a, b in zip(cl, cl[1:]):
            gaps_by_op[opn].append(b["ts"] - a["ts"])
    out.append("  --- QD1 detector (per-object submission gaps) ---")
    R["qd1"] = {}
    for opn, gaps in sorted(gaps_by_op.items()):
        g50, g95 = pct(gaps, .5), pct(gaps, .95)
        # QD~1 signature: consecutive submissions spaced by ~a full service
        # time (submit-wait-submit) instead of back-to-back queuing.  The
        # reference service time must be the MATCHING op's: at QD1 the
        # device is unloaded, so its latency is the FLOOR — compare against
        # that op's minimum-quartile latency, not a mixed-op median.
        cmd_op = "read" if opn == "load" else "write"
        svc_pool = [c["dur"] for c in tagged
                    if c["real"] and c["op"] == cmd_op]
        svc = pct(svc_pool, .25) if svc_pool else None
        if svc:
            verdict = ("QD~1 (gap ~= service time — serialized)"
                       if g50 >= 0.5 * svc else "pipelined")
        else:
            verdict = ("QD~1 suspicious (gap >= 40us)" if g50 >= 40_000
                       else "pipelined")
        out.append(f"    {opn:5s}: gap p50 {fmt_us(g50)}  p95 {fmt_us(g95)}"
                   f"  -> {verdict}")
        R["qd1"][opn] = {"gap_p50": g50, "gap_p95": g95, "verdict": verdict}

    # ---- achieved QD (needs completions) ------------------------------
    if n_real:
        evs = []
        for c in pool:
            if c["real"]:
                evs.append((c["ts"], 1))
                evs.append((c["ts"] + c["dur"], -1))
        evs.sort()
        qd, last_ts, area, t_le1, span = 0, None, 0, 0, 0
        qmax = 0
        for ts, d in evs:
            if last_ts is not None and ts > last_ts:
                dt = ts - last_ts
                area += qd * dt
                span += dt
                if qd <= 1:
                    t_le1 += dt
            qd += d
            qmax = max(qmax, qd)
            last_ts = ts
        if span:
            out.append(f"  achieved QD: mean {area / span:.1f}  max {qmax}  "
                       f"%time QD<=1: {100 * t_le1 / span:.0f}%")
            R["qd"] = {"mean": area / span, "max": qmax,
                       "pct_time_le1": t_le1 / span}

    # ---- inferred batches ---------------------------------------------
    subs = sorted(c["ts"] for c in pool)
    batches, cur = [], 1
    for a, b in zip(subs, subs[1:]):
        if b - a > batch_gap_ns:
            batches.append(cur)
            cur = 1
        else:
            cur += 1
    if cur:
        batches.append(cur)
    if batches:
        out.append(f"  inferred batches (gap>{batch_gap_ns // 1000}us): "
                   f"{len(batches)} batches, size p50 {pct(batches, .5):.0f} "
                   f"p95 {pct(batches, .95):.0f} max {max(batches)}")
        R["batches"] = {"n": len(batches), "size_p50": pct(batches, .5),
                        "size_p95": pct(batches, .95)}

    # ---- objects ------------------------------------------------------
    ok_objs = [o for o in objs if not o.get("error")]
    failed = [o for o in objs if o.get("error")]
    out.append("  --- objects (span = op-start..op-end when schema-2) ---")
    R["objects"] = {}
    for opn in ("store", "load", "delete"):
        ol = [o for o in ok_objs if o.get("op") == opn]
        if not ol:
            continue
        spans = [o["dur"] for o in ol]
        mb = [(o["bytes"] or 0) / max(1e-9, o["dur"] / 1e9) / 1e6 for o in ol
              if o["dur"]]
        pre = []
        for o in ol:
            cl = by_tid.get(o["tid"])
            if cl:
                pre.append(min(c["ts"] for c in cl) - o["ts"])
        line = (f"    {opn:6s}: n={len(ol):4d}  span p50 {fmt_ms(pct(spans, .5))}"
                f"  p99 {fmt_ms(pct(spans, .99))}")
        if mb:
            line += f"  eff {pct(mb, .5):.0f} MB/s"
        if pre:
            line += f"  pre-submit p50 {fmt_ms(pct(pre, .5))}"
        out.append(line)
        R["objects"][opn] = {"n": len(ol), "span_p50": pct(spans, .5),
                             "span_p99": pct(spans, .99),
                             "eff_mbs_p50": pct(mb, .5) if mb else None,
                             "presubmit_p50": pct(pre, .5) if pre else None}
    if failed:
        out.append(f"    FAILED ops: {len(failed)} "
                   f"({sorted({o['error'] for o in failed})})")
        R["failed_ops"] = len(failed)

    # ---- TP all-rank-ready barrier ------------------------------------
    fmts = sorted({o.get("fmt") for o in ok_objs if o.get("fmt")})
    if len(fmts) > 1:
        by_chunk = defaultdict(list)
        for o in ok_objs:
            if o.get("chunk") and o.get("op") in ("store", "load"):
                by_chunk[(o["op"], o["chunk"])].append(o["ts"] + o["dur"])
        barr = [max(ends) - min(ends) for ends in by_chunk.values()
                if len(ends) == len(fmts)]
        if barr:
            out.append(f"  TP barrier ({len(fmts)} shards): all-rank-ready gap "
                       f"p50 {fmt_ms(pct(barr, .5))}  p99 {fmt_ms(pct(barr, .99))}"
                       f"  (n={len(barr)} chunks)")
            R["tp_barrier"] = {"shards": len(fmts), "gap_p50": pct(barr, .5),
                               "gap_p99": pct(barr, .99)}

    # ---- space axis ---------------------------------------------------
    writes = sorted((c for c in pool if c["op"] == "write"),
                    key=lambda c: c["ts"])
    if writes:
        seen, reused = set(), 0
        seq = 0
        prev = None
        for c in writes:
            if c["slba"] in seen:
                reused += 1
            seen.add(c["slba"])
            if prev is not None and c["slba"] == prev["slba"] + \
                    (prev["dlen"] or 0) // lba:
                seq += 1
            prev = c
        hdrs = sum(1 for c in writes if c.get("role") == "header")
        out.append(f"  space: {reused}/{len(writes)} write-LBA reuses, "
                   f"sequentiality {100 * seq / max(1, len(writes) - 1):.0f}%, "
                   f"header cmds {hdrs} "
                   f"({100 * hdrs * hdr / max(1, total_bytes):.1f}% of bytes)")
        R["space"] = {"lba_reuse": reused, "seq_pct": seq / max(1, len(writes) - 1),
                      "header_cmds": hdrs}

    # ---- throughput ---------------------------------------------------
    if wall:
        out.append(f"  throughput: {total_bytes / wall:.2f} GB/s tagged aggregate")
        R["throughput_gbs"] = total_bytes / wall

    # ---- serving spans ------------------------------------------------
    if serving:
        out.append("  --- serving spans ---")
        R["serving"] = {}
        by_op = defaultdict(list)
        for s in serving:
            by_op[s.get("op") or s["name"]].append(s["dur"])
        for opn, ds in sorted(by_op.items()):
            out.append(f"    {opn:12s}: n={len(ds):3d}  p50 {fmt_ms(pct(ds, .5))}"
                       f"  p99 {fmt_ms(pct(ds, .99))}")
            R["serving"][opn] = {"n": len(ds), "p50": pct(ds, .5),
                                 "p99": pct(ds, .99)}
    return out, R


def paired_diff(objs_by_label):
    """A/B: match objects across labels by (key, op, occurrence order)."""
    labels = sorted(objs_by_label)
    if len(labels) < 2:
        return []
    out = ["===== A/B paired object diff ====="]
    base = labels[0]

    def keyed(objs):
        d = defaultdict(list)
        for o in sorted(objs, key=lambda o: o["ts"]):
            if o.get("key") and o.get("op") in ("store", "load"):
                d[(o["key"], o["op"])].append(o)
        return d

    kb = keyed(objs_by_label[base])
    for other in labels[1:]:
        ko = keyed(objs_by_label[other])
        deltas = defaultdict(list)
        for k, bl in kb.items():
            ol = ko.get(k)
            if not ol:
                continue
            for bo, oo in zip(bl, ol):
                deltas[k[1]].append(oo["dur"] - bo["dur"])
        for opn, ds in sorted(deltas.items()):
            if ds:
                out.append(f"  {other} vs {base} [{opn}]: span delta "
                           f"p50 {fmt_ms(pct(ds, .5))} "
                           f"(n={len(ds)} paired; negative = {other} faster)")
    return out if len(out) > 1 else []


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("trace", help=".pftrace from kvio2perfetto.py")
    ap.add_argument("--batch-gap-us", type=int, default=50,
                    help="submission-gap threshold splitting inferred batches")
    ap.add_argument("--json", help="also write machine-readable metrics here")
    args = ap.parse_args()

    cmds, objs, info, serving = load_trace(args.trace)
    if not cmds and not objs:
        sys.exit("no kvio slices found — is this a kvio2perfetto trace?")

    labels = sorted({label_of(r["proc"]) for r in cmds + objs})
    print(f"=== kvio report: {args.trace} ({len(labels)} capture label(s)) ===")
    results = {}
    objs_by_label = {}
    for lb in labels:
        lc = [c for c in cmds if label_of(c["proc"]) == lb]
        lo = [o for o in objs if label_of(o["proc"]) == lb]
        li = [i for i in info if (i.get("label") or label_of(i["proc"])) == lb]
        ls = [s for s in serving if label_of(s["proc"]) == lb]
        objs_by_label[lb] = lo
        lines, R = analyze_label(lb, lc, lo, li, ls,
                                 args.batch_gap_us * 1000)
        print("\n".join(lines))
        results[lb] = R
    for line in paired_diff(objs_by_label):
        print(line)
    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=1, default=float)
        print(f"(json -> {args.json})")


if __name__ == "__main__":
    main()
