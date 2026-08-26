#!/usr/bin/env python3
"""Verify io_uring tracer output against application ground truth (Phase 1/2).

Two modes:

  * self-check (only --truth):   validate the ground-truth JSONL is internally
    consistent (unique+monotonic user_data, successful res == requested bytes,
    no duplicates). This is meaningful before the tracer exists.

  * cross-check (--truth + --tracer): match every accepted application SQE to a
    tracer `intent_prepared` event by user_data and verify offset / requested
    bytes / direction; flag missing, duplicate, and mis-decoded events, check
    completion correlation, and surface tracer ring-buffer drops.

Exit code is non-zero if any discrepancy is found, so it can gate CI.
"""
import argparse, json, sys
from collections import defaultdict


def load_jsonl(path):
    rows = []
    with open(path) as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"  ! {path}:{ln}: bad JSON: {e}", file=sys.stderr)
    return rows


def self_check(truth):
    problems = []
    seen = {}
    for r in truth:
        ud = r.get("user_data")
        if ud in seen:
            problems.append(f"duplicate user_data {ud}")
        seen[ud] = r
        res = r.get("cqe_res")
        req = r.get("requested_bytes")
        # scalar/fixed: successful res must equal requested bytes.
        if res is not None and res >= 0 and r.get("op_name") not in ("READV", "WRITEV"):
            if res != req:
                problems.append(f"ud {ud}: cqe_res {res} != requested {req}")
        # vectored: iov_sizes must sum to requested.
        if r.get("op_name") in ("READV", "WRITEV"):
            s = sum(r.get("iov_sizes", []))
            if s != req:
                problems.append(f"ud {ud}: iov sum {s} != requested {req}")
    uds = [r["user_data"] for r in truth]
    if uds != sorted(uds):
        problems.append("user_data not monotonic in emission order")
    return problems


def cross_check(truth, tracer):
    """tracer rows are expected to carry: event_type ('intent'|'completion'),
    user_data, offset, requested_bytes, ddir, (completion: cqe_res), and an
    optional top-level {'dropped': N} sentinel row for ringbuf loss."""
    problems = []
    drops = sum(r.get("dropped", 0) for r in tracer if "dropped" in r)
    intents = defaultdict(list)
    comps = defaultdict(list)
    for r in tracer:
        et = r.get("event_type")
        if et == "intent":
            intents[r.get("user_data")].append(r)
        elif et == "completion":
            comps[r.get("user_data")].append(r)

    matched = 0
    for r in truth:
        ud = r["user_data"]
        ti = intents.get(ud, [])
        if not ti:
            problems.append(f"MISSING intent for ud {ud} ({r['op_name']} off={r['offset']})")
            continue
        if len(ti) > 1:
            problems.append(f"DUPLICATE intent ({len(ti)}) for ud {ud}")
        t = ti[0]
        if t.get("offset") != r["offset"]:
            problems.append(f"ud {ud}: offset tracer {t.get('offset')} != truth {r['offset']}")
        # requested bytes: only compare when tracer claims a valid decode
        if t.get("requested_bytes_valid", True):
            if t.get("requested_bytes") != r["requested_bytes"]:
                problems.append(f"ud {ud}: req tracer {t.get('requested_bytes')} != truth {r['requested_bytes']}")
        else:
            # vectored degraded decode is allowed, but must not exceed truth
            lb = t.get("requested_bytes_lower", 0)
            if lb > r["requested_bytes"]:
                problems.append(f"ud {ud}: degraded lower-bound {lb} > truth {r['requested_bytes']}")
        td = t.get("ddir")
        if td and td != r["ddir"]:
            problems.append(f"ud {ud}: ddir tracer {td} != truth {r['ddir']}")
        if ud not in comps:
            problems.append(f"ud {ud}: no completion event correlated")
        matched += 1

    # tracer intents with no corresponding truth row (spurious)
    truth_uds = {r["user_data"] for r in truth}
    for ud in intents:
        if ud not in truth_uds:
            problems.append(f"SPURIOUS tracer intent ud {ud} not in ground truth")

    print(f"  matched {matched}/{len(truth)} application ops; tracer drops reported: {drops}")
    if drops:
        problems.append(f"tracer reported {drops} ringbuf drops (non-zero)")
    return problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--truth", required=True, help="application ground-truth JSONL")
    ap.add_argument("--tracer", help="tracer JSONL (omit for self-check only)")
    args = ap.parse_args()

    truth = load_jsonl(args.truth)
    print(f"ground truth: {len(truth)} ops from {args.truth}")
    problems = self_check(truth)

    if args.tracer:
        tracer = load_jsonl(args.tracer)
        print(f"tracer: {len(tracer)} rows from {args.tracer}")
        problems += cross_check(truth, tracer)

    if problems:
        print(f"\nFAIL: {len(problems)} problem(s):")
        for p in problems[:50]:
            print(f"  - {p}")
        if len(problems) > 50:
            print(f"  ... and {len(problems)-50} more")
        sys.exit(1)
    print("\nOK: no discrepancies")


if __name__ == "__main__":
    main()
