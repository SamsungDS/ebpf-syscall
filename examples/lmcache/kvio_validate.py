#!/usr/bin/env python3
"""kvio validate — is the projection faithful?

Join the eBPF NVMe trace (nvme_uring_cmd_monitor JSONL, carries the io_uring
user_data) with LMCache's semantic records (LMCACHE_KVIO_TRACE JSONL, maps
trace_id -> {op, key, bytes}) to recover the MEASURED per-object device I/O, then
compare it to the kvio_plan PROJECTION.

Metrics follow the design review: per-quantity exact-match rate + WAPE (weighted
absolute percentage error) + per-command size-distribution agreement (ordered
multiset match, min/max, and a log2-binned total-variation distance) -- reported
per object and bucketed by (op, part) so it splits by K/V automatically once the
semantic trace carries a per-component 'part' field.  NOT AUC (there is no class
label; the geometry is deterministic), and not a single tautological R^2.
"""
import argparse
import json
from collections import defaultdict

import kvio_plan


def load_jsonl(path):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def _log2_bin(nbytes):
    """Bin a command size by floor(log2(bytes)); 0 bytes -> -1 sentinel."""
    return nbytes.bit_length() - 1 if nbytes > 0 else -1


def _hist(sizes):
    h = defaultdict(int)
    for s in sizes:
        h[_log2_bin(s)] += 1
    return h


def _tv_distance(a_sizes, b_sizes):
    """Total-variation distance between two command-size distributions binned by
    floor(log2(bytes)).  0 = identical shape, 1 = disjoint.  This is what catches
    the 256K+768K vs 512K+512K case that command-count + total-byte exact-match
    both pass (same count, same sum, different shape)."""
    ha, hb = _hist(a_sizes), _hist(b_sizes)
    na, nb = sum(ha.values()), sum(hb.values())
    if na == 0 and nb == 0:
        return 0.0
    if na == 0 or nb == 0:
        return 1.0
    bins = set(ha) | set(hb)
    return 0.5 * sum(abs(ha.get(k, 0) / na - hb.get(k, 0) / nb) for k in bins)


def _minmaxn(sizes):
    return (min(sizes), max(sizes), len(sizes)) if sizes else (0, 0, 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tracer", required=True,
                    help="nvme_uring_cmd_monitor JSONL (event_type=nvme_cmd, has user_data)")
    ap.add_argument("--semantic", required=True,
                    help="LMCACHE_KVIO_TRACE JSONL (trace_id -> op,key,bytes)")
    ap.add_argument("--header-bytes", type=int, default=4096)
    ap.add_argument("--max-xfer", type=int, default=0)
    ap.add_argument("--mdts-bytes", type=int, default=128 * 1024)
    ap.add_argument("--lba-bytes", type=int, default=512,
                    help="device LBA size; commands round up to this (match --lba-size)")
    args = ap.parse_args()

    sem = {o["trace_id"]: o for o in load_jsonl(args.semantic)}

    measured = defaultdict(lambda: {"cmds": 0, "bytes": 0, "sizes": []})
    untagged = {"cmds": 0, "bytes": 0}
    for o in load_jsonl(args.tracer):
        if o.get("event_type") != "nvme_cmd":
            continue
        tid = o["user_data"] >> 32
        if tid == 0:
            untagged["cmds"] += 1
            untagged["bytes"] += o["bytes"]
            continue
        measured[tid]["cmds"] += 1
        measured[tid]["bytes"] += o["bytes"]
        measured[tid]["sizes"].append(o["bytes"])

    exact = 0
    tot_meas_bytes = 0
    tot_abs_err = 0
    cmd_exact = 0
    size_exact = 0
    # command-size distributions bucketed by (op, part).  'part' defaults to
    # "kv" (today's aggregate records); when LMCache emits a per-component
    # 'part' (k/v/header) this splits into ("store","k")/("store","v") with no
    # code change -- the forward-compatible seam for the async K/V split.
    proj_by = defaultdict(list)
    meas_by = defaultdict(list)
    print("  tid | op    | proj_cmds meas_cmds | proj_bytes  meas_bytes | match")
    print("  ----+-------+---------------------+------------------------+------")
    for tid, s in sorted(sem.items()):
        m = measured.get(tid, {"cmds": 0, "bytes": 0, "sizes": []})
        p = kvio_plan.project(s["bytes"], s["op"], args.header_bytes,
                              args.max_xfer, args.mdts_bytes, args.lba_bytes)
        cmd_ok = m["cmds"] == p["nvme_commands"]
        byte_ok = m["bytes"] == p["total_device_bytes"]
        ok = cmd_ok and byte_ok
        exact += ok
        cmd_exact += cmd_ok
        tot_meas_bytes += m["bytes"]
        tot_abs_err += abs(m["bytes"] - p["total_device_bytes"])
        bucket = (s["op"], s.get("part", "kv"))
        proj_by[bucket].extend(p["command_sizes"])
        meas_by[bucket].extend(m["sizes"])
        size_exact += sorted(m["sizes"]) == sorted(p["command_sizes"])
        print(f"  {tid:3d} | {s['op']:5s} | {p['nvme_commands']:9d} {m['cmds']:9d} | "
              f"{p['total_device_bytes']:10d}  {m['bytes']:10d} | {'OK' if ok else 'MISMATCH'}")

    n = len(sem)
    wape = (tot_abs_err / tot_meas_bytes) if tot_meas_bytes else 0.0
    print()
    print(f"  objects: {n}")
    print(f"  exact-match (cmds AND bytes): {exact}/{n} = {100 * exact / n:.1f}%")
    print(f"  exact-match (command count):  {cmd_exact}/{n} = {100 * cmd_exact / n:.1f}%")
    print(f"  WAPE (device bytes):          {100 * wape:.4f}%")

    # ── Command-size distribution ─────────────────────────────────────────
    # exact-match + WAPE above check command COUNT and TOTAL bytes; they miss
    # size-SHAPE errors (a wrong split with the same count and sum still passes).
    # This checks the per-command size distribution: ordered-multiset match,
    # min/max, and a log2-binned total-variation distance, bucketed by (op,part).
    all_proj = [x for v in proj_by.values() for x in v]
    all_meas = [x for v in meas_by.values() for x in v]
    pmn, pmx, pc = _minmaxn(all_proj)
    mmn, mmx, mc = _minmaxn(all_meas)
    print(f"  per-cmd size exact-match:     {size_exact}/{n} = "
          f"{100 * size_exact / n:.1f}%")
    print(f"  command sizes  proj: n={pc} min={pmn} max={pmx} | "
          f"meas: n={mc} min={mmn} max={mmx}")
    print(f"  size-distribution TV (log2):  {_tv_distance(all_proj, all_meas):.4f} "
          f"(0=identical shape, 1=disjoint)")
    for bucket in sorted(set(proj_by) | set(meas_by)):
        op, part = bucket
        tv = _tv_distance(proj_by[bucket], meas_by[bucket])
        ppmn, ppmx, ppc = _minmaxn(proj_by[bucket])
        mbmn, mbmx, mbc = _minmaxn(meas_by[bucket])
        print(f"    {op:5s}/{part:5s}: proj n={ppc} [{ppmn}..{ppmx}]  "
              f"meas n={mbc} [{mbmn}..{mbmx}]  TV={tv:.4f}")

    if untagged["cmds"]:
        print(f"  (untagged trace_id=0: {untagged['cmds']} cmds / {untagged['bytes']} B "
              f"= non-KV metadata I/O, correctly excluded)")
    print("  metric note: regression/agreement (exact-match + WAPE), not AUC.")


if __name__ == "__main__":
    main()
