#!/usr/bin/env python3
"""kvio validate — is the projection faithful?

Join the eBPF NVMe trace (nvme_uring_cmd_monitor JSONL, carries the io_uring
user_data) with LMCache's semantic records (LMCACHE_KVIO_TRACE JSONL, maps
trace_id -> {op, key, bytes}) to recover the MEASURED per-object device I/O, then
compare it to the kvio_plan PROJECTION.

Metrics follow the design review: per-quantity exact-match rate + WAPE (weighted
absolute percentage error) + command-size agreement, reported per object/op --
NOT AUC (there is no class label; the geometry is deterministic), and not a single
tautological R^2.
"""
import argparse
import json
from collections import defaultdict

import kvio_plan


def load_jsonl(path):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


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
        print(f"  {tid:3d} | {s['op']:5s} | {p['nvme_commands']:9d} {m['cmds']:9d} | "
              f"{p['total_device_bytes']:10d}  {m['bytes']:10d} | {'OK' if ok else 'MISMATCH'}")

    n = len(sem)
    wape = (tot_abs_err / tot_meas_bytes) if tot_meas_bytes else 0.0
    print()
    print(f"  objects: {n}")
    print(f"  exact-match (cmds AND bytes): {exact}/{n} = {100 * exact / n:.1f}%")
    print(f"  exact-match (command count):  {cmd_exact}/{n} = {100 * cmd_exact / n:.1f}%")
    print(f"  WAPE (device bytes):          {100 * wape:.4f}%")
    if untagged["cmds"]:
        print(f"  (untagged trace_id=0: {untagged['cmds']} cmds / {untagged['bytes']} B "
              f"= non-KV metadata I/O, correctly excluded)")
    print("  metric note: regression/agreement (exact-match + WAPE), not AUC.")


if __name__ == "__main__":
    main()
