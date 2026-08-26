#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""kvio sem2manifest — turn a REAL captured run into a replayable manifest.

Reads an LMCACHE_KVIO_TRACE semantic trace (what a real vLLM+LMCache serving
run actually stored/loaded) and emits a ``kvio_record.json`` replay manifest in
the same schema ``run_kv_offload_io.py --record`` writes, so ``kvio_replay.py
--record`` can reproduce the recorded object set on any device — no GPU needed.

Unlike the generator's manifest (uniform calculator-derived payloads), payload
bytes here are per-object as OBSERVED — so TP-sharded or partial-chunk objects
replay exactly as the real run issued them.

    kvio_sem2manifest.py --semantic real_gpu_trace.jsonl \
        --model meta-llama/Llama-3.1-8B-Instruct \
        --out kvio_record_real.json \
        [--mdts-bytes 131072 --block-align 131072 --header-bytes 131072]
"""
import argparse
import json
from collections import OrderedDict


def load_jsonl(path):
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass  # tolerate a truncated tail line from a killed tracer
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--semantic", required=True,
                    help="LMCACHE_KVIO_TRACE JSONL from the real run")
    ap.add_argument("--out", required=True, help="manifest path to write")
    ap.add_argument("--model", default="",
                    help="model name (informational; recorded in the manifest)")
    ap.add_argument("--device", default="", help="device the run used (informational)")
    ap.add_argument("--engine", default="uring_cmd",
                    choices=["posix", "io_uring", "uring_cmd"])
    ap.add_argument("--mdts-bytes", type=int, default=131072)
    ap.add_argument("--block-align", type=int, default=131072)
    ap.add_argument("--header-bytes", type=int, default=131072)
    ap.add_argument("--slot-bytes", type=int, default=0,
                    help="0 = derive: max payload + header, rounded to block_align")
    ap.add_argument("--capacity-bytes", type=int, default=0)
    args = ap.parse_args()

    recs = load_jsonl(args.semantic)
    # object_id -> {payload, ops in observed order, first-seen order}
    objs = OrderedDict()
    for r in recs:
        oid = r.get("object_id") or r.get("key")
        if oid is None or "op" not in r:
            continue
        # schema-2 traces add delete records and failed-op records (error
        # field); neither is replayable device I/O.
        if r["op"] not in ("store", "load") or "error" in r:
            continue
        o = objs.setdefault(oid, {"payload_bytes": 0, "ops": []})
        o["payload_bytes"] = max(o["payload_bytes"], int(r["bytes"]))
        if r["op"] not in o["ops"]:
            o["ops"].append(r["op"])

    if not objs:
        raise SystemExit("no objects found in semantic trace")

    max_payload = max(o["payload_bytes"] for o in objs.values())
    slot = args.slot_bytes
    if not slot:
        raw = max_payload + args.header_bytes
        slot = (raw + args.block_align - 1) // args.block_align * args.block_align

    # geometry detail: shape/dtype as observed (present in real traces)
    detail = {}
    for r in recs:
        if "shape" in r:
            detail = {"observed_shape": r["shape"], "observed_dtype": r.get("dtype"),
                      "source": "real-run semantic trace"}
            break

    rec = {
        "schema_version": 1,
        "source": f"kvio_sem2manifest: real capture ({args.semantic})",
        "model": args.model,
        "geometry": detail,
        "device_geometry": {
            "engine": args.engine,
            "use_uring_cmd": args.engine == "uring_cmd",
            "mdts_bytes": args.mdts_bytes,
            "block_align": args.block_align,
            "header_bytes": args.header_bytes,
            "slot_bytes": slot,
            "capacity_bytes": args.capacity_bytes,
        },
        "access_pattern": "store-all-then-load-all",
        "objects": [
            {"index": i, "part": "kv", "payload_bytes": o["payload_bytes"],
             "ops": o["ops"]}
            for i, o in enumerate(objs.values())
        ],
    }
    with open(args.out, "w") as f:
        json.dump(rec, f, indent=2)
    n_load = sum(1 for o in objs.values() if "load" in o["ops"])
    print(f"wrote {args.out}: {len(objs)} objects "
          f"(max payload {max_payload} B, slot {slot} B, {n_load} also loaded)")


if __name__ == "__main__":
    main()
