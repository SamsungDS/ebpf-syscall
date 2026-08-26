#!/usr/bin/env python3
"""What does the TP KV-load actually do on the wire? Parallel per-rank or serial?
Reconstruct from the eBPF NVMe trace + semantic (trace_id->kv_rank) join."""
import json, sys, collections

ebpf, sem = sys.argv[1], sys.argv[2]
label = sys.argv[3] if len(sys.argv) > 3 else ebpf

# semantic: trace_id -> (op, kv_rank)
S = {}
for l in open(sem):
    l = l.strip()
    if not l: continue
    try: r = json.loads(l)
    except: continue
    if "trace_id" in r:
        S[r["trace_id"]] = (r.get("op"), r.get("kv_rank"))

# eBPF read commands, in ts order
cmds = []
for l in open(ebpf):
    l = l.strip()
    if not l: continue
    try: r = json.loads(l)
    except: continue
    if r.get("event_type") != "nvme_cmd": continue
    tid = r["user_data"] >> 32
    if tid == 0: continue
    op, rank = S.get(tid, (None, None))
    cmds.append((r["ts"], tid, r["tid"], r["pid"], r["op_name"], r["bytes"], op, rank))
cmds.sort()

reads = [c for c in cmds if c[4] == "read"]
writes = [c for c in cmds if c[4] == "write"]
print(f"=== {label} ===")
print(f"read cmds={len(reads)}  write cmds={len(writes)}")

# per-object (trace_id) load bytes + rank
by_obj = collections.defaultdict(lambda: {"cmds": 0, "bytes": 0, "rank": None, "ts0": None, "ts1": None})
for ts, tid, thr, pid, op_name, byt, op, rank in reads:
    o = by_obj[tid]; o["cmds"] += 1; o["bytes"] += byt; o["rank"] = rank
    o["ts0"] = ts if o["ts0"] is None else min(o["ts0"], ts)
    o["ts1"] = ts if o["ts1"] is None else max(o["ts1"], ts)
nobj = len(by_obj)
bytes_by_obj = collections.Counter(o["bytes"] for o in by_obj.values())
print(f"load objects={nobj}  per-object bytes={dict(bytes_by_obj)}  "
      f"aggregate load bytes={sum(o['bytes'] for o in by_obj.values())/2**20:.0f} MiB")
rank_hist = collections.Counter(o["rank"] for o in by_obj.values())
print(f"objects per kv_rank={dict(rank_hist)}")

# concurrency: distinct threads / pids doing reads
print(f"read-issuing PIDs={sorted(set(c[3] for c in reads))}  "
      f"distinct TIDs={len(set(c[2] for c in reads))}")

# interleaving: consecutive reads from same object vs different?
same = diff = 0
for a, b in zip(reads, reads[1:]):
    if a[1] == b[1]: same += 1
    else: diff += 1
print(f"consecutive-read same-object={same} diff-object={diff} "
      f"(interleave rate={diff/(same+diff):.2%}) "
      f"[serial-per-object ~= 1/cmds_per_obj; parallel -> high]")

# max concurrent objects: how many objects have overlapping [ts0,ts1] at once
events = []
for tid, o in by_obj.items():
    if o["ts0"] is not None:
        events.append((o["ts0"], +1)); events.append((o["ts1"], -1))
events.sort()
cur = mx = 0
for _, d in events:
    cur += d; mx = max(mx, cur)
print(f"max concurrent in-flight load objects (by ts overlap)={mx}")

# span of the load phase + effective aggregate bandwidth
if reads:
    span_s = (reads[-1][0] - reads[0][0]) / 1e9
    agg = sum(o["bytes"] for o in by_obj.values())
    print(f"load-phase wall span={span_s:.3f}s  effective aggregate read BW="
          f"{agg/span_s/1e6:.0f} MB/s (all objects, wall-clock)")
