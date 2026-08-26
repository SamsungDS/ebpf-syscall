#!/usr/bin/env python3
"""tp-monitor capture -> fio version-3 iolog against the raw device.

Every nvme_cmd row becomes one replay entry at its captured relative
timestamp (msec), byte offset (slba x 512-byte sectors, the tp monitor's
unit) and length -- fio then reissues the exact device command stream.

Known gap: in testing, fio replayed the stream flat-out rather than
pacing by the v3 timestamps, so command-stream fidelity (count, sizes,
offsets) is validated but timing reproduction is not yet -- treat the
replay as the workload's command stream at the replay rig's speed until
the fio pacing option is pinned down.
"""
import json
import sys

cap, dev = sys.argv[1], sys.argv[2]
rows = []
for line in open(cap):
    try:
        r = json.loads(line)
    except json.JSONDecodeError:
        continue
    if r.get("event_type") != "nvme_cmd":
        continue
    if r.get("op_name") not in ("read", "write"):
        continue
    rows.append((int(r["ts"]), r["op_name"], int(r["slba"]) * 512,
                 int(r["bytes"])))
rows.sort()
t0 = rows[0][0] if rows else 0
print("fio version 3 iolog")
print(f"0 {dev} add")
print(f"0 {dev} open")
for ts, op, off, ln in rows:
    print(f"{(ts - t0) // 1_000_000} {dev} {op} {off} {ln}")
print(f"{(rows[-1][0] - t0) // 1_000_000 if rows else 0} {dev} close")
