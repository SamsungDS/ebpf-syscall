#!/usr/bin/env python3
"""Device-stream fidelity referee: capture vs replays, from tp-monitor JSONLs."""
import json
import sys
from collections import Counter


def load(path):
    cmds, lats = [], []
    for line in open(path):
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        et = r.get("event_type")
        if et == "nvme_cmd" and r.get("op_name") in ("read", "write"):
            cmds.append(r)
        elif et == "nvme_cmp":
            lats.append(int(r["lat_ns"]) / 1e3)
    lats.sort()
    return cmds, lats


def stats(cmds, lats):
    n = len(cmds)
    byt = sum(int(c["bytes"]) for c in cmds)
    wr = [c for c in cmds if c["op_name"] == "write"]
    sizes = Counter(int(c["bytes"]) for c in cmds)
    top = ", ".join(f"{s//1024}K:{c*100//n}%" for s, c in sizes.most_common(3))
    dur = (max(int(c["ts"]) for c in cmds) - min(int(c["ts"]) for c in cmds)) / 1e9 if n else 0
    return {"cmds": n, "writes": len(wr), "MB": byt / 1e6,
            "avgKB": byt / n / 1024 if n else 0,
            "sizes": top, "dur_s": dur,
            "p50us": lats[len(lats) // 2] if lats else 0,
            "p99us": lats[int(len(lats) * 0.99)] if lats else 0}


for spec in sys.argv[1:]:
    name, cap, ra, rb = spec.split(":")
    S = {"capture": stats(*load(cap)), "replayA-file": stats(*load(ra)),
         "replayB-device": stats(*load(rb))}
    print(f"\n##### {name}")
    hdr = f"{'':16s}" + "".join(f"{k:>16s}" for k in S)
    print(hdr)
    base = S["capture"]
    for field, fmt in [("cmds", "d"), ("writes", "d"), ("MB", ".0f"),
                       ("avgKB", ".1f"), ("dur_s", ".1f"),
                       ("p50us", ".0f"), ("p99us", ".0f")]:
        row = f"{field:16s}"
        for k, v in S.items():
            row += f"{format(v[field], fmt):>16s}"
        print(row)
    for k, v in S.items():
        if k != "capture" and base["cmds"]:
            d = (v["cmds"] - base["cmds"]) * 100.0 / base["cmds"]
            print(f"{'cmd inflation':16s}{k:>16s}: {d:+.1f}%")
    for k, v in S.items():
        print(f"  sizes[{k}]: {v['sizes']}")
