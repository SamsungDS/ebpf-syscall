#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Device queue depth per tool phase, from an nvme_tp_monitor capture.

    python3 qdepth.py capture.jsonl run.txt [--disk nvme2n1]

The tracer's nvme_cmp records carry the completion timestamp ``ts`` and the
command's ``lat_ns`` (both from bpf_ktime_get_ns, CLOCK_MONOTONIC), so every
command is the interval [ts - lat_ns, ts]. The tool prints
``@@@ PHASE <store|load> pass=N start_ns=.. end_ns=..`` on the same clock, so
each phase is a window. For every phase this reports the commands completed
in it, the time-weighted mean number of commands outstanding on the device,
its p50/p95/max, the mean completion latency, and the command-size histogram
(from the nvme_cmd records, which carry ``bytes``). "Outstanding" is what the
NVMe driver saw, whatever the engine believed it was issuing."""
import argparse
import json
import re
from collections import Counter


def load(capture, disk):
    cmds, cmps = [], []
    with open(capture) as f:
        for line in f:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            t = e.get("event_type")
            if t == "nvme_cmd":
                if disk and e.get("disk") != disk:
                    continue
                cmds.append((int(e["ts"]), int(e["bytes"]), e.get("op_name", "")))
            elif t == "nvme_cmp":
                ts, lat = int(e["ts"]), int(e["lat_ns"])
                cmps.append((ts - lat, ts, int(e.get("status", 0))))
    return cmds, cmps


def phases(run_txt):
    out = []
    for m in re.finditer(r"@@@ PHASE (\w+) pass=(\d+) start_ns=(\d+) end_ns=(\d+)", open(run_txt).read()):
        out.append((m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4))))
    return out


def depth_stats(cmps, t0, t1):
    """Time-weighted outstanding-command statistics inside [t0, t1)."""
    ev = []
    n_in = 0
    lat_sum = 0
    errs = 0
    for s, e, st in cmps:
        if e <= t0 or s >= t1:
            continue
        ev.append((max(s, t0), 1))
        ev.append((min(e, t1), -1))
        if t0 <= e < t1:
            n_in += 1
            lat_sum += e - s
            errs += st != 0
    if not ev:
        return None
    ev.sort()
    depth, last, acc = 0, t0, Counter()
    for t, d in ev:
        if t > last:
            acc[depth] += t - last
        depth += d
        last = t
    if t1 > last:
        acc[0] += t1 - last
    total = sum(acc.values())
    mean = sum(d * w for d, w in acc.items()) / total
    busy = total - acc[0]
    mean_busy = sum(d * w for d, w in acc.items() if d) / busy if busy else 0.0
    cum, p50, p95 = 0, None, None
    for d in sorted(acc):
        cum += acc[d]
        if p50 is None and cum >= 0.5 * total:
            p50 = d
        if p95 is None and cum >= 0.95 * total:
            p95 = d
    return {"commands": n_in, "errors": errs, "mean_depth": round(mean, 2),
            "mean_depth_while_busy": round(mean_busy, 2), "p50_depth": p50,
            "p95_depth": p95, "max_depth": max(acc), "busy_fraction": round(busy / total, 3),
            "mean_lat_us": round(lat_sum / n_in / 1e3, 1) if n_in else None}


def size_hist(cmds, t0, t1):
    c = Counter(b for ts, b, _ in cmds if t0 <= ts < t1)
    return {f"{b >> 10}K": n for b, n in sorted(c.items())}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("capture")
    ap.add_argument("run_txt")
    ap.add_argument("--disk")
    ap.add_argument("--json", action="store_true", help="emit one JSON object instead of a table")
    a = ap.parse_args()
    cmds, cmps = load(a.capture, a.disk)
    ph = phases(a.run_txt)
    if not ph:
        raise SystemExit("no @@@ PHASE lines in the tool output")
    rows = []
    for name, p, t0, t1 in ph:
        st = depth_stats(cmps, t0, t1)
        if st is None:
            continue
        st.update({"phase": name, "pass": p, "wall_ms": round((t1 - t0) / 1e6, 1), "sizes": size_hist(cmds, t0, t1)})
        rows.append(st)
    if a.json:
        print(json.dumps(rows))
        return
    print(f"{'phase':6s} {'pass':>4s} {'cmds':>7s} {'err':>4s} {'wall ms':>8s} {'mean QD':>8s} {'busy QD':>8s} {'p50':>4s} {'p95':>4s} {'max':>4s} {'busy':>5s} {'lat us':>7s}  sizes")
    for r in rows:
        print(f"{r['phase']:6s} {r['pass']:>4d} {r['commands']:>7d} {r['errors']:>4d} {r['wall_ms']:>8.1f} "
              f"{r['mean_depth']:>8.2f} {r['mean_depth_while_busy']:>8.2f} {r['p50_depth']:>4d} {r['p95_depth']:>4d} "
              f"{r['max_depth']:>4d} {r['busy_fraction']:>5.2f} {r['mean_lat_us'] or 0:>7.1f}  {r['sizes']}")


if __name__ == "__main__":
    main()
