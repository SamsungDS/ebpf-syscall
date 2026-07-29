#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Render a device read-amplification A/B onto a Perfetto timeline.

This is the read-amplification counterpart of kvio2perfetto. It takes, for
each arm of a comparison, two witnesses of the same run:

  * the MECHANISM -- an nvme_tp_monitor JSONL capture of the real device
    commands (slba, bytes, ts): what the SSD actually did; and
  * the INTENT -- the workload driver's own progress markers (signal
    bytes = the useful bytes the application actually consumes, plus the
    store's self-reported device bytes), stamped on the same
    CLOCK_MONOTONIC axis as the eBPF capture.

The gap between the two witnesses IS the read amplification: a GNN that
consumes a few MB of node features can drag hundreds of MB off the SSD
because every scattered neighbor lands on its own 4 KiB page. Plotting
"useful MB" against "device MB read" on one arm makes that gap literal;
laying a naive arm beside an architecturally-improved arm (both rebased
to t=0) makes the engineering win literal.

Crucially the mechanism witness carries NO application data -- only
offsets, lengths, and timing. That is what lets a third party capture a
confidential workload (financial-fraud GNN, private graph) and share the
IO behaviour for replay and visualization without sharing the data.

Each arm becomes a process group with counter tracks:
  - useful MB (intent)        -- what the workload consumes
  - device MB, store count    -- the store's own read accounting (intent side)
  - device MB, eBPF measured  -- independent device-side truth; should
                                 track the store count (self-verification)
  - read amplification x       -- device MB / useful MB, running
  - device LBA (sector)        -- slba over time: the access pattern
                                 (scatter = poor locality, banded = good)
and a sampled slice lane of the device reads for browsing.

Requires: pip install perfetto.  View: drag the .pftrace onto
https://ui.perfetto.dev (processing is local to your browser).
"""
from __future__ import annotations

import argparse
import gzip
import json
import re
import sys

SEQ = 1
SLICE_DUR_NS = 4000     # nominal slice length for a sampled device read


def load_jsonl(path):
    op = gzip.open if path.endswith(".gz") else open
    with op(path, "rt") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def parse_phase(path):
    """Parse the driver's PHASE_START / PROGRESS / PHASE_END markers."""
    start = end = None
    prog = []          # (mono_ns, signal_bytes, store_bytes, store_pages)
    meta = {}
    kv = lambda s, k: re.search(rf"{k}=(-?\d+)", s)  # noqa: E731
    for line in open(path):
        if line.startswith("PHASE_START"):
            m = kv(line, "mono_ns")
            if m:
                start = int(m.group(1))
            for k in ("nodes_per_page", "feat_bytes"):
                mm = kv(line, k)
                if mm:
                    meta[k] = int(mm.group(1))
        elif line.startswith("PROGRESS"):
            mn = kv(line, "mono_ns")
            sb = kv(line, "signal_bytes")
            db = kv(line, "store_bytes")
            pg = kv(line, "store_pages")
            if mn and sb and db:
                prog.append((int(mn.group(1)), int(sb.group(1)),
                             int(db.group(1)),
                             int(pg.group(1)) if pg else 0))
        elif line.startswith("PHASE_END"):
            m = kv(line, "mono_ns")
            if m:
                end = int(m.group(1))
            for k in ("signal_bytes", "store_bytes", "read_ops"):
                mm = kv(line, k)
                if mm:
                    meta[k] = int(mm.group(1))
            for k in ("ra_signal", "ra_fetch"):
                mm = re.search(rf"{k}=([\d.]+)", line)
                if mm:
                    meta[k] = float(mm.group(1))
    return start, end, prog, meta


def load_reads(path, start, end):
    """Device read commands within [start, end], sorted by ts."""
    reads = []
    for r in load_jsonl(path):
        if r.get("event_type") != "nvme_cmd":
            continue
        if r.get("op_name") != "read":
            continue
        ts = int(r["ts"])
        if start is not None and ts < start:
            continue
        if end is not None and ts > end:
            continue
        reads.append((ts, int(r["slba"]), int(r["bytes"])))
    reads.sort()
    return reads


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--arm", action="append", default=[], metavar="SPEC",
                    help="NAME:capture.jsonl:phase.txt  (repeatable)")
    ap.add_argument("-o", "--out", required=True, help="output .pftrace[.gz]")
    ap.add_argument("--slice-sample", type=int, default=400,
                    help="emit one browsable slice per N device reads")
    ap.add_argument("--counter-points", type=int, default=1500,
                    help="target sample count for the device-MB/LBA counters")
    args = ap.parse_args()
    if not args.arm:
        ap.error("need at least one --arm NAME:capture.jsonl:phase.txt")

    try:
        from perfetto.trace_builder.proto_builder import \
            StreamingTraceProtoBuilder
        from perfetto.protos.perfetto.trace.perfetto_trace_pb2 import TrackEvent
    except ImportError:
        sys.exit("pip install perfetto  (required for .pftrace emission)")

    arms = []
    for spec in args.arm:
        name, cap, phase = spec.split(":")
        start, end, prog, meta = parse_phase(phase)
        reads = load_reads(cap, start, end)
        if not reads:
            print(f"warning: no reads for arm {name}", file=sys.stderr)
        arms.append((name, reads, prog, meta, start))

    opener = gzip.open if args.out.endswith(".gz") else open
    with opener(args.out, "wb") as f:
        b = StreamingTraceProtoBuilder(f)
        T = TrackEvent
        uid = [1000]

        def newid():
            uid[0] += 1
            return uid[0]

        def track(uuid, name=None, parent=None, pid=None, pname=None,
                  unit=None, order=None, counter=False):
            p = b.create_packet()
            d = p.track_descriptor
            d.uuid = uuid
            if parent is not None:
                d.parent_uuid = parent
            if name is not None:
                d.name = name
            if pid is not None:
                d.process.pid = pid
                d.process.process_name = pname or name
            if counter:
                if unit is not None:
                    d.counter.unit_name = unit
                else:
                    d.counter.SetInParent()
            if order is not None:
                d.sibling_order_rank = order
            b.write_packet(p)

        events = []  # (ts, order, packet) collected then emitted time-sorted

        def counter_pkt(ts, uuid_, value, is_double=True):
            p = b.create_packet()
            p.timestamp = max(0, ts)
            p.trusted_packet_sequence_id = SEQ
            te = p.track_event
            te.type = T.TYPE_COUNTER
            te.track_uuid = uuid_
            if is_double:
                te.double_counter_value = float(value)
            else:
                te.counter_value = int(value)
            return p

        def slice_pkts(ts, dur, uuid_, name, args_):
            pb = b.create_packet()
            pb.timestamp = max(0, ts)
            pb.trusted_packet_sequence_id = SEQ
            te = pb.track_event
            te.type = T.TYPE_SLICE_BEGIN
            te.track_uuid = uuid_
            te.name = name
            for k, v in args_.items():
                a = te.debug_annotations.add()
                a.name = k
                if isinstance(v, bool):
                    a.bool_value = v
                elif isinstance(v, int):
                    a.int_value = v
                else:
                    a.string_value = str(v)
            pe = b.create_packet()
            pe.timestamp = max(0, ts + dur)
            pe.trusted_packet_sequence_id = SEQ
            pe.track_event.type = T.TYPE_SLICE_END
            pe.track_event.track_uuid = uuid_
            return pb, pe

        for ai, (name, reads, prog, meta, start) in enumerate(arms):
            t0 = start if start is not None else (reads[0][0] if reads else 0)
            rel = lambda t: int(t) - t0  # noqa: E731

            pgid = newid()
            track(pgid, name=name, pid=6000 + ai, pname=name)

            # counter tracks
            c_useful = newid()
            track(c_useful, name="useful MB (intent: what the GNN consumes)",
                  parent=pgid, unit="MB", order=0, counter=True)
            c_store = newid()
            track(c_store, name="device MB read (store self-count)",
                  parent=pgid, unit="MB", order=1, counter=True)
            c_ebpf = newid()
            track(c_ebpf, name="device MB read (eBPF, independent)",
                  parent=pgid, unit="MB", order=2, counter=True)
            c_ra = newid()
            track(c_ra, name="read amplification (device / useful)",
                  parent=pgid, unit="x", order=3, counter=True)
            c_lba = newid()
            track(c_lba, name="device LBA (sector) -- access pattern",
                  parent=pgid, unit="sector", order=4, counter=True)
            lane = newid()
            track(lane, name="device reads (sampled)", parent=pgid, order=5)

            # intent witness: driver progress markers
            for mn, sb, db, _pg in prog:
                ts = rel(mn)
                events.append((ts, 1, counter_pkt(ts, c_useful, sb / 1e6)))
                events.append((ts, 1, counter_pkt(ts, c_store, db / 1e6)))
                if sb > 0:
                    events.append((ts, 1, counter_pkt(ts, c_ra, db / sb)))

            # mechanism witness: eBPF device reads
            cum = 0
            n = len(reads)
            step = max(1, n // max(1, args.counter_points))
            for i, (ts_abs, slba, byt) in enumerate(reads):
                cum += byt
                ts = rel(ts_abs)
                if i % step == 0 or i == n - 1:
                    events.append((ts, 1, counter_pkt(ts, c_ebpf, cum / 1e6)))
                    events.append((ts, 1, counter_pkt(ts, c_lba, slba,
                                                      is_double=False)))
                if i % max(1, args.slice_sample) == 0:
                    pb, pe = slice_pkts(
                        ts, SLICE_DUR_NS, lane, f"{byt // 1024}K",
                        {"slba": slba, "bytes": byt})
                    events.append((ts, 2, pb))
                    events.append((ts + SLICE_DUR_NS, 3, pe))

            sb = meta.get("signal_bytes", 0)
            db = meta.get("store_bytes", 0)
            rf = meta.get("ra_fetch", 0.0)
            print(f"arm {name}: {n:,} device reads, "
                  f"useful {sb/1e6:.2f} MB, device {db/1e6:.0f} MB, "
                  f"RA_signal {db/sb if sb else 0:.1f}x "
                  f"(store-reported RA_fetch {rf:.1f}x)")

        for ts, order, packet in sorted(events, key=lambda e: (e[0], e[1])):
            b.write_packet(packet)

    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
