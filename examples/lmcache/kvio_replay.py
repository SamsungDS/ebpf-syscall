#!/usr/bin/env python3
"""kvio replay (KR2.2) — materialize a PROJECTED KV-offload workload against real
storage and measure latency / throughput / IOPS, GPU-free.

The projector (kvio_plan) says "model X + this config = N NVMe commands of these
sizes." Replay then issues exactly that store/load workload through the real
LMCache RawBlockCore (io_uring / NVMe passthrough) on a real device and reports
what it costs on *this* drive -- no GPU, no model, no inference.

Numbers are device-specific. On the QEMU file-backed NVMe guest they reflect the
emulation path, not bare metal; the point here is that the replay MECHANISM and
the projected-vs-measured geometry line up end to end.

Two input modes:
  * --model / --payload-bytes : one payload size, hammered --iters x --slots.
  * --record FILE.json        : a kvio_record.json manifest (device_geometry +
    an `objects` list of payload_bytes); replays the WHOLE recorded object set
    (store-all-then-load-all) with the recorded geometry, so the exact NVMe
    command stream is reissued. Geometry is content-independent, so replaying
    payload_bytes of zeros reproduces the recorded commands byte-for-byte.
"""
import argparse, json, os, sys, importlib.util, threading, time

SRC = os.environ.get("KVIO_SRC", "/home/ubuntu/lmcache-src")
sys.path.insert(0, SRC)


class ProgressWatchdog:
    """Abort if a single store/load makes no progress for `timeout` seconds.

    put_many / load_many_into are synchronous FFI calls into the Rust io_uring
    engine; a rare device/engine wedge would otherwise hang the whole replay
    indefinitely (observed once: a 70B-manifest replay sat ~16h at object 253
    during an unattended campaign). This watchdog turns that silent 16h wedge
    into a loud few-second abort that names the stuck object, so a campaign
    driver can time it out and move on instead of losing a run.
    """

    def __init__(self, timeout_s):
        self.timeout = float(timeout_s)
        self.last = time.monotonic()
        self.label = "init"
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True,
                                   name="kvio-replay-watchdog")

    def start(self):
        if self.timeout > 0:
            self._t.start()
        return self

    def tick(self, label):
        self.last = time.monotonic()
        self.label = label

    def stop(self):
        self._stop.set()

    def _run(self):
        poll = max(1.0, min(5.0, self.timeout / 4))
        while not self._stop.wait(poll):
            stuck = time.monotonic() - self.last
            if stuck > self.timeout:
                sys.stderr.write(
                    f"\n[kvio_replay WATCHDOG] no progress for {stuck:.0f}s "
                    f"(> {self.timeout:.0f}s) at '{self.label}' — aborting so the "
                    f"run does not hang. This is the rare io_uring_cmd wedge; "
                    f"re-run this manifest (it is not a projection error).\n")
                sys.stderr.flush()
                os._exit(42)

import kvio_plan
from lmcache.v1.storage_backend.raw_block import RawBlockCore, RawBlockCoreConfig
from lmcache.v1.storage_backend.raw_block.key_codec import encode_object_key

spec = importlib.util.spec_from_file_location(
    "rbtu", os.path.join(SRC, "tests/v1/storage_backend/raw_block_test_utils.py"))
rbtu = importlib.util.module_from_spec(spec); spec.loader.exec_module(rbtu)


def pct(xs, q):
    xs = sorted(xs)
    if not xs:
        return 0.0
    i = min(len(xs) - 1, int(q * len(xs)))
    return xs[i]


def build_core(*, device, capacity_bytes, block_align, header_bytes, slot_bytes,
               odirect, mdts, engine):
    """Construct a RawBlockCore for one replay run."""
    io_engine = "posix" if engine == "posix" else "io_uring"
    use_uring_cmd = engine == "uring_cmd"
    cfg = RawBlockCoreConfig(
        device_path=device, capacity_bytes=capacity_bytes,
        block_align=block_align, header_bytes=header_bytes, slot_bytes=slot_bytes,
        use_odirect=odirect, enable_zero_copy=False, meta_total_bytes=1 * 1024 * 1024,
        meta_magic=b"LMCIDX01", meta_version=1, meta_checkpoint_interval_sec=60,
        meta_idle_quiet_ms=0, meta_enable_periodic=False, meta_verify_on_load=False,
        max_data_transfer_size=mdts, load_checkpoint_on_init=False,
        io_engine=io_engine, iouring_queue_depth=8, use_uring_cmd=use_uring_cmd)
    return RawBlockCore(cfg, key_namespace="object")


def report_one(name, ms, proj, payload):
    mean = sum(ms) / len(ms)
    mbps = (payload / (mean / 1e3)) / 1e6
    iops = proj["nvme_commands"] / (mean / 1e3)
    print(f"  {name:5s}: proj {proj['nvme_commands']:>3} cmds / "
          f"{proj['total_device_bytes']} B | "
          f"p50 {pct(ms, .5):7.3f} ms  p99 {pct(ms, .99):7.3f} ms | "
          f"{mbps:8.1f} MB/s | {iops:9.0f} NVMe cmd/s")


def run_record(args):
    """Replay a whole recorded object set from a kvio_record.json manifest.

    Reads the device geometry (mdts / block_align / header / engine) and the
    per-object payload_bytes from the manifest, then reissues the recorded
    access pattern (store-all-then-load-all) --warmup+--iters times with a fresh
    key per pass (so every store is a real write, not an index-hit no-op). CLI
    --device / --odirect win over the record (they are machine-specific).
    """
    with open(args.record) as f:
        rec = json.load(f)
    geo = rec.get("device_geometry", {})
    mdts = int(geo.get("mdts_bytes", args.mdts_bytes))
    block_align = int(geo.get("block_align", 4096))
    header_bytes = int(geo.get("header_bytes", 4096))
    # engine: record's, unless the box can't do it and the user overrides via CLI
    engine = args.engine or ("uring_cmd" if geo.get("use_uring_cmd")
                             else geo.get("engine", "uring_cmd"))
    objs = rec.get("objects", [])
    if not objs:
        sys.exit("record has no objects[]")
    payloads = [int(o["payload_bytes"]) for o in objs]
    n = len(objs)
    slot = ((max(payloads) + header_bytes + (1 << 20) - 1) >> 20) << 20
    cap = int(geo.get("capacity_bytes", args.capacity_gb * 1024 * 1024 * 1024))
    core = build_core(device=args.device, capacity_bytes=cap, block_align=block_align,
                      header_bytes=header_bytes, slot_bytes=slot, odirect=args.odirect,
                      mdts=mdts, engine=engine)

    bufs = [bytes(bytearray(p)) for p in payloads]  # zeros; geometry is content-free
    store_ms = [[] for _ in range(n)]
    load_ms = [[] for _ in range(n)]
    passes = args.warmup + args.iters
    wd = ProgressWatchdog(args.op_timeout).start()
    for it in range(passes):
        # fresh keys per pass so each store issues real device I/O
        keys = [encode_object_key(rbtu.make_object_key(it * n + i, model_name="replay"))
                for i in range(n)]
        st = [0.0] * n
        # store-all ...
        for i in range(n):
            wd.tick(f"pass {it} store obj{i}/{n}")
            obj = rbtu.make_memory_obj(bufs[i])
            t0 = time.perf_counter(); core.put_many([keys[i]], [obj]); t1 = time.perf_counter()
            st[i] = (t1 - t0) * 1e3
        # ... then load-all (the recorded access pattern)
        for i in range(n):
            wd.tick(f"pass {it} load obj{i}/{n}")
            empty = rbtu.make_empty_memory_obj(payloads[i])
            t2 = time.perf_counter(); core.load_many_into([keys[i].encoded], [empty]); t3 = time.perf_counter()
            if it >= args.warmup:
                store_ms[i].append(st[i]); load_ms[i].append((t3 - t2) * 1e3)
    wd.stop()
    try:
        core.close()
    except Exception:
        pass

    print(f"=== kvio replay (record): {args.record}")
    print(f"    source: {rec.get('source', '?')}")
    print(f"    geometry: max_xfer={mdts // 1024} KiB/cmd, block_align={block_align}, "
          f"engine={engine}, O_DIRECT={'on' if args.odirect else 'off'}, "
          f"{n} objects x {args.iters} iters, dev={args.device} ===")
    tot_store = tot_load = 0
    for i in range(n):
        p = payloads[i]
        proj_s = kvio_plan.project(p, "store", header_bytes, mdts, mdts, block_align)
        proj_l = kvio_plan.project(p, "load", header_bytes, mdts, mdts, block_align)
        tot_store += proj_s["nvme_commands"]; tot_load += proj_l["nvme_commands"]
        print(f"  obj{i} payload={p} B:")
        report_one("store", store_ms[i], proj_s, p)
        report_one("load", load_ms[i], proj_l, p)
    print(f"  projected per-pass total: {tot_store} store + {tot_load} load "
          f"= {tot_store + tot_load} NVMe cmds")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--record", help="kvio_record.json manifest; replays the whole object set")
    ap.add_argument("--model", choices=list(kvio_plan.MODELS))
    ap.add_argument("--chunk-tokens", type=int, default=256)
    ap.add_argument("--payload-bytes", type=int, help="override model-derived payload")
    ap.add_argument("--device", default="/dev/ng0n1")
    ap.add_argument("--iters", type=int, default=40)
    ap.add_argument("--warmup", type=int, default=5)
    ap.add_argument("--slots", type=int, default=16, help="rotating keys (bounds capacity)")
    ap.add_argument("--mdts-bytes", type=int, default=131072)
    ap.add_argument("--engine", choices=["posix", "io_uring", "uring_cmd"],
                    default=None,
                    help="posix/io_uring run on a regular file or block dev; "
                         "uring_cmd is NVMe passthrough (needs /dev/ngXnY). "
                         "In --record mode, overrides the recorded engine.")
    ap.add_argument("--odirect", action="store_true",
                    help="bypass the page cache (real media latency for stores)")
    ap.add_argument("--capacity-gb", type=int, default=8)
    ap.add_argument("--op-timeout", type=float, default=120,
                    help="watchdog: abort if any single store/load makes no "
                         "progress for this many seconds (0 disables). Guards "
                         "against the rare io_uring_cmd wedge.")
    args = ap.parse_args()

    if args.record:
        run_record(args)
        return

    args.engine = args.engine or "uring_cmd"  # single-size default
    if args.payload_bytes is not None:
        payload = args.payload_bytes
        label = f"payload={payload} B"
    else:
        payload = kvio_plan.payload_for_model(args.model, args.chunk_tokens)
        label = f"{args.model} chunk={args.chunk_tokens}tok ({payload // 1024} KiB)"

    proj_store = kvio_plan.project(payload, "store", 4096, args.mdts_bytes, args.mdts_bytes)
    proj_load = kvio_plan.project(payload, "load", 4096, args.mdts_bytes, args.mdts_bytes)

    slot = ((payload + 4096 + (1 << 20) - 1) >> 20) << 20  # round up to MiB, room for header
    core = build_core(device=args.device, capacity_bytes=args.capacity_gb * 1024 * 1024 * 1024,
                      block_align=4096, header_bytes=4096, slot_bytes=slot,
                      odirect=args.odirect, mdts=args.mdts_bytes, engine=args.engine)

    buf = bytes(bytearray(payload))  # CPU bytes, no GPU
    keys = [encode_object_key(rbtu.make_object_key(i, model_name="replay"))
            for i in range(args.slots)]

    store_ms, load_ms = [], []
    wd = ProgressWatchdog(args.op_timeout).start()
    for n in range(args.warmup + args.iters):
        wd.tick(f"iter {n} store")
        k = keys[n % args.slots]
        obj = rbtu.make_memory_obj(buf)
        t0 = time.perf_counter(); core.put_many([k], [obj]); t1 = time.perf_counter()
        wd.tick(f"iter {n} load")
        empty = rbtu.make_empty_memory_obj(payload)
        t2 = time.perf_counter(); core.load_many_into([k.encoded], [empty]); t3 = time.perf_counter()
        if n >= args.warmup:
            store_ms.append((t1 - t0) * 1e3); load_ms.append((t3 - t2) * 1e3)
    wd.stop()
    try:
        core.close()
    except Exception:
        pass

    print(f"=== kvio replay: {label}, MDTS={args.mdts_bytes // 1024} KiB, "
          f"engine={args.engine}, O_DIRECT={'on' if args.odirect else 'off'}, "
          f"{args.iters} iters x {args.slots} slots, dev={args.device} ===")
    report_one("store", store_ms, proj_store, payload)
    report_one("load", load_ms, proj_load, payload)


if __name__ == "__main__":
    main()
