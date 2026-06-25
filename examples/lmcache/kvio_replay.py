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
"""
import argparse, os, sys, importlib.util, time

SRC = os.environ.get("KVIO_SRC", "/home/ubuntu/lmcache-src")
sys.path.insert(0, SRC)

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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", choices=list(kvio_plan.MODELS))
    ap.add_argument("--chunk-tokens", type=int, default=256)
    ap.add_argument("--payload-bytes", type=int, help="override model-derived payload")
    ap.add_argument("--device", default="/dev/ng0n1")
    ap.add_argument("--iters", type=int, default=40)
    ap.add_argument("--warmup", type=int, default=5)
    ap.add_argument("--slots", type=int, default=16, help="rotating keys (bounds capacity)")
    ap.add_argument("--mdts-bytes", type=int, default=131072)
    ap.add_argument("--engine", choices=["posix", "io_uring", "uring_cmd"],
                    default="uring_cmd",
                    help="posix/io_uring run on a regular file or block dev; "
                         "uring_cmd is NVMe passthrough (needs /dev/ngXnY)")
    ap.add_argument("--odirect", action="store_true",
                    help="bypass the page cache (real media latency for stores)")
    ap.add_argument("--capacity-gb", type=int, default=8)
    args = ap.parse_args()

    if args.payload_bytes is not None:
        payload = args.payload_bytes
        label = f"payload={payload} B"
    else:
        payload = kvio_plan.payload_for_model(args.model, args.chunk_tokens)
        label = f"{args.model} chunk={args.chunk_tokens}tok ({payload // 1024} KiB)"

    proj_store = kvio_plan.project(payload, "store", 4096, args.mdts_bytes, args.mdts_bytes)
    proj_load = kvio_plan.project(payload, "load", 4096, args.mdts_bytes, args.mdts_bytes)

    slot = ((payload + 4096 + (1 << 20) - 1) >> 20) << 20  # round up to MiB, room for header
    io_engine = "posix" if args.engine == "posix" else "io_uring"
    use_uring_cmd = args.engine == "uring_cmd"
    cfg = RawBlockCoreConfig(
        device_path=args.device, capacity_bytes=args.capacity_gb * 1024 * 1024 * 1024,
        block_align=4096, header_bytes=4096, slot_bytes=slot,
        use_odirect=args.odirect, enable_zero_copy=False, meta_total_bytes=1 * 1024 * 1024,
        meta_magic=b"LMCIDX01", meta_version=1, meta_checkpoint_interval_sec=60,
        meta_idle_quiet_ms=0, meta_enable_periodic=False, meta_verify_on_load=False,
        max_data_transfer_size=args.mdts_bytes, load_checkpoint_on_init=False,
        io_engine=io_engine, iouring_queue_depth=8, use_uring_cmd=use_uring_cmd)
    core = RawBlockCore(cfg, key_namespace="object")

    buf = bytes(bytearray(payload))  # CPU bytes, no GPU
    keys = [encode_object_key(rbtu.make_object_key(i, model_name="replay"))
            for i in range(args.slots)]

    store_ms, load_ms = [], []
    for n in range(args.warmup + args.iters):
        k = keys[n % args.slots]
        obj = rbtu.make_memory_obj(buf)
        t0 = time.perf_counter(); core.put_many([k], [obj]); t1 = time.perf_counter()
        empty = rbtu.make_empty_memory_obj(payload)
        t2 = time.perf_counter(); core.load_many_into([k.encoded], [empty]); t3 = time.perf_counter()
        if n >= args.warmup:
            store_ms.append((t1 - t0) * 1e3); load_ms.append((t3 - t2) * 1e3)
    try:
        core.close()
    except Exception:
        pass

    def report(name, ms, proj):
        mean = sum(ms) / len(ms)
        mbps = (payload / (mean / 1e3)) / 1e6
        iops = proj["nvme_commands"] / (mean / 1e3)
        print(f"  {name:5s}: proj {proj['nvme_commands']:>3} cmds / "
              f"{proj['total_device_bytes']} B | "
              f"p50 {pct(ms, .5):7.3f} ms  p99 {pct(ms, .99):7.3f} ms | "
              f"{mbps:8.1f} MB/s | {iops:9.0f} NVMe cmd/s")

    print(f"=== kvio replay: {label}, MDTS={args.mdts_bytes // 1024} KiB, "
          f"engine={args.engine}, O_DIRECT={'on' if args.odirect else 'off'}, "
          f"{args.iters} iters x {args.slots} slots, dev={args.device} ===")
    report("store", store_ms, proj_store)
    report("load", load_ms, proj_load)


if __name__ == "__main__":
    main()
