#!/usr/bin/env python3
"""Is the KV-load bottleneck the device or the software path?

The real TP4 captures showed the LMCache raw_block load path is single-threaded,
QD~1 (per-128KiB-command serial submit-wait ~83us, ~11% of the drive's 11.3 GB/s).
This probe stores K objects then loads them back under several concurrency configs,
measuring aggregate load bandwidth, to see whether *parallelizing across objects*
recovers device bandwidth (the load_many_into lock is released before the I/O, so
thread-pool parallelism should work IF the rust binding drops the GIL in the wait).

  KVIO_SRC=~/kvio/LMCache python kvio_parallel_probe.py --device /dev/ng1n1 \
      --obj-mib 20 --nobj 128 --workers 1,2,4,8,16,32 [--qd 8]
"""
import argparse, importlib.util, os, sys, time
from concurrent.futures import ThreadPoolExecutor

SRC = os.environ.get("KVIO_SRC", os.path.expanduser("~/kvio/LMCache"))
sys.path.insert(0, SRC)
from lmcache.v1.storage_backend.raw_block import RawBlockCore, RawBlockCoreConfig
from lmcache.v1.storage_backend.raw_block.key_codec import encode_object_key
spec = importlib.util.spec_from_file_location(
    "rbtu", os.path.join(SRC, "tests/v1/storage_backend/raw_block_test_utils.py"))
rbtu = importlib.util.module_from_spec(spec); spec.loader.exec_module(rbtu)


def build(device, slot, cap_gb, qd, mdts=131072):
    cfg = RawBlockCoreConfig(
        device_path=device, capacity_bytes=cap_gb * (1 << 30),
        block_align=131072, header_bytes=131072, slot_bytes=slot,
        use_odirect=False, enable_zero_copy=False, meta_total_bytes=1 << 20,
        meta_magic=b"LMCIDX01", meta_version=1, meta_checkpoint_interval_sec=60,
        meta_idle_quiet_ms=0, meta_enable_periodic=False, meta_verify_on_load=False,
        max_data_transfer_size=mdts, load_checkpoint_on_init=False,
        io_engine="io_uring", iouring_queue_depth=qd, use_uring_cmd=True)
    return RawBlockCore(cfg, key_namespace="object")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--device", default="/dev/ng1n1")
    ap.add_argument("--obj-mib", type=int, default=20)
    ap.add_argument("--nobj", type=int, default=128)
    ap.add_argument("--workers", default="1,2,4,8,16,32")
    ap.add_argument("--qd", type=int, default=8)
    ap.add_argument("--reps", type=int, default=3)
    args = ap.parse_args()

    payload = args.obj_mib << 20
    slot = ((payload + 131072 + (1 << 20) - 1) >> 20) << 20
    cap_gb = max(8, (slot * args.nobj) // (1 << 30) + 2)
    core = build(args.device, slot, cap_gb, args.qd)
    print(f"device={args.device} obj={args.obj_mib}MiB nobj={args.nobj} qd={args.qd} "
          f"cap={cap_gb}GiB slot={slot} | 160 cmds/obj @128KiB")

    buf = bytes(payload)
    keys = [encode_object_key(rbtu.make_object_key(i, model_name="probe"))
            for i in range(args.nobj)]
    # store all
    t0 = time.perf_counter()
    for i in range(args.nobj):
        core.put_many([keys[i]], [rbtu.make_memory_obj(buf)])
    store_s = time.perf_counter() - t0
    print(f"store: {args.nobj} objs in {store_s:.3f}s = "
          f"{args.nobj*payload/store_s/1e9:.2f} GB/s (serial)")

    def load_one(k):
        core.load_many_into([k.encoded], [rbtu.make_empty_memory_obj(payload)])

    print(f"\n{'workers':>8} {'wall_s':>8} {'GB/s':>8} {'vs serial':>10}")
    base = None
    for W in [int(x) for x in args.workers.split(",")]:
        best = 1e9
        for _ in range(args.reps):
            t0 = time.perf_counter()
            if W == 1:
                for k in keys:
                    load_one(k)
            else:
                with ThreadPoolExecutor(max_workers=W) as ex:
                    list(ex.map(load_one, keys))
            best = min(best, time.perf_counter() - t0)
        gbps = args.nobj * payload / best / 1e9
        if base is None:
            base = gbps
        print(f"{W:>8} {best:>8.3f} {gbps:>8.2f} {gbps/base:>9.2f}x")
    try:
        core.close()
    except Exception:
        pass


if __name__ == "__main__":
    main()
