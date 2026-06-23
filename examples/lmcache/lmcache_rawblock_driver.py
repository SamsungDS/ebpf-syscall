#!/usr/bin/env python3
"""Minimal direct driver for LMCache's raw-block device engine (Phase 4 A/B).

Drives `lmcache_rust_raw_block_io.RawBlockDevice` against a REGULAR FILE with no
vLLM / GPU / torch, so we can trace its file I/O and answer: does one logical
raw-block operation map to one lower-layer command, or is it split?

  Test A: --engine posix     -> pwrite_from_buffer / pread_into  (pwrite64/pread64)
  Test B: --engine io_uring   -> write_uring / read_uring or batched_*  (io_uring SQEs)

Emits a JSONL manifest of logical ops (one line per op) so a tracer's events can
be correlated to application intent. Verifies every read matches the written
pattern. Test C (use_uring_cmd / NVMe passthrough) needs /dev/ngXnY and is out of
scope here (Phase 3 / QEMU).

LMCache pin: branch 20260513-serdes-asym @ 83ccc6bb (record in results).
"""
import argparse, json, os, sys, time

import lmcache_rust_raw_block_io as rb


import functools


@functools.lru_cache(maxsize=1)
def _base():
    # 64 KiB deterministic base pattern, computed once (pure-python per-byte
    # generation of multi-MiB buffers is too slow and would push the real I/O
    # outside a tracer's capture window).
    return bytes((i * 2654435761 >> 8) & 0xFF for i in range(1 << 16))


def pattern(n, off):
    # deterministic per-op buffer at C speed: tile the base, then tag the first
    # 8 bytes with the offset so a misaddressed read is caught on verify.
    base = _base()
    b = bytearray(base * (n // len(base) + 1))[:n]
    b[0:8] = (off & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
    return bytes(b)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", choices=["posix", "io_uring"], default="posix")
    ap.add_argument("--file", default="/tmp/lmcache_rawblock.bin")
    ap.add_argument("--size", type=int, default=128 * 1024, help="bytes per op")
    ap.add_argument("--count", type=int, default=8)
    ap.add_argument("--qd", type=int, default=8)
    ap.add_argument("--batch", type=int, default=1,
                    help="io_uring: ops per batched_write/read call (1 = single write_uring)")
    ap.add_argument("--align", type=int, default=4096)
    ap.add_argument("--odirect", action="store_true")
    ap.add_argument("--uring-cmd", action="store_true",
                    help="NVMe passthrough via io_uring_cmd (needs --engine io_uring + /dev/ngXnY)")
    ap.add_argument("--max-xfer", type=int, default=0,
                    help="split each logical op into <=N-byte device ops (mimics LMCache "
                         "max_data_transfer_size; one NVMe command per device op)")
    ap.add_argument("--trace-id-base", type=int, default=0,
                    help="if set, tag op i with trace_id=base+i (encoded into io_uring "
                         "user_data high 32 bits) so an eBPF tracer can attribute every "
                         "NVMe command to KV object i; needs the kvio LMCache engine")
    ap.add_argument("--manifest", default=None, help="JSONL op manifest out")
    ap.add_argument("--header", type=int, default=1 << 20, help="reserved prefix bytes")
    args = ap.parse_args()

    if args.uring_cmd:
        assert args.engine == "io_uring", "--uring-cmd requires --engine io_uring"
        assert args.file.startswith("/dev/ng"), "--uring-cmd requires a /dev/ngXnY device"
        # raw NVMe namespace char device: fixed size, do NOT truncate
    else:
        cap = args.header + args.count * max(args.size, args.align) + (1 << 20)
        with open(args.file, "wb") as f:
            f.truncate(cap)

    dev = rb.RawBlockDevice(
        args.file, writable=True, use_odirect=args.odirect,
        alignment=args.align, io_engine=args.engine,
        iouring_queue_depth=args.qd, use_uring_cmd=args.uring_cmd,
    )

    man = open(args.manifest, "w") if args.manifest else None
    pid = os.getpid()
    sys.stderr.write(f"driver pid={pid} engine={args.engine} size={args.size} "
                     f"count={args.count} qd={args.qd} batch={args.batch}\n")

    stride = max(args.size, args.align)
    offs = [args.header + i * stride for i in range(args.count)]
    bufs = [bytearray(pattern(args.size, o)) for o in offs]

    def record(seq, ddir, off):
        if man:
            man.write(json.dumps({"seq": seq, "ddir": ddir, "offset": off,
                                  "size": args.size, "engine": args.engine}) + "\n")

    t0 = time.monotonic()
    # ---- WRITE pass ----
    if args.engine == "posix":
        for i, o in enumerate(offs):
            dev.pwrite_from_buffer(o, bufs[i], args.size, args.size)
            record(i, "write", o)
    else:
        if args.batch <= 1:
            mx = args.max_xfer or args.size
            for i, o in enumerate(offs):
                tid = (args.trace_id_base + i) if args.trace_id_base else 0
                mv = memoryview(bufs[i])
                for off in range(0, args.size, mx):
                    n = min(mx, args.size - off)
                    dev.write_uring(o + off, mv[off:off + n], n, n, tid)
                record(i, "write", o)
        else:
            for s in range(0, args.count, args.batch):
                grp = list(range(s, min(s + args.batch, args.count)))
                bid = dev.batched_write([offs[i] for i in grp],
                                        [bufs[i] for i in grp],
                                        [args.size for _ in grp])
                dev.wait_iouring(bid)
                for i in grp:
                    record(i, "write", offs[i])

    # ---- READ pass (verify) ----
    outs = [bytearray(args.size) for _ in offs]
    fails = 0
    if args.engine == "posix":
        for i, o in enumerate(offs):
            dev.pread_into(o, outs[i], args.size, args.size)
            record(i, "read", o)
    else:
        if args.batch <= 1:
            mx = args.max_xfer or args.size
            for i, o in enumerate(offs):
                tid = (args.trace_id_base + i) if args.trace_id_base else 0
                mv = memoryview(outs[i])
                for off in range(0, args.size, mx):
                    n = min(mx, args.size - off)
                    dev.read_uring(o + off, mv[off:off + n], n, n, tid)
                record(i, "read", o)
        else:
            for s in range(0, args.count, args.batch):
                grp = list(range(s, min(s + args.batch, args.count)))
                bid = dev.batched_read([offs[i] for i in grp],
                                       [outs[i] for i in grp],
                                       [args.size for _ in grp])
                dev.wait_iouring(bid)
                for i in grp:
                    record(i, "read", offs[i])

    for i in range(args.count):
        if bytes(outs[i]) != bytes(bufs[i]):
            fails += 1
    dt = time.monotonic() - t0
    dev.close()
    if man:
        man.close()

    total = args.count * args.size
    sys.stderr.write(
        f"driver done: {args.count} ops x {args.size} B = {total} B logical "
        f"per direction; verify_fail={fails}; {dt*1e3:.1f} ms\n")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
