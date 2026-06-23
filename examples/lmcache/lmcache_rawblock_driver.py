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


def pattern(n, off):
    # deterministic, offset-keyed
    return bytes(((off + i) * 1103515245 >> 16) & 0xFF for i in range(n))


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
    ap.add_argument("--manifest", default=None, help="JSONL op manifest out")
    ap.add_argument("--header", type=int, default=1 << 20, help="reserved prefix bytes")
    args = ap.parse_args()

    cap = args.header + args.count * max(args.size, args.align) + (1 << 20)
    with open(args.file, "wb") as f:
        f.truncate(cap)

    dev = rb.RawBlockDevice(
        args.file, writable=True, use_odirect=args.odirect,
        alignment=args.align, io_engine=args.engine,
        iouring_queue_depth=args.qd,
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
            for i, o in enumerate(offs):
                dev.write_uring(o, bufs[i], args.size, args.size)
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
            for i, o in enumerate(offs):
                dev.read_uring(o, outs[i], args.size, args.size)
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
