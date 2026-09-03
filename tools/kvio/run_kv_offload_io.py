# SPDX-License-Identifier: Apache-2.0
"""GPU-free KV-cache-offload IO workload generator.

The KV-cache calculator answers "how many bytes is this model's KV cache?"
This answers the next question -- "what does *offloading* it to disk actually
do?" -- without a GPU or a model.

It takes a real model config (the calculator's ``modelconfig.json`` format),
computes the KV-cache block size for one chunk of tokens with the calculator's
geometry (``kv_geometry.py``), then issues that store/load workload against a
real device through LMCache's ``raw_block`` engine -- POSIX, io_uring, or
io_uring_cmd NVMe passthrough. The KV payload is fake bytes: storage IO geometry
(command count, sizes, total bytes) depends only on the block size and the
device's transfer limit, not on the tensor values, so real model *dimensions* +
fake *content* reproduce the real offload IO pattern.

It reports the per-chunk NVMe-command geometry and measured store/load latency,
and can emit a ``kvio_record.json`` manifest (replayable) and fire LMCache's
``LMCACHE_KVIO_TRACE`` semantic trace for cross-layer validation.

Example (real NVMe passthrough):
    python run_kv_offload_io.py --model meta-llama/Llama-3.1-8B-Instruct \\
        --dtype bfloat16 --chunk-tokens 256 --num-chunks 8 \\
        --device /dev/ng0n1 --engine uring_cmd --record /tmp/kvio_record.json
"""
from __future__ import annotations

import argparse
import json
import math
import os
import time

from kv_geometry import kv_cache_bytes, shard_kv_bytes, load_hf_config

# LMCache public API (no dependency on the test suite).
from lmcache.v1.distributed.api import ObjectKey
from lmcache.v1.memory_management import (
    MemoryFormat,
    MemoryObjMetadata,
    TensorMemoryObj,
)
from lmcache.v1.storage_backend.raw_block import RawBlockCore, RawBlockCoreConfig
from lmcache.v1.storage_backend.raw_block.key_codec import encode_object_key

import torch


class SemanticTrace:
    """Tool-side semantic JSONL emitter for the offset-join.

    The upstream (vendored) engine has no LMCACHE_KVIO_TRACE hook -- that was a
    kvio-branch engine patch. It is also not needed: RawBlockCore's public
    ``entry_offset(encoded_key)`` tells the tool exactly where an object
    landed, so the TOOL emits the per-object record itself -- the offset-join's
    "zero engine changes" made literal. The record schema matches the branch
    emitter byte-for-byte so kvio2perfetto --sem consumes either source:
    {trace_id, op, key, object_id, part, bytes, slot_offset, ts, ts_start,
    pid, instance} plus one self-describing event_type="meta" header line
    anchoring monotonic to realtime.
    """

    def __init__(self, path, *, header_bytes=None, mdts_bytes=None):
        import json as _json
        self._json = _json
        self._f = open(path, "w", buffering=1)
        self._pid = os.getpid()
        self._instance = os.urandom(4).hex()
        self._next_id = 1
        self._f.write(_json.dumps({
            "event_type": "meta", "emitter": "kvio-tool", "pid": self._pid,
            "instance": self._instance, "ts_monotonic": time.monotonic(),
            "ts_realtime": time.time(), "header_bytes": header_bytes,
            "mdts_bytes": mdts_bytes,
        }) + "\n")

    def emit(self, op, encoded_key, nbytes, slot_offset, ts_start, **context):
        rec = {
            "trace_id": self._next_id, "op": op, "key": encoded_key,
            "object_id": encoded_key, "part": "kv", "bytes": int(nbytes),
            "slot_offset": int(slot_offset), "ts": time.monotonic(),
            "ts_start": ts_start, "pid": self._pid, "instance": self._instance,
        }
        rec.update(context)
        self._next_id += 1
        self._f.write(self._json.dumps(rec) + "\n")

    def close(self):
        self._f.close()


def make_memory_obj(payload: bytes) -> TensorMemoryObj:
    data = bytearray(payload)
    raw = torch.frombuffer(data, dtype=torch.uint8)
    meta = MemoryObjMetadata(
        shape=torch.Size([len(data)]), dtype=torch.uint8, address=0,
        phy_size=len(data), fmt=MemoryFormat.BINARY, ref_count=1)
    return TensorMemoryObj(raw, meta, parent_allocator=None)


def make_empty_obj(size_bytes: int) -> TensorMemoryObj:
    raw = torch.zeros(size_bytes, dtype=torch.uint8)
    meta = MemoryObjMetadata(
        shape=torch.Size([size_bytes]), dtype=torch.uint8, address=0,
        phy_size=size_bytes, fmt=MemoryFormat.BINARY, ref_count=1)
    return TensorMemoryObj(raw, meta, parent_allocator=None)


def split_commands(nbytes, xfer, lba):
    """A logical transfer -> ceil(nbytes/xfer) commands, each rounded up to lba."""
    if nbytes <= 0:
        return []
    n = math.ceil(nbytes / xfer)
    cmds = [xfer] * (n - 1) + [nbytes - xfer * (n - 1)]
    return [((c + lba - 1) // lba) * lba for c in cmds]


def project(payload, mdts, header, lba):
    """Per-op NVMe command geometry (store = header op + payload; load = payload)."""
    store = split_commands(header, mdts, lba) + split_commands(payload, mdts, lba)
    load = split_commands(payload, mdts, lba)
    return {"store_cmds": len(store), "store_bytes": sum(store),
            "load_cmds": len(load), "load_bytes": sum(load)}


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else 0.0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("--modelconfig",
                    default=os.path.join(here, "modelconfig.json"),
                    help="modelconfig.json (calculator format)")
    ap.add_argument("--model", required=True,
                    help="model name: a key in modelconfig.json, or ANY Hugging "
                         "Face model id (its config is fetched automatically -- "
                         "config only, no weights, no GPU)")
    ap.add_argument("--dtype", default="bfloat16",
                    choices=["float32", "float16", "bfloat16", "int8", "fp8"])
    ap.add_argument("--chunk-tokens", type=int, default=256,
                    help="tokens per KV chunk = one offloaded block (LMCache default 256)")
    ap.add_argument("--num-chunks", type=int, default=8, help="how many chunks to offload")
    ap.add_argument("--tp", type=int, default=1,
                    help="tensor-parallel degree: one LMCache worker per rank, so "
                         "each chunk becomes tp offloaded objects (same chunk, "
                         "distinct kv_rank), sized by the family's KV-head sharding")
    ap.add_argument("--device", required=True, help="/dev/ngXnY (uring_cmd) or a file path")
    ap.add_argument("--engine",
                    choices=["posix", "io_uring", "uring_cmd", "cufile",
                             "opends"],
                    default="uring_cmd",
                    help="kernel engines (posix/io_uring/uring_cmd) move via "
                         "host DRAM; cufile/opends are GPU-direct (GDS) -- "
                         "same slot layout, same semantic trace")
    ap.add_argument("--gds-backend", default="gds",
                    help="opends engine only: which libopends_<X>.so variant "
                         "to load. 'gds' wraps proprietary cuFile (GPU "
                         "memory), 'ref' is the POSIX reference (host "
                         "memory, runs GPU-free); any future variant name "
                         "works unmodified")
    ap.add_argument("--gds-lib-dir",
                    help="extra directory to search for libopends_<X>.so")
    ap.add_argument("--mdts-bytes", type=int, default=131072,
                    help="bytes per NVMe command: LMCache's "
                         "max_data_transfer_size knob, <= the device's MDTS "
                         "(the engine does the splitting, not the device)")
    ap.add_argument("--block-align", type=int, default=4096)
    ap.add_argument("--header-bytes", type=int, default=4096)
    ap.add_argument("--iters", type=int, default=1, help="passes over the chunk set")
    ap.add_argument("--warmup", type=int, default=0)
    ap.add_argument("--odirect", action="store_true")
    ap.add_argument("--capacity-gb", type=int, default=8)
    ap.add_argument("--record", help="write a kvio_record.json replay manifest here")
    ap.add_argument("--trace", help="LMCACHE_KVIO_TRACE path (semantic trace)")
    args = ap.parse_args()

    if args.trace:
        os.environ["LMCACHE_KVIO_TRACE"] = args.trace
        open(args.trace, "w").close()

    with open(args.modelconfig) as f:
        configs = json.load(f)
    if args.model in configs:
        config, cfg_src = configs[args.model], "catalog"
    else:
        # Not in the calculator catalog: pull the config from HF (config JSON
        # only -- no weights, no GPU) so any model can be projected.
        config, cfg_src = load_hf_config(args.model), "HF AutoConfig"
    block_bytes, detail = kv_cache_bytes(args.model, config,
                                         args.chunk_tokens, args.dtype)
    # Under TP, each chunk is offloaded as `ranks` per-rank objects (see
    # shard_kv_bytes); at tp=1 this is the whole block as one object.
    obj_bytes, ranks, shard_note = shard_kv_bytes(block_bytes, detail, args.tp)
    geom = project(obj_bytes, args.mdts_bytes, args.header_bytes, args.block_align)

    print(f"=== KV-offload IO: {args.model} ({detail['family']}, {cfg_src}), "
          f"dtype={args.dtype} ===")
    print(f"  chunk={args.chunk_tokens} tok -> KV block = {block_bytes} B "
          f"({block_bytes / 1024 / 1024:.2f} MiB)  [{detail['total_elements']} elems]")
    if args.tp > 1:
        print(f"  TP={args.tp}: {shard_note} -> {ranks} objects/chunk x "
              f"{obj_bytes} B ({obj_bytes / 1024 / 1024:.2f} MiB) per rank")
    print(f"  per object: store {geom['store_cmds']} cmds / {geom['store_bytes']} B, "
          f"load {geom['load_cmds']} cmds / {geom['load_bytes']} B "
          f"(max_xfer={args.mdts_bytes // 1024} KiB/cmd, align={args.block_align})")
    engine_label = (f"opends:{args.gds_backend}" if args.engine == "opends"
                    else args.engine)
    odirect = args.odirect or args.engine in ("cufile", "opends")  # GDS: forced
    print(f"  workload: {args.num_chunks} chunks x {ranks} rank(s) = "
          f"{args.num_chunks * ranks} objects, engine={engine_label}, "
          f"O_DIRECT={'on' if odirect else 'off'}, dev={args.device}")

    slot = ((obj_bytes + args.header_bytes + (1 << 20) - 1) >> 20) << 20
    gds = args.engine in ("cufile", "opends")
    if gds:
        # GPU-direct path: same slot layout + semantic trace as
        # RawBlockCore, data moved by cuFile/OpenDS instead of the kernel
        # engines (destination GPU HBM, or host for opends ref backend).
        from gds_engine import GdsKVEngine
        core = GdsKVEngine(
            path=args.device, engine=args.engine, backend=args.gds_backend,
            lib_dir=args.gds_lib_dir, slot_bytes=slot,
            header_bytes=args.header_bytes, block_align=args.block_align,
            obj_bytes=obj_bytes,
            capacity_bytes=args.capacity_gb * 1024 * 1024 * 1024,
            mdts=args.mdts_bytes, trace_path=args.trace or None)
    if not gds:
        io_engine = "posix" if args.engine == "posix" else "io_uring"
        cfg = RawBlockCoreConfig(
            device_path=args.device, capacity_bytes=args.capacity_gb * 1024 * 1024 * 1024,
            block_align=args.block_align, header_bytes=args.header_bytes, slot_bytes=slot,
            use_odirect=args.odirect, enable_zero_copy=False, meta_total_bytes=1 * 1024 * 1024,
            meta_magic=b"LMCIDX01", meta_version=1, meta_checkpoint_interval_sec=60,
            meta_idle_quiet_ms=0, meta_enable_periodic=False, meta_verify_on_load=False,
            max_data_transfer_size=args.mdts_bytes, load_checkpoint_on_init=False,
            io_engine=io_engine, iouring_queue_depth=8,
            use_uring_cmd=(args.engine == "uring_cmd"))
        core = RawBlockCore(cfg, key_namespace="object")

    buf = bytes(obj_bytes)  # zeros; geometry is content-free
    n_obj = args.num_chunks * ranks
    store_ms, load_ms = [], []
    for it in range(args.warmup + args.iters):
        # fresh keys per pass so every store is a real write (not an index hit).
        # Under TP the `ranks` objects of a chunk share the chunk hash and differ
        # only by kv_rank -- exactly what the per-rank LMCache workers emit.
        keys = [encode_object_key(ObjectKey(
                    chunk_hash=ObjectKey.IntHash2Bytes(it * args.num_chunks + i),
                    model_name="kvoffload", kv_rank=r))
                for i in range(args.num_chunks) for r in range(ranks)]
        st = [0.0] * n_obj
        for j in range(n_obj):
            t0 = time.perf_counter()
            if gds:
                core.store(keys[j].encoded, it * n_obj + j)
            else:
                core.put_many([keys[j]], [make_memory_obj(buf)])
            st[j] = (time.perf_counter() - t0) * 1e3
        for j in range(n_obj):
            t2 = time.perf_counter()
            if gds:
                core.load(keys[j].encoded, it * n_obj + j)
            else:
                core.load_many_into([keys[j].encoded], [make_empty_obj(obj_bytes)])
            dt = (time.perf_counter() - t2) * 1e3
            if it >= args.warmup:
                store_ms.append(st[j]); load_ms.append(dt)
    try:
        core.close()
    except Exception:
        pass

    def line(name, ms, cmds, tbytes):
        mean = sum(ms) / len(ms)
        print(f"  {name:5s}: p50 {pct(ms, .5):7.3f} ms  p99 {pct(ms, .99):7.3f} ms | "
              f"{(obj_bytes / (mean / 1e3)) / 1e6:8.1f} MB/s | "
              f"{cmds / (mean / 1e3):9.0f} NVMe cmd/s")
    print("  --- measured (real device I/O) ---")
    line("store", store_ms, geom["store_cmds"], geom["store_bytes"])
    line("load", load_ms, geom["load_cmds"], geom["load_bytes"])

    if args.record:
        rec = {
            "schema_version": 1,
            "source": f"kv_cache_offload_io: {args.model} on {args.device}",
            "model": args.model, "geometry": detail,
            "device_geometry": {
                "engine": engine_label, "use_uring_cmd": args.engine == "uring_cmd",
                "mdts_bytes": args.mdts_bytes, "block_align": args.block_align,
                "header_bytes": args.header_bytes, "slot_bytes": slot,
                "capacity_bytes": args.capacity_gb * 1024 * 1024 * 1024,
            },
            "tp": args.tp, "ranks_per_chunk": ranks, "shard": shard_note,
            "chunk_block_bytes": block_bytes,
            "access_pattern": "store-all-then-load-all",
            # Under TP the objects of a chunk share chunk_index and differ by
            # kv_rank -- matching the per-rank LMCache workers.
            "objects": [{"index": i * ranks + r, "chunk_index": i, "kv_rank": r,
                         "part": "kv", "payload_bytes": obj_bytes,
                         "ops": ["store", "load"]}
                        for i in range(args.num_chunks) for r in range(ranks)],
        }
        with open(args.record, "w") as f:
            json.dump(rec, f, indent=2)
        print(f"  wrote replay manifest: {args.record}")


if __name__ == "__main__":
    main()
