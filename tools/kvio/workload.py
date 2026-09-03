# SPDX-License-Identifier: Apache-2.0
"""GPU-free KV-offload IO for a whole *workload*, not a fixed chunk count.

``run_kv_offload_io.py`` issues N identical chunks -- one request's worth. Real
serving traffic is a *distribution* of prompt lengths (so a distribution of
per-request chunk counts) with a store/load mix set by the cache hit rate: a
miss stores fresh KV, a hit loads cached KV. This replays that shape against a
real device with no GPU and no model, so you can size storage for the workload
you actually run, not a single request.

Three ways to describe the workload:

  * ``--agent-plan plan.json`` -- a strict, evidence-labeled plan produced by
    ``kvio trace``. It preserves source request/session metadata, derives
    chunk-level loads and stores, and can pace requests by captured timing.

  * ``--trace file.jsonl`` -- one request per line; the token count is read from
    the first present of num_tokens/prompt_tokens/input_tokens/tokens/prompt_len,
    Numeric token fields are required. Content-only traces must first pass
    through ``kvio trace`` with a pinned tokenizer; token counts are not guessed.
  * ``--num-requests N`` with a synthetic lognormal prompt-length distribution
    (``--median-tokens``, ``--sigma``) -- a decent stand-in for LLM traffic.

``--hit-rate`` sets the fraction of requests served as loads (cache hits); the
rest are stores that grow the cached pool. Geometry (per-object command sizes,
TP sharding) comes from ``kv_geometry`` exactly as the single-request generator,
so an object here is byte-identical to one there -- only the *mix* is new.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import random
import time

from kv_geometry import kv_cache_bytes, shard_kv_bytes, load_hf_config
from agent_trace import TraceError, validate_plan
from run_kv_offload_io import (
    make_memory_obj, make_empty_obj, project, pct, SemanticTrace,
)
from lmcache.v1.distributed.api import ObjectKey
from lmcache.v1.storage_backend.raw_block import RawBlockCore, RawBlockCoreConfig
from lmcache.v1.storage_backend.raw_block.key_codec import encode_object_key

_TOKEN_FIELDS = ("num_tokens", "prompt_tokens", "input_tokens", "tokens", "prompt_len")


def request_tokens_from_trace(path):
    """Yield a per-request token count for each line of a JSONL trace."""
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if isinstance(obj, (int, float)):
                yield int(obj); continue
            for k in _TOKEN_FIELDS:
                if isinstance(obj.get(k), (int, float)):
                    yield int(obj[k]); break
            else:
                raise ValueError(
                    f"{path}: trace record has no numeric token count; "
                    "compile content traces with `kvio trace` and a pinned tokenizer")


def synthetic_tokens(n, median_tokens, sigma, seed):
    """Lognormal prompt-length draws (median = median_tokens)."""
    rng = random.Random(seed)
    mu = math.log(median_tokens)
    return [max(1, int(rng.lognormvariate(mu, sigma))) for _ in range(n)]


def histogram(counts, edges=(1, 2, 4, 8, 16, 32, 64)):
    """Bucket per-request chunk counts for a compact request-size profile."""
    buckets = {f"<= {e} chunks": 0 for e in edges}
    buckets[f"> {edges[-1]} chunks"] = 0
    for c in counts:
        for e in edges:
            if c <= e:
                buckets[f"<= {e} chunks"] += 1; break
        else:
            buckets[f"> {edges[-1]} chunks"] += 1
    return buckets


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("--modelconfig",
                    default=os.path.join(here, "modelconfig.json"))
    ap.add_argument("--model", required=True,
                    help="catalog key or any HF model id (config auto-fetched)")
    ap.add_argument("--dtype", default="bfloat16",
                    choices=["float32", "float16", "bfloat16", "int8", "fp8"])
    ap.add_argument("--chunk-tokens", type=int, default=256)
    ap.add_argument("--tp", type=int, default=1)
    ap.add_argument("--device", required=True, help="/dev/ngXnY (uring_cmd) or a file path")
    ap.add_argument("--engine", choices=["posix", "io_uring", "uring_cmd"], default="uring_cmd")
    ap.add_argument("--mdts-bytes", type=int, default=131072,
                    help="bytes per NVMe command (LMCache's "
                         "max_data_transfer_size, <= device MDTS)")
    ap.add_argument("--block-align", type=int, default=4096)
    ap.add_argument("--header-bytes", type=int, default=4096)
    ap.add_argument("--capacity-gb", type=int, default=32)
    ap.add_argument("--odirect", action="store_true")
    # workload shape
    ap.add_argument("--trace", help="JSONL request trace (numeric token count per line)")
    ap.add_argument("--agent-plan", help="plan JSON produced by `kvio trace`")
    ap.add_argument("--timing-scale", type=float, default=0.0,
                    help="agent-plan arrival pacing: 1=recorded gaps, 0=run flat-out")
    ap.add_argument("--num-requests", type=int, default=200,
                    help="synthetic request count when no --trace")
    ap.add_argument("--median-tokens", type=int, default=1024,
                    help="synthetic lognormal median prompt length")
    ap.add_argument("--sigma", type=float, default=1.0, help="synthetic lognormal sigma")
    ap.add_argument("--hit-rate", type=float, default=0.5,
                    help="fraction of requests served as cache-hit loads (rest are stores)")
    ap.add_argument("--sem-out", help="write the per-object semantic JSONL here "
                    "(slot_offset/bytes/ts via the engine's public entry_offset; "
                    "feed to `kvio perfetto --join-by-offset --sem ...`)")
    ap.add_argument("--seed", type=int, default=1234)
    args = ap.parse_args()
    if args.trace and args.agent_plan:
        ap.error("--trace and --agent-plan are mutually exclusive")
    if args.timing_scale < 0:
        ap.error("--timing-scale must be non-negative")

    agent_plan = None
    if args.agent_plan:
        try:
            with open(args.agent_plan, encoding="utf-8") as source:
                agent_plan = json.load(source)
            validate_plan(agent_plan)
        except (OSError, json.JSONDecodeError, TraceError) as error:
            ap.error(f"invalid --agent-plan: {error}")
        if agent_plan["chunk_tokens"] != args.chunk_tokens:
            ap.error(
                f"agent plan uses {agent_plan['chunk_tokens']} tokens/chunk but "
                f"--chunk-tokens is {args.chunk_tokens}")

    # geometry: identical to the single-request generator
    if os.path.exists(args.modelconfig):
        with open(args.modelconfig) as f:
            configs = json.load(f)
    else:
        configs = {}
    if args.model in configs:
        config, cfg_src = configs[args.model], "catalog"
    else:
        config, cfg_src = load_hf_config(args.model), "HF AutoConfig"
    block_bytes, detail = kv_cache_bytes(args.model, config, args.chunk_tokens, args.dtype)
    obj_bytes, ranks, shard_note = shard_kv_bytes(block_bytes, detail, args.tp)
    geom = project(obj_bytes, args.mdts_bytes, args.header_bytes, args.block_align)

    # per-request token counts -> per-request chunk counts
    if agent_plan:
        tokens = [int(request["input_tokens"]) for request in agent_plan["requests"]]
        wl_src = (f"agent plan {args.agent_plan} "
                  f"({agent_plan['source']['format']}, trace-derived)")
    elif args.trace:
        tokens = list(request_tokens_from_trace(args.trace))
        wl_src = f"trace {args.trace}"
    else:
        tokens = synthetic_tokens(args.num_requests, args.median_tokens, args.sigma, args.seed)
        wl_src = f"synthetic lognormal (median={args.median_tokens}, sigma={args.sigma})"
    if agent_plan:
        chunks_per_req = [int(request["complete_chunks"])
                          for request in agent_plan["requests"]]
    else:
        chunks_per_req = [max(1, math.ceil(t / args.chunk_tokens)) for t in tokens]
    n_req = len(chunks_per_req)

    print(f"=== KV-offload workload: {args.model} ({detail['family']}, {cfg_src}) ===")
    print(f"  object: {obj_bytes} B ({obj_bytes/1024/1024:.2f} MiB), "
          f"store {geom['store_cmds']} cmds / load {geom['load_cmds']} cmds, "
          f"TP={args.tp} ({ranks} obj/chunk)")
    if agent_plan:
        print(f"  workload: {n_req} requests, {wl_src}")
        print("  NOTE: application evidence + explicit cache assumptions; not captured device IO")
    else:
        print(f"  workload: {n_req} requests, {wl_src}, hit-rate={args.hit_rate}")
    print(f"  request-size profile (chunks/request): {histogram(chunks_per_req)}")
    if agent_plan:
        logical_ops = agent_plan["summary"]["loads"] + agent_plan["summary"]["stores"]
        total_obj = logical_ops * ranks
        print(f"  planned object IOs = {total_obj}  "
              f"(~{total_obj*obj_bytes/1024**3:.2f} GiB before command headers)")
    else:
        total_obj = sum(chunks_per_req) * ranks
        print(f"  total objects = {total_obj}  (~{total_obj*obj_bytes/1024**3:.2f} GiB of KV)")

    slot = ((obj_bytes + args.header_bytes + (1 << 20) - 1) >> 20) << 20
    io_engine = "posix" if args.engine == "posix" else "io_uring"
    cfg = RawBlockCoreConfig(
        device_path=args.device, capacity_bytes=args.capacity_gb * 1024**3,
        block_align=args.block_align, header_bytes=args.header_bytes, slot_bytes=slot,
        use_odirect=args.odirect, enable_zero_copy=False, meta_total_bytes=1 << 20,
        meta_magic=b"LMCIDX01", meta_version=1, meta_checkpoint_interval_sec=60,
        meta_idle_quiet_ms=0, meta_enable_periodic=False, meta_verify_on_load=False,
        max_data_transfer_size=args.mdts_bytes, load_checkpoint_on_init=False,
        io_engine=io_engine, iouring_queue_depth=16,
        use_uring_cmd=(args.engine == "uring_cmd"))
    core = RawBlockCore(cfg, key_namespace="object")
    buf = bytes(obj_bytes)
    sem = SemanticTrace(args.sem_out, header_bytes=args.header_bytes,
                        mdts_bytes=args.mdts_bytes) if args.sem_out else None

    def rank_keys(chunk_key):
        chunk_hash = bytes.fromhex(chunk_key)
        return [encode_object_key(ObjectKey(
            chunk_hash=chunk_hash, model_name=args.model, kv_rank=rank))
                for rank in range(ranks)]

    if agent_plan:
        required = (int(agent_plan["summary"].get("max_resident_chunks", 0))
                    * ranks * slot + (1 << 20))
        capacity = args.capacity_gb * 1024**3
        if required > capacity:
            raise SystemExit(
                f"agent plan needs up to {required / 1024**3:.2f} GiB of raw-block slots; "
                f"--capacity-gb provides {args.capacity_gb} GiB")

        # TraceLab can begin in the middle of a warm provider-cache session.
        # Materialize those logical chunks before starting timing or metrics.
        for chunk_key in agent_plan.get("warm_keys", []):
            for key in rank_keys(chunk_key):
                result = core.put_many([key], [make_memory_obj(buf)])
                if not result.results[0]:
                    raise RuntimeError("failed to precondition an agent-plan warm chunk")

        store_ms, load_ms = [], []
        store_chunks = load_chunks = delete_chunks = 0
        t_start = time.perf_counter()
        for request in agent_plan["requests"]:
            if args.timing_scale:
                target = float(request["offset_s"]) * args.timing_scale
                delay = target - (time.perf_counter() - t_start)
                if delay > 0:
                    time.sleep(delay)
            context = {
                "request_index": request["request_index"],
                "session": request["session"],
                "source_offset_s": request["offset_s"],
            }
            for plan_op_index, operation in enumerate(request["operations"]):
                keys = rank_keys(operation["chunk_key"])
                encoded_keys = [key.encoded for key in keys]
                if operation["op"] == "delete":
                    result = core.delete_many(encoded_keys, force=True)
                    if not all(result):
                        raise RuntimeError(
                            f"agent plan eviction missed at request {request['request_index']}")
                    delete_chunks += 1
                    continue
                if operation["op"] == "store":
                    store_chunks += 1
                    for key in keys:
                        encoded = key.encoded
                        t0 = time.perf_counter()
                        sem_t0 = time.monotonic() if sem else 0.0
                        result = core.put_many([key], [make_memory_obj(buf)])
                        if not result.results[0]:
                            raise RuntimeError(
                                f"agent plan store failed at request "
                                f"{request['request_index']}")
                        store_ms.append((time.perf_counter() - t0) * 1e3)
                        if sem:
                            off = core.entry_offset(encoded)
                            if off is not None:
                                sem.emit("store", encoded, obj_bytes, off, sem_t0,
                                         plan_op_index=plan_op_index, **context)
                    continue
                load_chunks += 1
                for encoded in encoded_keys:
                    t0 = time.perf_counter()
                    sem_t0 = time.monotonic() if sem else 0.0
                    result = core.load_many_into([encoded], [make_empty_obj(obj_bytes)])
                    load_ms.append((time.perf_counter() - t0) * 1e3)
                    if not result or not result[0]:
                        raise RuntimeError(
                            f"agent plan load missed at request {request['request_index']}")
                    if sem:
                        off = core.entry_offset(encoded)
                        if off is not None:
                            sem.emit("load", encoded, obj_bytes, off, sem_t0,
                                     plan_op_index=plan_op_index, **context)
        wall = time.perf_counter() - t_start
        if sem:
            sem.close()
        try:
            core.close()
        except Exception:
            pass
        stored_gb = len(store_ms) * obj_bytes / 1024**3
        loaded_gb = len(load_ms) * obj_bytes / 1024**3
        print(f"  --- served {n_req} requests from the agent plan ---")
        print(f"  logical chunks: {load_chunks} loads, {store_chunks} stores, "
              f"{delete_chunks} evictions")
        print(f"  stores: n={len(store_ms):6d}  p50 {pct(store_ms,.5):7.3f} ms  "
              f"p99 {pct(store_ms,.99):7.3f} ms  ({stored_gb:.2f} GiB)")
        print(f"  loads : n={len(load_ms):6d}  p50 {pct(load_ms,.5):7.3f} ms  "
              f"p99 {pct(load_ms,.99):7.3f} ms  ({loaded_gb:.2f} GiB)")
        print(f"  wall {wall:.2f}s  aggregate {(stored_gb+loaded_gb)/max(wall, 1e-9):.2f} "
              f"GiB/s ({(len(store_ms)+len(load_ms))/max(wall, 1e-9):.0f} objects/s)")
        return

    rng = random.Random(args.seed ^ 0x5151)
    stored_keys = []          # pool of objects available to be loaded (cache hits)
    next_hash = 0
    store_ms, load_ms = [], []
    n_hit = n_miss = 0
    t_start = time.perf_counter()
    for nchunks in chunks_per_req:
        want_hit = stored_keys and rng.random() < args.hit_rate
        if want_hit:
            n_hit += 1
            # load nchunks objects (all ranks) from the existing pool
            for _ in range(nchunks):
                base = rng.randrange(len(stored_keys))
                for enc in stored_keys[base]:
                    t0 = time.perf_counter()
                    sem_t0 = time.monotonic() if sem else 0.0
                    core.load_many_into([enc], [make_empty_obj(obj_bytes)])
                    load_ms.append((time.perf_counter() - t0) * 1e3)
                    if sem:
                        off = core.entry_offset(enc)
                        if off is not None:
                            sem.emit("load", enc, obj_bytes, off, sem_t0)
        else:
            n_miss += 1
            for _ in range(nchunks):
                rank_encs = []
                for r in range(ranks):
                    key = encode_object_key(ObjectKey(
                        chunk_hash=ObjectKey.IntHash2Bytes(next_hash),
                        model_name="kvoffload", kv_rank=r))
                    t0 = time.perf_counter()
                    sem_t0 = time.monotonic() if sem else 0.0
                    core.put_many([key], [make_memory_obj(buf)])
                    store_ms.append((time.perf_counter() - t0) * 1e3)
                    if sem:
                        off = core.entry_offset(key.encoded)
                        if off is not None:
                            sem.emit("store", key.encoded, obj_bytes, off, sem_t0)
                    rank_encs.append(key.encoded)
                next_hash += 1
                stored_keys.append(rank_encs)
    wall = time.perf_counter() - t_start
    if sem:
        sem.close()
    try:
        core.close()
    except Exception:
        pass

    stored_gb = len(store_ms) * obj_bytes / 1024**3
    loaded_gb = len(load_ms) * obj_bytes / 1024**3
    print(f"  --- served {n_req} requests: {n_hit} hits (loads), {n_miss} misses (stores) ---")
    print(f"  stores: n={len(store_ms):6d}  p50 {pct(store_ms,.5):7.3f} ms  "
          f"p99 {pct(store_ms,.99):7.3f} ms  ({stored_gb:.2f} GiB)")
    print(f"  loads : n={len(load_ms):6d}  p50 {pct(load_ms,.5):7.3f} ms  "
          f"p99 {pct(load_ms,.99):7.3f} ms  ({loaded_gb:.2f} GiB)")
    print(f"  wall {wall:.2f}s  aggregate {(stored_gb+loaded_gb)/wall:.2f} GiB/s "
          f"({(len(store_ms)+len(load_ms))/wall:.0f} objects/s)")


if __name__ == "__main__":
    main()
