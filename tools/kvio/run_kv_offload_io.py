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
import dataclasses
import hashlib
import json
import math
import mmap
import os
import sys
import threading
import time
from pathlib import Path

# Pin BLAS/OpenMP thread pools BEFORE importing anything that loads torch/numpy.
# This is an I/O benchmark, not a compute one: it does no matrix math, but torch
# and numpy drag in OpenBLAS, whose worker threads BUSY-WAIT (spin) when idle.
# During the offload's I/O waits those spinning threads burn cycles and retire
# instructions doing nothing, so an unpinned run's measured CPU tracks wall time,
# not work -- profiling showed ~70% of "CPU cost" was `blas_thread_server` spin,
# which fabricated a difference between object sizes that vanished once pinned.
# Default to 1; KVIO_CPU_THREADS overrides for anyone who wants BLAS parallelism.
_threads = os.environ.get("KVIO_CPU_THREADS", "1")
for _v in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS",
           "NUMEXPR_NUM_THREADS", "VECLIB_MAXIMUM_THREADS"):
    os.environ.setdefault(_v, _threads)

from kv_geometry import kv_cache_bytes, shard_kv_bytes, load_hf_config
from intent import (
    IntentError,
    build_kv_offload_intent,
    intent_sha256,
    load_intent,
    lower_intent,
    validate_target_plan,
)


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


HUGEPAGE_BYTES = 2 << 20


def alloc_kv_buffer(size_bytes: int, *, hugepage: bool = False) -> torch.Tensor:
    """Zero-filled, pre-faulted uint8 buffer for one KV object.

    With ``hugepage`` the buffer is a 2 MiB-aligned anonymous mapping under
    MADV_HUGEPAGE, so the kernel backs it with 2 MiB folios wherever
    ``/sys/kernel/mm/transparent_hugepage/enabled`` is ``always`` or ``madvise``.
    That is what lets one io_uring_cmd passthrough command carry more than
    ``max_segments`` pages: the kernel maps a user buffer one segment per
    physically contiguous run, so N MiB on 4 KiB pages needs N*256 segments and
    is rejected with EINVAL past ``max_segments``, while the same N MiB on
    2 MiB folios needs N/2. Pre-faulting keeps the page faults out of the timed
    region, like the pinned buffer pool a real engine stores from and restores
    into.
    """
    if hugepage:
        # MAP_PRIVATE matters: Python's default for an anonymous mmap is
        # MAP_SHARED, which is shmem and follows shmem_enabled (never, by
        # default) instead of the anonymous THP policy.
        mm = mmap.mmap(-1, size_bytes + HUGEPAGE_BYTES,
                       flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
        mm.madvise(mmap.MADV_HUGEPAGE)
        whole = torch.frombuffer(mm, dtype=torch.uint8)
        off = (-whole.data_ptr()) % HUGEPAGE_BYTES
        raw = whole[off:off + size_bytes]
    else:
        raw = torch.empty(size_bytes, dtype=torch.uint8)
    raw.fill_(0)
    return raw


class DmabufPool:
    """One dma-buf backed staging region, sliced into per-stream buffers.

    The raw_block engine registers its staging buffers with io_uring once,
    through an allocator that reports both the buffers themselves and the
    dma-buf that exports the memory they live in. LMCache's own allocator does
    that; kvio allocates its own buffers, so this is the same report in the
    smallest form the engine accepts. With the registration in place each
    fixed read or write is one command up to the device's dma-buf ceiling,
    instead of being DMA-mapped per command and clamped at 128 KiB behind a
    translating IOMMU.
    """

    def __init__(self, kind: str, nbuffers: int, buf_bytes: int,
                 *, hugepage: bool = False):
        # First Party
        from lmcache.v1.memory_management import (
            _DMABUF_REGIONS,
            _allocate_dmabuf_cpu_memory,
        )

        # Slices must start on a page boundary: the engine hands the kernel a
        # byte offset into the dma-buf, and an unaligned O_DIRECT address is
        # rejected long before the dma-buf matters.
        self.stride = (buf_bytes + HUGEPAGE_BYTES - 1) // HUGEPAGE_BYTES * HUGEPAGE_BYTES
        self.pool = _allocate_dmabuf_cpu_memory(
            self.stride * nbuffers, kind, hugepage
        )
        base = self.pool.data_ptr()
        region = _DMABUF_REGIONS.get(base)
        if region is None:
            raise RuntimeError(
                f"dma-buf allocation of kind {kind!r} reported no region; "
                "the engine cannot register it map-once"
            )
        self.fd = region[0]
        self.base = base
        self.kind = kind
        self.buffers = [
            self.pool[i * self.stride:i * self.stride + buf_bytes]
            for i in range(nbuffers)
        ]
        for buf in self.buffers:
            buf.fill_(0)

    def get_paged_buffers(self):
        return self.buffers

    def get_paged_dmabuf_regions(self):
        # Every slice lives in the one dma-buf, mapped at self.base.
        return [(self.fd, self.base) for _ in self.buffers]


def make_kv_obj(raw: torch.Tensor) -> TensorMemoryObj:
    meta = MemoryObjMetadata(
        shape=torch.Size([raw.numel()]), dtype=torch.uint8, address=0,
        phy_size=raw.numel(), fmt=MemoryFormat.BINARY, ref_count=1)
    return TensorMemoryObj(raw, meta, parent_allocator=None)


def anon_hugepages_kb() -> int:
    """This process's THP-backed anonymous memory (proof that --hugepage took)."""
    try:
        with open("/proc/self/smaps_rollup") as f:
            for ln in f:
                if ln.startswith("AnonHugePages:"):
                    return int(ln.split()[1])
    except OSError:
        pass
    return 0


def kernel_passthrough_cap(device_path: str):
    """What this kernel lets one NVMe passthrough command carry on ``device_path``.

    Returns ``max_hw_sectors_kb`` and ``max_segments`` from the namespace's
    sysfs queue, plus ``page_cap`` = min(max_hw_sectors_kb, max_segments * page):
    the largest command the kernel maps from ordinary 4 KiB pages. ``None`` when
    the path is not an NVMe device (a plain file) -- there is no cap to check.
    """
    from lmcache.v1.storage_backend.raw_block.core import (
        _read_sysfs_int,
        _resolve_sysfs_queue_dir,
    )
    queue_dir = _resolve_sysfs_queue_dir(device_path)
    if queue_dir is None:
        return None
    hw_kb = _read_sysfs_int(f"{queue_dir}/max_hw_sectors_kb")
    segs = _read_sysfs_int(f"{queue_dir}/max_segments")
    if not hw_kb or not segs:
        return None
    page = os.sysconf("SC_PAGE_SIZE")
    return {"max_hw_sectors_kb": hw_kb, "max_segments": segs,
            "hw_cap": hw_kb * 1024, "page_cap": min(hw_kb * 1024, segs * page)}


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


def _read_optional(path):
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return None


def target_descriptor(device_path, advertised_mdts_bytes):
    """Describe target-side facts without importing source-run realization."""
    name = os.path.basename(os.path.realpath(device_path))
    namespace = f"nvme{name[2:]}" if name.startswith("ng") else name
    controller = (
        namespace.rsplit("n", 1)[0] if namespace.startswith("nvme") else None
    )
    queue = f"/sys/block/{namespace}/queue"
    queue_fields = (
        "logical_block_size", "physical_block_size", "max_hw_sectors_kb",
        "max_sectors_kb", "max_hw_dmabuf_sectors_kb", "max_segments",
    )
    return {
        "device_path": device_path,
        "namespace": namespace,
        "controller": controller,
        "kernel_release": os.uname().release,
        "kernel_cmdline": _read_optional("/proc/cmdline"),
        "advertised_mdts_bytes": advertised_mdts_bytes,
        "advertised_mdts_interpretation": (
            "not-recorded" if advertised_mdts_bytes is None else
            "no-controller-transfer-limit" if advertised_mdts_bytes == 0 else
            "caller-recorded-controller-limit"),
        "queue": {field: _read_optional(f"{queue}/{field}")
                  for field in queue_fields},
        "controller_identity": ({
            "model": _read_optional(f"/sys/class/nvme/{controller}/model"),
            "serial": _read_optional(f"/sys/class/nvme/{controller}/serial"),
            "firmware_rev": _read_optional(
                f"/sys/class/nvme/{controller}/firmware_rev"),
        } if controller else None),
    }


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("--modelconfig",
                    default=os.path.join(here, "modelconfig.json"),
                    help="modelconfig.json (calculator format)")
    ap.add_argument("--model",
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
    ap.add_argument("--device", help="/dev/ngXnY (uring_cmd) or a file path")
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
                         "(the engine does the splitting, not the device). "
                         "0 = auto: the largest command this kernel maps from "
                         "4 KiB pages, min(max_hw_sectors_kb, max_segments*page)")
    ap.add_argument("--hugepage", action="store_true",
                    help="back the KV buffers with 2 MiB THP so one passthrough "
                         "command can exceed max_segments*4 KiB")
    ap.add_argument("--dmabuf", metavar="KIND", default=None,
                    help="stage through one dma-buf and register it with "
                         "io_uring map-once, so a fixed read or write is one "
                         "command up to the device's dma-buf ceiling instead "
                         "of being DMA-mapped per command. KIND is udmabuf (a "
                         "memfd, 2 MiB hugetlb folios with --hugepage), "
                         "system_heap, cma_heap, or a /dev/dma_heap name. "
                         "Needs a kernel with io_uring dma-buf registered "
                         "buffers; refused with --use-uring-cmd, which cannot "
                         "import one")
    ap.add_argument("--allow-io-errors", action="store_true",
                    help="exit 0 even when some store/load operations failed "
                         "(failed operations are never counted in the numbers)")
    ap.add_argument("--concurrency", type=int, default=1,
                    help="streams (threads) storing, then loading, their own "
                         "objects at the same time: N requests restoring at "
                         "once, or N TP ranks loading their shards")
    ap.add_argument("--load-parallelism", type=int, default=0,
                    help="engine-internal cross-object load threads "
                         "(RawBlockCoreConfig.load_parallelism, LMCache PR "
                         "#4697); 0 = engine default; refused by an engine "
                         "without it")
    ap.add_argument("--ring-depth", type=int, default=0,
                    help="io_uring ring depth handed to the engine "
                         "(iouring_queue_depth); 0 = engine default")
    ap.add_argument("--block-align", type=int, default=4096)
    ap.add_argument("--header-bytes", type=int, default=4096)
    ap.add_argument("--iters", type=int, default=1, help="passes over the chunk set")
    ap.add_argument("--warmup", type=int, default=0)
    ap.add_argument("--odirect", action="store_true")
    ap.add_argument("--capacity-gb", type=int, default=8)
    ap.add_argument("--record", help="write a kvio_record.json replay manifest here")
    ap.add_argument("--trace", help="LMCACHE_KVIO_TRACE path (semantic trace)")
    ap.add_argument("--intent-out", help="write a device-independent kvio.intent.v1 artifact")
    ap.add_argument("--intent-only", action="store_true",
                    help="write --intent-out and exit before opening a storage device")
    ap.add_argument(
        "--intent", help="execute this validated kvio.intent.v1 file"
    )
    ap.add_argument("--target-plan",
                    help="modeled target plan bound to --intent")
    ap.add_argument("--target-manifest",
                    help="write the target-side intent replay manifest")
    ap.add_argument(
        "--dma-ceiling-bytes",
        type=int,
        help="target dma-buf ceiling used only to bind --target-plan",
    )
    ap.add_argument(
        "--software-limit-bytes",
        type=int,
        help="target software ceiling used only to bind --target-plan",
    )
    ap.add_argument(
        "--advertised-mdts-bytes",
        type=int,
        help="recorded controller MDTS in bytes; 0 means no controller limit",
    )
    args = ap.parse_args()

    if args.intent_only and not args.intent_out:
        ap.error("--intent-only requires --intent-out")
    if args.intent and args.intent_out:
        ap.error("--intent and --intent-out cannot be used together")
    if args.intent_only and args.intent:
        ap.error("--intent-only cannot execute an intent")
    if args.intent and args.engine not in ("posix", "io_uring", "uring_cmd"):
        ap.error(
            "intent replay currently supports only host raw_block engines"
        )
    if not args.intent and not args.model:
        ap.error("--model is required unless --intent is used")
    if args.intent and (not args.target_plan or not args.target_manifest):
        ap.error("--intent requires --target-plan and --target-manifest")
    if not args.intent_only and not args.device:
        ap.error("--device is required unless --intent-only is used")

    replay_intent = None
    replay_plan = None
    if args.intent:
        try:
            replay_intent = load_intent(args.intent)
            replay_plan = json.loads(
                Path(args.target_plan).read_text(encoding="utf-8")
            )
            validate_target_plan(replay_plan, replay_intent)
            expected_plan = lower_intent(
                replay_intent, mdts_bytes=args.mdts_bytes,
                dma_ceiling_bytes=args.dma_ceiling_bytes,
                software_limit_bytes=args.software_limit_bytes)
            if replay_plan != expected_plan:
                raise IntentError(
                    "target plan limits disagree with replay options"
                )
            if args.dmabuf and args.dma_ceiling_bytes is None:
                raise IntentError(
                    "dma-buf replay requires --dma-ceiling-bytes"
                )
            if (
                args.advertised_mdts_bytes is not None
                and args.advertised_mdts_bytes < 0
            ):
                raise IntentError("advertised_mdts_bytes must be non-negative")
        except (IntentError, OSError, json.JSONDecodeError) as error:
            ap.error(str(error))
        args.model = replay_intent["model"]["name"]
        args.dtype = replay_intent["model"]["dtype"]
        args.chunk_tokens = replay_intent["model"]["chunk_tokens"]
        args.num_chunks = replay_intent["execution"]["num_chunks"]
        args.concurrency = replay_intent["execution"]["streams"]
        args.iters = replay_intent["execution"]["iters"]
        args.warmup = replay_intent["execution"]["warmup"]
        args.header_bytes = replay_intent["object"]["store_metadata_bytes"]
        obj_bytes = replay_intent["object"]["payload_bytes"]
        ranks = replay_intent["object"]["ranks_per_chunk"]
        args.tp = ranks
        block_bytes = obj_bytes * ranks
        detail = replay_intent["model"]["geometry"]
        cfg_src = "intent-v1"
        shard_note = "reconstructed from intent-v1"
    else:
        with open(args.modelconfig) as f:
            configs = json.load(f)
        if args.model in configs:
            config, cfg_src = configs[args.model], "catalog"
        else:
            # Not in the calculator catalog: pull config JSON from HF (no
            # weights and no GPU) so any model can be projected.
            config, cfg_src = load_hf_config(args.model), "HF AutoConfig"
        block_bytes, detail = kv_cache_bytes(args.model, config,
                                             args.chunk_tokens, args.dtype)
        # Under TP, each chunk is offloaded as `ranks` per-rank objects (see
        # shard_kv_bytes); at tp=1 this is the whole block as one object.
        obj_bytes, ranks, shard_note = shard_kv_bytes(
            block_bytes, detail, args.tp
        )
    if args.intent_out:
        intent = build_kv_offload_intent(
            model=args.model, geometry=detail, dtype=args.dtype,
            chunk_tokens=args.chunk_tokens, payload_bytes=obj_bytes,
            ranks_per_chunk=ranks, num_chunks=args.num_chunks,
            streams=max(1, args.concurrency), iters=args.iters,
            warmup=args.warmup, store_metadata_bytes=args.header_bytes)
        with open(args.intent_out, "w", encoding="utf-8") as output:
            json.dump(intent, output, indent=2, sort_keys=True)
            output.write("\n")
        print(f"  wrote device-independent intent: {args.intent_out}")
    if args.intent_only:
        return

    if args.trace:
        os.environ["LMCACHE_KVIO_TRACE"] = args.trace
        open(args.trace, "w").close()

    # The engine splits every object into --mdts-bytes commands and hands each
    # to the kernel as one user buffer. Intent deliberately does not need this
    # source realization; validate it only when a real engine run follows.
    cap = (kernel_passthrough_cap(args.device)
           if args.engine == "uring_cmd" else None)
    if args.mdts_bytes <= 0:
        if cap is None:
            sys.exit("--mdts-bytes 0 (auto) needs an NVMe device path and "
                     "--engine uring_cmd")
        args.mdts_bytes = cap["page_cap"]
        print(f"  mdts auto: {args.mdts_bytes // 1024} KiB/cmd "
              f"(max_hw_sectors_kb={cap['max_hw_sectors_kb']}, "
              f"max_segments={cap['max_segments']})")
    elif cap is not None:
        limit = cap["hw_cap"] if args.hugepage else cap["page_cap"]
        if args.mdts_bytes > limit:
            print(f"  WARNING: --mdts-bytes {args.mdts_bytes // 1024} KiB is above "
                  f"what this kernel maps per command "
                  f"({limit // 1024} KiB: max_hw_sectors_kb="
                  f"{cap['max_hw_sectors_kb']}, max_segments={cap['max_segments']}"
                  f"{'' if args.hugepage else ', 4 KiB pages; --hugepage lifts the segment part'}"
                  f"); expect every command to fail with EINVAL", file=sys.stderr)
    geom = project(obj_bytes, args.mdts_bytes, args.header_bytes, args.block_align)

    target_run = None
    if replay_intent is not None:
        manifest_path = Path(args.target_manifest)
        if manifest_path.exists():
            ap.error(
                f"refusing to overwrite existing artifact: {manifest_path}"
            )
        plan_bytes = Path(args.target_plan).read_bytes()
        target_run = {
            "schema": "kvio.intent-replay-run.v1",
            "evidence": "target-run-manifest-not-device-measurement",
            "status": "started",
            "intent": {
                "sha256": intent_sha256(replay_intent),
                "logical_operations": len(replay_intent["operations"]),
            },
            "target_plan": {
                "path": args.target_plan,
                "sha256": hashlib.sha256(plan_bytes).hexdigest(),
                "effective_command_bytes": (
                    replay_plan["effective_command_bytes"]
                ),
            },
            "realization": {
                "engine": args.engine,
                "dmabuf": args.dmabuf,
                "requested_mdts_bytes": args.mdts_bytes,
                "dma_ceiling_bytes": args.dma_ceiling_bytes,
                "software_limit_bytes": args.software_limit_bytes,
                "hugepage_buffers": args.hugepage,
                "odirect": args.odirect,
                "ring_depth": args.ring_depth,
                "load_parallelism": args.load_parallelism,
                "capacity_gb": args.capacity_gb,
            },
            "target": target_descriptor(
                args.device, args.advertised_mdts_bytes
            ),
            "artifacts": {"record": args.record, "semantic_trace": args.trace},
        }
        write_json(manifest_path, target_run)

    # Intent-only deliberately stays below the engine and torch dependency
    # boundary. The real workload still uses LMCache's public API and torch.
    global lmcache, ObjectKey, MemoryFormat, MemoryObjMetadata, TensorMemoryObj
    global RawBlockCore, RawBlockCoreConfig, encode_object_key, torch
    import lmcache
    from lmcache.v1.distributed.api import ObjectKey
    from lmcache.v1.memory_management import (
        MemoryFormat,
        MemoryObjMetadata,
        TensorMemoryObj,
    )
    from lmcache.v1.storage_backend.raw_block import RawBlockCore, RawBlockCoreConfig
    from lmcache.v1.storage_backend.raw_block.key_codec import encode_object_key
    import torch

    family = detail.get("family", "recorded geometry")
    print(f"=== KV-offload IO: {args.model} ({family}, {cfg_src}), "
          f"dtype={args.dtype} ===")
    print(f"  chunk={args.chunk_tokens} tok -> KV block = {block_bytes} B "
          f"({block_bytes / 1024 / 1024:.2f} MiB)  "
          f"[{detail.get('total_elements', 'recorded')} elems]")
    if args.tp > 1:
        print(f"  TP={args.tp}: {shard_note} -> {ranks} objects/chunk x "
              f"{obj_bytes} B ({obj_bytes / 1024 / 1024:.2f} MiB) per rank")
    print(f"  per object: store {geom['store_cmds']} cmds / "
          f"{geom['store_bytes']} B, "
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
        cfg_kwargs = dict(
            device_path=args.device, capacity_bytes=args.capacity_gb * 1024 * 1024 * 1024,
            block_align=args.block_align, header_bytes=args.header_bytes, slot_bytes=slot,
            use_odirect=args.odirect, enable_zero_copy=False, meta_total_bytes=1 * 1024 * 1024,
            meta_magic=b"LMCIDX01", meta_version=1, meta_checkpoint_interval_sec=60,
            meta_idle_quiet_ms=0, meta_enable_periodic=False, meta_verify_on_load=False,
            max_data_transfer_size=args.mdts_bytes, load_checkpoint_on_init=False,
            io_engine=io_engine, use_uring_cmd=(args.engine == "uring_cmd"))
        if args.ring_depth > 0:
            cfg_kwargs["iouring_queue_depth"] = args.ring_depth
        # The engine's read path decides what a load's queue depth can be: the
        # pre-#4697 raw_block issues one command at a time per object, PR #4697
        # batches an object's chunk reads and adds a cross-object load pool
        # (load_parallelism). Say which one this run drives.
        cfg_fields = {f.name for f in dataclasses.fields(RawBlockCoreConfig)}
        batched_reads = "load_parallelism" in cfg_fields
        if args.load_parallelism > 0:
            if not batched_reads:
                sys.exit("--load-parallelism: this engine has no load_parallelism "
                         "(raw_block before LMCache PR #4697)")
            cfg_kwargs["load_parallelism"] = args.load_parallelism
        core = RawBlockCore(RawBlockCoreConfig(**cfg_kwargs), key_namespace="object")
        print(f"  engine: raw_block from {os.path.dirname(lmcache.__file__)}; loads "
              f"{'batched per object + load_parallelism=' + str(cfg_kwargs.get('load_parallelism', 1)) + ' (PR #4697)' if batched_reads else 'one command at a time (before PR #4697)'}; "
              f"ring depth {core.iouring_queue_depth}; streams {args.concurrency}")

    # One source and one destination buffer per stream, allocated and
    # pre-faulted once and reused for every object: a real engine stores from
    # and restores into a pinned buffer pool, so allocating per object would
    # time page faults and garbage collection as offload cost. Content is zeros;
    # geometry is content-free. --concurrency N runs N streams (threads), each
    # with its own objects and buffers, at the same time: N requests restoring
    # at once, or N TP ranks loading their shards. The engine drops the GIL
    # while it waits on the ring, so the streams' commands overlap on the
    # device; the per-object Python bookkeeping stays serialised, as it is in
    # LMCache itself.
    nstreams = max(1, args.concurrency)
    dmabuf_pool = None
    if args.dmabuf and args.engine != "io_uring":
        sys.exit(f"--dmabuf needs --engine io_uring; {args.engine} either has "
                 "no fixed buffers or, for uring_cmd, cannot import a dma-buf")
    if args.dmabuf:
        # Both buffers of every stream come out of one dma-buf, which is what
        # the engine registers; a second region would cost a second sparse
        # registered-buffer slot for no gain.
        dmabuf_pool = DmabufPool(args.dmabuf, 2 * nstreams, obj_bytes,
                                 hugepage=args.hugepage)
        bufs = [(make_kv_obj(dmabuf_pool.buffers[2 * i]),
                 make_kv_obj(dmabuf_pool.buffers[2 * i + 1]))
                for i in range(nstreams)]
        core.register_fixed_buffers_from_allocator(dmabuf_pool)
        print(f"  buffers: {2 * nstreams} x {obj_bytes} B in one "
              f"{dmabuf_pool.kind} dma-buf (fd {dmabuf_pool.fd}), registered "
              f"map-once with io_uring")
    else:
        bufs = [(make_kv_obj(alloc_kv_buffer(obj_bytes, hugepage=args.hugepage)),
                 make_kv_obj(alloc_kv_buffer(obj_bytes, hugepage=args.hugepage)))
                for _ in range(nstreams)]
    if args.hugepage and not args.dmabuf:
        print(f"  buffers: {2 * nstreams} x {obj_bytes} B on THP; AnonHugePages now "
              f"{anon_hugepages_kb() // 1024} MiB")

    # Every operation's result is checked. The engine logs a failed write and
    # returns False instead of raising, and a load of a key that never landed
    # is a no-op that returns False without touching the device -- so timing an
    # unchecked call reports the cost of doing nothing as device throughput.
    def do_store(key, idx, src):
        try:
            if gds:
                return core.store(key.encoded, idx) is not False
            return bool(core.put_many([key], [src]).results[0])
        except Exception as e:
            print(f"  store {key.encoded} raised: {e}", file=sys.stderr)
            return False

    def do_load(key, idx, dst):
        try:
            if gds:
                return core.load(key.encoded, idx) is not False
            return bool(core.load_many_into([key.encoded], [dst])[0])
        except Exception as e:
            print(f"  load {key.encoded} raised: {e}", file=sys.stderr)
            return False

    n_obj = args.num_chunks * ranks  # objects per stream per pass

    def key_for_operation(operation):
        # Key material is a deterministic target implementation detail. The
        # input's pass/stream/chunk/rank identity, not a source key or offset,
        # determines it; store and load for one logical object get one key.
        base = ((operation["pass"] * nstreams + operation["stream"]) *
                args.num_chunks + operation["chunk_index"])
        return encode_object_key(ObjectKey(
            chunk_hash=ObjectKey.IntHash2Bytes(base), model_name="kvoffload",
            kv_rank=operation["kv_rank"]))

    def phase_operations(it, name, stream):
        if replay_intent is not None:
            return [operation for operation in replay_intent["operations"]
                    if operation["pass"] == it and operation["phase"] == name
                    and operation["stream"] == stream]
        return [{
            "pass": it, "stream": stream, "chunk_index": chunk_index,
            "kv_rank": rank, "sequence": (
                ((it * 2 + (name == "load")) * nstreams + stream) *
                args.num_chunks * ranks + chunk_index * ranks + rank),
        } for chunk_index in range(args.num_chunks) for rank in range(ranks)]

    def run_phase(name, it, fn):
        """Every stream runs `fn` over its objects at once; returns the per-stream
        latency lists (None = failed operation) and the phase wall time.

        The phase window is printed as CLOCK_MONOTONIC nanoseconds -- the clock
        nvme_tp_monitor stamps device commands with -- so a capture taken during
        the run can be cut per phase (tools/reproduce/kv-offload-io/qdepth.py).
        """
        stamp = {}
        barrier = threading.Barrier(
            nstreams, action=lambda: stamp.__setitem__("start", time.monotonic_ns()))
        out = [None] * nstreams

        def worker(s):
            operations = phase_operations(it, name, s)
            buf = bufs[s][0] if name == "store" else bufs[s][1]
            lat = [None] * len(operations)
            barrier.wait()
            for j, operation in enumerate(operations):
                t0 = time.perf_counter()
                key = key_for_operation(operation)
                ok = fn(key, operation["sequence"], buf)
                lat[j] = (time.perf_counter() - t0) * 1e3 if ok else None
            out[s] = lat

        threads = [threading.Thread(target=worker, args=(s,), name=f"{name}-{s}")
                   for s in range(nstreams)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        end = time.monotonic_ns()
        print(f"  @@@ PHASE {name} pass={it} start_ns={stamp['start']} end_ns={end}",
              flush=True)
        return out, (end - stamp["start"]) / 1e9

    store_ms, load_ms = [], []
    fails = {"store": 0, "load": 0}
    phase_wall = {"store": 0.0, "load": 0.0}
    for it in range(args.warmup + args.iters):
        phase_results = {}
        for name, fn in (("store", do_store), ("load", do_load)):
            phase_results[name] = run_phase(name, it, fn)
        st, wall_s = phase_results["store"]
        ld, wall_l = phase_results["load"]
        fails["store"] += sum(x.count(None) for x in st)
        fails["load"] += sum(x.count(None) for x in ld)
        if it >= args.warmup:
            store_ms += [v for x in st for v in x if v is not None]
            load_ms += [v for x in ld for v in x if v is not None]
            phase_wall["store"] += wall_s
            phase_wall["load"] += wall_l
    try:
        core.close()
    except Exception:
        pass

    n_ops = n_obj * nstreams * (args.warmup + args.iters)
    aggregate = {}

    def line(name, ms, cmds):
        nfail = fails[name]
        if not ms:
            print(f"  {name:5s}: NO successful operations "
                  f"({nfail}/{n_ops} failed) -- nothing measured")
            return
        mean = sum(ms) / len(ms)
        # per-stream rate from the per-operation mean; aggregate rate = every
        # stream's successful bytes over the phase wall time (what the device
        # delivered with all streams in flight)
        agg = (len(ms) * obj_bytes / phase_wall[name] / 1e6) if phase_wall[name] else 0.0
        aggregate[name] = agg
        print(f"  {name:5s}: p50 {pct(ms, .5):7.3f} ms  p99 {pct(ms, .99):7.3f} ms | "
              f"{(obj_bytes / (mean / 1e3)) / 1e6:8.1f} MB/s | "
              f"{cmds / (mean / 1e3):9.0f} NVMe cmd/s | "
              f"{len(ms)} timed, {nfail}/{n_ops} failed | "
              f"aggregate {agg:8.1f} MB/s x{nstreams}")
    print("  --- measured (real device I/O; failed operations excluded) ---")
    line("store", store_ms, geom["store_cmds"])
    line("load", load_ms, geom["load_cmds"])
    failed = fails["store"] + fails["load"]
    if failed:
        print(f"  !!! {fails['store']} store / {fails['load']} load operations "
              f"FAILED (engine errors above); the numbers cover only the "
              f"successful ones", file=sys.stderr)

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
                "hugepage_buffers": args.hugepage,
                "dmabuf": args.dmabuf,
            },
            "tp": args.tp, "ranks_per_chunk": ranks, "shard": shard_note,
            "chunk_block_bytes": block_bytes,
            "access_pattern": "store-all-then-load-all",
            "io_errors": dict(fails), "operations_attempted": n_ops,
            "concurrency": nstreams, "aggregate_MBps": aggregate,
            "engine_batched_reads": (not gds) and batched_reads,
            "load_parallelism": args.load_parallelism, "ring_depth": args.ring_depth,
            # Under TP the objects of a chunk share chunk_index and differ by
            # kv_rank -- matching the per-rank LMCache workers.
            "objects": [{"index": i * ranks + r, "chunk_index": i, "kv_rank": r,
                         "part": "kv", "payload_bytes": obj_bytes,
                         "ops": ["store", "load"]}
                        for i in range(args.num_chunks) for r in range(ranks)],
        }
        if replay_intent is not None:
            rec["intent_sha256"] = intent_sha256(replay_intent)
        with open(args.record, "w") as f:
            json.dump(rec, f, indent=2)
        print(f"  wrote replay manifest: {args.record}")

    if target_run is not None:
        target_run["status"] = (
            "complete" if not failed else "completed-with-io-errors"
        )
        target_run["outcomes"] = {
            "operations_per_phase": n_ops,
            "store_failures": fails["store"],
            "load_failures": fails["load"],
            "all_operations_succeeded": failed == 0,
            "aggregate_MBps": aggregate,
        }
        write_json(args.target_manifest, target_run)

    if failed and not args.allow_io_errors:
        sys.exit(2)


if __name__ == "__main__":
    main()
