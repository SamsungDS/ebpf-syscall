#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Derive one KV-offload intent per stored representation of the same chunk.

A ``kvio.intent.v1`` record carries one payload size for every logical
object, which is right for the plain BF16 K/V object LMCache's raw_block
engine stores today and wrong the moment the same chunk is stored in a
different representation: complete K16/V8, where V is FP8 with scales and a
codec header, or V8-only split-tier, where only V goes to storage and K stays
resident in host memory.  Those three are different objects with different
byte counts, and a comparison between them is only honest when every one is
derived from the same model geometry by the same arithmetic the engine's
codec uses.

This module does that derivation without a GPU, torch, or the engine.  The
byte accounting mirrors LMCache's merged asymmetric codec:

* ``lmcache/v1/kv_codec/encoded_kv.py`` fixes the encoded blob as a header
  (76 fixed bytes, then the scale shape, three payload lengths, the hash
  string table, and a CRC) followed by ``K || V || scales``;
* ``lmcache/v1/distributed/serde/asym_k16_v8.py`` writes exactly that blob
  for the complete representation and ``header || V || scales`` for V-only,
  and reserves a 1024-byte header allowance when sizing a destination.

Every number here is labelled derived.  The realized size of an encoded
object depends on runtime strings the codec writes into its header (model
id, tokenizer hash and so on), which are inputs to this module rather than
facts it can know.  Whether the derivation matches what the engine actually
writes is a Gate C question that needs the real serde on a GPU host.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

try:  # imported as tools.kvio.kv_representation (tests, offline package)
    from .intent import (
        IntentError,
        build_kv_offload_intent,
        intent_sha256,
        validate_intent,
    )
    from .kv_geometry import (
        DTYPE_BYTES,
        kv_cache_bytes,
        load_hf_config,
        shard_kv_bytes,
    )
except ImportError:  # run as a script from tools/kvio, like the runner
    from intent import (
        IntentError,
        build_kv_offload_intent,
        intent_sha256,
        validate_intent,
    )
    from kv_geometry import (
        DTYPE_BYTES,
        kv_cache_bytes,
        load_hf_config,
        shard_kv_bytes,
    )

SET_SCHEMA = "kvio.representation-set.v1"

# The codec's fixed header: magic (8) + six uint16 + seven int64.
_FIXED_HEADER_BYTES = struct.calcsize("<8sHHHHHH" + "qqqqqqq")
assert _FIXED_HEADER_BYTES == 76, _FIXED_HEADER_BYTES
_PAYLOAD_LENS_BYTES = struct.calcsize("<qqq")
_HASH_COUNT_BYTES = struct.calcsize("<H")
_CRC_BYTES = struct.calcsize("<I")
# The string table the codec always writes, in its fixed order.
CODEC_HASH_KEYS = (
    "model_id",
    "model_revision_hash",
    "tokenizer_hash",
    "rope_config_hash",
    "attention_backend",
    "kv_layout",
)
# The serde reserves this much for the header when it sizes a destination
# object; the header it actually writes is smaller.
SERDE_HEADER_ALLOWANCE = 1024
SCALE_DTYPE_BYTES = 4  # the codec's default scale dtype is float32

# Which representation stores which planes, and how.
REPRESENTATIONS = {
    "bf16_kv": {
        "stored": ("k", "v"),
        "host_resident": (),
        "codec": None,
        "k_stored_dtype": "bfloat16",
        "v_stored_dtype": "bfloat16",
        "description": "the plain K/V object raw_block stores today, no codec",
    },
    "k16_v8": {
        "stored": ("k", "v"),
        "host_resident": (),
        "codec": "AsymK16V8MultiSerializer",
        "k_stored_dtype": "bfloat16",
        "v_stored_dtype": "float8_e4m3fn",
        "description": "complete K16/V8: one self-contained encoded object",
    },
    "v8_only": {
        "stored": ("v",),
        "host_resident": ("k",),
        "codec": "AsymK16V8VOnlyMultiSerializer",
        "k_stored_dtype": None,
        "v_stored_dtype": "float8_e4m3fn",
        "description": "split-tier: V8 to storage, exact K kept in host memory",
    },
}
SCALE_SCOPES = ("per_tensor", "per_page_head")


class RepresentationError(ValueError):
    """Raised when a representation cannot be derived honestly."""


def codec_header_bytes(scale_shape, hashes):
    """Exact length of the header ``encoded_kv.serialize_header`` writes.

    ``hashes`` maps every key in ``CODEC_HASH_KEYS`` to the string the
    codec would write; an absent key is written as the empty string, which
    is what the codec does for a hash it was not given.
    """
    strings = 0
    for key in CODEC_HASH_KEYS:
        value = str(hashes.get(key, "")).encode("utf-8")
        strings += 2 + len(key.encode("utf-8")) + 2 + len(value)
    return (_FIXED_HEADER_BYTES + 8 * len(scale_shape) + _PAYLOAD_LENS_BYTES
            + _HASH_COUNT_BYTES + strings + _CRC_BYTES)


def _plane_bytes(detail, dtype_bytes):
    """Bytes of one plane, K or V, of one chunk at ``dtype_bytes`` per element.

    The families kvio sizes all store K and V as equal-shaped planes, so one
    plane is half the chunk's element count.  MLA does not: its latent
    cache is one tensor with no separable K and V, so neither a K16/V8
    split nor a V-only split has a defined meaning for it.
    """
    family = detail.get("family")
    if family == "mla":
        raise RepresentationError(
            "MLA stores one latent tensor with no separable K and V planes; "
            "an asymmetric or V-only representation is undefined for it"
        )
    if family not in ("default", "gqa_head_dim", "cla"):
        raise RepresentationError(f"unknown KV family {family!r}")
    elements = int(detail["total_elements"])
    if elements % 2:
        raise RepresentationError(
            f"chunk has {elements} elements, which does not split into two "
            "equal K and V planes"
        )
    return (elements // 2) * dtype_bytes


def _scale_shape(detail, chunk_tokens, page_size, scope):
    if scope == "per_tensor":
        return ()
    if scope != "per_page_head":
        raise RepresentationError(f"unknown scale scope {scope!r}")
    if page_size <= 0 or chunk_tokens % page_size:
        raise RepresentationError(
            f"chunk of {chunk_tokens} tokens is not a whole number of "
            f"{page_size}-token pages; per-page scales need one"
        )
    kv_heads = int(detail.get("num_key_value_heads") or 0)
    if kv_heads <= 0:
        raise RepresentationError(
            f"family {detail.get('family')!r} reports no KV-head count; "
            "per-page-head scales need one"
        )
    return (chunk_tokens // page_size, kv_heads)


def derive_representation(*, name, detail, dtype, chunk_tokens, tp=1,
                          scale_scope="per_tensor", page_size=16,
                          codec_hashes=None, store_metadata_bytes=4096,
                          block_align=4096, pad_to_block_align=False):
    """Byte accounting for one representation of one chunk on one rank."""
    if name not in REPRESENTATIONS:
        raise RepresentationError(f"unknown representation {name!r}")
    spec = REPRESENTATIONS[name]
    if dtype not in DTYPE_BYTES:
        raise RepresentationError(f"unknown logical dtype {dtype!r}")
    logical_bytes = DTYPE_BYTES[dtype]
    hashes = dict(codec_hashes or {})
    unknown = set(hashes) - set(CODEC_HASH_KEYS)
    if unknown:
        raise RepresentationError(
            f"codec hash keys {sorted(unknown)} are not written by the codec"
        )

    k_logical = _plane_bytes(detail, logical_bytes)
    v_logical = _plane_bytes(detail, logical_bytes)
    # Sharding is along the KV-head axis and applies to K and V alike, so
    # each plane shards exactly as the whole chunk does.
    k_rank, ranks, shard_note = shard_kv_bytes(k_logical, detail, tp)
    v_rank, ranks_v, _ = shard_kv_bytes(v_logical, detail, tp)
    if ranks != ranks_v:
        raise RepresentationError("K and V shard to different rank counts")

    if spec["codec"] is None:
        components = {"k": k_rank, "v": v_rank}
        scale_shape = ()
        header = 0
        scales = 0
    else:
        scale_shape = _scale_shape(detail, chunk_tokens, page_size, scale_scope)
        if scale_shape and tp > 1:
            # Per-page-head scales follow the heads a rank holds.
            scale_shape = (scale_shape[0], max(1, scale_shape[1] // ranks))
        scales = SCALE_DTYPE_BYTES
        for extent in scale_shape:
            scales *= extent
        header = codec_header_bytes(scale_shape, hashes)
        components = {}
        if "k" in spec["stored"]:
            components["k"] = k_rank  # K is never quantized by this codec
        components["v"] = v_rank // logical_bytes  # FP8: one byte per element
        components["scales"] = scales
        components["codec_header"] = header

    if pad_to_block_align:
        # An encoded object is a few hundred bytes past a block boundary
        # because of its header and scales.  A raw-block engine doing
        # O_DIRECT I/O then has an unaligned tail, which it can only move
        # through a bounce buffer, and a dma-buf-registered slot is refused
        # that bounce.  Padding the stored object to the namespace's physical
        # block size is what an engine has to do to keep the map-once path;
        # charging it here keeps the byte count honest.
        unpadded = sum(components.values())
        padding = (-unpadded) % block_align
        if padding:
            components["padding"] = padding
    stored_payload = sum(components.values())
    physical_extent = -(-(store_metadata_bytes + stored_payload) // block_align) * block_align
    host_retained = {plane: {"k": k_rank, "v": v_rank}[plane]
                     for plane in spec["host_resident"]}
    return {
        "representation": name,
        "description": spec["description"],
        "codec": spec["codec"],
        "evidence": "derived-from-codec-layout-not-measured",
        "logical": {
            "dtype": dtype,
            "k_bytes_per_rank": k_rank,
            "v_bytes_per_rank": v_rank,
            "ranks_per_chunk": ranks,
            "shard": shard_note,
        },
        "stored": {
            "planes": list(spec["stored"]),
            "k_dtype": spec["k_stored_dtype"],
            "v_dtype": spec["v_stored_dtype"],
            "scale_scope": scale_scope if spec["codec"] else None,
            "scale_shape": list(scale_shape),
            "components_bytes": components,
            "payload_bytes": stored_payload,
            "serde_reservation_bytes": (
                None if spec["codec"] is None
                else stored_payload - header + SERDE_HEADER_ALLOWANCE
            ),
        },
        "storage": {
            "store_metadata_bytes": store_metadata_bytes,
            "block_align": block_align,
            "physical_extent_bytes": physical_extent,
        },
        "host": {
            "retained_bytes": host_retained,
            "h2d_bytes_per_restore": sum(host_retained.values()),
            "note": (
                "a restore is usable only while the retained K is still "
                "resident; a V object whose K was evicted is a miss"
                if host_retained else "self-contained: nothing retained"
            ),
        },
        "assumptions": [
            "K and V are equal-shaped planes (true for MHA/GQA/CLA, refused for MLA)",
            "FP8 V is one byte per element and K is never quantized",
            f"scales are float32 ({SCALE_DTYPE_BYTES} B each)",
            "codec header length uses the supplied hash strings; unsupplied "
            "hashes are written empty, as the codec does",
            "physical extent is raw_block's fixed store metadata plus the "
            "payload, rounded up to the block alignment",
        ],
    }


def derive_representation_set(*, model, config, dtype, chunk_tokens,
                              num_chunks, streams, iters, warmup, tp=1,
                              representations=None, scale_scope="per_tensor",
                              page_size=16, codec_hashes=None,
                              store_metadata_bytes=4096, block_align=4096,
                              pad_to_block_align=False):
    """One intent per representation of the same logical schedule.

    Returns ``(manifest, intents)``.  Each intent is an ordinary
    ``kvio.intent.v1`` record whose only difference is the stored payload
    size, so the existing planner and replayer run it unchanged; the
    manifest binds the intents by digest and carries everything an intent
    cannot say: which planes were stored, in what dtype, and what stays in
    host memory.
    """
    names = list(representations or REPRESENTATIONS)
    for name in names:
        if name not in REPRESENTATIONS:
            raise RepresentationError(f"unknown representation {name!r}")
    hashes = dict(codec_hashes or {})
    hashes.setdefault("model_id", model)

    total_bytes, detail = kv_cache_bytes(model, config, chunk_tokens, dtype)
    if int(total_bytes) != int(detail["total_bytes"]):
        raise RepresentationError("geometry reports inconsistent chunk bytes")

    intents = {}
    entries = {}
    for name in names:
        entry = derive_representation(
            name=name, detail=detail, dtype=dtype, chunk_tokens=chunk_tokens,
            tp=tp, scale_scope=scale_scope, page_size=page_size,
            codec_hashes=hashes, store_metadata_bytes=store_metadata_bytes,
            block_align=block_align, pad_to_block_align=pad_to_block_align)
        intent = build_kv_offload_intent(
            model=model, geometry=detail, dtype=dtype,
            chunk_tokens=chunk_tokens,
            payload_bytes=entry["stored"]["payload_bytes"],
            ranks_per_chunk=entry["logical"]["ranks_per_chunk"],
            num_chunks=num_chunks, streams=streams, iters=iters,
            warmup=warmup, store_metadata_bytes=store_metadata_bytes)
        entry["intent_sha256"] = intent_sha256(intent)
        intents[name] = intent
        entries[name] = entry

    reference = entries.get("bf16_kv")
    ratios = {}
    if reference is not None:
        base = reference["stored"]["payload_bytes"]
        ratios = {name: entries[name]["stored"]["payload_bytes"] / base
                  for name in names}

    per_chunk_objects = entries[names[0]]["logical"]["ranks_per_chunk"]
    manifest = {
        "schema": SET_SCHEMA,
        "evidence": "derived-from-codec-layout-not-measured",
        "model": {"name": model, "dtype": dtype, "chunk_tokens": chunk_tokens,
                  "tp": tp, "geometry": detail},
        "schedule": {"num_chunks": num_chunks, "streams": streams,
                     "iters": iters, "warmup": warmup,
                     "objects_per_chunk": per_chunk_objects},
        "codec": {"scale_scope": scale_scope, "page_size": page_size,
                  "hashes": hashes,
                  "header_allowance_bytes": SERDE_HEADER_ALLOWANCE},
        "storage": {"store_metadata_bytes": store_metadata_bytes,
                    "block_align": block_align,
                    "pad_to_block_align": pad_to_block_align},
        "representations": entries,
        "payload_ratio_to_bf16_kv": ratios,
        "equal_host_budget_control": {
            "representation": "k16_v8",
            "host_budget_bytes": (
                entries["v8_only"]["host"]["h2d_bytes_per_restore"]
                * per_chunk_objects * num_chunks
                if "v8_only" in entries else 0
            ),
            "l2_operations": "not-derived: needs a hit model for which "
                             "complete objects the host budget keeps",
        },
        "limits": [
            "one payload size per intent: a representation that stores K "
            "and V as separate objects needs two intents, which this set "
            "does not model",
            "no cancellation, overwrite, or stale-generation operations: "
            "kvio.intent.v1 has store and load only",
            "the derived header length is exact only for the hash strings "
            "recorded above; the engine writes its own at runtime",
        ],
    }
    return manifest, intents


def manifest_sha256(manifest):
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def validate_representation_set(manifest, intents):
    """Reject a manifest that does not bind exactly to ``intents``."""
    if not isinstance(manifest, dict) or manifest.get("schema") != SET_SCHEMA:
        raise RepresentationError(f"manifest must use {SET_SCHEMA}")
    if manifest.get("evidence") != "derived-from-codec-layout-not-measured":
        raise RepresentationError("manifest must keep its derived evidence label")
    entries = manifest.get("representations")
    if not isinstance(entries, dict) or not entries:
        raise RepresentationError("manifest lists no representations")
    if set(entries) != set(intents):
        raise RepresentationError("manifest and intents name different representations")
    for name, entry in entries.items():
        intent = intents[name]
        validate_intent(intent)
        if entry.get("intent_sha256") != intent_sha256(intent):
            raise RepresentationError(f"{name}: intent digest does not bind")
        stored = entry.get("stored", {})
        if intent["object"]["payload_bytes"] != stored.get("payload_bytes"):
            raise RepresentationError(f"{name}: intent payload disagrees with manifest")
        if sum(stored.get("components_bytes", {}).values()) != stored.get("payload_bytes"):
            raise RepresentationError(f"{name}: components do not sum to the payload")
        if intent["object"]["ranks_per_chunk"] != entry["logical"]["ranks_per_chunk"]:
            raise RepresentationError(f"{name}: rank count disagrees")
        expected_planes = list(REPRESENTATIONS[name]["stored"])
        if stored.get("planes") != expected_planes:
            raise RepresentationError(f"{name}: stored planes are not {expected_planes}")


def _load_config(path, model):
    with open(path, encoding="utf-8") as handle:
        configs = json.load(handle)
    if model in configs:
        return configs[model]
    return load_hf_config(model)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    here = Path(__file__).resolve().parent
    parser.add_argument("--model", required=True)
    parser.add_argument("--modelconfig", default=str(here / "modelconfig.json"))
    parser.add_argument("--dtype", default="bfloat16")
    parser.add_argument("--chunk-tokens", type=int, default=256)
    parser.add_argument("--num-chunks", type=int, default=4)
    parser.add_argument("--streams", type=int, default=1)
    parser.add_argument("--iters", type=int, default=1)
    parser.add_argument("--warmup", type=int, default=0)
    parser.add_argument("--tp", type=int, default=1)
    parser.add_argument("--scale-scope", choices=SCALE_SCOPES, default="per_tensor")
    parser.add_argument("--page-size", type=int, default=16)
    parser.add_argument("--codec-hash", action="append", default=[],
                        metavar="KEY=VALUE",
                        help="a string the codec writes into its header; "
                             f"keys: {', '.join(CODEC_HASH_KEYS)}")
    parser.add_argument("--representation", action="append", default=None,
                        choices=sorted(REPRESENTATIONS))
    parser.add_argument("--block-align", type=int, default=4096,
                        help="the target namespace's physical block size in "
                             "bytes (sysfs queue/physical_block_size, which the "
                             "kernel derives from the drive's preferred write "
                             "granularity; 16384 on a 16 KiB indirection-unit "
                             "drive). O_DIRECT only demands the logical block "
                             "size, but the physical one is what the drive "
                             "wants. 4096 is a fallback, not a fact")
    parser.add_argument("--pad-to-block-align", action="store_true",
                        help="round each encoded object up to --block-align, "
                             "charging the padding, as an engine must to keep "
                             "an O_DIRECT dma-buf slot off the bounce path")
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args(argv)

    hashes = {}
    for item in args.codec_hash:
        key, sep, value = item.partition("=")
        if not sep:
            parser.error(f"--codec-hash expects KEY=VALUE, got {item!r}")
        hashes[key] = value
    try:
        manifest, intents = derive_representation_set(
            model=args.model, config=_load_config(args.modelconfig, args.model),
            dtype=args.dtype, chunk_tokens=args.chunk_tokens,
            num_chunks=args.num_chunks, streams=args.streams,
            iters=args.iters, warmup=args.warmup, tp=args.tp,
            representations=args.representation,
            scale_scope=args.scale_scope, page_size=args.page_size,
            codec_hashes=hashes, block_align=args.block_align,
            pad_to_block_align=args.pad_to_block_align)
        validate_representation_set(manifest, intents)
    except (RepresentationError, IntentError, ValueError, KeyError) as error:
        parser.error(str(error))

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for name, intent in intents.items():
        (out / f"{name}.intent.json").write_text(
            json.dumps(intent, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "representation-set.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for name, entry in manifest["representations"].items():
        stored = entry["stored"]
        print(f"{name:8s} payload {stored['payload_bytes']:>11d} B "
              f"({manifest['payload_ratio_to_bf16_kv'].get(name, 1.0):.4f}x bf16) "
              f"host-retained {entry['host']['h2d_bytes_per_restore']:>10d} B "
              f"extent {entry['storage']['physical_extent_bytes']:>11d} B")
    print(f"wrote {len(intents)} intents + representation-set.json to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
