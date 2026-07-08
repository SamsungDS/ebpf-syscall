#!/usr/bin/env python3
"""Run-proof for the PACKED asymmetric-KV kvio producer wiring.

Unlike ``kvio_put_many_proof.py`` (plain uint8 objects, which only exercise
``part``/``object_id``), this drives the real ``AsymK16V8Codec``: it encodes
(K, V) tensors into a packed ``EncodedKV`` blob (``K16 ‖ V8 ‖ scales`` in one
buffer) and stores/loads that blob through ``RawBlockCore`` on a real NVMe char
device with ``use_uring_cmd`` and ``LMCACHE_KVIO_TRACE`` on.

It then confirms, against the EncodedKV header as ground truth, that every kvio
semantic record carries:
  - ``part == "kv"``           (the packed object is genuinely one device I/O),
  - ``object_id == key``       (the join seam for a future K/V split),
  - ``components.{k,v,scale}_bytes`` EXACTLY matching the header's
    ``k/v/scale_payload_len`` (the K/V split the wire can't see but the blob
    carries verbatim), and
  - ``components{k,v,scale} + codec_header == bytes`` (the record's device-byte
    total accounts for every packed byte).

Run under the nvme_uring_cmd tracer to also validate the wire join + geometry
via kvio_validate.py (see the Latitude runbook). GPU is optional -- the codec
inherits the input tensors' device; build them on CUDA when available.

Env:
  KVIO_SRC   path to the lmcache `kvio` branch checkout (default
             /home/ubuntu/lmcache-src, matching the Latitude convention).
  KVIO_DEV   NVMe generic namespace char device (default /dev/ng0n1). MUST be a
             disposable/empty namespace -- this writes to it.
  KVIO_SEM   semantic-trace output path (default /tmp/sem.jsonl).
  KVIO_JSON  optional path to also dump a machine-readable result summary.
"""
import importlib.util
import json
import os
import sys

SRC = os.environ.get("KVIO_SRC", "/home/ubuntu/lmcache-src")
DEV = os.environ.get("KVIO_DEV", "/dev/ng0n1")
SEM = os.environ.get("KVIO_SEM", "/tmp/sem.jsonl")
sys.path.insert(0, SRC)
os.environ["LMCACHE_KVIO_TRACE"] = SEM
open(SEM, "w").close()

import torch  # noqa: E402

from lmcache.v1.kv_codec import AsymK16V8Codec, ScaleScope  # noqa: E402
from lmcache.v1.kv_codec.encoded_kv import deserialize_header  # noqa: E402
from lmcache.v1.storage_backend.raw_block import (  # noqa: E402
    RawBlockCore,
    RawBlockCoreConfig,
)
from lmcache.v1.storage_backend.raw_block.key_codec import (  # noqa: E402
    encode_object_key,
)

spec = importlib.util.spec_from_file_location(
    "rbtu",
    os.path.join(SRC, "tests/v1/storage_backend/raw_block_test_utils.py"),
)
rbtu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rbtu)

DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
# (num_tokens, kv_heads, head_dim) per object -- varied so the packed blob spans
# a different NVMe-command count each time (exercises the size distribution).
SHAPES = [(64, 8, 128), (128, 8, 128), (256, 8, 128)]

codec = AsymK16V8Codec(scale_scope=ScaleScope.PER_TENSOR)
print(f"AsymK16V8Codec on device={DEVICE}, PER_TENSOR scales")


def make_blob(shape):
    """Encode a random (K16, V8) pair into a packed EncodedKV byte blob."""
    t, h, d = shape
    k = torch.randn(t, h, d, dtype=torch.bfloat16, device=DEVICE)
    v = torch.randn(t, h, d, dtype=torch.bfloat16, device=DEVICE)
    enc = codec.encode(k, v, kv_head_count=h, head_dim=d)
    return codec.to_bytes(enc)


blobs = [make_blob(s) for s in SHAPES]
# Ground truth straight from each packed header (independent of the emit path).
truth = [deserialize_header(b) for b in blobs]
for i, (b, e) in enumerate(zip(blobs, truth)):
    hdr = len(b) - e.expected_payload_len()
    print(f"  obj{i}: blob={len(b)}B  k={e.k_payload_len} v={e.v_payload_len} "
          f"scale={e.scale_payload_len}  codec_header={hdr}")

N = len(blobs)
slot_bytes = max(len(b) for b in blobs)
slot_bytes = ((slot_bytes + (1 << 20) - 1) >> 20) << 20  # round up to MiB
cfg = RawBlockCoreConfig(
    device_path=DEV,
    capacity_bytes=8 * 1024 * 1024 * 1024,
    block_align=4096,
    header_bytes=4096,
    slot_bytes=slot_bytes,
    use_odirect=False,
    enable_zero_copy=False,
    meta_total_bytes=1 * 1024 * 1024,
    meta_magic=b"LMCIDX01",
    meta_version=1,
    meta_checkpoint_interval_sec=60,
    meta_idle_quiet_ms=0,
    meta_enable_periodic=False,
    meta_verify_on_load=False,
    max_data_transfer_size=131072,
    load_checkpoint_on_init=False,
    io_engine="io_uring",
    iouring_queue_depth=8,
    use_uring_cmd=True,
)
core = RawBlockCore(cfg, key_namespace="object")
print(f"RawBlockCore(use_uring_cmd=True, slot={slot_bytes}B) on {DEV}")

objs = [rbtu.make_memory_obj(b) for b in blobs]
keys = [encode_object_key(rbtu.make_object_key(i, model_name="asym-proof"))
        for i in range(N)]

pres = core.put_many(keys, objs)
print("put_many:", pres.results if hasattr(pres, "results") else pres)

empties = [rbtu.make_empty_memory_obj(len(b)) for b in blobs]
enc_keys = [k.encoded for k in keys]
lres = core.load_many_into(enc_keys, empties)
print("load_many_into:", lres)

# The packed blob is stored verbatim, so the round-trip must be byte-exact.
data_fail = sum(1 for i in range(N)
                if bytes(empties[i].byte_array) != blobs[i])
print("blob round-trip byte-fail:", data_fail)

try:
    core.close()
except Exception as e:
    print("close:", e)

# ── Validate the emitted semantic records against the header ground truth ────
sem = [json.loads(l) for l in open(SEM) if l.strip()]
by_key = {}
for r in sem:
    by_key.setdefault(r["key"], []).append(r)

failures = []
checked = 0
for i, ek in enumerate(enc_keys):
    e = truth[i]
    codec_header = len(blobs[i]) - e.expected_payload_len()
    for r in by_key.get(ek, []):
        checked += 1
        c = r.get("components")
        why = []
        if r.get("part") != "kv":
            why.append(f"part={r.get('part')!r}!=kv")
        if r.get("object_id") != ek:
            why.append("object_id!=key")
        if c is None:
            why.append("components missing (blob not recognized as EncodedKV)")
        else:
            if c.get("k_bytes") != e.k_payload_len:
                why.append(f"k {c.get('k_bytes')}!={e.k_payload_len}")
            if c.get("v_bytes") != e.v_payload_len:
                why.append(f"v {c.get('v_bytes')}!={e.v_payload_len}")
            if c.get("scale_bytes") != e.scale_payload_len:
                why.append(f"scale {c.get('scale_bytes')}!={e.scale_payload_len}")
            total = (c.get("k_bytes", 0) + c.get("v_bytes", 0)
                     + c.get("scale_bytes", 0) + codec_header)
            if total != r.get("bytes"):
                why.append(f"k+v+scale+hdr={total}!=bytes={r.get('bytes')}")
        if why:
            failures.append((r.get("op"), ek, why))

print("\n=== semantic records ===")
for r in sem:
    print("  ", json.dumps(r))

ok = data_fail == 0 and checked > 0 and not failures
print(f"\nrecords checked: {checked}  failures: {len(failures)}")
for op, ek, why in failures:
    print(f"  FAIL {op} {ek[:24]}: {'; '.join(why)}")

if os.environ.get("KVIO_JSON"):
    with open(os.environ["KVIO_JSON"], "w") as f:
        json.dump({
            "device": DEV, "compute_device": DEVICE, "n_objects": N,
            "blob_round_trip_fail": data_fail, "records_checked": checked,
            "failures": [{"op": o, "key": k, "why": w} for o, k, w in failures],
            "pass": ok,
        }, f, indent=2)

print("\nRESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
