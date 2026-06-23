#!/usr/bin/env python3
"""Run-proof: drive real LMCache RawBlockCore.put_many / load_many_into with
use_uring_cmd against /dev/ng0n1, with LMCACHE_KVIO_TRACE on, so we can confirm:
  - each KV object's NVMe commands carry that object's trace_id (eBPF side), and
  - the semantic record (trace_id -> {key, bytes, ...}) matches.
No GPU: MemoryObj is a CPU uint8 tensor.
"""
import os, sys, importlib.util

# absolute (this runs under sudo, where ~ would expand to /root)
SRC = "/home/ubuntu/lmcache-src"
sys.path.insert(0, SRC)
os.environ["LMCACHE_KVIO_TRACE"] = "/tmp/sem.jsonl"
open("/tmp/sem.jsonl", "w").close()

from lmcache.v1.storage_backend.raw_block import RawBlockCore, RawBlockCoreConfig
from lmcache.v1.storage_backend.raw_block.key_codec import encode_object_key

spec = importlib.util.spec_from_file_location(
    "rbtu", os.path.join(SRC, "tests/v1/storage_backend/raw_block_test_utils.py"))
rbtu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rbtu)

DEV = "/dev/ng0n1"
N = 3
SZ = 512 * 1024           # 512 KiB payload -> 4 NVMe cmds each @128 KiB MDTS

cfg = RawBlockCoreConfig(
    device_path=DEV,
    capacity_bytes=8 * 1024 * 1024 * 1024,
    block_align=4096,
    header_bytes=4096,
    slot_bytes=1024 * 1024,
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
print("RawBlockCore constructed (use_uring_cmd=True) on", DEV)

objs = [rbtu.make_memory_obj(bytes([0x41 + i]) * SZ) for i in range(N)]
keys = [encode_object_key(rbtu.make_object_key(i, model_name="proof")) for i in range(N)]

res = core.put_many(keys, objs)
print("put_many results:", res.results if hasattr(res, "results") else res)

empties = [rbtu.make_empty_memory_obj(SZ) for _ in range(N)]
enc = [k.encoded for k in keys]
lres = core.load_many_into(enc, empties)
print("load_many_into results:", lres)

fails = sum(1 for i in range(N)
            if bytes(empties[i].byte_array) != bytes(objs[i].byte_array))
print("data verify_fail:", fails)

try:
    core.close()
except Exception as e:
    print("close:", e)

print("=== semantic records (LMCACHE_KVIO_TRACE) ===")
for l in open("/tmp/sem.jsonl"):
    print("  ", l.strip())
