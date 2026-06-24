#!/usr/bin/env python3
"""kvio sweep — drive real LMCache RawBlockCore.put_many / load_many_into across a
range of payload sizes (use_uring_cmd against /dev/ng0n1), with LMCACHE_KVIO_TRACE
on, so kvio_validate.py can confirm the projector (kvio_plan) is faithful across
sizes -- especially NON-MDTS-aligned ones, where naive ceil/remainder math fails.

One RawBlockCore drives every size so the minted trace_ids stay unique and the
eBPF join is unambiguous. No GPU: MemoryObj is a CPU uint8 tensor.
"""
import os, sys, importlib.util

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
MDTS = 131072
SLOT = 2 * 1024 * 1024  # > max payload + header_bytes
# Payload sizes (bytes). MDTS=128 KiB. Deliberately mix aligned and NON-aligned:
#   4096        header-sized tiny (1 payload cmd)
#   131072      exactly 1 MDTS  (1 cmd)
#   196608      1.5 MDTS        (2 cmds, 64 KiB remainder)   <- non-aligned
#   327680      2.5 MDTS        (3 cmds, 64 KiB remainder)   <- non-aligned
#   524288      4 MDTS          (4 cmds)  [the original proof point]
#   700000      odd, non-LBA    (6 cmds, sub-LBA tail)       <- exercises LBA round-up
#   1048576     8 MDTS          (8 cmds)
#   1572864     12 MDTS         (12 cmds)
SIZES = [4096, 131072, 196608, 327680, 524288, 700000, 1048576, 1572864]

cfg = RawBlockCoreConfig(
    device_path=DEV,
    capacity_bytes=8 * 1024 * 1024 * 1024,
    block_align=4096,
    header_bytes=4096,
    slot_bytes=SLOT,
    use_odirect=False,
    enable_zero_copy=False,
    meta_total_bytes=1 * 1024 * 1024,
    meta_magic=b"LMCIDX01",
    meta_version=1,
    meta_checkpoint_interval_sec=60,
    meta_idle_quiet_ms=0,
    meta_enable_periodic=False,
    meta_verify_on_load=False,
    max_data_transfer_size=MDTS,
    load_checkpoint_on_init=False,
    io_engine="io_uring",
    iouring_queue_depth=8,
    use_uring_cmd=True,
)
core = RawBlockCore(cfg, key_namespace="object")
print("RawBlockCore constructed (use_uring_cmd=True) on", DEV)

fails = 0
for i, sz in enumerate(SIZES):
    obj = rbtu.make_memory_obj(bytes([0x41 + (i % 26)]) * sz)
    key = encode_object_key(rbtu.make_object_key(i, model_name="sweep"))
    pres = core.put_many([key], [obj])
    empty = rbtu.make_empty_memory_obj(sz)
    lres = core.load_many_into([key.encoded], [empty])
    ok = bytes(empty.byte_array) == bytes(obj.byte_array)
    fails += (0 if ok else 1)
    print(f"  size={sz:>8} put={pres} load={lres} verify={'OK' if ok else 'FAIL'}")

print("data verify_fail:", fails)
try:
    core.close()
except Exception as e:
    print("close:", e)

print("=== semantic records (LMCACHE_KVIO_TRACE) ===")
for l in open("/tmp/sem.jsonl"):
    print("  ", l.strip())
