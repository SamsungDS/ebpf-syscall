# SPDX-License-Identifier: Apache-2.0
"""G1 and G2 on a file-backed vendored raw_block core.

G1: an independent ledger of what the driver asked the engine to do, item
by item, must match the normalized capture in operations, outcomes,
versions and initial state, with the recorder's loss counters at zero.
G2: replaying that intent through the executor on a fresh core of the same
kind must reproduce every object outcome, and the replay's own capture
must normalize to the same object operations.

These need the vendored engine and torch; they skip cleanly without them.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KVIO = ROOT / "tools" / "kvio"
for p in (KVIO, KVIO / "vendor" / "lmcache", KVIO / "build"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

try:
    import torch  # noqa: F401
    from lmcache.v1.storage_backend.raw_block.key_codec import encode_object_key  # noqa: E402
    from lmcache.v1.distributed.api import ObjectKey  # noqa: E402
    ENGINE = True
except Exception as error:  # pragma: no cover - environment dependent
    ENGINE = False
    ENGINE_ERROR = repr(error)

import capture_events  # noqa: E402
import intent2  # noqa: E402
import intent_exec  # noqa: E402

SLOT = 16384


def key(i, rank=0):
    return encode_object_key(ObjectKey(chunk_hash=ObjectKey.IntHash2Bytes(i), model_name="g1", kv_rank=rank))


@unittest.skipUnless(ENGINE, "vendored raw_block engine or torch not importable here")
class LmcacheAdapterTest(unittest.TestCase):
    def _core(self, tmp, name):
        path = tmp / name
        with open(path, "wb") as f:
            f.truncate(64 * 1024 * 1024)
        return intent_exec.open_raw_block_core(path, capacity_bytes=64 * 1024 * 1024, slot_bytes=SLOT)

    def test_g1_capture_matches_the_drivers_own_ledger(self):
        import lmcache_adapter
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            core = self._core(tmp, "dev.bin")
            # One object exists before capture begins.
            pre, _ = intent_exec.RawBlockBackend._memory_obj(intent_exec.synthetic_bytes(key(0).encoded, 1, 0, 4096))
            core.put_many([key(0)], [pre])
            rec = lmcache_adapter.open_recorder(tmp / "cap.jsonl", core=core)
            wrapped = lmcache_adapter.RecordingRawBlockCore(core, rec, stream="drv")
            self.assertEqual(wrapped.record_initial_state(), 1)
            ledger = []      # what the driver asked, independently of the recorder
            mk = intent_exec.RawBlockBackend._memory_obj

            def store(i, size, expect):
                obj, _ = mk(intent_exec.synthetic_bytes(key(i).encoded, 1, 0, size))
                r = wrapped.put_many([key(i)], [obj])
                ledger.append(("store", key(i).encoded, size, expect, bool(r.results[0])))

            def load(i, size, expect):
                obj, data = mk(bytes(size))
                ok = wrapped.load_many_into([key(i).encoded], [obj])[0]
                ledger.append(("load", key(i).encoded, size, expect, ok))

            store(1, 8000, "success")
            store(2, 12000, "success")
            store(1, 8000, "already_present")
            load(1, 8000, "success")
            load(0, 4096, "success")             # the pre-existing object
            load(7, 100, "miss")
            self.assertEqual(wrapped.delete_many([key(2).encoded]), [True])
            ledger.append(("release", key(2).encoded, 0, "success", True))
            load(2, 12000, "miss")
            store(2, 6000, "success")            # identity reused after release
            health = rec.close()
            core.close()
            self.assertEqual(health["dropped"], 0)
            self.assertEqual(health["open_operations"], [])
            it, sidecar = capture_events.normalize_capture(capture_events.read_events(tmp / "cap.jsonl"))
            self.assertEqual(it["provenance"]["completeness"]["status"], "complete", it["provenance"])
            self.assertEqual(it["engine"]["name"], "lmcache-raw_block")
            self.assertEqual([(o["object_id"], o["version"]) for o in it["initial_state"]["live"]],
                             [(key(0).encoded, 1)])
            got = [(o["op"], o["object_id"], o["requested_bytes"], o["source_outcome"]) for o in it["operations"]]
            want = [(op, k, size, expect) for op, k, size, expect, _ in ledger]
            self.assertEqual(got, want)
            # the reuse after release is a new version of the same identity
            self.assertEqual(sorted(it["objects"][key(2).encoded]["versions"]), ["1", "2"])
            self.assertEqual(it["objects"][key(2).encoded]["versions"]["2"]["bytes"], 6000)
            (tmp / "intent.json").write_text(json.dumps(it))
            self.g1 = (it, sidecar)
            return it, sidecar

    def test_g2_same_kind_replay_reproduces_outcomes_and_its_own_capture(self):
        it, sidecar = self.test_g1_capture_matches_the_drivers_own_ledger()
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            core = self._core(tmp, "dev2.bin")
            backend = intent_exec.RawBlockBackend(core, record_to=tmp / "replay-cap.jsonl")
            rows, res = intent_exec.Executor(it, backend, profile="dependency", mode="real", workers=2).run()
            self.assertEqual(res["unfinished"], [])
            self.assertEqual(intent_exec.check_dependencies(rows, it), [])
            self.assertEqual(intent_exec.compare_outcomes(rows), [], [r.__dict__ for r in rows])
            re_it, _ = capture_events.normalize_capture(capture_events.read_events(tmp / "replay-cap.jsonl"))
            got = [(o["op"], o["object_id"], o["requested_bytes"], o["source_outcome"]) for o in re_it["operations"]]
            want = [(o["op"], o["object_id"], o["requested_bytes"], o["source_outcome"]) for o in it["operations"]]
            # The replay's initial-state materialization is its own store, before
            # the workload. Two workers may record independent operations in
            # another order than the source; order is not causality, and the
            # dependency check above is the causal test.
            self.assertEqual(got[0], ("store", key(0).encoded, 4096, "success"))
            self.assertEqual(sorted(got[1:]), sorted(want))


if __name__ == "__main__":
    unittest.main()
