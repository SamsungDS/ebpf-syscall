# SPDX-License-Identifier: Apache-2.0
"""G0: the v2 contract, the capture normalizer and the executor on a fake target.

The fixture is deliberately heterogeneous: two object sizes, a repeated
read, an overwrite that changes the version, a release followed by reuse
of the identity, a partial-range load, two interleaved batches, a miss, a
cancelled operation and an object that was live before capture began.
"""
import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KVIO = ROOT / "tools" / "kvio"
if str(KVIO) not in sys.path:
    sys.path.insert(0, str(KVIO))

import capture_events  # noqa: E402
import intent2  # noqa: E402
import intent_exec  # noqa: E402
from intent import build_kv_offload_intent  # noqa: E402


def fixture(timing="absent"):
    it = intent2.new_intent(capture_level="A1", mapping_method="declared",
                            timing_model=timing, engine={"name": "fixture", "revision": "0"})
    small = intent2.add_representation(it, "small", codec="opaque", encoded_bytes=4096)
    big = intent2.add_representation(it, "big", codec="asym-k16v8",
                                     encoded_bytes=12288, logical_bytes=16384,
                                     components=[{"role": "header", "offset": 0, "length": 256},
                                                 {"role": "k", "offset": 256, "length": 8192},
                                                 {"role": "v", "offset": 8448, "length": 3840}])
    intent2.add_object_version(it, "live-0", 1, representation=small)
    it["initial_state"]["live"].append({"object_id": "live-0", "version": 1, "tier": "storage"})
    intent2.add_object_version(it, "a", 1, representation=big)
    intent2.add_object_version(it, "a", 2, representation=big)
    intent2.add_object_version(it, "b", 1, representation=small)
    intent2.add_object_version(it, "b", 2, representation=big)
    t = [0]

    def rel():
        t[0] += 1000
        return t[0] if timing == "captured" else None
    add = intent2.add_operation
    add(it, op_id="s-a1", op="store", object_id="a", version=1, stream="x", batch_id="B1", release_ns=rel())
    add(it, op_id="s-b1", op="store", object_id="b", version=1, stream="y", batch_id="B2", release_ns=rel())
    add(it, op_id="l-live", op="load", object_id="live-0", version=1, stream="y", release_ns=rel(),
        source_outcome="success")
    add(it, op_id="l-a1", op="load", object_id="a", version=1, stream="x", deps=["s-a1"], release_ns=rel(),
        source_outcome="success")
    add(it, op_id="l-a1-again", op="load", object_id="a", version=1, stream="x", deps=["s-a1"],
        range={"offset": 256, "length": 8192}, release_ns=rel(), source_outcome="success")
    add(it, op_id="l-miss", op="load", object_id="b", version=2, stream="y", release_ns=rel(),
        source_outcome="miss")
    add(it, op_id="s-a2", op="store", object_id="a", version=2, stream="x", deps=["l-a1", "l-a1-again"],
        release_ns=rel())
    add(it, op_id="l-a2", op="load", object_id="a", version=2, stream="x", deps=["s-a2"], release_ns=rel(),
        source_outcome="success")
    add(it, op_id="r-b1", op="release", object_id="b", version=1, stream="y", deps=["s-b1"], release_ns=rel())
    add(it, op_id="s-b2", op="store", object_id="b", version=2, stream="y", deps=["r-b1"], release_ns=rel())
    add(it, op_id="l-b2", op="load", object_id="b", version=2, stream="y", deps=["s-b2"], release_ns=rel(),
        source_outcome="success")
    add(it, op_id="c-b2", op="load", object_id="b", version=2, stream="y", deps=["s-b2"], release_ns=rel(),
        source_outcome="cancelled")
    if timing == "captured":
        it["timing"] = {"sidecar": "timing.jsonl", "sidecar_sha256": hashlib.sha256(b"").hexdigest()}
    intent2.validate_intent2(it)
    return it


class ContractTest(unittest.TestCase):
    def test_fixture_validates_and_carries_no_placement(self):
        it = fixture()
        blob = json.dumps(it)
        for banned in ("slba", "offset_bytes", "mdts", "/dev/"):
            self.assertNotIn(banned, blob)
        self.assertEqual(len(it["operations"]), 12)

    def test_unknown_version_and_missing_initial_state_fail(self):
        it = fixture()
        bad = copy.deepcopy(it)
        bad["operations"][3]["version"] = 9
        with self.assertRaises(intent2.Intent2Error):
            intent2.validate_intent2(bad)
        bad = copy.deepcopy(it)
        bad["initial_state"]["live"] = []      # live-0 is now loaded before any store
        with self.assertRaises(intent2.Intent2Error):
            intent2.validate_intent2(bad)
        bad = copy.deepcopy(it)
        bad["operations"][3]["deps"] = ["l-a2"]  # a later operation
        with self.assertRaises(intent2.Intent2Error):
            intent2.validate_intent2(bad)
        bad = copy.deepcopy(it)
        bad["schema"] = "kvio.intent.v3"
        with self.assertRaises(intent2.Intent2Error):
            intent2.validate_intent2(bad)

    def test_captured_timing_requires_a_bound_sidecar(self):
        it = fixture("captured")
        self.assertEqual(intent2.bundle_sha256(it, b""), intent2.bundle_sha256(it, b""))
        with self.assertRaises(intent2.Intent2Error):
            intent2.bundle_sha256(it, b"different")
        with self.assertRaises(intent2.Intent2Error):
            intent2.bundle_sha256(it, None)
        bad = copy.deepcopy(it)
        bad["timing"] = {"sidecar": None, "sidecar_sha256": None}
        with self.assertRaises(intent2.Intent2Error):
            intent2.validate_intent2(bad)
        absent = fixture("absent")
        self.assertIsNone(absent["operations"][0]["release_ns"])
        with self.assertRaises(ValueError):
            intent_exec.Executor(absent, intent_exec.FakeBackend(), profile="offered")

    def test_v1_normalizes_with_its_partial_order_and_stays_generated(self):
        v1 = build_kv_offload_intent(model="m", geometry={"f": 1}, dtype="bfloat16", chunk_tokens=16,
                                     payload_bytes=100, ranks_per_chunk=2, num_chunks=2, streams=2,
                                     iters=1, warmup=1, store_metadata_bytes=8)
        v2 = intent2.normalize_v1(v1)
        self.assertEqual(v2["provenance"]["capture_level"], "generated")
        self.assertEqual(v2["provenance"]["timing_model"], "absent")
        self.assertEqual(len(v2["operations"]), len(v1["operations"]))
        by = {o["op_id"]: o for o in v2["operations"]}
        # second store in stream 0 of pass 0 follows the first
        self.assertIn("v1/0", by["v1/1"]["deps"])
        # every load of pass 0 waits for every store of pass 0
        loads0 = [o for o in v2["operations"] if o["op"] == "load" and o["batch_id"].startswith("pass0/")]
        stores0 = {o["op_id"] for o in v2["operations"] if o["op"] == "store" and o["batch_id"].startswith("pass0/")}
        for o in loads0:
            self.assertTrue(stores0 <= set(o["deps"]))
        # pass 1 stores wait for pass 0 loads
        s1 = next(o for o in v2["operations"] if o["op"] == "store" and o["batch_id"].startswith("pass1/"))
        self.assertTrue({o["op_id"] for o in loads0} <= set(s1["deps"]))
        self.assertEqual(v2["engine"]["layout"]["store_metadata_bytes"], 8)
        self.assertEqual(v2["provenance"]["source"]["schema"], "kvio.intent.v1")


class ExecutorTest(unittest.TestCase):
    def test_dependency_replay_waits_for_slow_prerequisites_and_keeps_independents_concurrent(self):
        it = fixture()
        slow = {"s-a1": 50_000}
        backend = intent_exec.FakeBackend(latency_ns=lambda op: slow.get(op["op_id"], 1_000))
        rows, result = intent_exec.Executor(it, backend, profile="dependency", workers=4).run()
        self.assertEqual(intent_exec.check_dependencies(rows, it), [])
        by = {r.op_id: r for r in rows}
        self.assertGreaterEqual(by["l-a1"].submit_ns, by["s-a1"].complete_ns)
        # s-b1 and l-live do not depend on the slow store and finish long before it.
        self.assertLess(by["s-b1"].complete_ns, by["s-a1"].complete_ns)
        self.assertLess(by["l-live"].complete_ns, by["s-a1"].complete_ns)
        self.assertEqual(result["diverged_from_source"], [])
        self.assertEqual(by["l-miss"].outcome, "miss")
        self.assertEqual(by["c-b2"].outcome, "cancelled")
        self.assertEqual(by["l-a1-again"].completed_bytes, 8192)
        self.assertEqual(result["unfinished"], [])
        # the overwrite is a distinct version; the reused identity holds new content
        self.assertEqual(by["l-a2"].outcome, "success")
        self.assertEqual(by["l-b2"].outcome, "success")

    def test_declared_delay_pushes_successors_back(self):
        it = fixture()
        backend = intent_exec.FakeBackend(latency_ns=1_000)
        rows, _ = intent_exec.Executor(it, backend, profile="dependency", declared_delay_ns=7_000).run()
        by = {r.op_id: r for r in rows}
        self.assertGreaterEqual(by["l-a1"].submit_ns, by["s-a1"].complete_ns + 7_000)
        self.assertEqual(intent_exec.check_dependencies(rows, it, 7_000), [])

    def test_offered_load_keeps_nominal_release_and_reports_backlog_on_a_slow_target(self):
        it = fixture("captured")
        fast = intent_exec.FakeBackend(latency_ns=10)
        rows_f, res_f = intent_exec.Executor(it, fast, profile="offered", workers=8).run()
        slow = intent_exec.FakeBackend(latency_ns=40_000)
        rows_s, res_s = intent_exec.Executor(it, slow, profile="offered", workers=1).run()
        rel_f = [r.release_ns for r in rows_f]
        rel_s = [r.release_ns for r in rows_s]
        self.assertEqual(rel_f, rel_s)                              # offered load is not reduced
        self.assertGreater(res_s["scheduler_lag_ns"]["max"], res_f["scheduler_lag_ns"]["max"])
        self.assertGreater(res_s["release_to_complete_ns"]["p95"], res_f["release_to_complete_ns"]["p95"])
        for r in rows_s:
            self.assertGreaterEqual(r.submit_ns, r.release_ns)

    def test_saturation_ignores_release_times_and_dependency_still_holds(self):
        it = fixture("captured")
        backend = intent_exec.FakeBackend(latency_ns=100)
        rows, res = intent_exec.Executor(it, backend, profile="saturation", workers=8).run()
        self.assertEqual(intent_exec.check_dependencies(rows, it), [])
        self.assertLess(res["wall_ns"], 12_000)      # the recorded 1 us spacing is not honoured

    def test_injected_failure_is_reported_as_divergence_not_success(self):
        it = fixture()
        backend = intent_exec.FakeBackend(latency_ns=1, fail={"l-a1": "error"})
        rows, res = intent_exec.Executor(it, backend, profile="dependency").run()
        self.assertEqual([d["op_id"] for d in intent_exec.compare_outcomes(rows)], ["l-a1"])
        self.assertIn("l-a1", res["diverged_from_source"])
        self.assertEqual(res["outcomes"].get("error"), 1)

    def test_real_mode_obeys_the_same_contract(self):
        it = fixture()
        backend = intent_exec.FakeBackend(latency_ns=0)
        rows, res = intent_exec.Executor(it, backend, profile="dependency", mode="real", workers=3).run()
        self.assertEqual(intent_exec.check_dependencies(rows, it), [])
        self.assertEqual(res["unfinished"], [])
        self.assertEqual(res["diverged_from_source"], [])

    def test_content_model_is_deterministic_and_not_zero(self):
        a = intent_exec.synthetic_bytes("o", 1, 100, 300)
        b = intent_exec.synthetic_bytes("o", 1, 0, 400)[100:400]
        self.assertEqual(a, b)
        self.assertNotEqual(a, bytes(300))
        self.assertNotEqual(intent_exec.synthetic_bytes("o", 2, 100, 300), a)


class CaptureTest(unittest.TestCase):
    def _record(self, tmp, *, drop_end=False, capacity=1 << 10):
        clock = [1_000_000]

        def tick():
            clock[0] += 500
            return clock[0]
        rec = capture_events.Recorder(tmp / "cap.jsonl", engine={"name": "fixture", "revision": "0"},
                                      adapter={"name": "test", "revision": "0"}, clock=tick,
                                      capacity=capacity)
        rec.object_state([("live-0", 1, {"codec": "opaque", "encoded_bytes": 4096}, 4096, "storage")])
        b = rec.begin(op="store", stream="x", batch_id="B1",
                      items=[{"object_id": "a", "representation": {"codec": "opaque", "encoded_bytes": 8}, "requested_bytes": 8},
                             {"object_id": "b", "representation": {"codec": "opaque", "encoded_bytes": 8}, "requested_bytes": 8}])
        rec.end(b, items=[{"outcome": "success", "completed_bytes": 8}, {"outcome": "rejected", "completed_bytes": 0}])
        l1 = rec.begin(op="load", object_id="a", version=1, stream="x", requested_bytes=8, deps=[b])
        rec.end(l1, outcome="success", completed_bytes=8)
        l2 = rec.begin(op="load", object_id="live-0", version=1, stream="y", requested_bytes=4096)
        rec.end(l2, outcome="success", completed_bytes=4096)
        m = rec.begin(op="load", object_id="zzz", version=1, stream="y", requested_bytes=8)
        rec.end(m, outcome="miss", completed_bytes=0)
        s2 = rec.begin(op="store", object_id="a", stream="x", requested_bytes=8,
                       representation={"codec": "opaque", "encoded_bytes": 8})
        rec.end(s2, outcome="success", completed_bytes=8)      # overwrite: version 2
        o = rec.begin(op="load", object_id="a", version=2, stream="x", requested_bytes=8)
        if not drop_end:
            rec.end(o, outcome="success", completed_bytes=8)
        health = rec.close()
        rec.batch_id, rec.first_load = b, l1
        return rec, health

    def test_capture_normalizes_to_v2_with_bound_timing(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            rec, health = self._record(tmp)
            self.assertEqual(health["dropped"], 0)
            events = capture_events.read_events(tmp / "cap.jsonl")
            it, sidecar = capture_events.normalize_capture(events)
            self.assertEqual(it["provenance"]["capture_level"], "A1")
            self.assertEqual(it["provenance"]["completeness"]["status"], "complete")
            self.assertEqual(it["provenance"]["timing_model"], "captured")
            ops = {o["op_id"]: o for o in it["operations"]}
            self.assertEqual(ops[f"{rec.batch_id}/0"]["source_outcome"], "success")   # batch item 0
            self.assertEqual(ops[f"{rec.batch_id}/1"]["source_outcome"], "rejected")
            self.assertEqual(sorted(ops[rec.first_load]["deps"]),
                             [f"{rec.batch_id}/0", f"{rec.batch_id}/1"])
            self.assertEqual(it["objects"]["a"]["versions"].keys(), {"1", "2"})
            self.assertEqual([o for o in it["initial_state"]["live"]][0]["object_id"], "live-0")
            self.assertEqual(intent2.bundle_sha256(it, sidecar), intent2.bundle_sha256(it, sidecar))
            # every op carries its recorded release; the sidecar has begin/end/outcome
            self.assertTrue(all(o["release_ns"] for o in it["operations"]))
            lines = [json.loads(l) for l in sidecar.decode().splitlines()]
            self.assertEqual(len(lines), len(it["operations"]))
            # the record is executable: replay it on the fake target
            rows, res = intent_exec.Executor(it, intent_exec.FakeBackend(), profile="offered").run()
            self.assertEqual(res["unfinished"], [])
            self.assertEqual(intent_exec.check_dependencies(rows, it), [])
            # the source rejected b's store, the fake target accepted it: divergence, reported
            self.assertEqual([x["op_id"] for x in intent_exec.compare_outcomes(rows)], [f"{rec.batch_id}/1"])

    def test_open_operations_make_the_capture_partial(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            self._record(tmp, drop_end=True)
            it, _ = capture_events.normalize_capture(capture_events.read_events(tmp / "cap.jsonl"))
            self.assertEqual(it["provenance"]["completeness"]["status"], "partial")
            self.assertTrue(any("never ended" in n for n in it["provenance"]["completeness"]["notes"]))

    def test_recorder_drops_and_counts_when_full(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            rec = capture_events.Recorder(tmp / "cap.jsonl", engine={"name": "f", "revision": "0"},
                                          adapter={"name": "t", "revision": "0"}, capacity=2)
            # Stall the writer by flooding faster than it drains; drops are counted, never blocked.
            for i in range(200):
                rec.begin(op="store", object_id=f"o{i}", stream="x", requested_bytes=1)
            health = rec.close()
            self.assertEqual(health["emitted"] + health["dropped"], 202)  # start + 200 begins + end

    def test_cli_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            self._record(tmp)
            proc = subprocess.run([sys.executable, str(KVIO / "capture_events.py"), str(tmp / "cap.jsonl"),
                                   "--out", str(tmp / "norm")], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            proc = subprocess.run([sys.executable, str(KVIO / "intent2.py"), "validate",
                                   str(tmp / "norm" / "intent.json"), "--sidecar", str(tmp / "norm" / "timing.jsonl")],
                                  capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("bundle_sha256", proc.stdout)
            proc = subprocess.run([sys.executable, str(KVIO / "intent_exec.py"), str(tmp / "norm" / "intent.json"),
                                   "--profile", "offered", "--out", str(tmp / "run")],
                                  capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            self.assertTrue((tmp / "run" / "ledger.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
