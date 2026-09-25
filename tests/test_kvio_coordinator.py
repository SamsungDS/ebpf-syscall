# SPDX-License-Identifier: Apache-2.0
"""The coordinator shards by stream, refuses cross-shard edges, starts clients
together, merges honestly, and fails a run that a client did not finish."""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KVIO = ROOT / "tools" / "kvio"
if str(KVIO) not in sys.path:
    sys.path.insert(0, str(KVIO))

import coordinator  # noqa: E402
import workload3  # noqa: E402
from test_kvio_s3 import s3_fixture  # noqa: E402


def disjoint_fixture(streams=("a", "b", "c", "d"), n=6):
    """Each stream stores, reads and lists its own keys: no cross-stream edge."""
    wl = workload3.new_workload(capture_level="generated", mapping_method="declared", timing_model="synthetic",
                                release_provenance="declared", engine={"family": "s3", "name": "fixture", "revision": "0"})
    t = 0
    for s in streams:
        prev = None
        for i in range(n):
            t += 1000
            key = f"{s}/k{i}"
            op = workload3.add_op(wl, op_id=f"{s}-put{i}", family="s3", call="put", stream=s, key=key, size=65536,
                                  deps=[prev] if prev else [], release_ns=t, expected={"outcome": "success"})
            t += 1000
            op2 = workload3.add_op(wl, op_id=f"{s}-get{i}", family="s3", call="get", stream=s, key=key,
                                   deps=[op["op_id"]], release_ns=t, expected={"outcome": "success", "bytes": 65536})
            prev = op2["op_id"]
        t += 1000
        workload3.add_op(wl, op_id=f"{s}-list", family="s3", call="list", stream=s, prefix=f"{s}/", deps=[prev],
                         release_ns=t, expected={"outcome": "success", "count": n})
    workload3.validate_workload(wl)
    return wl


class ShardTest(unittest.TestCase):
    def test_cross_shard_dependency_is_refused_with_edges_named(self):
        with self.assertRaises(coordinator.CrossShardError) as cm:
            coordinator.shard_workload(s3_fixture(), ["c0", "c1"])
        self.assertIn("m2", str(cm.exception))

    def test_shards_are_valid_workloads_covering_every_operation_once(self):
        wl = disjoint_fixture()
        before = workload3.workload_sha256(wl)
        shards, assignment = coordinator.shard_workload(wl, ["c0", "c1"])
        self.assertEqual(workload3.workload_sha256(wl), before)          # the source is untouched
        ids = [o["op_id"] for s in shards.values() for o in s["operations"]]
        self.assertEqual(sorted(ids), sorted(o["op_id"] for o in wl["operations"]))
        self.assertEqual(assignment, {"a": "c0", "b": "c1", "c": "c0", "d": "c1"})


def _client(coord_addr, cid, extra=()):
    return subprocess.Popen([sys.executable, str(KVIO / "coordinator.py"), "client", "--coordinator", coord_addr,
                             "--client-id", cid, "--engine-name", "fake-s3", *extra],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


class RunTest(unittest.TestCase):
    def _serve(self, wl, clients, out, timeout_s=60):
        coord = coordinator.Coordinator(wl, clients, bind="127.0.0.1:0", profile="offered", out=out, timeout_s=timeout_s)
        result = {}
        th = threading.Thread(target=lambda: result.setdefault("status", coord.run()), daemon=True)
        th.start()
        while not hasattr(coord, "bound_port"):
            time.sleep(0.02)
        return coord, th, result

    def test_two_processes_run_together_and_merge(self):
        wl = disjoint_fixture()
        with tempfile.TemporaryDirectory() as d:
            coord, th, result = self._serve(wl, ["c0", "c1"], Path(d) / "run")
            addr = f"127.0.0.1:{coord.bound_port}"
            procs = [_client(addr, "c0"), _client(addr, "c1")]
            th.join(60)
            outs = [p.communicate(timeout=30) for p in procs]
            self.assertEqual(result.get("status"), "complete", outs)
            man = json.loads((Path(d) / "run" / "run-manifest.json").read_text())
            self.assertEqual(man["status"], "complete")
            self.assertEqual(set(man["clocks"]), {"c0", "c1"})
            for c in ("c0", "c1"):
                self.assertLess(man["clocks"][c]["uncertainty_ns"], 50_000_000)
                self.assertIn("drift_ns", man["clocks"][c])
            rows = [json.loads(l) for l in (Path(d) / "run" / "merged-ledger.jsonl").read_text().splitlines()]
            self.assertEqual(len(rows), len(wl["operations"]))
            self.assertEqual({r["client"] for r in rows}, {"c0", "c1"})
            self.assertTrue(all(r["outcome"] == "success" for r in rows), [r for r in rows if r["outcome"] != "success"])
            pooled = man["summary"]["pooled"]
            self.assertEqual(pooled["completed"], len(rows))
            self.assertIsNotNone(pooled["throughput_ops_per_s"])
            self.assertTrue((Path(d) / "run" / "client-c0" / "fidelity-manifest.json").exists())
            # both clients started after the coordinator's start in its own clock domain
            self.assertTrue(all(r["coord_release_ns"] >= -man["clocks"][r["client"]]["uncertainty_ns"] for r in rows))

    def test_missing_client_makes_the_run_partial_not_a_replay(self):
        wl = disjoint_fixture()
        with tempfile.TemporaryDirectory() as d:
            coord, th, result = self._serve(wl, ["c0", "c1"], Path(d) / "run", timeout_s=3)
            addr = f"127.0.0.1:{coord.bound_port}"
            p = _client(addr, "c0")
            th.join(30)
            p.communicate(timeout=30)
            self.assertEqual(result.get("status"), "partial")
            man = json.loads((Path(d) / "run" / "run-manifest.json").read_text())
            self.assertEqual(man["failures"]["c1"], "never connected")
            self.assertEqual((Path(d) / "run" / "merged-ledger.jsonl").read_text(), "")

    def test_duplicate_client_is_rejected_and_the_run_is_partial(self):
        wl = disjoint_fixture()
        with tempfile.TemporaryDirectory() as d:
            # The coordinator waits for c1, so both c0 claims arrive while it listens.
            coord, th, result = self._serve(wl, ["c0", "c1"], Path(d) / "run", timeout_s=20)
            addr = f"127.0.0.1:{coord.bound_port}"
            p1 = _client(addr, "c0")
            time.sleep(0.5)
            p2 = _client(addr, "c0")
            time.sleep(0.5)
            p3 = _client(addr, "c1")
            th.join(40)
            outs = [p.communicate(timeout=30) for p in (p1, p2, p3)]
            self.assertIn("duplicate", outs[1][0] + outs[1][1])
            self.assertEqual(result.get("status"), "partial")
            man = json.loads((Path(d) / "run" / "run-manifest.json").read_text())
            self.assertEqual(man["failures"]["c0"], "duplicate shard claim")

if __name__ == "__main__":
    unittest.main()
