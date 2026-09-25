# SPDX-License-Identifier: Apache-2.0
"""The v3 envelope, its v2 adapter and the engine registry.

Fixtures are adversarial on purpose: rename while a handle is open, unlink
while open, recreation under a freed name, a missing lookup, a short read
at end of file, a race declared with a permitted-outcome set, fsync, and a
directory that is not empty.
"""
import copy
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

import content_profile  # noqa: E402
import engines  # noqa: E402
import intent2  # noqa: E402
import intent_exec  # noqa: E402
import workload3  # noqa: E402
from test_kvio_intent2 import fixture as v2_fixture  # noqa: E402


def posix_fixture():
    wl = workload3.new_workload(capture_level="generated", mapping_method="declared", timing_model="absent",
                                release_provenance="none", engine={"family": "posix", "name": "fixture", "revision": "0"})
    workload3.add_node(wl, "d0", kind="dir")
    workload3.add_node(wl, "f0", kind="file", size=8192)
    workload3.add_entry(wl, "e0", "d0")
    workload3.add_entry(wl, "e0/e0", "f0")
    add = lambda **kw: workload3.add_op(wl, family="posix", stream=kw.pop("stream", "a"), **kw)
    add(op_id="o1", call="open", path="e0/e0", flags=["rdwr"], handle="h1", expected={"outcome": "success", "node": "f0"})
    add(op_id="r1", call="pread", handle="h1", offset=0, length=4096, deps=["o1"], expected={"outcome": "success", "bytes": 4096})
    add(op_id="r2", call="pread", handle="h1", offset=6144, length=4096, deps=["r1"], expected={"outcome": "eof", "bytes": 2048})
    add(op_id="w1", call="pwrite", handle="h1", offset=8192, length=4096, deps=["r2"], expected={"outcome": "success"})
    add(op_id="s1", call="fsync", handle="h1", deps=["w1"], expected={"outcome": "success"})
    add(op_id="mv", call="rename", path="e0/e0", new_path="e0/e1", deps=["s1"], expected={"outcome": "success"})
    add(op_id="r3", call="pread", handle="h1", offset=8192, length=4096, deps=["mv"], expected={"outcome": "success"})   # open handle survives the rename
    add(op_id="st", call="stat", path="e0/e0", deps=["mv"], expected={"outcome": "miss"})
    add(op_id="ul", call="unlink", path="e0/e1", deps=["r3", "st"], expected={"outcome": "success"})
    add(op_id="r4", call="pread", handle="h1", offset=0, length=1024, deps=["ul"], expected={"outcome": "success"})   # open after unlink
    add(op_id="c1", call="close", handle="h1", deps=["r4"], expected={"outcome": "success"})
    add(op_id="o2", call="open", path="e0/e1", flags=["rdwr", "creat", "excl"], handle="h2", deps=["c1"], expected={"outcome": "success"})  # name reused
    add(op_id="w2", call="write", handle="h2", length=100, deps=["o2"], expected={"outcome": "success"})
    add(op_id="c2", call="close", handle="h2", deps=["w2"])
    add(op_id="rd", call="readdir", path="e0", deps=["c2"], expected={"outcome": "success", "count": 1})
    add(op_id="rm", call="rmdir", path="e0", deps=["rd"], expected={"outcome": "not_empty"})
    # Two streams race to create the same name; either may win, exactly one does.
    add(op_id="x1", call="open", path="e0/race", flags=["wr", "creat", "excl"], handle="hx", stream="x",
        expected={"outcomes": ["success", "exists"]})
    add(op_id="y1", call="open", path="e0/race", flags=["wr", "creat", "excl"], handle="hy", stream="y",
        expected={"outcomes": ["success", "exists"]})
    add(op_id="x2", call="close", handle="hx", stream="x", deps=["x1"], expected={"outcomes": ["success", "error"]})
    add(op_id="y2", call="close", handle="hy", stream="y", deps=["y1"], expected={"outcomes": ["success", "error"]})
    workload3.validate_workload(wl)
    return wl


class EnvelopeTest(unittest.TestCase):
    def test_fixture_validates_and_names_its_capabilities(self):
        wl = posix_fixture()
        caps = workload3.required_capabilities(wl)
        self.assertIn("posix.rename", caps)
        self.assertIn("posix.readdir", caps)
        self.assertEqual(len(wl["operations"]), 20)

    def test_rejections(self):
        wl = posix_fixture()
        bad = copy.deepcopy(wl); bad["operations"][1]["args"]["handle"] = "never-opened"
        with self.assertRaises(workload3.Workload3Error):
            workload3.validate_workload(bad)
        bad = copy.deepcopy(wl); bad["operations"][5]["args"]["new_path"] = "../escape"
        with self.assertRaises(workload3.Workload3Error):
            workload3.validate_workload(bad)
        bad = copy.deepcopy(wl); bad["operations"][1]["deps"] = [{"op": "o1", "kind": "guess"}]
        with self.assertRaises(workload3.Workload3Error):
            workload3.validate_workload(bad)
        bad = copy.deepcopy(wl); bad["provenance"]["timing_model"] = "captured"
        with self.assertRaises(workload3.Workload3Error):
            workload3.validate_workload(bad)
        bad = copy.deepcopy(wl); bad["operations"][0]["call"] = "put"
        with self.assertRaises(workload3.Workload3Error):
            workload3.validate_workload(bad)

    def test_v2_carries_into_v3_with_labelled_edges_and_no_upgrade(self):
        it = v2_fixture("captured")
        wl = workload3.from_intent2(it)
        self.assertEqual(wl["provenance"]["capture_level"], "A1")
        self.assertEqual(wl["provenance"]["release_provenance"], "observed_submission")
        self.assertTrue(all(o["family"] == "object" for o in wl["operations"]))
        kinds = {d["kind"] for o in wl["operations"] for d in o["deps"]}
        self.assertEqual(kinds, {"program"})           # the fixture carried no identity rule
        self.assertEqual(wl["provenance"]["source"]["schema"], "kvio.intent.v2")
        self.assertIn("a@1", wl["namespace"]["nodes"])
        # replays through the v3 dispatch on the object fake exactly as v2 did
        rows, res = intent_exec.Executor(wl, intent_exec.FakeBackend(), profile="offered").run()
        self.assertEqual(res["diverged_from_source"], [])
        self.assertEqual(res["unfinished"], [])


class RegistryTest(unittest.TestCase):
    def test_preflight_refuses_a_family_or_call_the_engine_lacks(self):
        wl = posix_fixture()
        with self.assertRaises(engines.PreflightError):
            engines.preflight(wl, "fake")                     # object engine, posix workload
        with self.assertRaises(engines.PreflightError):
            engines.preflight(wl, "fake-fs", provider="nope")
        spec = engines.preflight(workload3.from_intent2(v2_fixture()), "fake", provider="memory")
        self.assertEqual(spec.family, "object")

    def test_fidelity_manifest_names_loaded_modules_and_missing_dimensions(self):
        wl = workload3.from_intent2(v2_fixture())
        spec = engines.preflight(wl, "fake")
        man = engines.fidelity_manifest(wl, spec, "memory", {}, timing_profile="offered",
                                        content_profile="zeros", backend=intent_exec.FakeBackend())
        self.assertEqual(man["workload"]["sha256"], workload3.workload_sha256(wl))
        self.assertIn("offered-load profile requested without recorded release times", man["missing"])
        self.assertEqual(man["engine"]["family"], "object")




if __name__ == "__main__":
    unittest.main()
