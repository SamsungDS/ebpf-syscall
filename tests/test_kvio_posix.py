# SPDX-License-Identifier: Apache-2.0
"""The POSIX slice: replay on the fake and on a real directory, capture in-process.

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
import posix_fs  # noqa: E402
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


class PosixReplayTest(unittest.TestCase):
    def _run(self, backend):
        wl = posix_fixture()
        rows, res = intent_exec.Executor(wl, backend, profile="dependency", mode="real", workers=3).run()
        self.assertEqual(res["unfinished"], [], res)
        self.assertEqual(intent_exec.check_dependencies(rows, wl), [])
        div = intent_exec.compare_outcomes(rows, wl)
        self.assertEqual(div, [], div)
        by = {r.op_id: r for r in rows}
        self.assertEqual(by["r2"].completed_bytes, 2048)                   # eof, not error
        self.assertEqual({by["x1"].outcome, by["y1"].outcome}, {"success", "exists"})   # exactly one winner
        state = backend.final_state()
        self.assertEqual([e for e in state["entries"] if e[1] == "file"],
                         [("e0/e1", "file", 100), ("e0/race", "file", 0)])
        return wl, rows, res, state

    def test_fake_fs_keeps_every_promise(self):
        self._run(posix_fs.FakeFS())

    def test_real_directory_keeps_every_promise_and_matches_the_fake(self):
        with tempfile.TemporaryDirectory() as d:
            _, _, _, real = self._run(posix_fs.PosixBackend(Path(d) / "root"))
        _, _, _, fake = self._run(posix_fs.FakeFS())
        self.assertEqual(real["sha256"], fake["sha256"])

    def test_unsupported_outcome_is_divergence_not_success(self):
        wl = posix_fixture()
        rows, res = intent_exec.Executor(wl, posix_fs.FakeFS(fail={"r1": "error"}), mode="real").run()
        self.assertIn("r1", res["diverged_from_source"])

    def test_path_escape_is_refused_at_replay(self):
        wl = posix_fixture()
        wl["operations"][5]["args"]["new_path"] = "e0/../../escape"     # bypass the validator on purpose
        with tempfile.TemporaryDirectory() as d:
            b = posix_fs.PosixBackend(Path(d) / "root")
            b.initialize(wl)
            res = b.perform(wl["operations"][5])
            self.assertEqual(res.outcome, "denied")
            self.assertFalse((Path(d) / "escape").exists())


class PosixCaptureTest(unittest.TestCase):
    def test_capture_equals_the_scripts_ledger_and_replays_to_the_same_state(self):
        with tempfile.TemporaryDirectory() as d:
            app = Path(d) / "app"; app.mkdir()
            (app / "pre").mkdir(); (app / "pre" / "old.bin").write_bytes(bytes(4096))
            fs = posix_fs.RecordingFS(app, Path(d) / "cap.jsonl", stream="app")
            ledger = []
            fd = fs.open("pre/old.bin", ["rdwr"]); ledger.append(("open", "success"))
            fs.pread(fd, 4096, 0); ledger.append(("pread", "success"))
            fs.pread(fd, 4096, 4000); ledger.append(("pread", "eof"))
            fs.pwrite(fd, b"x" * 100, 4096); ledger.append(("pwrite", "success"))
            fs.rename("pre/old.bin", "pre/new.bin"); ledger.append(("rename", "success"))
            try:
                fs.stat("pre/old.bin")
            except FileNotFoundError:
                ledger.append(("stat", "miss"))
            fs.unlink("pre/new.bin"); ledger.append(("unlink", "success"))
            fs.fstat(fd); ledger.append(("fstat", "success"))
            fs.close(fd); ledger.append(("close", "success"))
            fd2 = fs.open("pre/new.bin", ["wr", "creat", "excl"]); ledger.append(("open", "success"))
            fs.write(fd2, b"y" * 10); ledger.append(("write", "success"))
            fs.fsync(fd2); ledger.append(("fsync", "success"))
            fs.close(fd2); ledger.append(("close", "success"))
            fs.readdir("pre"); ledger.append(("readdir", "success"))
            try:
                fs.rmdir("pre")
            except OSError:
                ledger.append(("rmdir", "not_empty"))
            health = fs.close_capture()
            self.assertEqual(health["open_handles"], [])
            wl, side = posix_fs.normalize_posix_capture(Path(d) / "cap.jsonl")
            self.assertEqual(wl["provenance"]["completeness"]["status"], "complete")
            got = [(o["call"], o["expected"]["outcome"]) for o in wl["operations"]]
            self.assertEqual(got, ledger)
            # no real name leaked; the mapping is separate
            blob = json.dumps(wl)
            self.assertNotIn("old.bin", blob); self.assertNotIn("new.bin", blob); self.assertNotIn("pre/", blob)
            self.assertIn("pre/old.bin", fs.mapping["paths"])
            # replay on a fresh real directory: same outcomes, same final namespace shape
            b = posix_fs.PosixBackend(Path(d) / "replay", profile="zeros")
            rows, res = intent_exec.Executor(wl, b, profile="offered", mode="real", workers=1).run()
            self.assertEqual(res["diverged_from_source"], [], [r.__dict__ for r in rows])
            self.assertEqual(intent_exec.check_dependencies(rows, wl), [])
            self.assertEqual([e for e in b.final_state()["entries"] if e[1] == "file"], [("e0/e1", "file", 10)])
            self.assertEqual(workload3.bundle_sha256(wl, side), workload3.bundle_sha256(wl, side))

    def test_open_handles_at_end_make_the_capture_partial(self):
        with tempfile.TemporaryDirectory() as d:
            app = Path(d) / "app"; app.mkdir()
            fs = posix_fs.RecordingFS(app, Path(d) / "cap.jsonl")
            fs.open("f", ["wr", "creat"])
            fs.close_capture()
            wl, _ = posix_fs.normalize_posix_capture(Path(d) / "cap.jsonl")
            self.assertEqual(wl["provenance"]["completeness"]["status"], "partial")


class PosixCliTest(unittest.TestCase):
    def test_cli_round_trip(self):
        wl = posix_fixture()
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "wl.json"; p.write_text(json.dumps(wl))
            proc = subprocess.run([sys.executable, str(KVIO / "workload3.py"), "validate", str(p)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            proc = subprocess.run([sys.executable, str(KVIO / "intent_exec.py"), str(p), "--engine-name", "posix-direct",
                                   "--provider", "mount", "--root", str(Path(d) / "root"), "--mode", "real",
                                   "--manifest", str(Path(d) / "man.json"), "--out", str(Path(d) / "run")],
                                  capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            man = json.loads((Path(d) / "man.json").read_text())
            self.assertEqual(man["engine"]["name"], "posix-direct")
            self.assertIn("final_state", man)
            proc = subprocess.run([sys.executable, str(KVIO / "intent_exec.py"), str(p), "--engine-name", "fake"],
                                  capture_output=True, text=True)
            self.assertNotEqual(proc.returncode, 0)          # preflight refuses the wrong family



if __name__ == "__main__":
    unittest.main()
