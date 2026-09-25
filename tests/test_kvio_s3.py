# SPDX-License-Identifier: Apache-2.0
"""The S3 slice: typed calls on the fake bucket, and against a real endpoint when one is configured.

Set KVIO_S3_ENDPOINT, KVIO_S3_BUCKET, KVIO_S3_ACCESS_KEY and KVIO_S3_SECRET_KEY
to run the endpoint tests; they are skipped otherwise and say so.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KVIO = ROOT / "tools" / "kvio"
if str(KVIO) not in sys.path:
    sys.path.insert(0, str(KVIO))

import engines  # noqa: E402
import intent_exec  # noqa: E402
import s3_client  # noqa: E402
import workload3  # noqa: E402

ENV = {k: os.environ.get(f"KVIO_S3_{k.upper()}") for k in ("endpoint", "bucket", "access_key", "secret_key")}
HAVE_ENDPOINT = all(ENV.values())


def s3_fixture():
    wl = workload3.new_workload(capture_level="generated", mapping_method="declared", timing_model="absent",
                                release_provenance="none", engine={"family": "s3", "name": "fixture", "revision": "0"})
    workload3.add_node(wl, "pre", kind="object", size=65536)
    workload3.add_entry(wl, "k0/k9", "pre")
    add = lambda **kw: workload3.add_op(wl, family="s3", stream=kw.pop("stream", "a"), **kw)
    add(op_id="p1", call="put", key="k0/k1", size=100000, expected={"outcome": "success"})
    add(op_id="g1", call="get", key="k0/k1", deps=["p1"], expected={"outcome": "success", "bytes": 100000})
    add(op_id="g2", call="get", key="k0/k1", offset=4096, length=8192, deps=["p1"], expected={"outcome": "success", "bytes": 8192})
    add(op_id="h1", call="head", key="k0/k1", deps=["p1"], expected={"outcome": "success", "size": 100000})
    add(op_id="g3", call="get", key="k0/none", expected={"outcome": "miss"})
    add(op_id="l1", call="list", prefix="k0/", deps=["p1"], expected={"outcome": "success", "count": 2})
    add(op_id="m1", call="mpu_create", key="k0/big", upload="u0", expected={"outcome": "success"})
    add(op_id="m2", call="mpu_part", key="k0/big", upload="u0", part=1, size=5 * 1024 * 1024, deps=[{"op": "m1", "kind": "sync"}], stream="b")
    add(op_id="m3", call="mpu_part", key="k0/big", upload="u0", part=2, size=1024, deps=[{"op": "m1", "kind": "sync"}], stream="c")
    add(op_id="m4", call="mpu_complete", key="k0/big", upload="u0", deps=["m2", "m3"], expected={"outcome": "success"})
    add(op_id="h2", call="head", key="k0/big", deps=["m4"], expected={"outcome": "success", "size": 5 * 1024 * 1024 + 1024})
    add(op_id="m5", call="mpu_create", key="k0/aborted", upload="u1", expected={"outcome": "success"})
    add(op_id="m6", call="mpu_abort", key="k0/aborted", upload="u1", deps=["m5"], expected={"outcome": "success"})
    add(op_id="h3", call="head", key="k0/aborted", deps=["m6"], expected={"outcome": "miss"})
    add(op_id="d1", call="delete", key="k0/k1", deps=["g1", "g2", "h1", "l1"], expected={"outcome": "success"})
    add(op_id="g4", call="get", key="k0/k1", deps=["d1"], expected={"outcome": "miss"})
    add(op_id="d2", call="delete", key="k0/k1", deps=["g4"], expected={"outcome": "success"})     # S3 deletes are idempotent
    workload3.validate_workload(wl)
    return wl


class FakeS3Test(unittest.TestCase):
    def _run(self, backend):
        wl = s3_fixture()
        rows, res = intent_exec.Executor(wl, backend, profile="dependency", mode="real", workers=3).run()
        self.assertEqual(res["unfinished"], [], res)
        self.assertEqual(intent_exec.check_dependencies(rows, wl), [])
        self.assertEqual(intent_exec.compare_outcomes(rows, wl), [], [r.__dict__ for r in rows])
        by = {r.op_id: r for r in rows}
        self.assertGreaterEqual(by["m2"].submit_ns, by["m1"].complete_ns)
        state = backend.final_state()
        self.assertEqual(state["entries"], [("k0/big", 5 * 1024 * 1024 + 1024), ("k0/k9", 65536)])
        return state

    def test_fake_bucket_keeps_every_promise(self):
        self._run(s3_client.FakeS3())

    def test_preflight_and_injected_failure(self):
        wl = s3_fixture()
        self.assertEqual(engines.preflight(wl, "fake-s3").family, "s3")
        with self.assertRaises(engines.PreflightError):
            engines.preflight(wl, "fake-fs")
        rows, res = intent_exec.Executor(wl, s3_client.FakeS3(fail={"g1": "timeout"}), mode="real").run()
        self.assertIn("g1", res["diverged_from_source"])

    @unittest.skipUnless(HAVE_ENDPOINT, "KVIO_S3_ENDPOINT/BUCKET/ACCESS_KEY/SECRET_KEY not set")
    def test_real_endpoint_matches_the_fake(self):
        cfg = {"endpoint": ENV["endpoint"], "bucket": ENV["bucket"], "access_key": ENV["access_key"],
               "secret_key": ENV["secret_key"], "prefix": "kvio-test/"}
        b = s3_client.S3Backend(cfg)
        try:
            real = self._run(b)
        finally:
            b.cleanup()
        fake = self._run(s3_client.FakeS3())
        self.assertEqual(real["sha256"], fake["sha256"])

    @unittest.skipUnless(HAVE_ENDPOINT, "KVIO_S3_ENDPOINT/BUCKET/ACCESS_KEY/SECRET_KEY not set")
    def test_capture_through_the_sdk_replays_to_the_same_state(self):
        import boto3
        from botocore.config import Config
        client = boto3.client("s3", endpoint_url=ENV["endpoint"], aws_access_key_id=ENV["access_key"],
                              aws_secret_access_key=ENV["secret_key"], region_name="us-east-1",
                              config=Config(s3={"addressing_style": "path"}))
        with tempfile.TemporaryDirectory() as d:
            rec = s3_client.RecordingS3(client, ENV["bucket"], Path(d) / "cap.jsonl")
            ledger = []
            p = "kvio-capture/"
            rec.put(p + "alpha/one", b"a" * 5000); ledger.append(("put", "success"))
            rec.get(p + "alpha/one"); ledger.append(("get", "success"))
            rec.get(p + "alpha/one", 100, 200); ledger.append(("get", "success"))
            rec.head(p + "alpha/one"); ledger.append(("head", "success"))
            try:
                rec.get(p + "alpha/none")
            except Exception:
                ledger.append(("get", "miss"))
            rec.list(p + "alpha/"); ledger.append(("list", "success"))
            up = rec.mpu_create(p + "alpha/big"); ledger.append(("mpu_create", "success"))
            e1 = rec.mpu_part(p + "alpha/big", up, 1, b"b" * (5 * 1024 * 1024)); ledger.append(("mpu_part", "success"))
            e2 = rec.mpu_part(p + "alpha/big", up, 2, b"c" * 10); ledger.append(("mpu_part", "success"))
            rec.mpu_complete(p + "alpha/big", up, [(1, e1), (2, e2)]); ledger.append(("mpu_complete", "success"))
            rec.delete(p + "alpha/one"); ledger.append(("delete", "success"))
            rec.close_capture()
            wl, side = s3_client.normalize_s3_capture(Path(d) / "cap.jsonl")
            self.assertEqual([(o["call"], o["expected"]["outcome"]) for o in wl["operations"]], ledger)
            blob = json.dumps(wl)
            self.assertNotIn("alpha", blob); self.assertNotIn("kvio-capture", blob)
            b = s3_client.S3Backend({"endpoint": ENV["endpoint"], "bucket": ENV["bucket"], "access_key": ENV["access_key"],
                                     "secret_key": ENV["secret_key"], "prefix": "kvio-replay/"})
            try:
                rows, res = intent_exec.Executor(wl, b, profile="offered", mode="real", workers=2).run()
                self.assertEqual(res["diverged_from_source"], [], [r.__dict__ for r in rows])
                self.assertEqual([k for k, _ in b.final_state()["entries"]], ["k0/k0/k2"])
            finally:
                b.cleanup()
                for key in (p + "alpha/one", p + "alpha/big"):
                    client.delete_object(Bucket=ENV["bucket"], Key=key)


if __name__ == "__main__":
    unittest.main()
