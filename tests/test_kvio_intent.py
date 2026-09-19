# SPDX-License-Identifier: Apache-2.0
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.kvio import intent as intent_module
from tools.kvio.intent import (
    IntentError,
    build_kv_offload_intent,
    intent_sha256,
    lower_intent,
    validate_intent,
    validate_target_plan,
)


ROOT = Path(__file__).resolve().parents[1]


def sample():
    return build_kv_offload_intent(
        model="example", geometry={"family": "example"}, dtype="bfloat16",
        chunk_tokens=16, payload_bytes=10, ranks_per_chunk=1,
        num_chunks=2, streams=2, iters=1, warmup=1, store_metadata_bytes=2)


class KvioIntentTest(unittest.TestCase):
    def test_intent_is_device_independent_and_encodes_partial_order(self):
        intent = sample()
        validate_intent(intent)
        self.assertNotIn("mdts_bytes", intent)
        self.assertNotIn("device", intent)
        self.assertEqual(intent["evidence"]["device_io"], "not-recorded")
        self.assertEqual(intent["execution"]["cross_stream_order"],
                         "unordered-within-phase")
        self.assertEqual(len(intent["operations"]), 16)
        self.assertEqual(intent["operations"][0]["logical_object"],
                         "pass=0/stream=0/chunk=0/rank=0")
        self.assertFalse(intent["operations"][0]["timed"])
        self.assertTrue(intent["operations"][-1]["timed"])

    def test_target_lowering_uses_the_smallest_declared_ceiling(self):
        plan = lower_intent(sample(), mdts_bytes=8,
                            dma_ceiling_bytes=6, software_limit_bytes=7)
        self.assertEqual(plan["effective_command_bytes"], 6)
        self.assertEqual(plan["summary"]["logical_operations"], 16)
        self.assertEqual(plan["summary"]["commands"], 40)
        self.assertEqual(plan["commands"][:2], [
            {"logical_sequence": 0,
             "logical_object": "pass=0/stream=0/chunk=0/rank=0",
             "op": "store", "component": "metadata", "command_index": 0,
             "component_offset_bytes": 0, "bytes": 2},
            {"logical_sequence": 0,
             "logical_object": "pass=0/stream=0/chunk=0/rank=0",
             "op": "store", "component": "payload", "command_index": 1,
             "component_offset_bytes": 0, "bytes": 6},
        ])

    def test_validator_rejects_an_inconsistent_operation(self):
        intent = copy.deepcopy(sample())
        intent["operations"][0]["payload_bytes"] = 9
        with self.assertRaisesRegex(IntentError, "payload_bytes"):
            validate_intent(intent)

    def test_validator_rejects_reordered_operations(self):
        intent = copy.deepcopy(sample())
        intent["operations"][0]["phase"] = "load"
        with self.assertRaisesRegex(IntentError, "execution order"):
            validate_intent(intent)

    def test_target_plan_binds_exactly_to_one_intent(self):
        intent = sample()
        plan = lower_intent(intent, mdts_bytes=8, software_limit_bytes=7)
        validate_target_plan(plan, intent)
        self.assertEqual(plan["intent_sha256"], intent_sha256(intent))
        plan["commands"][0]["bytes"] = 3
        with self.assertRaisesRegex(IntentError, "exact lowering"):
            validate_target_plan(plan, intent)

    def test_intent_only_runs_without_a_device_or_engine_import(self):
        with tempfile.TemporaryDirectory() as directory:
            intent_path = Path(directory) / "llama.intent.json"
            command = [
                sys.executable, str(ROOT / "tools/kvio/run_kv_offload_io.py"),
                "--model", "meta-llama/Llama-3.1-8B-Instruct",
                "--chunk-tokens", "16", "--num-chunks", "2",
                "--mdts-bytes", "0",
                "--intent-out", str(intent_path), "--intent-only",
            ]
            subprocess.run(command, cwd=ROOT, check=True, capture_output=True,
                           text=True)
            intent = json.loads(intent_path.read_text(encoding="utf-8"))
            validate_intent(intent)
            self.assertNotIn("device", intent)
            plan = lower_intent(intent, mdts_bytes=8 << 20,
                                dma_ceiling_bytes=4 << 20)
            self.assertEqual(plan["effective_command_bytes"], 4 << 20)

    def test_dmabuf_sweep_emits_one_intent_per_logical_workload(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "sweep.txt"
            intents = Path(directory) / "intents"
            env = dict(os.environ, KVIO=str(ROOT / "tools/kvio"),
                       PYTHON=sys.executable, OUT=str(output),
                       INTENT_DIR=str(intents),
                       MODELS="meta-llama/Llama-3.1-8B-Instruct",
                       CHUNKS="16", KINDS=" ")
            subprocess.run(
                ["bash", str(ROOT / "tools/reproduce/kv-offload-io/sweep_dmabuf.sh")],
                cwd=ROOT, env=env, check=True, capture_output=True, text=True)
            files = list(intents.glob("*.intent.json"))
            self.assertEqual(len(files), 1)
            validate_intent(json.loads(files[0].read_text(encoding="utf-8")))
            self.assertIn("@@@ INTENT model=meta-llama/Llama-3.1-8B-Instruct",
                          output.read_text(encoding="utf-8"))

    def test_dmabuf_replay_requires_odirect(self):
        with tempfile.TemporaryDirectory() as directory:
            intent_path = Path(directory) / "workload.intent.json"
            intent_path.write_text(json.dumps(sample()), encoding="utf-8")
            command = [
                sys.executable, str(ROOT / "tools/kvio/intent.py"), "replay",
                str(intent_path), "--device", "/dev/example", "--engine",
                "io_uring", "--mdts-bytes", "8", "--dmabuf", "udmabuf",
                "--dma-ceiling-bytes", "8", "--target-plan",
                str(Path(directory) / "target-plan.json"), "--target-manifest",
                str(Path(directory) / "target-manifest.json"),
            ]
            result = subprocess.run(command, cwd=ROOT, capture_output=True,
                                    text=True, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertIn("dma-buf replay requires --odirect", result.stderr)

    def test_replay_uses_the_vendored_engine_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            intent_path = Path(directory) / "workload.intent.json"
            plan_path = Path(directory) / "target-plan.json"
            manifest_path = Path(directory) / "target-manifest.json"
            intent_path.write_text(json.dumps(sample()), encoding="utf-8")
            argv = [
                "replay", str(intent_path), "--device", "/dev/example",
                "--engine", "io_uring", "--mdts-bytes", "8", "--dmabuf",
                "udmabuf", "--dma-ceiling-bytes", "8", "--odirect",
                "--target-plan", str(plan_path), "--target-manifest",
                str(manifest_path), "--phase-gate-dir", str(Path(directory)),
                "--phase-gate-timeout-seconds", "15",
            ]
            with patch.dict(os.environ, {"PYTHONPATH": "/tmp/shadow"}):
                with patch.object(intent_module.subprocess, "run") as run:
                    run.return_value.returncode = 0
                    self.assertEqual(intent_module.main(argv), 0)
            env = run.call_args.kwargs["env"]
            prefix = env["PYTHONPATH"].split(os.pathsep)
            self.assertEqual(prefix[0], str(ROOT / "tools/kvio/vendor/lmcache"))
            self.assertEqual(prefix[1], str(ROOT / "tools/kvio/build"))
            self.assertEqual(prefix[2], str(ROOT / "tools/kvio"))
            self.assertEqual(prefix[3], "/tmp/shadow")
            command = run.call_args.args[0]
            self.assertIn("--phase-gate-dir", command)
            self.assertIn(str(Path(directory)), command)
            self.assertIn("--phase-gate-timeout-seconds", command)
            self.assertIn("15.0", command)


if __name__ == "__main__":
    unittest.main()
