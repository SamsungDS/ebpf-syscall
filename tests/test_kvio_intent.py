# SPDX-License-Identifier: Apache-2.0
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.kvio.intent import (
    IntentError,
    build_kv_offload_intent,
    lower_intent,
    validate_intent,
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


if __name__ == "__main__":
    unittest.main()
