# SPDX-License-Identifier: Apache-2.0
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.kvio.intent import validate_intent
from tools.kvio.kv_geometry import kv_cache_bytes
from tools.kvio.kv_representation import (
    CODEC_HASH_KEYS,
    RepresentationError,
    codec_header_bytes,
    derive_representation,
    derive_representation_set,
    validate_representation_set,
)


ROOT = Path(__file__).resolve().parents[1]
MODEL = "meta-llama/Llama-3.1-8B-Instruct"
MIB = 1 << 20


def catalog():
    with open(ROOT / "tools/kvio/modelconfig.json", encoding="utf-8") as handle:
        return json.load(handle)


def llama_detail(chunk_tokens=256):
    _, detail = kv_cache_bytes(MODEL, catalog()[MODEL], chunk_tokens, "bfloat16")
    return detail


def derive_set(**overrides):
    args = dict(model=MODEL, config=catalog()[MODEL], dtype="bfloat16",
                chunk_tokens=256, num_chunks=4, streams=1, iters=1, warmup=0)
    args.update(overrides)
    return derive_representation_set(**args)


class CodecHeaderTest(unittest.TestCase):
    def test_header_length_matches_the_codec_layout(self):
        # 76 fixed + 24 payload lengths + 2 string count + 4 CRC, plus one
        # (2 + key, 2 + value) pair per hash key the codec always writes.
        strings = sum(2 + len(key) + 2 for key in CODEC_HASH_KEYS)
        self.assertEqual(codec_header_bytes((), {}), 76 + 24 + 2 + strings + 4)
        self.assertEqual(codec_header_bytes((16, 8), {}),
                         codec_header_bytes((), {}) + 16)
        self.assertEqual(codec_header_bytes((), {"model_id": "abc"}),
                         codec_header_bytes((), {}) + 3)


class RepresentationBytesTest(unittest.TestCase):
    def test_llama_8b_chunk_of_256_tokens(self):
        manifest, intents = derive_set()
        reps = manifest["representations"]
        header = codec_header_bytes((), {"model_id": MODEL})
        # 32 layers x 256 tokens x 8 heads x 128 x 2 bytes = 16 MiB per plane.
        self.assertEqual(reps["bf16_kv"]["stored"]["payload_bytes"], 32 * MIB)
        self.assertEqual(reps["k16_v8"]["stored"]["components_bytes"],
                         {"k": 16 * MIB, "v": 8 * MIB, "scales": 4,
                          "codec_header": header})
        self.assertEqual(reps["v8_only"]["stored"]["components_bytes"],
                         {"v": 8 * MIB, "scales": 4, "codec_header": header})
        self.assertEqual(reps["v8_only"]["host"]["retained_bytes"], {"k": 16 * MIB})
        self.assertEqual(reps["v8_only"]["host"]["h2d_bytes_per_restore"], 16 * MIB)
        self.assertEqual(reps["k16_v8"]["host"]["h2d_bytes_per_restore"], 0)
        ratios = manifest["payload_ratio_to_bf16_kv"]
        self.assertAlmostEqual(ratios["k16_v8"], 0.75, places=4)
        self.assertAlmostEqual(ratios["v8_only"], 0.25, places=4)
        self.assertGreater(ratios["k16_v8"], 0.75)  # header and scales are charged
        for name, intent in intents.items():
            validate_intent(intent)
            self.assertEqual(intent["object"]["payload_bytes"],
                             reps[name]["stored"]["payload_bytes"])

    def test_physical_extent_charges_metadata_and_alignment(self):
        entry = derive_representation(name="v8_only", detail=llama_detail(),
                                      dtype="bfloat16", chunk_tokens=256)
        payload = entry["stored"]["payload_bytes"]
        extent = entry["storage"]["physical_extent_bytes"]
        self.assertEqual(extent % 4096, 0)
        self.assertGreaterEqual(extent, 4096 + payload)
        self.assertLess(extent, 4096 + payload + 4096)

    def test_tensor_parallel_shards_every_plane(self):
        manifest, _ = derive_set(tp=2)
        reps = manifest["representations"]
        self.assertEqual(reps["bf16_kv"]["stored"]["payload_bytes"], 16 * MIB)
        self.assertEqual(reps["v8_only"]["stored"]["components_bytes"]["v"], 4 * MIB)
        self.assertEqual(reps["v8_only"]["host"]["retained_bytes"]["k"], 8 * MIB)
        self.assertEqual(reps["v8_only"]["logical"]["ranks_per_chunk"], 2)
        self.assertEqual(manifest["schedule"]["objects_per_chunk"], 2)

    def test_per_page_head_scales_follow_pages_and_heads(self):
        manifest, _ = derive_set(scale_scope="per_page_head", page_size=16)
        stored = manifest["representations"]["k16_v8"]["stored"]
        self.assertEqual(stored["scale_shape"], [16, 8])
        self.assertEqual(stored["components_bytes"]["scales"], 16 * 8 * 4)

    def test_padding_rounds_the_encoded_object_to_the_block(self):
        plain = derive_representation(name="k16_v8", detail=llama_detail(),
                                      dtype="bfloat16", chunk_tokens=256)
        padded = derive_representation(name="k16_v8", detail=llama_detail(),
                                       dtype="bfloat16", chunk_tokens=256,
                                       pad_to_block_align=True)
        self.assertNotEqual(plain["stored"]["payload_bytes"] % 4096, 0)
        self.assertEqual(padded["stored"]["payload_bytes"] % 4096, 0)
        self.assertEqual(padded["stored"]["payload_bytes"]
                         - plain["stored"]["payload_bytes"],
                         padded["stored"]["components_bytes"]["padding"])
        self.assertEqual(padded["storage"]["physical_extent_bytes"],
                         plain["storage"]["physical_extent_bytes"])
        # The plain BF16 object is already a block multiple: nothing to pad.
        bf16 = derive_representation(name="bf16_kv", detail=llama_detail(),
                                     dtype="bfloat16", chunk_tokens=256,
                                     pad_to_block_align=True)
        self.assertNotIn("padding", bf16["stored"]["components_bytes"])

    def test_padding_follows_the_physical_block_size(self):
        # A 16 KiB indirection-unit drive reports a 16 KiB physical block.
        entry = derive_representation(name="v8_only", detail=llama_detail(),
                                      dtype="bfloat16", chunk_tokens=256,
                                      block_align=16384, pad_to_block_align=True)
        self.assertEqual(entry["stored"]["payload_bytes"] % 16384, 0)
        self.assertEqual(entry["storage"]["block_align"], 16384)
        self.assertEqual(entry["storage"]["physical_extent_bytes"] % 16384, 0)
        manifest, _ = derive_set(block_align=16384, pad_to_block_align=True)
        self.assertEqual(manifest["storage"]["block_align"], 16384)

    def test_serde_reservation_uses_the_header_allowance(self):
        entry = derive_representation(name="k16_v8", detail=llama_detail(),
                                      dtype="bfloat16", chunk_tokens=256)
        stored = entry["stored"]
        self.assertEqual(stored["serde_reservation_bytes"],
                         24 * MIB + 4 + 1024)
        self.assertGreater(stored["serde_reservation_bytes"], stored["payload_bytes"])


class FailClosedTest(unittest.TestCase):
    def test_mla_has_no_separable_planes(self):
        mla = "deepseek-ai/DeepSeek-V3"
        _, detail = kv_cache_bytes(mla, catalog()[mla], 256, "bfloat16")
        with self.assertRaisesRegex(RepresentationError, "MLA"):
            derive_representation(name="v8_only", detail=detail,
                                  dtype="bfloat16", chunk_tokens=256)

    def test_per_page_scales_need_whole_pages(self):
        with self.assertRaisesRegex(RepresentationError, "whole number"):
            derive_representation(name="k16_v8", detail=llama_detail(250),
                                  dtype="bfloat16", chunk_tokens=250,
                                  scale_scope="per_page_head", page_size=16)

    def test_unknown_hash_key_is_refused(self):
        with self.assertRaisesRegex(RepresentationError, "not written by the codec"):
            derive_representation(name="k16_v8", detail=llama_detail(),
                                  dtype="bfloat16", chunk_tokens=256,
                                  codec_hashes={"weights_hash": "x"})

    def test_unknown_representation_is_refused(self):
        with self.assertRaisesRegex(RepresentationError, "unknown representation"):
            derive_set(representations=["k4_v4"])


class ManifestBindingTest(unittest.TestCase):
    def test_manifest_binds_to_its_intents(self):
        manifest, intents = derive_set()
        validate_representation_set(manifest, intents)

    def test_tampered_payload_is_rejected(self):
        manifest, intents = derive_set()
        tampered = copy.deepcopy(intents)
        tampered["v8_only"]["object"]["payload_bytes"] += 1
        for op in tampered["v8_only"]["operations"]:
            op["payload_bytes"] += 1
        with self.assertRaisesRegex(RepresentationError, "does not bind"):
            validate_representation_set(manifest, tampered)

    def test_missing_representation_is_rejected(self):
        manifest, intents = derive_set()
        del intents["k16_v8"]
        with self.assertRaisesRegex(RepresentationError, "different representations"):
            validate_representation_set(manifest, intents)

    def test_components_must_sum_to_the_payload(self):
        manifest, intents = derive_set()
        broken = copy.deepcopy(manifest)
        broken["representations"]["k16_v8"]["stored"]["components_bytes"]["scales"] += 1
        with self.assertRaisesRegex(RepresentationError, "do not sum"):
            validate_representation_set(broken, intents)


class CommandLineTest(unittest.TestCase):
    def test_launcher_writes_intents_and_manifest_without_an_engine(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "reps"
            command = [sys.executable, str(ROOT / "tools/kvio/kvio"),
                       "representations", "--model", MODEL,
                       "--chunk-tokens", "16", "--num-chunks", "2",
                       "--codec-hash", "tokenizer_hash=abcd",
                       "--out-dir", str(out)]
            result = subprocess.run(command, cwd=ROOT, check=True,
                                    capture_output=True, text=True)
            self.assertIn("wrote 3 intents", result.stdout)
            manifest = json.loads((out / "representation-set.json").read_text())
            intents = {name: json.loads((out / f"{name}.intent.json").read_text())
                       for name in manifest["representations"]}
            validate_representation_set(manifest, intents)
            self.assertEqual(manifest["codec"]["hashes"]["tokenizer_hash"], "abcd")
            self.assertEqual(manifest["evidence"],
                             "derived-from-codec-layout-not-measured")

    def test_mla_model_fails_closed_at_the_command_line(self):
        with tempfile.TemporaryDirectory() as directory:
            command = [sys.executable, str(ROOT / "tools/kvio/kv_representation.py"),
                       "--model", "deepseek-ai/DeepSeek-V3",
                       "--out-dir", str(Path(directory) / "x")]
            result = subprocess.run(command, cwd=ROOT / "tools/kvio",
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertIn("MLA", result.stderr)
