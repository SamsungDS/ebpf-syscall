# SPDX-License-Identifier: Apache-2.0
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "examples" / "replay" / "mk_dev_iolog.py"
SPEC = importlib.util.spec_from_file_location("mk_dev_iolog", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
COMPARE_PATH = ROOT / "examples" / "replay" / "compare_streams.py"
COMPARE_SPEC = importlib.util.spec_from_file_location("compare_streams", COMPARE_PATH)
COMPARE = importlib.util.module_from_spec(COMPARE_SPEC)
COMPARE_SPEC.loader.exec_module(COMPARE)
VERIFIER = ROOT / "tools" / "kvio" / "build" / "kvio-ir"


def write_capture(path, rows, *, lba=4096, drops=0):
    records = [{"event_type": "capture_meta", "lba_bytes": lba}, *rows,
               {"event_type": "drops", "dropped": drops}]
    path.write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")


class IologTest(unittest.TestCase):
    def test_exact_referee_checks_offsets_and_order(self):
        source = {"commands": [
            {"op": "read", "slba": 1, "bytes": 4096, "ts": 100},
            {"op": "write", "slba": 2, "bytes": 4096, "ts": 200},
        ], "drops": 0}
        same = {"commands": [dict(command) for command in source["commands"]],
                "drops": 0}
        moved = {"commands": [dict(command) for command in source["commands"]],
                 "drops": 0}
        moved["commands"][1]["slba"] = 3
        self.assertTrue(COMPARE.exact_comparison(source, same, 512)[
            "device_stream_equal"])
        comparison = COMPARE.exact_comparison(source, moved, 512)
        self.assertTrue(comparison["operation_sequence_equal"])
        self.assertFalse(comparison["offset_sequence_equal"])
        self.assertFalse(comparison["tuple_sequence_equal"])

    def test_referee_rejects_malformed_or_unsupported_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "capture.jsonl"
            capture.write_text("{not-json}\n", encoding="utf-8")
            with self.assertRaisesRegex(COMPARE.ComparisonError, "invalid JSON"):
                COMPARE.load(str(capture))
            write_capture(capture, [
                {"event_type": "nvme_cmd", "seq": 0, "ts": 1,
                 "op_name": "discard", "slba": 0, "bytes": 4096},
            ])
            with self.assertRaisesRegex(COMPARE.ComparisonError, "unsupported"):
                COMPARE.load(str(capture))

    def test_iolog_uses_microseconds_and_stable_equal_timestamp_order(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "capture.jsonl"
            write_capture(capture, [
                {"event_type": "nvme_cmd", "seq": 1, "ts": 1_000_001_999,
                 "op_name": "read", "slba": 3, "bytes": 4096},
                {"event_type": "nvme_cmd", "seq": 0, "ts": 1_000_000_000,
                 "op_name": "write", "slba": 2, "bytes": 8192},
                {"event_type": "nvme_cmd", "seq": 2, "ts": 1_000_001_999,
                 "op_name": "write", "slba": 4, "bytes": 4096},
            ])
            rows, metadata = MODULE.load_capture(str(capture))
            iolog = MODULE.emit_iolog(rows, "/dev/source")
            self.assertEqual(MODULE.parse_iolog(iolog), [
                (0, "write", 8192, 8192),
                (1, "read", 12288, 4096),
                (1, "write", 16384, 4096),
            ])
            certificate, _ = MODULE.translation_certificate(
                rows, iolog, str(capture), metadata)
            self.assertTrue(certificate["operation_offset_length_sequence_equal"])
            self.assertEqual(certificate["maximum_timestamp_quantization_error_ns"], 999)

    def test_iolog_rejects_drops_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "capture.jsonl"
            write_capture(capture, [
                {"event_type": "nvme_cmd", "ts": 1_000_000_000,
                 "op_name": "read", "slba": 0, "bytes": 4096},
            ], drops=2)
            with self.assertRaisesRegex(MODULE.CaptureError, "dropped events"):
                MODULE.load_capture(str(capture))

    def test_legacy_capture_requires_explicit_lba_size(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "capture.jsonl"
            capture.write_text(
                json.dumps({"event_type": "nvme_cmd", "ts": 1_000_000_000,
                            "op_name": "read", "slba": 1, "bytes": 512}) + "\n" +
                json.dumps({"event_type": "drops", "dropped": 0}) + "\n",
                encoding="utf-8")
            with self.assertRaisesRegex(MODULE.CaptureError, "pass --lba-bytes"):
                MODULE.load_capture(str(capture))
            rows, metadata = MODULE.load_capture(str(capture), requested_lba=512)
            self.assertEqual(rows[0]["offset_bytes"], 512)
            self.assertEqual(metadata["lba_bytes"], 512)

    def test_bundle_has_checksums_and_fio_accepts_jobs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / "capture.jsonl"
            write_capture(capture, [
                {"event_type": "nvme_cmd", "seq": 0, "ts": 1_000_000_000,
                 "op_name": "read", "slba": 0, "bytes": 4096},
            ])
            rows, metadata = MODULE.load_capture(str(capture))
            iolog = MODULE.emit_iolog(rows, "/dev/source")
            certificate, normalized = MODULE.translation_certificate(
                rows, iolog, str(capture), metadata)
            bundle = root / "bundle"
            MODULE.write_bundle(str(bundle), iolog, certificate, normalized)
            self.assertEqual((bundle / "SHA256SUMS").read_text().count("\n"), 6)
            if shutil.which("fio"):
                environment = dict(os.environ, KVIO_TARGET="/dev/null")
                for jobfile in ("replay-block.fio", "replay-uring-cmd.fio"):
                    result = subprocess.run(
                        ["fio", "--parse-only", jobfile], cwd=bundle,
                        env=environment, text=True, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(
                "cmd_type=nvme\n",
                (bundle / "replay-uring-cmd.fio").read_text(encoding="utf-8"),
            )

    @unittest.skipUnless(VERIFIER.is_file(), "build verifier with make kvio-ir")
    def test_rust_verifier_checks_python_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = root / "capture.jsonl"
            write_capture(capture, [
                {"event_type": "nvme_cmd", "seq": 0, "ts": 1_000_000_000,
                 "op_name": "read", "slba": 0, "bytes": 4096},
            ])
            rows, metadata = MODULE.load_capture(str(capture))
            iolog = MODULE.emit_iolog(rows, "/dev/source")
            certificate, normalized = MODULE.translation_certificate(
                rows, iolog, str(capture), metadata)
            bundle = root / "bundle"
            MODULE.write_bundle(str(bundle), iolog, certificate, normalized)
            result = subprocess.run(
                [str(VERIFIER), "certify", str(bundle)],
                text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            rust_certificate = json.loads(result.stdout)
            self.assertTrue(rust_certificate[
                "operation_offset_length_sequence_equal"])
            self.assertTrue(rust_certificate["source_capture_complete"])
            self.assertFalse(rust_certificate[
                "performance_equivalence_claimed"])
            iolog_path = bundle / "commands.iolog"
            iolog_path.write_text(
                iolog_path.read_text(encoding="utf-8").replace(
                    "read 0 4096", "read 4096 4096"),
                encoding="utf-8")
            tampered = subprocess.run(
                [str(VERIFIER), "certify", str(bundle)],
                text=True, capture_output=True)
            self.assertNotEqual(tampered.returncode, 0)
            self.assertIn("iolog hash disagrees", tampered.stderr)


if __name__ == "__main__":
    unittest.main()
