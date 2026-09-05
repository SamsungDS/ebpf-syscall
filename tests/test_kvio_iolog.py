# SPDX-License-Identifier: Apache-2.0
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "examples" / "replay" / "mk_dev_iolog.py"
sys.path.insert(0, str(MODULE_PATH.parent))
SPEC = importlib.util.spec_from_file_location("mk_dev_iolog", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
COMPARE_PATH = ROOT / "examples" / "replay" / "compare_streams.py"
COMPARE_SPEC = importlib.util.spec_from_file_location("compare_streams", COMPARE_PATH)
COMPARE = importlib.util.module_from_spec(COMPARE_SPEC)
COMPARE_SPEC.loader.exec_module(COMPARE)
VERIFIER = ROOT / "tools" / "kvio" / "build" / "kvio-ir"


def write_capture(path, rows, *, lba=4096, drops=0):
    commands = []
    for row in rows:
        row = dict(row)
        if row.get("event_type") == "nvme_cmd":
            row.setdefault("disk", "nvme1n1")
            row.setdefault("nsid", 1)
        commands.append(row)
    records = [{
        "event_type": "capture_meta", "schema_version": 1,
        "emitter": "nvme_tp_monitor", "lba_bytes": lba,
        "lba_source": "sysfs", "disk_filter": True, "disk": "nvme1n1",
    }, *commands,
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

    def test_referee_pairs_completions_across_command_id_reuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "source.jsonl"
            replay_path = root / "replay.jsonl"
            commands = [
                {"event_type": "nvme_cmd", "seq": 0, "ts": 1_000_000,
                 "op_name": "read", "slba": 0, "bytes": 4096,
                 "hwq": 2, "cid": 7},
                {"event_type": "nvme_cmp", "ts": 1_100_000,
                 "lat_ns": 100_000, "hwq": 2, "cid": 7, "status": 0},
                {"event_type": "nvme_cmd", "seq": 1, "ts": 1_200_000,
                 "op_name": "read", "slba": 8, "bytes": 4096,
                 "hwq": 2, "cid": 7},
                {"event_type": "nvme_cmp", "ts": 1_400_000,
                 "lat_ns": 200_000, "hwq": 2, "cid": 7, "status": 0},
            ]
            write_capture(source_path, commands)
            replay = [dict(record) for record in commands]
            replay[1].update(ts=1_150_000, lat_ns=150_000)
            replay[3].update(ts=1_500_000, lat_ns=300_000)
            write_capture(replay_path, replay)

            source_capture = COMPARE.load(str(source_path))
            replay_capture = COMPARE.load(str(replay_path))
            comparison = COMPARE.exact_comparison(
                source_capture, replay_capture, 4096)
            self.assertTrue(source_capture["completion_pairing"]["complete"])
            self.assertTrue(replay_capture["completion_pairing"]["complete"])
            self.assertTrue(comparison[
                "per_command_completion_latency_compared"])
            self.assertEqual(
                comparison["completion_latency_error_max_us"], 100.0)

    def test_referee_rejects_ambiguous_completion_pairing_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "capture.jsonl"
            write_capture(capture, [
                {"event_type": "nvme_cmd", "seq": 0, "ts": 1,
                 "op_name": "read", "slba": 0, "bytes": 4096,
                 "hwq": 0, "cid": 3},
                {"event_type": "nvme_cmd", "seq": 1, "ts": 2,
                 "op_name": "read", "slba": 8, "bytes": 4096,
                 "hwq": 0, "cid": 3},
                {"event_type": "nvme_cmp", "ts": 3, "lat_ns": 1,
                 "hwq": 0, "cid": 3, "status": 0},
            ])
            loaded = COMPARE.load(str(capture))
            self.assertFalse(loaded["completion_pairing"]["complete"])
            self.assertEqual(
                loaded["completion_pairing"]["ambiguous_key_reuse"], 1)

    def test_referee_does_not_claim_empty_completion_comparison(self):
        empty = {
            "commands": [],
            "drops": 0,
            "completion_pairing": {"complete": True},
        }
        comparison = COMPARE.exact_comparison(empty, empty, 4096)
        self.assertTrue(comparison["tuple_sequence_equal"])
        self.assertFalse(comparison[
            "per_command_completion_latency_compared"])

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

    def test_capture_rejects_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "capture.jsonl"
            capture.write_text(
                '{"event_type":"capture_meta","schema_version":1,'
                '"emitter":"nvme_tp_monitor","lba_bytes":4096,'
                '"lba_source":"sysfs","disk_filter":true,'
                '"disk":"nvme1n1"}\n'
                '{"event_type":"nvme_cmd","disk":"nvme1n1","nsid":1,'
                '"seq":0,"ts":1,"op_name":"read","slba":1,'
                '"slba":2,"bytes":4096}\n'
                '{"event_type":"drops","dropped":0}\n',
                encoding="utf-8")
            with self.assertRaisesRegex(MODULE.CaptureError,
                                        "duplicate JSON key 'slba'"):
                MODULE.load_capture(str(capture))
            with self.assertRaisesRegex(COMPARE.ComparisonError,
                                        "duplicate JSON key 'slba'"):
                COMPARE.load(str(capture))

    def test_capture_requires_terminal_drop_accounting(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "capture.jsonl"
            write_capture(capture, [
                {"event_type": "nvme_cmd", "seq": 0, "ts": 1,
                 "op_name": "read", "slba": 0, "bytes": 4096},
            ])
            lines = capture.read_text(encoding="utf-8").splitlines()
            capture.write_text("\n".join([lines[0], lines[2], lines[1]]) + "\n",
                               encoding="utf-8")
            with self.assertRaisesRegex(MODULE.CaptureError,
                                        "drops record must be the final"):
                MODULE.load_capture(str(capture))

    def test_capture_rejects_unknown_version_and_mixed_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "capture.jsonl"
            rows = [
                {"event_type": "nvme_cmd", "seq": 0, "ts": 1,
                 "op_name": "read", "slba": 0, "bytes": 4096},
            ]
            write_capture(capture, rows)
            text = capture.read_text(encoding="utf-8")
            capture.write_text(text.replace('"schema_version": 1',
                                            '"schema_version": 2'),
                               encoding="utf-8")
            with self.assertRaisesRegex(MODULE.CaptureError,
                                        "unsupported capture schema_version 2"):
                MODULE.load_capture(str(capture))

            write_capture(capture, rows + [
                {"event_type": "nvme_cmd", "disk": "nvme1n1", "nsid": 2,
                 "seq": 1, "ts": 2, "op_name": "read", "slba": 1,
                 "bytes": 4096},
            ])
            with self.assertRaisesRegex(MODULE.CaptureError,
                                        "spans multiple device/namespace"):
                MODULE.load_capture(str(capture))

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
                MODULE.load_capture(str(capture), allow_legacy_capture=True)
            with self.assertRaisesRegex(MODULE.CaptureError,
                                        "legacy unversioned format"):
                MODULE.load_capture(str(capture), requested_lba=512)
            rows, metadata = MODULE.load_capture(
                str(capture), requested_lba=512, allow_legacy_capture=True)
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

    @unittest.skipUnless(VERIFIER.is_file(), "build verifier with make kvio-ir")
    def test_compare_updates_bundle_with_checked_runtime_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "source.jsonl"
            replay_path = root / "replay.jsonl"
            records = [
                {"event_type": "nvme_cmd", "seq": 0, "ts": 1_000_000,
                 "op_name": "read", "slba": 1, "bytes": 4096,
                 "hwq": 1, "cid": 9},
                {"event_type": "nvme_cmp", "ts": 1_100_000,
                 "lat_ns": 100_000, "hwq": 1, "cid": 9, "status": 0},
            ]
            write_capture(source_path, records)
            write_capture(replay_path, records)
            rows, metadata = MODULE.load_capture(str(source_path))
            iolog = MODULE.emit_iolog(rows, "/dev/source")
            certificate, normalized = MODULE.translation_certificate(
                rows, iolog, str(source_path), metadata)
            bundle = root / "bundle"
            MODULE.write_bundle(str(bundle), iolog, certificate, normalized)

            other_source = root / "other-source.jsonl"
            other_records = [dict(record) for record in records]
            other_records[0]["slba"] = 2
            write_capture(other_source, other_records)
            mismatched = subprocess.run(
                [
                    sys.executable,
                    str(COMPARE_PATH),
                    f"wrong:{other_source}:{other_source}",
                    "--update-bundle",
                    str(bundle),
                ],
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(mismatched.returncode, 0)
            self.assertIn(
                "source capture does not match the runtime bundle",
                mismatched.stderr,
            )

            updated = subprocess.run(
                [
                    sys.executable,
                    str(COMPARE_PATH),
                    f"same:{source_path}:{replay_path}",
                    "--update-bundle",
                    str(bundle),
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(updated.returncode, 0, updated.stderr)
            self.assertIn("device_stream_equal=True", updated.stdout)
            runtime = json.loads(
                (bundle / "certificate.json").read_text(encoding="utf-8")
            )["runtime_device_validation"]
            self.assertTrue(runtime["device_stream_equal"])
            self.assertTrue(runtime["completion_pairing"][
                "per_command_compared"])

            verified = subprocess.run(
                [str(VERIFIER), "certify", str(bundle)],
                text=True, capture_output=True)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            result = json.loads(verified.stdout)
            self.assertEqual(result["runtime_device_validation"], runtime)

            changed = json.loads(
                (bundle / "certificate.json").read_text(encoding="utf-8"))
            changed["runtime_device_validation"]["device_stream_equal"] = False
            (bundle / "certificate.json").write_text(
                json.dumps(changed), encoding="utf-8")
            rejected = subprocess.run(
                [str(VERIFIER), "certify", str(bundle)],
                text=True, capture_output=True)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("device-stream verdict", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
