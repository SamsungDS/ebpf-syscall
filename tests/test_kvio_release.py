# SPDX-License-Identifier: Apache-2.0
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.kvio import release

ROOT = Path(__file__).resolve().parents[1]
KVIO = ROOT / "tools" / "kvio" / "kvio"


def valid_result():
    return {
        "schema": "kvio-bank-local-result-v1",
        "status": "draft",
        "profile": "bank-local-results-v1",
        "question": "restore-tail-latency",
        "comparison": {
            "metric": "p99-completion-latency",
            "outcome": "candidate-lower",
            "ratio_band": "0.90-to-0.95",
            "repeat_count_band": "5-to-9",
        },
        "conditions": {
            "workload_evidence": "measured-capture",
            "offered_load": "fixed",
            "target_class": "local-nvme",
            "runtime_evidence": "re-recorded-device-stream",
        },
        "residual_disclosures": [
            "aggregate-comparison",
            "coarse-ratio-band",
            "storage-class",
            "workload-class",
        ],
    }


class ReleaseTest(unittest.TestCase):
    def write_result(self, path, result=None):
        path.write_text(json.dumps(result or valid_result()) + "\n", encoding="utf-8")

    def test_build_and_verify_keep_authorization_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "result-input.json"
            bundle = root / "candidate"
            self.write_result(source)
            verdict = release.build_candidate(str(source), str(bundle))
            self.assertEqual(
                set(path.name for path in bundle.iterdir()),
                {"manifest.json", "result.json"},
            )
            self.assertEqual(stat.S_IMODE(bundle.stat().st_mode), 0o700)
            self.assertEqual(
                stat.S_IMODE((bundle / "result.json").stat().st_mode), 0o600
            )
            self.assertEqual(verdict["bundle_conformance"], "pass")
            self.assertEqual(verdict["internal_evidence"], "not_checked")
            self.assertEqual(verdict["release_authorization"], "not_checked")
            self.assertFalse(verdict["export_allowed"])
            emitted = json.loads((bundle / "result.json").read_text())
            self.assertEqual(emitted, valid_result())

    def test_kvio_launcher_builds_and_verifies_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.json"
            bundle = root / "candidate"
            example = subprocess.run(
                [sys.executable, KVIO, "release-example"],
                text=True,
                capture_output=True,
            )
            self.assertEqual(example.returncode, 0, example.stderr)
            self.assertEqual(json.loads(example.stdout), valid_result())
            self.assertGreater(release.MAX_JSON_BYTES, 100 * len(example.stdout))
            source.write_text(example.stdout, encoding="utf-8")
            built = subprocess.run(
                [sys.executable, KVIO, "release-build", source, bundle],
                text=True,
                capture_output=True,
            )
            self.assertEqual(built.returncode, 0, built.stderr)
            self.assertFalse(json.loads(built.stdout)["export_allowed"])
            verified = subprocess.run(
                [sys.executable, KVIO, "release-verify", bundle],
                text=True,
                capture_output=True,
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertEqual(
                json.loads(verified.stdout)["release_authorization"], "not_checked"
            )

    def test_rejects_unknown_fields_and_non_draft_status(self):
        result = valid_result()
        result["source_trace_sha256"] = "0" * 64
        with self.assertRaisesRegex(release.ReleaseError, "E_RESULT_FIELDS"):
            release.validate_result(result)
        result = valid_result()
        result["status"] = "released"
        with self.assertRaisesRegex(release.ReleaseError, "E_RESULT_STATUS"):
            release.validate_result(result)

    def test_build_never_replaces_an_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.json"
            output = root / "candidate"
            output.mkdir()
            sentinel = output / "keep"
            sentinel.write_text("unchanged\n", encoding="utf-8")
            self.write_result(source)
            with self.assertRaisesRegex(release.ReleaseError, "E_OUTPUT_EXISTS"):
                release.build_candidate(str(source), str(output))
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "unchanged\n")

    def test_rejects_duplicate_json_keys_without_echoing_them(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.json"
            source.write_text(
                '{"secret-customer-name":1,"secret-customer-name":2}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(release.ReleaseError, "E_INPUT") as caught:
                release.build_candidate(str(source), str(Path(directory) / "out"))
            self.assertNotIn("secret-customer-name", str(caught.exception))

    def test_rejects_extra_files_symlinks_and_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.json"
            self.write_result(source)

            extra_bundle = root / "extra"
            release.build_candidate(str(source), str(extra_bundle))
            (extra_bundle / "README.txt").write_text("extra\n", encoding="utf-8")
            with self.assertRaisesRegex(release.ReleaseError, "E_BUNDLE_INVENTORY"):
                release.verify_candidate(str(extra_bundle))

            link_bundle = root / "link"
            release.build_candidate(str(source), str(link_bundle))
            os.unlink(link_bundle / "result.json")
            os.symlink(source, link_bundle / "result.json")
            with self.assertRaisesRegex(release.ReleaseError, "E_BUNDLE_FILE_TYPE"):
                release.verify_candidate(str(link_bundle))

            changed_bundle = root / "changed"
            release.build_candidate(str(source), str(changed_bundle))
            changed = valid_result()
            changed["comparison"]["outcome"] = "candidate-higher"
            changed["comparison"]["ratio_band"] = "1.05-to-1.10"
            self.write_result(changed_bundle / "result.json", changed)
            with self.assertRaisesRegex(release.ReleaseError, "E_MANIFEST_(SIZE|HASH)"):
                release.verify_candidate(str(changed_bundle))

    def test_rejects_free_text_and_unbounded_exact_values(self):
        result = valid_result()
        result["comparison"]["notes"] = "customer 123 had an outage"
        with self.assertRaisesRegex(release.ReleaseError, "E_COMPARISON_FIELDS"):
            release.validate_result(result)
        result = valid_result()
        result["comparison"]["ratio_band"] = 0.92341
        with self.assertRaisesRegex(release.ReleaseError, "E_COMPARISON_RATIO_BAND"):
            release.validate_result(result)

    def test_rejects_contradictory_result_claims(self):
        result = valid_result()
        result["comparison"]["metric"] = "throughput"
        with self.assertRaisesRegex(release.ReleaseError, "E_COMPARISON_QUESTION"):
            release.validate_result(result)
        result = valid_result()
        result["comparison"]["outcome"] = "candidate-higher"
        with self.assertRaisesRegex(release.ReleaseError, "E_COMPARISON_CONFLICT"):
            release.validate_result(result)
        result = valid_result()
        result["residual_disclosures"].remove("storage-class")
        with self.assertRaisesRegex(release.ReleaseError, "E_DISCLOSURES_SET"):
            release.validate_result(result)


if __name__ == "__main__":
    unittest.main()
