# SPDX-License-Identifier: Apache-2.0
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools" / "kvio"))

from workload_catalog import (  # noqa: E402
    CATALOG,
    CatalogError,
    load_catalog,
    validate_catalog,
)


class WorkloadCatalogTest(unittest.TestCase):
    def test_built_in_sources_are_pinned_without_fake_hardware(self):
        catalog = load_catalog()
        self.assertEqual(len(catalog["workloads"]), 2)
        for workload in catalog["workloads"]:
            self.assertEqual(workload["evidence_label"], "trace-derived")
            self.assertTrue(workload["source"]["revision"])
            self.assertFalse(workload["hardware_geometry"]["available"])
            self.assertTrue(all(
                value is None
                for field, value in workload["hardware_geometry"].items()
                if field != "available"
            ))

    def test_rejects_unknown_fields_and_duplicate_ids(self):
        catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        unknown = copy.deepcopy(catalog)
        unknown["workloads"][0]["representative"] = True
        with self.assertRaisesRegex(CatalogError, "unknown fields"):
            validate_catalog(unknown)

        duplicate = copy.deepcopy(catalog)
        duplicate["workloads"][1]["id"] = duplicate["workloads"][0]["id"]
        with self.assertRaisesRegex(CatalogError, "duplicate workload id"):
            validate_catalog(duplicate)

    def test_hardware_claim_requires_geometry_and_measured_label(self):
        catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        claimed = copy.deepcopy(catalog)
        hardware = claimed["workloads"][0]["hardware_geometry"]
        hardware["available"] = True
        hardware.update({
            "capture_tool": "nvme_tp_monitor-v1",
            "device_model": "example",
            "kernel": "example",
            "logical_block_bytes": 4096,
            "max_transfer_bytes": 131072,
        })
        with self.assertRaisesRegex(CatalogError, "hardware geometry disagree"):
            validate_catalog(claimed)

        missing = copy.deepcopy(catalog)
        missing["workloads"][0]["evidence_label"] = "measured"
        with self.assertRaisesRegex(CatalogError, "hardware geometry disagree"):
            validate_catalog(missing)

    def test_loader_rejects_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(
                '{"schema_version":1,"schema_version":1,"workloads":[]}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(CatalogError, "duplicate JSON key"):
                load_catalog(path)

    def test_kvio_dispatches_catalog_validation(self):
        result = subprocess.run(
            [sys.executable, ROOT / "tools/kvio/kvio", "catalog", "--check"],
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("valid workload catalog: 2 entries", result.stdout)


if __name__ == "__main__":
    unittest.main()
