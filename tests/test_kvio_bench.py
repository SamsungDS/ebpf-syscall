# SPDX-License-Identifier: Apache-2.0

import contextlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.kvio.bench import (
    GIB,
    PROFILES,
    Tuning,
    fio_config,
    hugepages_needed,
    load_profile,
    main,
    parse_fio,
    parse_size,
    profile_jobs,
    profile_record,
)
from tools.kvio.compare import load


class KvioBenchTest(unittest.TestCase):
    def test_sizes(self):
        self.assertEqual(parse_size("8GiB"), 8 * GIB)
        self.assertEqual(parse_size("7340032"), 7_340_032)

    def test_calibrated_size_override(self):
        jobs = profile_jobs("restore-calibrated", 32 << 20)
        self.assertEqual(jobs[0].bs, 32 << 20)
        self.assertEqual(jobs[0].iodepth, 1)
        self.assertEqual(jobs[0].numjobs, 4)

    def test_partitioned_profile_is_bounded(self):
        jobs = profile_jobs("evict")
        config = fio_config("/dev/nvme1n1", "evict", jobs, 8 * GIB, 1, 0, False)
        self.assertIn("size=2147483648", config)
        self.assertIn("offset_increment=2147483648", config)

    def test_hugepage_budget_covers_queues(self):
        jobs = profile_jobs("restore")
        self.assertGreaterEqual(hugepages_needed(jobs, 2 << 20), 32)

    def test_qos_sustain_keeps_small_reads_off_hugepages(self):
        jobs = profile_jobs("qos-sustain-4k")
        config = fio_config(
            Path("/dev/null"), "qos-sustain-4k", jobs, 8 * GIB, 1, 0, True
        )
        big, small = config.split("[qos_sustain_4k]")
        self.assertIn("iomem=mmaphuge", big)
        self.assertNotIn("iomem=mmaphuge", small)

    def test_external_profile_records_evidence_and_jobs(self):
        data = {
            "schema_version": 1,
            "name": "captured-restore",
            "description": "Restore shape from capture X",
            "evidence": {"kind": "measured", "source": "capture-X.jsonl"},
            "jobs": [
                {
                    "name": "restore",
                    "rw": "randread",
                    "bs": "32MiB",
                    "iodepth": 1,
                    "numjobs": 4,
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.json"
            path.write_text(json.dumps(data))
            profile = load_profile(path)
        self.assertEqual(profile.jobs[0].bs, 32 << 20)
        self.assertEqual(profile_record(profile)["evidence"]["kind"], "measured")

    def test_external_profile_requires_evidence(self):
        data = {
            "schema_version": 1,
            "name": "guess",
            "description": "Missing its source",
            "jobs": [{}],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.json"
            path.write_text(json.dumps(data))
            with self.assertRaisesRegex(RuntimeError, "evidence"):
                load_profile(path)

    def test_list_profiles_does_not_require_a_device(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["--list-profiles"]), 0)
        self.assertIn("restore-calibrated [measured]", output.getvalue())
        self.assertIn("qos-sustain-4k [synthetic]", output.getvalue())
        self.assertIn("bs=7340032 iodepth=1 numjobs=4", output.getvalue())

    def test_record_uses_calibrated_override(self):
        jobs = profile_jobs("restore-calibrated", 32 << 20)
        record = profile_record(PROFILES["restore-calibrated"], jobs)
        self.assertEqual(record["jobs"][0]["bs"], 32 << 20)

    def test_queue_tuning_is_restored(self):
        with tempfile.TemporaryDirectory() as directory:
            sysdev = Path(directory)
            queue = sysdev / "queue"
            queue.mkdir()
            knob = queue / "max_sectors_kb"
            knob.write_text("128\n")
            with Tuning(sysdev, 64, None):
                self.assertEqual(knob.read_text(), "64\n")
            self.assertEqual(knob.read_text(), "128\n")

    def test_parse_fio_nanoseconds(self):
        direction = {
            "io_bytes": GIB,
            "bw_bytes": 2 << 30,
            "iops": 1024,
            "clat_ns": {"percentile": {"50.000000": 2000, "99.000000": 9000}},
        }
        empty = {"io_bytes": 0}
        data = {
            "jobs": [
                {
                    "jobname": "restore",
                    "read": direction,
                    "write": empty,
                    "usr_cpu": 1.5,
                    "sys_cpu": 2.5,
                }
            ]
        }
        rows = parse_fio(data, "restore", 1, 100)
        self.assertEqual(rows[0]["p50_us"], 2.0)
        self.assertEqual(rows[0]["p99_us"], 9.0)
        self.assertEqual(rows[0]["irq_per_gib"], 100.0)

    def test_compare_reads_jsonl_and_result_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            jsonl = Path(directory) / "result.jsonl"
            text = Path(directory) / "result.log"
            jsonl.write_text(
                '{"case":"qos-sustain-4k","job":"reader",'
                '"dir":"read",'
                '"rep":1,"p99_us":10}\n'
            )
            text.write_text(
                "RESULT case=qos-sustain-4k job=reader dir=read rep=1 p99_us=12\n"
            )
            key = ("qos-sustain-4k", "reader", "read")
            self.assertEqual(load(jsonl)[key]["p99_us"], [10.0])
            self.assertEqual(load(text)[key]["p99_us"], [12.0])

    @unittest.skipUnless(shutil.which("fio"), "fio is not installed")
    def test_every_fio_profile_parses(self):
        with tempfile.TemporaryDirectory() as directory:
            for case in PROFILES:
                path = Path(directory) / f"{case}.fio"
                path.write_text(
                    fio_config(
                        Path("/dev/null"),
                        case,
                        profile_jobs(case),
                        8 * GIB,
                        1,
                        0,
                        False,
                    )
                )
                subprocess.run(
                    ["fio", "--parse-only", str(path)],
                    check=True,
                    capture_output=True,
                    text=True,
                )


if __name__ == "__main__":
    unittest.main()
