# SPDX-License-Identifier: Apache-2.0
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class OfflineInstallTest(unittest.TestCase):
    def run_kvio(self, launcher, *args, env, expected=0):
        result = subprocess.run(
            [sys.executable, launcher, *map(str, args)],
            text=True,
            capture_output=True,
            env=env,
        )
        self.assertEqual(result.returncode, expected, result.stderr)
        return result

    def test_installed_workflows_need_no_engine_or_network(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory)
            result = subprocess.run(
                [
                    "make",
                    "install-kvio-offline",
                    f"DESTDIR={stage}",
                    "prefix=/usr",
                    "KVIO_TRACER=/bin/true",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            package = stage / "usr/libexec/ebpf-syscall"
            launcher = package / "tools/kvio/kvio"
            self.assertFalse((package / "tools/kvio/vendor").exists())

            guard = stage / "network-guard"
            guard.mkdir()
            guard_marker = stage / "network-guard-loaded"
            (guard / "sitecustomize.py").write_text(
                "import os\n"
                "import socket\n"
                "from pathlib import Path\n"
                "Path(os.environ['KVIO_NETWORK_GUARD_MARKER']).touch()\n"
                "def blocked(*args, **kwargs):\n"
                "    raise RuntimeError('network disabled by test')\n"
                "socket.socket = blocked\n"
                "socket.create_connection = blocked\n",
                encoding="utf-8",
            )
            fake_bin = stage / "fake-bin"
            fake_bin.mkdir()
            fio = fake_bin / "fio"
            fio.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fio.chmod(0o755)
            env = dict(os.environ)
            env["PYTHONPATH"] = str(guard)
            env["KVIO_NETWORK_GUARD_MARKER"] = str(guard_marker)
            env["PATH"] = str(fake_bin) + os.pathsep + env["PATH"]

            help_result = self.run_kvio(launcher, "--help", env=env)
            self.assertTrue(guard_marker.exists())
            self.assertIn("iolog", help_result.stdout)
            self.assertNotIn("workload", help_result.stdout)
            self.run_kvio(launcher, "doctor", env=env)
            self.run_kvio(launcher, "record", "--help", env=env)

            example = self.run_kvio(launcher, "release-example", env=env)
            result_input = stage / "result.json"
            result_input.write_text(example.stdout, encoding="utf-8")
            candidate = stage / "candidate"
            built = self.run_kvio(
                launcher,
                "release-build",
                result_input,
                candidate,
                env=env,
            )
            self.assertFalse(json.loads(built.stdout)["export_allowed"])
            self.run_kvio(launcher, "release-verify", candidate, env=env)

            capture = package / "tools/kvio/offline-capture-v1.example.jsonl"
            replay = stage / "replay"
            self.run_kvio(
                launcher,
                "iolog",
                capture,
                "/dev/fixture",
                "--bundle-dir",
                replay,
                env=env,
            )
            self.run_kvio(launcher, "fio-certify", replay, env=env)
            self.run_kvio(
                launcher,
                "compare",
                f"same:{capture}:{capture}",
                env=env,
            )

            repeated = subprocess.run(
                [
                    "make",
                    "install-kvio-offline",
                    f"DESTDIR={stage}",
                    "prefix=/usr",
                    "KVIO_TRACER=/bin/true",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(repeated.returncode, 0)
            self.assertIn("use an empty staging root", repeated.stdout)


if __name__ == "__main__":
    unittest.main()
