# SPDX-License-Identifier: Apache-2.0
"""Named content profiles: the controls behave as controls, the mixed profile has knobs that bite."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KVIO = ROOT / "tools" / "kvio"
if str(KVIO) not in sys.path:
    sys.path.insert(0, str(KVIO))

import content_profile  # noqa: E402


class ContentProfileTest(unittest.TestCase):
    def test_controls_and_mixed_profiles_behave(self):
        z = content_profile.content("zeros", "o", 0, 8192)
        self.assertEqual(z, bytes(8192))
        a = content_profile.content("incompressible", "o", 100, 3000)
        self.assertEqual(a, content_profile.content("incompressible", "o", 0, 4000)[100:3100])   # ranged == full
        self.assertNotEqual(a, content_profile.content("incompressible", "p", 100, 3000))
        mixed = content_profile.parse_profile("mixed:zero=0.5,pattern=0.25,dup_classes=4")
        rep = content_profile.achieved(mixed, "o", 1 << 20)
        self.assertGreater(rep["algorithms"]["zlib-6"], 1.5)
        self.assertLess(rep["distinct_4k_blocks"], rep["blocks"])                  # duplicates exist
        inc = content_profile.achieved("incompressible", "o", 1 << 20)
        self.assertLess(inc["algorithms"]["zlib-6"], 1.05)
        self.assertEqual(inc["distinct_4k_blocks"], inc["blocks"])
        with self.assertRaises(ValueError):
            content_profile.parse_profile("mixed:zero=0.8,pattern=0.5")



if __name__ == "__main__":
    unittest.main()
