#!/usr/bin/env python3
"""
test_version_consistency.py — pin the ShieldNova version single-source.

Three things historically drift:
  - _common.__version__       (now the source of truth)
  - README.md version badge    (now the latest-release badge, which cannot drift)
  - GitHub release tag        (manual, but should match _common at release time)

The README badge follows the latest GitHub release, so it no longer needs
a hand edit; the test keeps a hand-written badge from coming back.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import _common  # noqa: E402


class TestVersionConsistency(unittest.TestCase):
    def test_common_has_version(self):
        self.assertTrue(
            hasattr(_common, "__version__"),
            "_common.py must expose __version__",
        )
        self.assertRegex(
            _common.__version__,
            r"^\d+\.\d+\.\d+$",
            f"__version__ must be SemVer (got {_common.__version__!r})",
        )

    def test_readme_badge_cannot_go_stale(self):
        # The badge shows the latest GitHub release, so it never needs a
        # hand edit; a hand-written `version-vX.Y.Z` badge used to drift.
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("img.shields.io/github/v/release/harryheros/shieldnova", readme)
        self.assertNotIn("img.shields.io/badge/version-", readme)

if __name__ == "__main__":
    unittest.main(verbosity=2)
