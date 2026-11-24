#!/usr/bin/env python3
"""
test_version_consistency.py — pin the ShieldNova version single-source.

Three things historically drift:
  - _common.__version__       (now the source of truth)
  - README.md shields badge   `version-vX.Y.Z-blue`
  - GitHub release tag        (manual, but should match _common at release time)

This test catches README badge drift at CI time, so the static badge never
lags behind the released code.
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

    def test_readme_badge_matches_version(self):
        # Static badge, updated with each release (a badge that made
        # shields.io query GitHub showed as a broken image).
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(
            f"img.shields.io/badge/version-v{_common.__version__}-blue", readme
        )
        self.assertNotIn("img.shields.io/github/", readme)


if __name__ == "__main__":
    unittest.main(verbosity=2)
