#!/usr/bin/env python3
"""
test_version_consistency.py — pin the ShieldNova version single-source.

Three things historically drift:
  - _common.__version__       (now the source of truth)
  - README.md shields badge   `version-vX.Y.Z-blue`
  - GitHub release tag        (manual, but should match _common at release time)

This test catches README drift at CI time so the badge never lags behind
the released code. The GitHub tag is checked manually at release; we just
make sure the code and README agree.
"""
from __future__ import annotations

import re
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
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        # Accept either full SemVer (vX.Y.Z) or two-segment shorthand (vX.Y).
        m = re.search(r"version-v(\d+\.\d+(?:\.\d+)?)-blue", readme)
        self.assertIsNotNone(m, "README must contain a version badge")
        badge = m.group(1)
        actual = _common.__version__
        if badge.count(".") == 2:
            self.assertEqual(
                badge, actual,
                f"README badge {badge!r} disagrees with "
                f"_common.__version__ {actual!r}",
            )
        else:
            actual_prefix = ".".join(actual.split(".")[:2])
            self.assertEqual(
                badge, actual_prefix,
                f"README badge {badge!r} disagrees with "
                f"_common.__version__ {actual!r}",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
