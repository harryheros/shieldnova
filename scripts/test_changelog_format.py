"""
test_changelog_format.py — CHANGELOG.md has one dated entry per release,
newest first: `## X.Y.Z (YYYY-MM-DD)`, closed by one `## Before 2.0.0`
section for the untagged version.
"""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import _common

HEADING = re.compile(r"^## (\d+)\.(\d+)\.(\d+) \(\d{4}-\d{2}-\d{2}\)$")


def headings():
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    return [line for line in text.splitlines() if line.startswith("## ")]


class TestChangelogFormat(unittest.TestCase):
    def test_every_release_has_a_dated_entry(self):
        hs = headings()
        self.assertEqual(hs[-1], "## Before 2.0.0")
        self.assertEqual([h for h in hs[:-1] if not HEADING.match(h)], [])

    def test_newest_first_from_200_to_current(self):
        versions = [tuple(int(x) for x in HEADING.match(h).groups())
                    for h in headings()[:-1]]
        self.assertEqual(versions, sorted(versions, reverse=True))
        self.assertEqual(versions[-2:], [(2, 1, 0), (2, 0, 0)])
        current = tuple(int(x) for x in _common.__version__.split("."))
        self.assertEqual(versions[0], current)

    def test_lists_are_credited_to_the_release_that_added_them(self):
        # src/security/cryptojacking.txt shipped with 2.0.0 (34 rules); 2.1.0
        # only grew it through the monthly feed.
        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        entry_210 = text.split("## 2.1.0 ", 1)[1].split("\n## ", 1)[0]
        entry_200 = text.split("## 2.0.0 ", 1)[1].split("\n## ", 1)[0]
        self.assertNotIn("cryptojacking", entry_210)
        self.assertIn("cryptojacking", entry_200)

    def test_releases_are_in_the_file_not_only_on_github(self):
        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertNotIn("see the [GitHub releases]", text)


if __name__ == "__main__":
    unittest.main()
