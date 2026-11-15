#!/usr/bin/env python3
"""
test_update_log.py — weekly refreshes go to dist/updates.md, not CHANGELOG.md.

CHANGELOG.md is the release history. The weekly threat-intelligence entries
used to be prepended to it, so after a few months the releases were lost
among dozens of "refreshed" entries.

Run:
  python3 scripts/test_update_log.py
"""
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import generate_release_report as grr  # noqa: E402


def report(day, new=5, retired=5, passed=True):
    return {
        'build': {'built_at': f'{day} 02:00:00 UTC'},
        'rule_delta': {'delta': 0, 'total_rules_now': 1000},
        'false_positive_gate': {'passed': passed},
        'fetch': {'total_new_domains': new, 'total_retired_domains': retired, 'total_platform_skipped': 0},
    }


class TestUpdateLog(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        (self.root / 'dist').mkdir()
        self.changelog = self.root / 'CHANGELOG.md'
        self.changelog.write_text('# ShieldNova Changelog\n\n## v9.9.9 (2026-01-01)\n\n- A release.\n', encoding='utf-8')
        for name, value in (('ROOT', self.root), ('DIST_DIR', self.root / 'dist')):
            p = mock.patch.object(grr, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.log = self.root / 'dist' / 'updates.md'

    def write(self, rep):
        with redirect_stdout(StringIO()):
            grr.update_log(rep)

    def test_changelog_untouched(self):
        before = self.changelog.read_bytes()
        self.write(report('2026-03-02'))
        self.assertEqual(self.changelog.read_bytes(), before)
        self.assertIn('## 2026-03-02', self.log.read_text(encoding='utf-8'))

    def test_newest_first_and_same_day_replaced(self):
        self.write(report('2026-03-02'))
        self.write(report('2026-03-09', new=7, retired=7))
        self.write(report('2026-03-09', new=8, retired=8))  # a second run that day
        text = self.log.read_text(encoding='utf-8')
        self.assertLess(text.index('## 2026-03-09'), text.index('## 2026-03-02'))
        self.assertEqual(text.count('## 2026-03-09'), 1)
        self.assertIn('+8 new', text)
        self.assertNotIn('+7 new', text)
        self.assertTrue(text.startswith('# ShieldNova rule updates\n'))
        self.assertIn('CHANGELOG.md', text.split('## ', 1)[0])  # the header points to the releases


if __name__ == '__main__':
    unittest.main(verbosity=2)
