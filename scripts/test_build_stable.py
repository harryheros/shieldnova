#!/usr/bin/env python3
"""
test_build_stable.py — a rebuild without rule changes rewrites nothing.

Every output carries a build time ("! Built:", "! Version:", "# Built:",
"Built:" and "built" in stats.json). Rewriting it on every build made each
sync and each weekly run change some 50 files whose rules were the same.
The time now changes only when the rest of the file does.

Run:
  python3 scripts/test_build_stable.py
"""
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build  # noqa: E402

REPO = Path(__file__).resolve().parent.parent


def snapshot(*dirs):
    out = {}
    for d in dirs:
        for p in sorted(Path(d).rglob('*')):
            if p.is_file():
                out[str(p.relative_to(d))] = p.read_bytes()
    return out


class TestStableBuild(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        shutil.copytree(REPO / 'src', self.tmp / 'src')
        self.dist, self.formats = self.tmp / 'dist', self.tmp / 'formats'
        patches = [
            mock.patch.object(build, 'SRC_DIR', str(self.tmp / 'src')),
            mock.patch.object(build, 'DIST_DIR', str(self.dist)),
            mock.patch.object(build, 'FORMATS_DIR', str(self.formats)),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(shutil.rmtree, self.tmp)

    def build_at(self, when):
        with mock.patch.object(build, 'utc_now', return_value=when), redirect_stdout(StringIO()):
            build.build()

    def test_same_rules_same_bytes(self):
        self.build_at('2026-01-01 00:00:00 UTC')
        first = snapshot(self.dist, self.formats)
        self.assertGreater(len(first), 40)
        self.build_at('2026-02-02 12:00:00 UTC')
        second = snapshot(self.dist, self.formats)
        changed = [name for name in first if first[name] != second.get(name)]
        self.assertEqual(changed, [], 'files rewritten although no rule changed')

    def test_changed_rules_get_new_time(self):
        self.build_at('2026-01-01 00:00:00 UTC')
        with open(self.tmp / 'src' / 'advertising' / 'core.txt', 'a', encoding='utf-8') as f:
            f.write('||stable-build-test-example.com^\n')
        self.build_at('2026-02-02 12:00:00 UTC')
        ads = (self.dist / 'shieldnova-ads.txt').read_text(encoding='utf-8')
        self.assertIn('! Built: 2026-02-02 12:00:00 UTC', ads)
        self.assertIn('stable-build-test-example.com', ads)
        surge = (self.formats / 'surge' / 'shieldnova-ads.txt').read_text(encoding='utf-8')
        self.assertIn('# Built: 2026-02-02 12:00:00 UTC', surge)
        adguard = (self.formats / 'adguard' / 'shieldnova-ads.txt').read_text(encoding='utf-8')
        self.assertIn('! Version: 2026-02-02 12:00:00 UTC', adguard)
        # A list whose rules did not change keeps its time.
        privacy = (self.dist / 'shieldnova-privacy.txt').read_text(encoding='utf-8')
        self.assertIn('! Built: 2026-01-01 00:00:00 UTC', privacy)
        # stats changed (a new total), so it carries the new time.
        self.assertIn('Built: 2026-02-02 12:00:00 UTC', (self.dist / 'stats.md').read_text(encoding='utf-8'))
        self.assertIn('"built": "2026-02-02 12:00:00 UTC"', (self.dist / 'stats.json').read_text(encoding='utf-8'))


if __name__ == '__main__':
    os.chdir(REPO)
    unittest.main(verbosity=2)
