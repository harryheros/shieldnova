#!/usr/bin/env python3
"""
test_fetch_rotation.py — regression tests for the v2.2.0 threat-intel changes.

  - ThreatFox CSV parsing (comma+space format; ioc_value column only)
  - Rolling window: liveness / age / FIFO eviction, manual entries untouched
  - Truncated feeds never trigger liveness eviction
  - Alphabet-neutral, deterministic selection
  - Release report: stale fetch stats are not re-announced
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import date, datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fetch_threat_intel as f  # noqa: E402
import generate_release_report as grr  # noqa: E402

TF_HEADER = ('# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware",'
             '"malware_alias","malware_printable","last_seen_utc","confidence_level",'
             '"is_compromised","reference","tags","anonymous","reporter"')


def tf_row(value, typ, conf="100", ref="None"):
    return (f'"2026-09-20 00:00:00", "1", "{value}", "{typ}", "botnet_cc", "x", "None", '
            f'"X", "", "{conf}", "False", "{ref}", "", "0", "r"')


class TestThreatFoxParser(unittest.TestCase):
    def test_real_format(self):
        content = "\n".join([
            TF_HEADER,
            tf_row("g4p227nh.highdesertarchers.org", "domain"),
            tf_row("https://roperotivo.pro/", "url", "90",
                   "https://clickfix.carsonww.com/domains/roperotivo.pro"),
            tf_row("195.222.53.130:6431", "ip:port", "75", "https://bazaar.abuse.ch/sample/x/"),
            tf_row("http://123.172.77.129:59541/Mozi.m", "url", "75",
                   "https://honeylabs.net/lookup/123.172.77.129"),
            tf_row("lowconf.example.xyz", "domain", "50"),
            tf_row("evil.github.io", "domain"),
        ])
        domains, skipped = f.parse_threatfox(content)
        self.assertEqual(domains, {"g4p227nh.highdesertarchers.org", "roperotivo.pro"})
        self.assertEqual(skipped, {"github.io": 1})

    def test_reference_column_never_used(self):
        content = TF_HEADER + "\n" + tf_row("1.2.3.4:80", "ip:port", "100", "https://bazaar.abuse.ch/s/1")
        self.assertEqual(f.parse_threatfox(content)[0], set())


def _fetched(**sources):
    out = {}
    for name, (eligible, live, sane) in sources.items():
        out[name] = {'ok': True, 'sane': sane, 'eligible': set(eligible), 'live': set(live)}
    return out


class TestRotation(unittest.TestCase):
    TODAY = date(2026, 9, 25)

    def _file(self, text):
        tmp = tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False, encoding='utf-8')
        tmp.write(text)
        tmp.close()
        return Path(tmp.name)

    BASE = "\n".join([
        "! ShieldNova - Security / Malware",
        "||manual-bad.com^                           ! curated",
        "",
        "! --- Auto-fetched from malware (2026-04-28) ---",
        "||old-legacy.com^                           ! auto: malware",
        "||still-live.com^                           ! auto: malware",
        "",
        "! --- Auto-fetched from threatfox (2026-01-01) ---",
        "||ancient-c2.net^                           ! auto: threatfox",
    ]) + "\n"

    def test_liveness_age_and_manual_untouched(self):
        path = self._file(self.BASE)
        fetched = _fetched(urlhaus=(["still-live.com", "fresh1.com"], ["still-live.com", "fresh1.com"], True),
                           threatfox=(["fresh-c2.net"], [], True))
        existing = {"manual-bad.com", "old-legacy.com", "still-live.com", "ancient-c2.net"}
        lines, stats, new = f.rotate_target('malware', path, fetched, existing, self.TODAY)
        text = "\n".join(lines)
        self.assertIn("||manual-bad.com^", text)            # curated: never touched
        self.assertIn("||still-live.com^", text)            # still listed upstream
        self.assertNotIn("old-legacy.com", text)            # legacy tag -> urlhaus, not listed
        self.assertNotIn("ancient-c2.net", text)            # > MAX_AGE_DAYS
        self.assertNotIn("from threatfox (2026-01-01)", text)  # empty header cleaned up
        self.assertEqual(stats['evicted_not_in_feed'], 1)
        self.assertEqual(stats['evicted_age'], 1)
        self.assertEqual(new, {'urlhaus': ['fresh1.com'], 'threatfox': ['fresh-c2.net']})
        self.assertIn("! --- Auto-fetched from urlhaus (2026-09-25) ---", text)

    def test_incomplete_feed_never_evicts(self):
        path = self._file(self.BASE)
        fetched = _fetched(urlhaus=([], [], False), threatfox=([], [], True))
        lines, stats, _ = f.rotate_target('malware', path, fetched, set(), self.TODAY)
        self.assertEqual(stats['evicted_not_in_feed'], 0)
        self.assertIn("||old-legacy.com^", "\n".join(lines))

    def test_failed_fetch_never_evicts(self):
        path = self._file(self.BASE)
        fetched = {'urlhaus': {'ok': False, 'sane': False, 'eligible': set(), 'live': set()}}
        lines, stats, new = f.rotate_target('malware', path, fetched, set(), self.TODAY)
        self.assertEqual(stats['evicted_not_in_feed'], 0)
        self.assertEqual(new, {})

    def test_fifo_makes_room_for_fresh_quota(self):
        auto = "\n".join(f"||old{i:03d}.com^   ! auto: urlhaus" for i in range(f.MAX_PER_FILE))
        path = self._file("! --- Auto-fetched from urlhaus (2026-09-01) ---\n" + auto + "\n")
        live = {f"old{i:03d}.com" for i in range(f.MAX_PER_FILE)}
        fresh = {f"fresh{i}.com" for i in range(300)}
        fetched = _fetched(urlhaus=(fresh | live, fresh | live, True), threatfox=([], [], True))
        lines, stats, new = f.rotate_target('malware', path, fetched, set(live), self.TODAY)
        self.assertEqual(stats['evicted_fifo'], f.FRESH_QUOTA)
        self.assertEqual(stats['total_after'], f.MAX_PER_FILE)
        self.assertEqual(len(new['urlhaus']), f.FRESH_QUOTA)

    def test_never_exceeds_file_cap(self):
        path = self._file("")
        fresh = {f"x{i}.com" for i in range(2000)}
        fetched = _fetched(urlhaus=(fresh, fresh, True), threatfox=({f"t{i}.net" for i in range(2000)}, [], True))
        _, stats, new = f.rotate_target('malware', path, fetched, set(), self.TODAY)
        self.assertLessEqual(stats['total_after'], f.MAX_PER_FILE)
        self.assertLessEqual(len(new['urlhaus']), f.MAX_PER_SOURCE)


class TestPick(unittest.TestCase):
    def test_deterministic_and_not_alphabetical(self):
        cands = {f"{c}{i}.com" for c in "0123456789abcdefghijklmnopqrstuvwxyz" for i in range(20)}
        a = f.pick(cands, 50, "2026-09-25")
        self.assertEqual(a, f.pick(cands, 50, "2026-09-25"))
        self.assertNotEqual(a, sorted(cands)[:50])
        self.assertGreater(len({d[0] for d in a}), 10)  # spread across the alphabet


class TestReport(unittest.TestCase):
    def test_stale_fetch_not_reported(self):
        self.assertIsNone(grr.collect_fetch_data({'fetched_at': '2026-07-01 08:25:40 UTC'}))
        today = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        data = grr.collect_fetch_data({'fetched_at': today, 'total_added': 5, 'total_removed': 3,
                                       'sources': {}})
        self.assertEqual(data['total_new_domains'], 5)
        self.assertEqual(data['total_retired_domains'], 3)

    def test_change_lines(self):
        self.assertEqual(grr._change_lines({'rule_delta': {'delta': 0}, 'fetch': None}),
                         ['- Rebuilt; no rule changes'])
        lines = grr._change_lines({'rule_delta': {'delta': -10},
                                   'fetch': {'total_new_domains': 250, 'total_retired_domains': 260}})
        self.assertEqual(lines, ['- Threat intelligence refreshed (+250 new, -260 retired)',
                                 '- Total rules: -10'])


if __name__ == '__main__':
    unittest.main()
