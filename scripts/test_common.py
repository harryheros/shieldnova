#!/usr/bin/env python3
"""
test_common.py — Unit tests for scripts/_common.py

Pins the contract of the shared primitives so future refactors of
build.py, fetch_threat_intel.py, audit_existing_rules.py, or
test_false_positives.py cannot silently break domain validation,
rule parsing, or hosting-platform classification.

Run:
  python3 scripts/test_common.py
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import (  # noqa: E402
    IPV4_RE,
    LABEL_RE,
    RULE_RE,
    is_valid_domain,
    parse_adguard_rule,
)


class TestIsValidDomain(unittest.TestCase):
    """is_valid_domain — the canonical domain-shape check used by both
    build.py (parsing curated src files) and fetch_threat_intel.py
    (validating incoming threat feed entries)."""

    def test_simple_two_label(self):
        self.assertTrue(is_valid_domain("example.com"))

    def test_multi_label(self):
        self.assertTrue(is_valid_domain("sub.domain.example.com"))

    def test_idn_punycode(self):
        # xn-- prefix bypasses TLD alpha-only check
        self.assertTrue(is_valid_domain("test.xn--fiqs8s"))

    def test_label_with_hyphen(self):
        self.assertTrue(is_valid_domain("a-b.c-d.example"))

    def test_trailing_dot_stripped(self):
        self.assertTrue(is_valid_domain("example.com."))

    def test_uppercase_lowercased(self):
        self.assertTrue(is_valid_domain("Example.COM"))

    def test_empty_rejected(self):
        self.assertFalse(is_valid_domain(""))

    def test_too_long_rejected(self):
        self.assertFalse(is_valid_domain("a" * 252 + ".com"))

    def test_ipv4_rejected(self):
        self.assertFalse(is_valid_domain("1.2.3.4"))
        self.assertFalse(is_valid_domain("127.0.0.1"))

    def test_ipv4_like_5_octets_rejected(self):
        # 5 octets — not a valid IPv4 but '5' is also not a valid TLD
        self.assertFalse(is_valid_domain("1.2.3.4.5"))

    def test_single_label_rejected(self):
        self.assertFalse(is_valid_domain("localhost"))

    def test_double_dot_rejected(self):
        self.assertFalse(is_valid_domain("foo..bar"))

    def test_leading_hyphen_rejected(self):
        self.assertFalse(is_valid_domain("-foo.com"))

    def test_trailing_hyphen_rejected(self):
        self.assertFalse(is_valid_domain("foo-.com"))

    def test_tld_too_short_rejected(self):
        self.assertFalse(is_valid_domain("foo.a"))

    def test_numeric_tld_rejected(self):
        # Numeric-only TLD isn't a real public TLD and would only show up
        # as noise from a broken feed.
        self.assertFalse(is_valid_domain("foo.123"))

    def test_underscore_rejected(self):
        # RFC 1123 forbids underscore in hostnames.
        self.assertFalse(is_valid_domain("under_score.com"))


class TestRegexShapes(unittest.TestCase):
    """Lightweight sanity for the exposed regex objects themselves."""

    def test_label_re_accepts_basic(self):
        self.assertIsNotNone(LABEL_RE.match("a"))
        self.assertIsNotNone(LABEL_RE.match("foo-bar"))
        self.assertIsNotNone(LABEL_RE.match("0abc1"))

    def test_label_re_rejects_edges(self):
        self.assertIsNone(LABEL_RE.match(""))
        self.assertIsNone(LABEL_RE.match("-foo"))
        self.assertIsNone(LABEL_RE.match("foo-"))

    def test_ipv4_re_accepts_dotted_quad(self):
        self.assertIsNotNone(IPV4_RE.match("1.2.3.4"))
        self.assertIsNotNone(IPV4_RE.match("255.255.255.255"))

    def test_ipv4_re_rejects_non_quad(self):
        self.assertIsNone(IPV4_RE.match("1.2.3"))
        self.assertIsNone(IPV4_RE.match("1.2.3.4.5"))
        self.assertIsNone(IPV4_RE.match("foo.bar.baz.qux"))

    def test_rule_re_basic(self):
        m = RULE_RE.match("||example.com^")
        self.assertIsNotNone(m)
        self.assertEqual(m.group("domain"), "example.com")
        self.assertEqual(m.group("options") or "", "")

    def test_rule_re_with_options(self):
        m = RULE_RE.match("||example.com^$third-party")
        self.assertIsNotNone(m)
        self.assertEqual(m.group("domain"), "example.com")
        self.assertEqual(m.group("options"), "$third-party")

    def test_rule_re_rejects_url_path(self):
        # Domain part must reject '/'.
        self.assertIsNone(RULE_RE.match("||example.com/path^"))

    def test_rule_re_rejects_pipe_in_domain(self):
        # Domain part must reject '|' (alternation marker).
        self.assertIsNone(RULE_RE.match("||a|b^"))

    def test_rule_re_rejects_at_in_domain(self):
        # Domain part must reject '@' (exception marker).
        self.assertIsNone(RULE_RE.match("||a@b^"))


class TestParseAdguardRule(unittest.TestCase):
    """parse_adguard_rule is the convenience helper that wraps RULE_RE +
    is_valid_domain + inline-comment stripping. It's what audit_existing_rules
    and most casual extractors should use."""

    def test_basic(self):
        self.assertEqual(parse_adguard_rule("||example.com^"), "example.com")

    def test_with_options(self):
        self.assertEqual(parse_adguard_rule("||example.com^$third-party"), "example.com")

    def test_with_inline_comment(self):
        # The most common src/ formatting style: rule + spaces + ! comment.
        self.assertEqual(
            parse_adguard_rule("||aeros02.tk^                  ! auto: cryptojacking"),
            "aeros02.tk",
        )

    def test_pure_comment_returns_none(self):
        self.assertIsNone(parse_adguard_rule("! this is a comment"))
        self.assertIsNone(parse_adguard_rule("# alt comment style"))

    def test_blank_returns_none(self):
        self.assertIsNone(parse_adguard_rule(""))
        self.assertIsNone(parse_adguard_rule("   "))

    def test_invalid_domain_returns_none(self):
        # Rule shape OK, but the captured domain fails is_valid_domain.
        self.assertIsNone(parse_adguard_rule("||1.2.3.4^"))     # IPv4
        self.assertIsNone(parse_adguard_rule("||foo^"))         # single label
        self.assertIsNone(parse_adguard_rule("||foo.123^"))     # numeric TLD

    def test_uppercase_domain_lowercased(self):
        self.assertEqual(parse_adguard_rule("||Example.COM^"), "example.com")

    def test_leading_whitespace_stripped(self):
        self.assertEqual(parse_adguard_rule("   ||example.com^"), "example.com")

    def test_malformed_returns_none(self):
        # Not a rule line at all.
        self.assertIsNone(parse_adguard_rule("just some text"))
        self.assertIsNone(parse_adguard_rule("||example.com"))   # missing ^
        self.assertIsNone(parse_adguard_rule("|example.com^"))   # single pipe


# Hosting platform helpers live in fetch_threat_intel.py, not _common.py,
# but they exercise _common.is_valid_domain and the shared module state.
# Test them here too so the entire shared primitive surface has coverage.
class TestHostingPlatformHelpers(unittest.TestCase):
    """_matched_hosting_apex + _record_skip in fetch_threat_intel.py

    These were extracted from four nearly-identical inline blocks across
    the parse_* functions. The classification order matters: parent
    matches win over self-match for bookkeeping purposes (so the per-apex
    tally aggregates correctly when intermediate subdomains are also
    listed for direct rejection).
    """

    def setUp(self):
        # We test against a frozen test set so changes to the real
        # HOSTING_PLATFORM_APEXES don't break the unit tests.
        import fetch_threat_intel as fti
        self.fti = fti
        self._orig = fti._HOSTING_APEXES_MERGED
        fti._HOSTING_APEXES_MERGED = frozenset({
            "github.com",
            "githubusercontent.com",
            "raw.githubusercontent.com",
            "github.io",
            "workers.dev",
            "pages.dev",
        })

    def tearDown(self):
        self.fti._HOSTING_APEXES_MERGED = self._orig

    def test_apex_self_match(self):
        self.assertEqual(self.fti._matched_hosting_apex("github.com"), "github.com")
        self.assertEqual(self.fti._matched_hosting_apex("workers.dev"), "workers.dev")

    def test_self_wins_over_parent(self):
        # raw.githubusercontent.com is in the set AND has a parent
        # (githubusercontent.com) also in the set. Self-match takes
        # priority — this preserves separate accounting for the
        # specific subdomain entry. See _matched_hosting_apex docstring.
        self.assertEqual(
            self.fti._matched_hosting_apex("raw.githubusercontent.com"),
            "raw.githubusercontent.com",
        )

    def test_subdomain_finds_parent(self):
        self.assertEqual(self.fti._matched_hosting_apex("api.github.io"), "github.io")
        self.assertEqual(
            self.fti._matched_hosting_apex("malicious.user.workers.dev"),
            "workers.dev",
        )

    def test_unknown_when_no_match(self):
        self.assertEqual(
            self.fti._matched_hosting_apex("not-hosted.example.com"),
            "unknown",
        )

    def test_record_skip_increments(self):
        skipped: dict = {}
        self.fti._record_skip(skipped, "user1.github.io")
        self.fti._record_skip(skipped, "user2.github.io")
        self.fti._record_skip(skipped, "deploy.workers.dev")
        self.assertEqual(skipped, {"github.io": 2, "workers.dev": 1})


if __name__ == "__main__":
    unittest.main(verbosity=2)
