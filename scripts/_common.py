"""
_common.py — Shared helpers for the ShieldNova script layer.

Consolidates primitives that were previously duplicated across build.py,
fetch_threat_intel.py, audit_existing_rules.py, and test_false_positives.py:

  - LABEL_RE / IPV4_RE          (RFC 1123 label regex + IPv4 reject pattern)
  - RULE_RE                     (AdGuard-style ||domain^ matcher)
  - is_valid_domain(domain)     (canonical RFC 1123 validation)
  - parse_adguard_rule(line)    (extract domain from ||domain^ or None)

The script-layer files retain their own logic and wrappers; only the
foundational primitives live here. Pure-stdlib, no side effects on import.

Drift was a real risk: build.py and fetch_threat_intel.py had two
separately maintained copies of is_valid_domain that happened to agree
but could diverge silently — and the three RULE_RE patterns in
build.py, audit_existing_rules.py, and test_false_positives.py had
slightly different character classes for what they each tolerated in
"\\| | @ ! /" inside a domain.
"""
from __future__ import annotations

import re

# ShieldNova project version (SemVer). Single source of truth — README
# badge, GitHub release tags, and any future log banners read from here.
# Bump on every release.
__version__ = "2.1.0"


# ── Regex primitives ────────────────────────────────────────────────────────

# RFC 1123 label: 1-63 chars, must start and end with [a-z0-9], hyphens
# permitted only in the interior. Used for both build-time validation
# and fetch-time validation of newly-pulled threat intel.
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

# Bare IPv4 reject pattern — anything that parses as four dotted octets
# is not a domain, regardless of label validity.
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

# AdGuard-style ||domain^ rule matcher.
#
# Domain part rejects: '/' (URL path), '^' (rule terminator), '|' (alternation),
# '@' (exception marker), and whitespace. The trailing options group is
# optional and may carry '$third-party' etc. — captured separately so
# callers that only want the domain can use the first group directly.
#
# This consolidates three previously-divergent regex copies:
#   build.py:35              RULE_RE        — also captured the options group
#   audit_existing_rules.py:33 RULE_RE      — domain-only, no options
#   test_false_positives.py:29 _ADGUARD_RE  — domain-only, no options
# All three are now serviced by this single pattern.
RULE_RE = re.compile(r"^\|\|(?P<domain>[^/\^\|@\s]+)\^(?P<options>\$[^\s!]+)?$")


# ── Validation ──────────────────────────────────────────────────────────────

def is_valid_domain(domain: str) -> bool:
    """Validate ordinary and punycode DNS names; reject IPs and malformed labels.

    Rules:
      - 1..253 chars total
      - not an IPv4 literal
      - no empty labels ("..")
      - at least one dot (rejects single-label entries like "localhost")
      - every label matches LABEL_RE
      - TLD >= 2 chars
      - TLD is alphabetic, OR starts with the IDN prefix "xn--"

    Identical contract to the two former copies in build.py and
    fetch_threat_intel.py.
    """
    domain = domain.lower().strip(".")
    if not domain or len(domain) > 253:
        return False
    if IPV4_RE.match(domain):
        return False
    if ".." in domain or "." not in domain:
        return False
    labels = domain.split(".")
    if any(not LABEL_RE.match(label) for label in labels):
        return False
    tld = labels[-1]
    if len(tld) < 2:
        return False
    if tld.startswith("xn--"):
        return True
    return tld.isalpha()


# ── AdGuard rule parsing ────────────────────────────────────────────────────

def parse_adguard_rule(line: str) -> str | None:
    """Extract the lower-cased domain from an ||domain^[$options] rule.

    Returns None for any line that does not match RULE_RE or whose
    captured domain fails is_valid_domain. The line is stripped of an
    inline AdGuard comment (text after a free-standing '!') before
    matching, so rules like '||example.com^    ! comment' parse cleanly.

    Callers that need richer information (options, original raw line)
    should keep using their own logic — this helper is intentionally
    narrow and matches the most common use case across the project:
    "give me the blocked domain, if any."
    """
    # Strip an inline comment but preserve a line that *starts* with '!'
    # (those are pure comments, not annotated rules).
    content = line.strip()
    if not content or content.startswith(("!", "#")):
        return None
    if "!" in content:
        content = content.split("!", 1)[0].rstrip()
    m = RULE_RE.match(content)
    if not m:
        return None
    domain = m.group("domain").lower().strip(".")
    if not is_valid_domain(domain):
        return None
    return domain
