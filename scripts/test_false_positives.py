#!/usr/bin/env python3
"""
test_false_positives.py — ShieldNova False Positive Gate

Scans all generated dist/ and formats/ rule files to verify that no
critical service domain appears in any block list.

Classification data is loaded from config/critical_domains.json —
the single source of truth shared with fetch_threat_intel.py and
audit_existing_rules.py.

Exit codes:
  0 — all checks passed
  1 — one or more Tier 0 / Tier 1 / Tier 2 root violations found
"""

import json
import re
import sys
from pathlib import Path

ROOT     = Path(__file__).resolve().parent.parent
DIST_DIR = ROOT / 'dist'
CONFIG   = ROOT / 'config' / 'critical_domains.json'

# Shared AdGuard rule matcher — see scripts/_common.py
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import RULE_RE as _ADGUARD_RE  # noqa: E402


def extract_domain_from_line(line: str) -> str | None:
    """
    Extract a blocked domain from a rule line in any supported format:
      - AdGuard:      ||example.com^
      - Clash YAML:   - DOMAIN-SUFFIX,example.com  or  - DOMAIN,example.com
      - Surge/SR/Loon: DOMAIN-SUFFIX,example.com,REJECT
      - QuantumultX:  HOST-SUFFIX,example.com,reject  or  HOST,example.com,reject
    Returns None if the line is a comment, header, or unrecognised format.
    """
    line = line.strip()
    if not line or line.startswith(('#', '!', 'payload:')):
        return None

    # AdGuard
    m = _ADGUARD_RE.match(line)
    if m:
        return m.group(1).lower().strip('.')

    # Clash YAML (indented)
    if line.startswith('- DOMAIN-SUFFIX,') or line.startswith('- DOMAIN,'):
        parts = line.split(',', 1)
        return parts[1].strip().lower().strip('.') if len(parts) == 2 else None

    # Surge / Shadowrocket / Loon
    if line.startswith('DOMAIN-SUFFIX,') or line.startswith('DOMAIN,'):
        parts = line.split(',')
        return parts[1].strip().lower().strip('.') if len(parts) >= 2 else None

    # QuantumultX
    if line.startswith('HOST-SUFFIX,') or line.startswith('HOST,'):
        parts = line.split(',')
        return parts[1].strip().lower().strip('.') if len(parts) >= 2 else None

    return None


# ── Config loader ─────────────────────────────────────────────────────────────

def load_config() -> dict:
    if not CONFIG.exists():
        print(f'[fp-test] ERROR: config not found at {CONFIG}')
        sys.exit(1)
    with open(CONFIG, encoding='utf-8') as f:
        return json.load(f)


# ── File scanner ──────────────────────────────────────────────────────────────

def load_blocked_domains(dist_dir: Path) -> dict[str, set[str]]:
    """
    Load all blocked domains from dist/*.txt and formats/**/*.txt.
    Supports all six output formats.

    Files containing 'aggressive' in their name are tagged with the
    'aggressive' key prefix so run_checks can apply relaxed Tier-1 rules.
    """
    result: dict[str, set[str]] = {}
    formats_dir = dist_dir.parent / 'formats'

    files: list[Path] = list(sorted(dist_dir.glob('shieldnova-*.txt')))
    if formats_dir.exists():
        for fmt_dir in sorted(formats_dir.iterdir()):
            if fmt_dir.is_dir():
                files.extend(sorted(fmt_dir.glob('shieldnova-*.txt')))

    for f in files:
        domains: set[str] = set()
        with open(f, encoding='utf-8') as fh:
            for line in fh:
                domain = extract_domain_from_line(line)
                if domain:
                    domains.add(domain)
        try:
            rel = str(f.relative_to(dist_dir.parent))
        except ValueError:
            rel = f.name
        result[rel] = domains

    return result


def is_aggressive_file(filename: str) -> bool:
    """Return True if the file belongs to the aggressive opt-in profile."""
    return 'aggressive' in Path(filename).stem


# ── Check logic ───────────────────────────────────────────────────────────────

def is_subdomain_of(domain: str, apex: str) -> bool:
    return domain == apex or domain.endswith('.' + apex)


def run_checks(blocked: dict[str, set[str]], cfg: dict) -> int:
    tier0         = [(d, desc) for d, desc in cfg['tier0']['domains']]
    tier0_core    = [(d, desc) for d, desc in cfg['tier0_core_only']['domains']]
    hosting_subs  = set(cfg['tier0_core_only']['hosting_subdomains'])
    tier1         = [(d, desc) for d, desc in cfg['tier1']['domains']]
    tier2_roots   = [(d, desc) for d, desc in cfg['tier2_roots']['domains']]
    tracking_exc  = set(cfg['tracking_exceptions']['domains'])

    violations = 0

    for filename, domains in blocked.items():
        file_violations: list[str] = []

        # ── Tier 0 (full subdomain check) ─────────────────────────────────
        for apex, description in tier0:
            for hit in [d for d in domains if is_subdomain_of(d, apex)]:
                if hit in tracking_exc:
                    continue
                file_violations.append(
                    f'  [TIER-0] {hit!r} ({description}) in {filename}'
                )
                violations += 1

        # ── Tier 0 core-only (apex + non-hosting subdomains only) ─────────
        for apex, description in tier0_core:
            for hit in [d for d in domains if is_subdomain_of(d, apex)]:
                if hit in tracking_exc:
                    continue
                # Allow known hosting surfaces (S3 buckets, firebase storage, etc.)
                if hit in hosting_subs or any(
                    is_subdomain_of(hit, hs) for hs in hosting_subs
                ):
                    continue
                file_violations.append(
                    f'  [TIER-0-CORE] {hit!r} ({description} — core API, not hosting surface) in {filename}'
                )
                violations += 1

        # ── Tier 1 ────────────────────────────────────────────────────────
        # Aggressive profile intentionally blocks some Tier-1 subdomains
        # (e.g. graph.facebook.com, platform.linkedin.com) that serve dual
        # tracking + legitimate purposes. Skip Tier-1 checks for aggressive
        # files — the WARNING in aggressive.txt documents this trade-off.
        if not is_aggressive_file(filename):
            for apex, description in tier1:
                for hit in [d for d in domains if is_subdomain_of(d, apex)]:
                    if hit in tracking_exc:
                        continue
                    file_violations.append(
                        f'  [TIER-1] {hit!r} ({description}) in {filename}'
                    )
                    violations += 1

        # ── Tier 2 (root-domain only) ─────────────────────────────────────
        for root, description in tier2_roots:
            for hit in [d for d in domains if d == root or d == f'www.{root}']:
                file_violations.append(
                    f'  [TIER-2 ROOT] {hit!r} ({description} root domain blocked) in {filename}'
                )
                violations += 1

        for msg in file_violations:
            print(msg)

    return violations


def main() -> int:
    print('[fp-test] ShieldNova False Positive Gate')
    print('[fp-test] ' + '=' * 50)

    cfg = load_config()

    if not DIST_DIR.exists():
        print(f'[fp-test] ERROR: dist/ not found at {DIST_DIR}')
        return 1

    blocked       = load_blocked_domains(DIST_DIR)
    total_files   = len(blocked)
    total_domains = sum(len(v) for v in blocked.values())
    print(f'[fp-test] Loaded {total_files} files, {total_domains} total rule entries')
    print()

    violations = run_checks(blocked, cfg)

    print()
    if violations == 0:
        print('[fp-test] PASS — no false positive violations detected')
        return 0
    else:
        print(f'[fp-test] FAIL — {violations} violation(s) detected')
        print('[fp-test] Build blocked. Fix rules before publishing.')
        return 1


if __name__ == '__main__':
    sys.exit(main())
