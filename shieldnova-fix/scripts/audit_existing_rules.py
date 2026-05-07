#!/usr/bin/env python3
"""
audit_existing_rules.py — ShieldNova Existing Rule Auditor

Scans src/security/ rule files for domains that may be hosting-platform
pollution from previous threat intel fetches.

Classification data is loaded from config/critical_domains.json.

Output categories:
  MUST-REMOVE   — known service that should never be blocked (immediate action)
  HOSTING       — subdomain of a hosting platform (human review required)
  MANUAL-REVIEW — suspicious characteristics warrant inspection
  SAFE          — no issues detected

Exit codes:
  0 — no MUST-REMOVE entries found (or --fix resolved them all)
  1 — MUST-REMOVE entries remain, or script execution error

Usage:
  python3 scripts/audit_existing_rules.py [--fix] [--output report.json]
"""

import json
import re
import sys
from pathlib import Path

ROOT    = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT / 'src' / 'security'
CONFIG  = ROOT / 'config' / 'critical_domains.json'

RULE_RE = re.compile(r'^\|\|([^/\^\|@\s]+)\^')

SUSPICIOUS_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'\d{6,}'),                   "long numeric string"),
    (re.compile(r'[a-f0-9]{8}-[a-f0-9]{4}'), "UUID-like"),
    (re.compile(r'[a-z0-9]{32,}\.'),          "hash-like subdomain"),
    (re.compile(r'\.(xyz|top|click|loan|win|bid|gq|cf|ml|ga|tk)$'),
                                               "high-abuse TLD"),
]


def load_config() -> dict:
    if not CONFIG.exists():
        print(f'[audit] ERROR: config not found at {CONFIG}')
        sys.exit(1)
    with open(CONFIG, encoding='utf-8') as f:
        return json.load(f)


def build_classifiers(cfg: dict):
    """Build classification sets from config."""
    must_never = set()

    # Tier 0 full
    for d, _ in cfg['tier0']['domains']:
        must_never.add(d)

    # Tier 0 core-only (apex only, not hosting subdomains)
    tier0_core_apexes = set()
    hosting_subs = set(cfg['tier0_core_only']['hosting_subdomains'])
    for d, _ in cfg['tier0_core_only']['domains']:
        tier0_core_apexes.add(d)

    # Tier 1
    for d, _ in cfg['tier1']['domains']:
        must_never.add(d)

    # Hosting surfaces (tier2 roots + known hosting subs)
    hosting_apexes = set()
    for d, _ in cfg['tier2_roots']['domains']:
        hosting_apexes.add(d)
    hosting_apexes.update(hosting_subs)

    # reviewed_hosting_domains: manually verified malicious hosting subdomains.
    # These are suppressed from HOSTING audit warnings — they are confirmed
    # malicious and safe to keep in security source files.
    reviewed_hosting = set(cfg.get('reviewed_hosting_domains', {}).get('domains', {}).keys())

    return must_never, tier0_core_apexes, hosting_subs, hosting_apexes, reviewed_hosting


def is_subdomain_of(domain: str, apex: str) -> bool:
    return domain == apex or domain.endswith('.' + apex)


def classify(domain: str, must_never: set, tier0_core_apexes: set,
             hosting_subs: set, hosting_apexes: set,
             reviewed_hosting: set | None = None) -> tuple[str, str]:
    d = domain.lower().strip('.')

    # Direct must-never match
    if d in must_never:
        return "MUST-REMOVE", "known service — must never be blocked"

    # Subdomain of must-never
    parts = d.split('.')
    for i in range(1, len(parts)):
        parent = '.'.join(parts[i:])
        if parent in must_never:
            return "MUST-REMOVE", f"subdomain of known service ({parent})"

    # Tier 0 core-only: apex is protected, but hosting subdomains are allowed
    for apex in tier0_core_apexes:
        if is_subdomain_of(d, apex):
            if d in hosting_subs or any(is_subdomain_of(d, hs) for hs in hosting_subs):
                return "HOSTING", f"hosting surface of {apex} — review if legitimately malicious"
            return "MUST-REMOVE", f"core API subdomain of {apex} — not a hosting surface"

    # Hosting platform — skip if manually reviewed and confirmed malicious
    if reviewed_hosting and d in reviewed_hosting:
        return "SAFE", "reviewed hosting domain — manually confirmed malicious"
    if d in hosting_apexes:
        return "HOSTING", "hosting platform apex — root domain should not be blocked"
    for apex in hosting_apexes:
        if is_subdomain_of(d, apex):
            if reviewed_hosting and d in reviewed_hosting:
                return "SAFE", "reviewed hosting domain — manually confirmed malicious"
            return "HOSTING", (
                f"subdomain of hosting platform ({apex}) — "
                "may be legitimate phishing domain or feed pollution; verify manually"
            )

    # Suspicious patterns
    for pattern, reason in SUSPICIOUS_PATTERNS:
        if pattern.search(d):
            return "MANUAL-REVIEW", f"suspicious pattern: {reason}"

    return "SAFE", "no issues detected"


def audit_file(filepath: Path, must_never, tier0_core_apexes,
               hosting_subs, hosting_apexes,
               reviewed_hosting: set | None = None) -> list[dict]:
    findings = []
    with open(filepath, encoding='utf-8') as f:
        for lineno, line in enumerate(f, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith('!') or stripped.startswith('#'):
                continue
            m = RULE_RE.match(stripped)
            if not m:
                continue
            domain = m.group(1).lower().strip('.')
            category, reason = classify(
                domain, must_never, tier0_core_apexes, hosting_subs, hosting_apexes,
                reviewed_hosting=reviewed_hosting,
            )
            if category != 'SAFE':
                findings.append({
                    'file':     str(filepath.relative_to(ROOT)),
                    'line':     lineno,
                    'domain':   domain,
                    'rule':     stripped.split('!')[0].strip(),
                    'category': category,
                    'reason':   reason,
                })
    return findings


def apply_fix(must_remove_findings: list[dict]) -> int:
    """
    Remove MUST-REMOVE lines from source files.
    Returns number of lines removed, raises on any file error.
    """
    files_to_fix: dict[str, set[int]] = {}
    for f in must_remove_findings:
        files_to_fix.setdefault(f['file'], set()).add(f['line'])

    total_removed = 0
    for rel_path, lines_to_remove in files_to_fix.items():
        abs_path = ROOT / rel_path
        with open(abs_path, encoding='utf-8') as fh:
            all_lines = fh.readlines()
        new_lines = [
            line for i, line in enumerate(all_lines, 1)
            if i not in lines_to_remove
        ]
        with open(abs_path, 'w', encoding='utf-8') as fh:
            fh.writelines(new_lines)
        removed = len(lines_to_remove)
        total_removed += removed
        print(f'[audit] Fixed: {rel_path} ({removed} line(s) removed)')

    return total_removed


def main() -> int:
    fix_mode   = '--fix' in sys.argv
    output_arg = None
    args = sys.argv[1:]
    for i, arg in enumerate(args):
        if arg == '--output' and i + 1 < len(args):
            output_arg = args[i + 1]

    print('[audit] ShieldNova Existing Rule Auditor')
    print('[audit] ' + '=' * 50)

    cfg = load_config()
    must_never, tier0_core_apexes, hosting_subs, hosting_apexes, reviewed_hosting = build_classifiers(cfg)

    if not SRC_DIR.exists():
        print(f'[audit] ERROR: src/security/ not found at {SRC_DIR}')
        return 1

    all_findings: list[dict] = []
    for txt_file in sorted(SRC_DIR.glob('*.txt')):
        findings = audit_file(
            txt_file, must_never, tier0_core_apexes, hosting_subs, hosting_apexes,
            reviewed_hosting=reviewed_hosting,
        )
        all_findings.extend(findings)

    by_category: dict[str, list[dict]] = {}
    for f in all_findings:
        by_category.setdefault(f['category'], []).append(f)

    must_remove   = by_category.get('MUST-REMOVE', [])
    hosting       = by_category.get('HOSTING', [])
    manual_review = by_category.get('MANUAL-REVIEW', [])

    print(f'[audit] Scanned: {len(list(SRC_DIR.glob("*.txt")))} files')
    print(f'[audit] Findings: {len(all_findings)} total')
    print(f'[audit]   MUST-REMOVE:   {len(must_remove)}')
    print(f'[audit]   HOSTING:       {len(hosting)}')
    print(f'[audit]   MANUAL-REVIEW: {len(manual_review)}')
    print()

    if must_remove:
        print('[audit] ── MUST-REMOVE ──────────────────────────────────────────')
        for f in must_remove:
            print(f'  {f["file"]}:{f["line"]}  {f["domain"]}  — {f["reason"]}')
        print()

    if hosting:
        print('[audit] ── HOSTING (human review) ──────────────────────────────')
        for f in hosting[:20]:
            print(f'  {f["file"]}:{f["line"]}  {f["domain"]}  — {f["reason"]}')
        if len(hosting) > 20:
            print(f'  ... and {len(hosting) - 20} more (see --output for full list)')
        print()

    if manual_review:
        print('[audit] ── MANUAL-REVIEW ────────────────────────────────────────')
        for f in manual_review[:10]:
            print(f'  {f["file"]}:{f["line"]}  {f["domain"]}  — {f["reason"]}')
        if len(manual_review) > 10:
            print(f'  ... and {len(manual_review) - 10} more (see --output for full list)')
        print()

    # --fix: auto-remove MUST-REMOVE entries (raises on error, no || true)
    if fix_mode and must_remove:
        print('[audit] ── AUTO-FIX ─────────────────────────────────────────────')
        removed = apply_fix(must_remove)
        print(f'[audit] Removed {removed} line(s) total')
        must_remove = []  # cleared after fix
        print()

    # Write JSON report
    if output_arg:
        report = {
            'scanned_files': len(list(SRC_DIR.glob('*.txt'))),
            'total_findings': len(all_findings),
            'summary': {
                'must_remove':   len(by_category.get('MUST-REMOVE', [])),
                'hosting':       len(hosting),
                'manual_review': len(manual_review),
            },
            'by_category': {
                'MUST-REMOVE':   by_category.get('MUST-REMOVE', []),
                'HOSTING':       by_category.get('HOSTING', []),
                'MANUAL-REVIEW': by_category.get('MANUAL-REVIEW', []),
            },
            'findings': all_findings,
        }
        out_path = Path(output_arg)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, 'w', encoding='utf-8') as fh:
            json.dump(report, fh, indent=2)
        print(f'[audit] Report written to {output_arg}')

    if must_remove:
        print('[audit] FAIL — MUST-REMOVE entries remain. Run with --fix to auto-remove.')
        return 1

    print('[audit] PASS — no MUST-REMOVE entries found')
    if hosting or manual_review:
        print('[audit] INFO — HOSTING/MANUAL-REVIEW entries found; human review recommended')
    return 0


if __name__ == '__main__':
    sys.exit(main())
