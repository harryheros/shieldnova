#!/usr/bin/env python3
"""
fetch_threat_intel.py — ShieldNova Threat Intelligence Fetcher

Pulls high-confidence malicious domains from public threat feeds,
deduplicates against existing rules, and appends verified entries
to the security source files.

Sources:
  - abuse.ch URLhaus (malware distribution domains)
  - abuse.ch ThreatFox (malware C2 IOCs)
  - NoCoin list (cryptojacking domains)
  - Phishing.Database (confirmed phishing domains)

Design principles:
  - Conservative: only high-confidence entries
  - Deduplicate against ALL existing src/ rules
  - Append-only: never removes existing rules
  - Capped per source per run to prevent bloat
  - Full audit trail in fetch_stats.json

Usage:
  python3 scripts/fetch_threat_intel.py [--dry-run]
"""

import csv
import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ── Config ──────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / 'src'
STATS_FILE = REPO_ROOT / 'dist' / 'fetch_stats.json'

MAX_PER_SOURCE = 50
MAX_PER_FILE = 500
DRY_RUN = '--dry-run' in sys.argv

LABEL_RE = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
HOSTS_PREFIX_RE = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+')

# ── Upstream Sources ────────────────────────────────────────────────────────

SOURCES = {
    'urlhaus': {
        'url': 'https://urlhaus.abuse.ch/downloads/text_online/',
        'target': 'malware',
        'description': 'abuse.ch URLhaus - active malware distribution URLs',
    },
    'threatfox': {
        'url': 'https://threatfox.abuse.ch/export/csv/recent/',
        'target': 'malware',
        'description': 'abuse.ch ThreatFox - recent malware IOCs',
    },
    'nocoin': {
        'url': 'https://raw.githubusercontent.com/nicehash/NoCoin/master/src/nocoin-list.txt',
        'target': 'cryptojacking',
        'description': 'NoCoin - browser mining domain list',
    },
    'phishing_database': {
        'url': 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt',
        'target': 'phishing',
        'description': 'Phishing.Database - confirmed active phishing domains',
    },
}

TARGET_FILES = {
    'malware': SRC_DIR / 'security' / 'malware.txt',
    'cryptojacking': SRC_DIR / 'security' / 'cryptojacking.txt',
    'phishing': SRC_DIR / 'security' / 'phishing.txt',
}


# ── Helpers ─────────────────────────────────────────────────────────────────

def log(msg: str):
    print(f'[fetch] {msg}')


def fetch_url(url: str, timeout: int = 30) -> str:
    """Fetch URL content as text. Returns empty string on failure."""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'ShieldNova/1.0'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode('utf-8', errors='replace')
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        log(f'  WARN: failed to fetch {url}: {e}')
        return ''


def is_valid_domain(domain: str) -> bool:
    domain = domain.lower().strip('.')
    if not domain or len(domain) > 253 or '..' in domain or '.' not in domain:
        return False

    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass

    labels = domain.split('.')
    if any(not LABEL_RE.match(label) for label in labels):
        return False

    tld = labels[-1]
    if len(tld) < 2:
        return False
    if tld.startswith('xn--'):
        return True
    return tld.isalpha()


def strip_rule_syntax(value: str) -> str:
    line = value.strip().lower()
    if not line:
        return ''

    # Drop inline comments before parsing rule-like text.
    for marker in (' #', ' ;'):
        if marker in line:
            line = line.split(marker, 1)[0].strip()
    if '!' in line and not line.startswith('!'):
        line = line.split('!', 1)[0].strip()

    # Hosts-file syntax: "0.0.0.0 example.com" or "127.0.0.1 example.com".
    line = HOSTS_PREFIX_RE.sub('', line).strip()
    if ' ' in line or '\t' in line:
        tokens = [token for token in re.split(r'\s+', line) if token]
        line = tokens[-1] if tokens else ''

    for prefix in ('@@||', '||'):
        if line.startswith(prefix):
            line = line[len(prefix):]

    if line.startswith('*.'):
        line = line[2:]

    # URL-aware parsing is safer than splitting blindly on ':', because ports
    # and schemes may both be present in upstream feeds.
    if '://' in line:
        parsed = urllib.parse.urlsplit(line)
        line = parsed.hostname or ''
    else:
        line = line.split('/')[0].split('^')[0].split('$')[0]
        if ':' in line:
            line = line.split(':', 1)[0]

    return line.strip().strip('.')


def extract_domain(url_or_line: str) -> str:
    """Extract a clean domain from a URL, hosts entry, or AdGuard-style rule."""
    line = url_or_line.strip()
    if not line or line.startswith(('#', '//', ';', '!')):
        return ''

    domain = strip_rule_syntax(line)
    if is_valid_domain(domain):
        return domain
    return ''


def load_existing_domains() -> set:
    """Load all domains from src/ rule files, including inline-commented rules."""
    existing = set()
    for txt_file in SRC_DIR.rglob('*.txt'):
        with open(txt_file, 'r', encoding='utf-8') as f:
            for line in f:
                domain = extract_domain(line)
                if domain:
                    existing.add(domain)
    return existing


def load_file_domain_count(filepath: Path) -> int:
    if not filepath.exists():
        return 0
    domains = set()
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            domain = extract_domain(line)
            if domain:
                domains.add(domain)
    return len(domains)


def append_domains(filepath: Path, domains: list, source_name: str):
    """Append new domains to a source file with attribution comment."""
    unique_domains = sorted(set(domains))
    if not unique_domains:
        return

    with open(filepath, 'a', encoding='utf-8') as f:
        f.write(f"\n! --- Auto-fetched from {source_name} ({datetime.now(timezone.utc).strftime('%Y-%m-%d')}) ---\n")
        for domain in unique_domains:
            rule = f'||{domain}^'
            f.write(f'{rule:<44}! auto: {source_name}\n')


# ── Source Parsers ──────────────────────────────────────────────────────────

def parse_urlhaus(content: str) -> set:
    domains = set()
    for line in content.splitlines():
        domain = extract_domain(line)
        if domain:
            domains.add(domain)
    return domains


def parse_threatfox(content: str) -> set:
    domains = set()
    for row in csv.reader(content.splitlines()):
        if not row or row[0].startswith('#'):
            continue
        # ThreatFox CSV has IOC value in column 3 in current exports; scan the
        # row defensively so the parser survives minor upstream schema changes.
        for cell in row[2:]:
            domain = extract_domain(cell)
            if domain:
                domains.add(domain)
                break
    return domains


def parse_nocoin(content: str) -> set:
    domains = set()
    for line in content.splitlines():
        domain = extract_domain(line)
        if domain:
            domains.add(domain)
    return domains


def parse_phishing_database(content: str) -> set:
    domains = set()
    for line in content.splitlines():
        domain = extract_domain(line)
        if domain:
            domains.add(domain)
    return domains


PARSERS = {
    'urlhaus': parse_urlhaus,
    'threatfox': parse_threatfox,
    'nocoin': parse_nocoin,
    'phishing_database': parse_phishing_database,
}


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    log('ShieldNova Threat Intelligence Fetch')
    log('=' * 50)

    if DRY_RUN:
        log('*** DRY-RUN MODE — no files will be modified ***')

    existing = load_existing_domains()
    log(f'Loaded {len(existing)} existing domains across all modules')

    stats = {
        'fetched_at': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
        'dry_run': DRY_RUN,
        'sources': {},
    }

    new_by_target: dict[str, list] = {target: [] for target in TARGET_FILES}

    for source_name, source_config in SOURCES.items():
        url = source_config['url']
        target = source_config['target']
        description = source_config['description']

        log(f'\nFetching: {description}')
        log(f'  URL: {url}')

        content = fetch_url(url)
        if not content:
            stats['sources'][source_name] = {'status': 'fetch_failed', 'new': 0}
            continue

        parser = PARSERS[source_name]
        raw_domains = parser(content)
        log(f'  Parsed: {len(raw_domains)} raw domains')

        new_domains = sorted(d for d in raw_domains if d not in existing)
        log(f'  New (after dedup): {len(new_domains)}')

        target_file = TARGET_FILES[target]
        current_count = load_file_domain_count(target_file)
        already_queued = len(set(new_by_target[target]))
        remaining_capacity = MAX_PER_FILE - current_count - already_queued

        if remaining_capacity <= 0:
            log(f'  SKIP: {target_file.name} already at cap ({current_count}/{MAX_PER_FILE})')
            stats['sources'][source_name] = {
                'status': 'file_cap_reached',
                'raw': len(raw_domains),
                'new': 0,
            }
            continue

        cap = min(MAX_PER_SOURCE, remaining_capacity)
        if len(new_domains) > cap:
            log(f'  Capped: {len(new_domains)} → {cap}')
            new_domains = new_domains[:cap]

        new_by_target[target].extend(new_domains)
        existing.update(new_domains)

        stats['sources'][source_name] = {
            'status': 'ok',
            'raw': len(raw_domains),
            'new': len(new_domains),
            'capped_at': cap,
        }
        log(f'  Will add: {len(new_domains)} to {target_file.name}')

    total_added = 0
    for target, domains in new_by_target.items():
        domains = sorted(set(domains))
        if not domains:
            continue
        target_file = TARGET_FILES[target]
        if DRY_RUN:
            log(f'\n[DRY-RUN] Would append {len(domains)} domains to {target_file.name}')
            for d in domains[:10]:
                log(f'  + {d}')
            if len(domains) > 10:
                log(f'  ... and {len(domains) - 10} more')
        else:
            append_domains(target_file, domains, target)
            log(f'\nAppended {len(domains)} domains to {target_file.name}')
        total_added += len(domains)

    stats['total_added'] = total_added

    if not DRY_RUN:
        os.makedirs(STATS_FILE.parent, exist_ok=True)
        with open(STATS_FILE, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2)
        log('\nStats written to dist/fetch_stats.json')

    log(f"\n{'=' * 50}")
    log(f'Total new domains added: {total_added}')
    log('Done.')

    return 0


if __name__ == '__main__':
    sys.exit(main())
