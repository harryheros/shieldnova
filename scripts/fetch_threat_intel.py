#!/usr/bin/env python3
"""
fetch_threat_intel.py — ShieldNova Threat Intelligence Fetcher

Pulls high-confidence malicious domains from public threat feeds,
deduplicates against existing rules, and appends verified entries
to the security source files.

Sources:
  - abuse.ch URLhaus (malware distribution domains)
  - abuse.ch ThreatFox (malware C2 IOCs)
  - adblock-nocoin-list (cryptojacking domains)
  - Phishing.Database (confirmed phishing domains)

Design principles:
  - Source-aware extraction: URLhaus/ThreatFox record malicious URLs,
    not malicious domains. Attackers abuse legitimate platforms (GitHub,
    Google Drive, OneDrive, Firebase, etc.) to host payloads. We extract
    the domain but skip any domain that belongs to a known hosting platform,
    CDN, or major service provider. This is not a whitelist patch — it is
    correct threat modelling: a malicious URL on GitHub does not make
    GitHub a malicious domain.
  - Conservative: only high-confidence entries
  - Trusted-platform-aware: hosting providers are classified and skipped
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

# Shared primitives (LABEL_RE, IPV4_RE, is_valid_domain).
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (  # noqa: E402
    IPV4_RE,
    LABEL_RE,
    is_valid_domain,
)

# ── Config ──────────────────────────────────────────────────────────────────

REPO_ROOT  = Path(__file__).resolve().parent.parent
SRC_DIR    = REPO_ROOT / 'src'
STATS_FILE = REPO_ROOT / 'dist' / 'fetch_stats.json'
CONFIG     = REPO_ROOT / 'config' / 'critical_domains.json'

MAX_PER_SOURCE = 50
MAX_PER_FILE   = 500
DRY_RUN = '--dry-run' in sys.argv

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
        'url': 'https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/nocoin.txt',
        'target': 'cryptojacking',
        'description': 'adblock-nocoin-list - actively maintained cryptojacking domain list',
    },
    'phishing_database': {
        'url': 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt',
        'target': 'phishing',
        'description': 'Phishing.Database - confirmed active phishing domains',
    },
}

TARGET_FILES = {
    'malware':       SRC_DIR / 'security' / 'malware.txt',
    'cryptojacking': SRC_DIR / 'security' / 'cryptojacking.txt',
    'phishing':      SRC_DIR / 'security' / 'phishing.txt',
}

# ── Platform Hosting Classification ─────────────────────────────────────────
#
# URLhaus and ThreatFox record malicious *URLs*, not malicious *domains*.
# Attackers routinely abuse legitimate hosting platforms to distribute
# malware or exfiltrate data. Extracting only the domain and blocking it
# would cause severe collateral damage to innocent users.
#
# The correct response is to classify the domain as belonging to a
# "hosting provider" and skip the record entirely. The threat is the
# specific URL/path/payload — not the platform.
#
# This classification covers:
#   - Source code / file hosting (GitHub, GitLab, Bitbucket, Pastebin)
#   - Cloud storage (Google Drive, OneDrive, Dropbox, Box)
#   - User-generated content platforms (WordPress.com, Blogger, Weebly, Wix)
#   - Serverless / PaaS platforms (Firebase, Vercel, Cloudflare Pages, Netlify)
#   - CDN edge networks (Cloudflare, Fastly, Akamai, jsDelivr)
#   - Major cloud providers (AWS, Azure, GCP)
#   - Communication / collaboration platforms (Telegram, Discord, Slack)
#   - Payment processors (Stripe, PayPal)
#   - Identity / auth providers (Okta, Auth0, Microsoft identity)
#   - OS / device update infrastructure (Apple, Microsoft, Google updates)
#
# This is NOT a "never block" list for end users — ShieldNova's privacy
# and ads modules may legitimately block subdomains of some of these
# for tracking purposes. This classification applies ONLY to the threat
# intelligence fetch pipeline.

# Apex domains whose subdomains are hosting surfaces for attacker-controlled
# content. Any domain that is a subdomain of one of these should be skipped
# during threat intel extraction.
HOSTING_PLATFORM_APEXES: frozenset[str] = frozenset({
    # ── Code / file hosting ──
    "github.com",
    "githubusercontent.com",
    "githubassets.com",
    "gitlab.com",
    "gitlab.io",            # GitLab Pages
    "bitbucket.org",
    "bitbucket.io",
    "sourceforge.net",
    "pastebin.com",
    "paste.ee",
    "hastebin.com",
    "gist.github.com",      # redundant but explicit

    # ── Cloud storage / file sharing ──
    "drive.google.com",
    "docs.google.com",
    "onedrive.live.com",
    "1drv.ms",
    "sharepoint.com",
    "dropbox.com",
    "dl.dropboxusercontent.com",
    "box.com",
    "app.box.com",
    "mediafire.com",
    "mega.nz",
    "mega.co.nz",
    "4shared.com",
    "sendspace.com",
    "zippyshare.com",
    "anonfiles.com",
    "gofile.io",

    # ── User-generated content / website builders ──
    "wordpress.com",
    "wp.com",
    "blogspot.com",
    "blogger.com",
    "tumblr.com",
    "weebly.com",
    "wix.com",
    "wixsite.com",
    "squarespace.com",
    "webflow.io",
    "cargo.site",
    "sites.google.com",
    "notion.site",
    "notion.so",

    # ── Serverless / PaaS / edge compute ──
    "pages.dev",            # Cloudflare Pages
    "workers.dev",          # Cloudflare Workers
    "web.app",              # Firebase Hosting
    "firebaseapp.com",
    "firebasestorage.googleapis.com",
    "vercel.app",
    "now.sh",
    "netlify.app",
    "netlify.com",
    "render.com",
    "onrender.com",
    "fly.dev",
    "railway.app",
    "heroku.com",
    "herokuapp.com",
    "appspot.com",          # Google App Engine
    "azurewebsites.net",    # Azure App Service
    "azurefd.net",          # Azure Front Door
    "cloudapp.net",         # Azure
    "cloudapp.azure.com",
    "blob.core.windows.net",
    "s3.amazonaws.com",
    "s3-website.amazonaws.com",
    "execute-api.amazonaws.com",
    "lambda-url.amazonaws.com",
    "storage.googleapis.com",
    "run.app",              # Google Cloud Run

    # ── CDN / edge delivery ──
    "cloudflare.com",
    "cloudflaressl.com",
    "cdn.cloudflare.net",
    "fastly.net",
    "fastly.com",
    "akamai.net",
    "akamaized.net",
    "edgekey.net",
    "akamaihd.net",
    "edgesuite.net",
    "llnwd.net",
    "jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
    "statically.io",

    # ── Major cloud infrastructure ──
    "amazonaws.com",
    "awsstatic.com",
    "aws.amazon.com",
    "azure.com",
    "azureedge.net",
    "microsoftonline.com",
    "live.com",
    "outlook.com",
    "office.com",
    "office365.com",
    "windows.com",
    "windowsupdate.com",
    "googleapis.com",
    "googleusercontent.com",
    "gstatic.com",
    "google.com",

    # ── Communication / collaboration (attackers use for C2 / exfil) ──
    "telegram.org",
    "t.me",
    "discord.com",
    "discordapp.com",
    "discord.gg",
    "slack.com",
    "slack-edge.com",
    "slackb.com",
    "teams.microsoft.com",
    "zoom.us",
    "zoomgov.com",

    # ── Social / content platforms ──
    "twitter.com",
    "twimg.com",
    "x.com",
    "t.co",
    "facebook.com",
    "fbcdn.net",
    "instagram.com",
    "cdninstagram.com",
    "reddit.com",
    "redd.it",
    "redditmedia.com",
    "reddit.com",
    "redd.it",
    "linkedin.com",
    "licdn.com",
    "tiktok.com",
    "tiktokcdn.com",
    "tiktokv.com",
    "youtube.com",
    "youtu.be",
    "ytimg.com",
    "googlevideo.com",

    # ── Apple / iOS ecosystem ──
    "apple.com",
    "icloud.com",
    "icloud-content.com",
    "aaplimg.com",
    "mzstatic.com",
    "itunes.apple.com",
    "apple-cloudkit.com",
    "me.com",

    # ── Payment / fintech ──
    "paypal.com",
    "paypalobjects.com",
    "stripe.com",
    "stripe.network",
    "squareup.com",
    "squareupsandbox.com",

    # ── Identity / auth ──
    "okta.com",
    "okta-emea.com",
    "auth0.com",
    "login.microsoftonline.com",
    "accounts.google.com",
    "signin.aws.amazon.com",

    # ── Developer tools / CI ──
    "github.io",            # GitHub Pages
    "raw.githubusercontent.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "media.githubusercontent.com",
    "avatars.githubusercontent.com",
    "npmjs.com",
    "pypi.org",
    "pypi.io",
    "registry.npmjs.org",
    "docker.com",
    "hub.docker.com",
    "ghcr.io",
    "replit.com",
    "glitch.me",
    "codepen.io",
    "codesandbox.io",
    "jsfiddle.net",
    "plnkr.co",

    # ── URL shorteners / redirect services (high abuse rate) ──
    "bit.ly",
    "bitly.com",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
    "buff.ly",
    "dlvr.it",
    "is.gd",
    "v.gd",
    "rb.gy",
    "cutt.ly",
    "short.io",
    "rebrand.ly",
    "linktr.ee",
    "lnkd.in",
})


def _load_hosting_apexes() -> frozenset[str]:
    """
    Load hosting platform classification.

    Two-tier defence:
      1. HOSTING_PLATFORM_APEXES (this file) is the curated baseline.
         It cannot be accidentally truncated by editing JSON, and ships
         with every release so a misconfigured environment still has
         platform-abuse protection.
      2. config/critical_domains.json supplements the baseline at runtime
         with entries from tier2_roots and tier0_core_only. Operators can
         expand coverage without touching code.

    The two sets are unioned. If the config file is missing or malformed,
    a warning is emitted and only the baseline is used — the pipeline
    never runs without platform-abuse protection.
    """
    if CONFIG.exists():
        try:
            with open(CONFIG, encoding='utf-8') as f:
                cfg = json.load(f)
            from_config: set[str] = set()
            for d, _ in cfg.get('tier2_roots', {}).get('domains', []):
                from_config.add(d)
            for d in cfg.get('tier0_core_only', {}).get('hosting_subdomains', []):
                from_config.add(d)
            # Also pull hosting apexes from tier0_core_only domains themselves
            for d, _ in cfg.get('tier0_core_only', {}).get('domains', []):
                from_config.add(d)
            if from_config:
                return HOSTING_PLATFORM_APEXES | frozenset(from_config)
            # Config parsed but no hosting entries — warn and fall back to baseline
            log('WARN: config/critical_domains.json has no hosting entries; using baseline only')
        except Exception as e:
            log(f'WARN: failed to load config/critical_domains.json: {e}; using baseline only')
    else:
        log('WARN: config/critical_domains.json not found; using baseline only')
    return HOSTING_PLATFORM_APEXES


# Runtime set — config-authoritative, built-in as emergency fallback
_HOSTING_APEXES_MERGED: frozenset[str] = _load_hosting_apexes()


def is_hosting_platform(domain: str) -> bool:
    """
    Return True if the domain is a known hosting platform or a subdomain of one.

    Rationale: threat intel feeds record malicious *URLs*, not malicious *domains*.
    When an attacker hosts malware on github.com/user/repo or distributes phishing
    via pages.dev subdomains, blocking the entire apex domain causes massive
    collateral damage. The correct response is to skip these records entirely.
    """
    domain = domain.lower().strip('.')
    if domain in _HOSTING_APEXES_MERGED:
        return True
    parts = domain.split('.')
    for i in range(1, len(parts)):
        parent = '.'.join(parts[i:])
        if parent in _HOSTING_APEXES_MERGED:
            return True
    return False


# ── Helpers ──────────────────────────────────────────────────────────────────

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


def strip_rule_syntax(value: str) -> str:
    line = value.strip().lower()
    if not line:
        return ''
    for marker in (' #', ' ;'):
        if marker in line:
            line = line.split(marker, 1)[0].strip()
    if '!' in line and not line.startswith('!'):
        line = line.split('!', 1)[0].strip()
    line = HOSTS_PREFIX_RE.sub('', line).strip()
    if ' ' in line or '\t' in line:
        tokens = [t for t in re.split(r'\s+', line) if t]
        line = tokens[-1] if tokens else ''
    for prefix in ('@@||', '||'):
        if line.startswith(prefix):
            line = line[len(prefix):]
    if line.startswith('*.'):
        line = line[2:]
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


def is_eligible(domain: str) -> bool:
    """
    Return True if the domain is eligible for inclusion in a block list.

    A domain is NOT eligible if:
    - It is invalid (IP, malformed, too short)
    - It belongs to a hosting platform (see HOSTING_PLATFORM_APEXES)

    This is the central quality gate for the threat intel pipeline.
    """
    if not is_valid_domain(domain):
        return False
    if is_hosting_platform(domain):
        return False
    return True


def load_existing_domains() -> set:
    """Load all domains from src/ rule files."""
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


def _matched_hosting_apex(domain: str) -> str:
    """Return the hosting apex this domain belongs to.

    Resolution order:
      1. If the domain itself is in _HOSTING_APEXES_MERGED, return it.
         (e.g. 'raw.githubusercontent.com' which is listed in its own
         right because it deserves separate accounting from its parent
         'githubusercontent.com'.)
      2. Otherwise walk up the labels and return the first apex match.
      3. Return 'unknown' if neither — should not happen when called
         after is_hosting_platform() returns True, but guarded for safety.

    Earlier code preferred parent matches even when the domain itself
    was a listed apex, which lumped 'raw.githubusercontent.com' hits
    under 'githubusercontent.com' and lost the distinction in
    fetch_stats.json. Self-first match preserves per-subdomain accounting
    while still falling back to parent for genuine subdomains like
    'user1.github.io' → 'github.io'.
    """
    if domain in _HOSTING_APEXES_MERGED:
        return domain
    parts = domain.split('.')
    for i in range(1, len(parts)):
        parent = '.'.join(parts[i:])
        if parent in _HOSTING_APEXES_MERGED:
            return parent
    return 'unknown'


def _record_skip(skipped: dict, domain: str) -> None:
    """Bump the per-apex counter for a domain skipped due to hosting-platform
    classification. Mutates `skipped` in place."""
    apex = _matched_hosting_apex(domain)
    skipped[apex] = skipped.get(apex, 0) + 1


# ── Source Parsers ────────────────────────────────────────────────────────────

def parse_urlhaus(content: str) -> tuple[set, dict]:
    """
    Parse URLhaus text feed.

    URLhaus records full malicious URLs (e.g. https://compromised-site.com/payload.exe).
    We extract the hostname. Entries where the hostname belongs to a hosting
    platform are discarded — the threat is the specific URL, not the platform.

    Returns (domains, platform_skipped_count).
    """
    domains: set = set()
    skipped_by_platform: dict[str, int] = {}
    for line in content.splitlines():
        domain = extract_domain(line)
        if not domain:
            continue
        if is_hosting_platform(domain):
            _record_skip(skipped_by_platform, domain)
            continue
        # extract_domain has already validated, but keep the guard for safety
        if is_valid_domain(domain):
            domains.add(domain)
    total_skipped = sum(skipped_by_platform.values())
    if total_skipped:
        log(f'  [platform-skip] urlhaus: {total_skipped} hosting-platform URLs discarded')
    return domains, skipped_by_platform


def parse_threatfox(content: str) -> tuple[set, dict]:
    """
    Parse ThreatFox CSV export. Returns (domains, platform_skipped_count).
    """
    domains: set = set()
    skipped_by_platform: dict[str, int] = {}
    for row in csv.reader(content.splitlines()):
        if not row or row[0].startswith('#'):
            continue
        for cell in row[2:]:
            domain = extract_domain(cell)
            if not domain:
                continue
            if is_hosting_platform(domain):
                _record_skip(skipped_by_platform, domain)
                break
            if is_valid_domain(domain):
                domains.add(domain)
                break
    total_skipped = sum(skipped_by_platform.values())
    if total_skipped:
        log(f'  [platform-skip] threatfox: {total_skipped} hosting-platform IOCs discarded')
    return domains, skipped_by_platform


def parse_nocoin(content: str) -> tuple[set, dict]:
    """
    Parse adblock-nocoin-list (AdBlock syntax: ||domain^).

    Cryptojacking domains are almost always purpose-built malicious
    infrastructure, not hosted on legitimate platforms. Platform-hosting
    check is still applied for correctness.
    """
    domains: set = set()
    skipped_by_platform: dict[str, int] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('!') or line.startswith('#'):
            continue
        if line.startswith('||') and line.endswith('^'):
            domain = line[2:-1]
        elif line.startswith('||'):
            domain = line[2:].split('^')[0]
        else:
            domain = extract_domain(line)
        if not domain:
            continue
        if is_hosting_platform(domain):
            _record_skip(skipped_by_platform, domain)
            continue
        if is_valid_domain(domain):
            domains.add(domain.lower())
    return domains, skipped_by_platform


def parse_phishing_database(content: str) -> tuple[set, dict]:
    """
    Parse Phishing.Database active phishing domain list. Returns (domains, skipped_by_platform).
    """
    domains: set = set()
    skipped_by_platform: dict[str, int] = {}
    for line in content.splitlines():
        domain = extract_domain(line)
        if not domain:
            continue
        if is_hosting_platform(domain):
            _record_skip(skipped_by_platform, domain)
            continue
        if is_valid_domain(domain):
            domains.add(domain)
    total_skipped = sum(skipped_by_platform.values())
    if total_skipped:
        log(f'  [platform-skip] phishing_database: {total_skipped} hosting-platform entries discarded')
    return domains, skipped_by_platform


PARSERS = {
    'urlhaus':           parse_urlhaus,
    'threatfox':         parse_threatfox,
    'nocoin':            parse_nocoin,
    'phishing_database': parse_phishing_database,
}


# ── Main ─────────────────────────────────────────────────────────────────────

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
        url         = source_config['url']
        target      = source_config['target']
        description = source_config['description']

        log(f'\nFetching: {description}')
        log(f'  URL: {url}')

        content = fetch_url(url)
        if not content:
            stats['sources'][source_name] = {'status': 'fetch_failed', 'new': 0}
            continue

        parser     = PARSERS[source_name]
        raw_domains, platform_skipped = parser(content)
        log(f'  Parsed: {len(raw_domains)} eligible domains (hosting-platform URLs already discarded)')

        new_domains = sorted(d for d in raw_domains if d not in existing)
        log(f'  New (after dedup): {len(new_domains)}')

        target_file   = TARGET_FILES[target]
        current_count = load_file_domain_count(target_file)
        already_queued = len(set(new_by_target[target]))
        remaining_capacity = MAX_PER_FILE - current_count - already_queued

        if remaining_capacity <= 0:
            log(f'  SKIP: {target_file.name} already at cap ({current_count}/{MAX_PER_FILE})')
            total_skipped = sum(platform_skipped.values()) if isinstance(platform_skipped, dict) else platform_skipped
            stats['sources'][source_name] = {
                'status': 'file_cap_reached',
                'raw': len(raw_domains),
                'platform_skipped': total_skipped,
                'platform_skipped_by_apex': platform_skipped if isinstance(platform_skipped, dict) else {},
                'new': 0,
            }
            continue

        cap = min(MAX_PER_SOURCE, remaining_capacity)
        if len(new_domains) > cap:
            log(f'  Capped: {len(new_domains)} → {cap}')
            new_domains = new_domains[:cap]

        new_by_target[target].extend(new_domains)
        existing.update(new_domains)

        total_skipped = sum(platform_skipped.values()) if isinstance(platform_skipped, dict) else platform_skipped
        stats['sources'][source_name] = {
            'status': 'ok',
            'raw': len(raw_domains),
            'platform_skipped': total_skipped,
            'platform_skipped_by_apex': platform_skipped if isinstance(platform_skipped, dict) else {},
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
