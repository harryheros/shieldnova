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
  - Rolling window (v2.2): auto-fetched entries are rotated, hand-curated
    entries are never touched. An auto entry is removed when
      * its feed lists *currently active* threats, was fetched successfully
        and looks complete, and no longer lists the domain; or
      * it is older than MAX_AGE_DAYS (ThreatFox itself expires IOCs
        after 6 months); or
      * the file is full and the oldest auto entries must make room for
        the per-run freshness quota.
    v2.1 was append-only with a 500-per-file cap: malware.txt and
    phishing.txt filled up on 2026-05-02 and no new threat intel entered
    them afterwards.
  - Capped per source per run and per file to keep client lists small
  - Full audit trail in fetch_stats.json

Usage:
  python3 scripts/fetch_threat_intel.py [--dry-run]
"""

import csv
import hashlib
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
    __version__,
    is_valid_domain,
)

USER_AGENT = f'ShieldNova/{__version__} (+https://github.com/harryheros/shieldnova)'

# ── Config ──────────────────────────────────────────────────────────────────

REPO_ROOT  = Path(__file__).resolve().parent.parent
SRC_DIR    = REPO_ROOT / 'src'
STATS_FILE = REPO_ROOT / 'dist' / 'fetch_stats.json'
CONFIG     = REPO_ROOT / 'config' / 'critical_domains.json'

MAX_PER_SOURCE = 250   # new domains one source may add in one run
MAX_PER_FILE   = 500   # hard size limit per security file (mobile clients)
FRESH_QUOTA    = 100   # new domains per file per run, making room if needed
MAX_AGE_DAYS   = 180   # auto entries older than this are always removed
THREATFOX_MIN_CONFIDENCE = 75
DRY_RUN = '--dry-run' in sys.argv

# Feeds that list *currently active* threats, so "no longer listed" means
# "no longer active". ThreatFox's CSV export is a short recent-additions
# window, so absence there says nothing — its entries rotate by age only.
LIVENESS_SOURCES = frozenset({'urlhaus', 'nocoin', 'phishing_database'})

# A feed smaller than this is treated as truncated/broken: its entries are
# NOT evicted for "no longer listed" in that run (new ones may still be added).
MIN_FEED_SIZE = {
    'urlhaus': 100,
    'threatfox': 0,
    'nocoin': 50,
    'phishing_database': 10000,
}

# v2.1 tagged auto entries with the target name ("! auto: malware") rather
# than the source. Map those legacy tags to the feed they came from.
LEGACY_TAG_SOURCE = {
    'malware': 'urlhaus',
    'phishing': 'phishing_database',
    'cryptojacking': 'nocoin',
}

AUTO_HEADER_RE = re.compile(
    r'^!\s*---\s*Auto-fetched from (\S+) \((\d{4}-\d{2}-\d{2})\)\s*---\s*$')
AUTO_TAG_RE = re.compile(r'!\s*auto:\s*([A-Za-z0-9_-]+)')

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
        req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
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


THREATFOX_DEFAULT_HEADER = [
    'first_seen_utc', 'ioc_id', 'ioc_value', 'ioc_type', 'threat_type',
    'fk_malware', 'malware_alias', 'malware_printable', 'last_seen_utc',
    'confidence_level', 'is_compromised', 'reference', 'tags', 'anonymous',
    'reporter',
]


def parse_threatfox(content: str) -> tuple[set, dict]:
    """
    Parse ThreatFox CSV export. Returns (domains, platform_skipped_by_apex).

    The export separates fields with '", "' (comma + space). v2.1 used
    csv.reader without skipinitialspace, so the quotes stayed attached and
    virtually nothing parsed (raw=1 in fetch_stats). It also scanned every
    column after index 2 and took the first domain-looking value, which —
    once quoting works — would pick the *reference* URL (bazaar.abuse.ch,
    honeylabs.net, ...) for ip:port IOCs. Now only the ioc_value column is
    used, only for ioc_type domain/url, with a minimum confidence level.
    """
    domains: set = set()
    skipped_by_platform: dict[str, int] = {}
    header: list[str] | None = None
    data_lines: list[str] = []
    for raw in content.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith('#'):
            body = line.lstrip('#').strip()
            if body.startswith('"first_seen_utc"'):
                header = next(csv.reader([body], skipinitialspace=True))
            continue
        data_lines.append(line)
    idx = {name: i for i, name in enumerate(header or THREATFOX_DEFAULT_HEADER)}
    i_val, i_type = idx.get('ioc_value'), idx.get('ioc_type')
    i_conf = idx.get('confidence_level')
    if i_val is None or i_type is None:
        log('  WARN: ThreatFox header missing ioc_value/ioc_type; skipping feed')
        return domains, skipped_by_platform

    for row in csv.reader(data_lines, skipinitialspace=True):
        if len(row) <= max(i_val, i_type):
            continue
        if row[i_type].strip().lower() not in ('domain', 'url'):
            continue
        if i_conf is not None and len(row) > i_conf:
            try:
                if int(row[i_conf]) < THREATFOX_MIN_CONFIDENCE:
                    continue
            except ValueError:
                pass
        domain = extract_domain(row[i_val])
        if not domain:
            continue  # e.g. URL on a bare IP
        if is_hosting_platform(domain):
            _record_skip(skipped_by_platform, domain)
            continue
        domains.add(domain)
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


# ── Rolling window ───────────────────────────────────────────────────────────

def live_domains(content: str) -> set:
    """Every valid domain a line-oriented feed currently lists — including
    hosting-platform subdomains, so manually reviewed hosting entries are
    judged against the feed too."""
    out = set()
    for line in content.splitlines():
        d = extract_domain(line)
        if d:
            out.add(d)
    return out


def _parse_date(value: str):
    try:
        return datetime.strptime(value, '%Y-%m-%d').date()
    except (TypeError, ValueError):
        return None


def classify_lines(lines: list[str], target: str) -> list[dict]:
    """Annotate each line of a security source file.

    Returns one dict per line: {'line', 'kind', 'domain', 'source', 'date'}
    where kind is 'auto' (auto-fetched rule), 'header' (auto section
    header) or 'other' (hand-curated rules, comments, blanks — never
    modified by the rotation).
    """
    out = []
    section_date = None
    for line in lines:
        m = AUTO_HEADER_RE.match(line.strip())
        if m:
            section_date = _parse_date(m.group(2))
            out.append({'line': line, 'kind': 'header', 'domain': None,
                        'source': m.group(1), 'date': section_date})
            continue
        tag = AUTO_TAG_RE.search(line)
        domain = extract_domain(line) if tag else None
        if tag and domain:
            source = tag.group(1)
            source = LEGACY_TAG_SOURCE.get(source, source) if source == target else source
            out.append({'line': line, 'kind': 'auto', 'domain': domain,
                        'source': source, 'date': section_date})
        else:
            out.append({'line': line, 'kind': 'other', 'domain': None,
                        'source': None, 'date': None})
    return out


def cleanup_lines(entries: list[dict]) -> list[str]:
    """Drop auto section headers left without rules; collapse blank runs."""
    lines: list[str] = []
    for i, e in enumerate(entries):
        if e['kind'] == 'evicted':
            continue
        if e['kind'] == 'header':
            has_rule = False
            for nxt in entries[i + 1:]:
                if nxt['kind'] == 'header':
                    break
                if nxt['kind'] == 'auto' or (
                        nxt['kind'] == 'other' and nxt['line'].strip().startswith('||')):
                    has_rule = True
                    break
            if not has_rule:
                continue
        lines.append(e['line'])
    out: list[str] = []
    for line in lines:
        if not line.strip() and out and not out[-1].strip():
            continue
        out.append(line)
    while out and not out[-1].strip():
        out.pop()
    return out


def pick(candidates: set, k: int, seed: str) -> list[str]:
    """Deterministic, alphabet-neutral selection of k candidates.

    v2.1 took the alphabetically first N, which systematically favoured
    names starting with digits/'a' (e.g. '01activar-...'). Ranking by a
    hash seeded with the run date spreads picks across the feed and still
    reproduces exactly for a given day.
    """
    ranked = sorted(candidates,
                    key=lambda d: hashlib.sha256(f'{seed}|{d}'.encode()).hexdigest())
    return sorted(ranked[:max(0, k)])


def rotate_target(target: str, path: Path, fetched: dict, existing_all: set,
                  today) -> tuple[list[str], dict, dict]:
    """Apply eviction + admission to one security file.

    Returns (new_file_lines, target_stats, new_by_source).
    """
    lines = path.read_text(encoding='utf-8').splitlines() if path.exists() else []
    entries = classify_lines(lines, target)
    sources = [s for s, cfg in SOURCES.items() if cfg['target'] == target]

    live = {s: fetched[s]['live'] for s in sources
            if s in LIVENESS_SOURCES and fetched.get(s, {}).get('sane')}

    evicted = {'age': [], 'not_in_feed': [], 'fifo': []}
    for e in entries:
        if e['kind'] != 'auto':
            continue
        if e['date'] and (today - e['date']).days > MAX_AGE_DAYS:
            e['kind'] = 'evicted'
            evicted['age'].append(e['domain'])
        elif e['source'] in live and e['domain'] not in live[e['source']]:
            e['kind'] = 'evicted'
            evicted['not_in_feed'].append(e['domain'])

    removed = set(evicted['age']) | set(evicted['not_in_feed'])
    known = existing_all - removed

    def file_domains():
        doms = set()
        for e in entries:
            if e['kind'] == 'auto':
                doms.add(e['domain'])
            elif e['kind'] == 'other':
                d = extract_domain(e['line'])
                if d:
                    doms.add(d)
        return doms

    candidates = {s: set(fetched[s]['eligible']) - known
                  for s in sources if fetched.get(s, {}).get('ok')}
    total_candidates = len(set().union(*candidates.values())) if candidates else 0
    wanted = min(total_candidates, FRESH_QUOTA, MAX_PER_FILE)

    # Make room for the freshness quota by retiring the oldest auto entries.
    shortfall = wanted - (MAX_PER_FILE - len(file_domains()))
    if shortfall > 0:
        autos = [e for e in entries if e['kind'] == 'auto']
        autos.sort(key=lambda e: e['date'] or today)  # stable: file order within a day
        for e in autos[:shortfall]:
            e['kind'] = 'evicted'
            evicted['fifo'].append(e['domain'])

    capacity = MAX_PER_FILE - len(file_domains())
    new_by_source: dict[str, list[str]] = {}
    taken: set = set()
    seed = today.isoformat()
    for s in sources:
        if capacity <= 0 or s not in candidates:
            continue
        k = min(MAX_PER_SOURCE, capacity)
        chosen = pick(candidates[s] - taken, k, f'{seed}|{s}')
        if chosen:
            new_by_source[s] = chosen
            taken.update(chosen)
            capacity -= len(chosen)

    new_lines = cleanup_lines(entries)
    for s, doms in new_by_source.items():
        new_lines.append('')
        new_lines.append(f'! --- Auto-fetched from {s} ({seed}) ---')
        for d in doms:
            rule = f'||{d}^'
            new_lines.append(f'{rule:<44}! auto: {s}')

    stats = {
        'evicted_age': len(evicted['age']),
        'evicted_not_in_feed': len(evicted['not_in_feed']),
        'evicted_fifo': len(evicted['fifo']),
        'liveness_checked_sources': sorted(live),
        'added': sum(len(v) for v in new_by_source.values()),
        'total_after': len(file_domains()) + sum(len(v) for v in new_by_source.values()),
    }
    return new_lines, stats, new_by_source


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    log('ShieldNova Threat Intelligence Fetch')
    log('=' * 50)
    if DRY_RUN:
        log('*** DRY-RUN MODE — no files will be modified ***')

    existing = load_existing_domains()
    log(f'Loaded {len(existing)} existing domains across all modules')
    today = datetime.now(timezone.utc).date()

    stats = {
        'fetched_at': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
        'dry_run': DRY_RUN,
        'policy': {
            'max_per_source': MAX_PER_SOURCE,
            'max_per_file': MAX_PER_FILE,
            'fresh_quota': FRESH_QUOTA,
            'max_age_days': MAX_AGE_DAYS,
        },
        'sources': {},
        'targets': {},
    }

    fetched: dict[str, dict] = {}
    for source_name, source_config in SOURCES.items():
        url = source_config['url']
        log(f"\nFetching: {source_config['description']}")
        log(f'  URL: {url}')
        content = fetch_url(url)
        if not content:
            fetched[source_name] = {'ok': False, 'sane': False, 'eligible': set(), 'live': set()}
            stats['sources'][source_name] = {'status': 'fetch_failed', 'new': 0}
            continue
        eligible, platform_skipped = PARSERS[source_name](content)
        live = live_domains(content) if source_name in LIVENESS_SOURCES else set()
        sane = len(live) >= MIN_FEED_SIZE.get(source_name, 0) if source_name in LIVENESS_SOURCES else True
        if source_name in LIVENESS_SOURCES and not sane:
            log(f'  WARN: {source_name} lists only {len(live)} domains '
                f'(< {MIN_FEED_SIZE[source_name]}); treating as incomplete — '
                'no liveness eviction for this source this run')
        fetched[source_name] = {'ok': True, 'sane': sane, 'eligible': eligible, 'live': live}
        log(f'  Parsed: {len(eligible)} eligible domains (hosting-platform URLs already discarded)')
        stats['sources'][source_name] = {
            'status': 'ok' if sane else 'feed_incomplete',
            'raw': len(eligible),
            'platform_skipped': sum(platform_skipped.values()),
            'platform_skipped_by_apex': platform_skipped,
            'new': 0,
        }

    total_added = 0
    for target, path in TARGET_FILES.items():
        new_lines, tstats, new_by_source = rotate_target(target, path, fetched, existing, today)
        stats['targets'][target] = tstats
        for s, doms in new_by_source.items():
            stats['sources'][s]['new'] = stats['sources'][s].get('new', 0) + len(doms)
            existing.update(doms)
        total_added += tstats['added']
        log(f"\n{path.name}: -{tstats['evicted_not_in_feed']} no longer listed, "
            f"-{tstats['evicted_age']} expired (> {MAX_AGE_DAYS}d), "
            f"-{tstats['evicted_fifo']} rotated out, +{tstats['added']} new "
            f"→ {tstats['total_after']} domains")
        if DRY_RUN:
            for s, doms in new_by_source.items():
                for d in doms[:5]:
                    log(f'  [DRY-RUN] + {d}  ({s})')
            continue
        path.write_text('\n'.join(new_lines) + '\n', encoding='utf-8')

    stats['total_added'] = total_added
    stats['total_removed'] = sum(
        t['evicted_age'] + t['evicted_not_in_feed'] + t['evicted_fifo']
        for t in stats['targets'].values())

    if not DRY_RUN:
        os.makedirs(STATS_FILE.parent, exist_ok=True)
        with open(STATS_FILE, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2)
            f.write('\n')
        log('\nStats written to dist/fetch_stats.json')

    log(f"\n{'=' * 50}")
    log(f"Total new domains added: {total_added}, removed: {stats['total_removed']}")
    log('Done.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
