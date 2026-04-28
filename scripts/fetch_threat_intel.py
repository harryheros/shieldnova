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

import json
import os
import re
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

# ── Config ──────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
STATS_FILE = REPO_ROOT / "dist" / "fetch_stats.json"

# Max new domains to add per source per run (prevents runaway growth)
MAX_PER_SOURCE = 50

# Max total domains per security file (hard cap)
MAX_PER_FILE = 500

DRY_RUN = "--dry-run" in sys.argv

# Domain validation regex
DOMAIN_RE = re.compile(
    r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
)

# ── Upstream Sources ────────────────────────────────────────────────────────

SOURCES = {
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/text_online/",
        "target": "malware",
        "description": "abuse.ch URLhaus - active malware distribution URLs",
    },
    "threatfox": {
        "url": "https://threatfox.abuse.ch/export/csv/recent/",
        "target": "malware",
        "description": "abuse.ch ThreatFox - recent malware IOCs",
    },
    "nocoin": {
        "url": "https://raw.githubusercontent.com/nicehash/NoCoin/master/src/nocoin-list.txt",
        "target": "cryptojacking",
        "description": "NoCoin - browser mining domain list",
    },
    "phishing_database": {
        "url": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
        "target": "phishing",
        "description": "Phishing.Database - confirmed active phishing domains",
    },
}


# ── Helpers ─────────────────────────────────────────────────────────────────

def log(msg: str):
    print(f"[fetch] {msg}")


def fetch_url(url: str, timeout: int = 30) -> str:
    """Fetch URL content as text. Returns empty string on failure."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ShieldNova/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        log(f"  WARN: failed to fetch {url}: {e}")
        return ""


def extract_domain(url_or_line: str) -> str:
    """Extract a clean domain from a URL or raw line."""
    line = url_or_line.strip().lower()

    # Skip comments and empty
    if not line or line.startswith("#") or line.startswith("//") or line.startswith(";"):
        return ""

    # Remove protocol
    for prefix in ("https://", "http://", "||", "@@||"):
        if line.startswith(prefix):
            line = line[len(prefix):]

    # Remove path, port, trailing markers
    line = line.split("/")[0].split(":")[0].split("^")[0].split("$")[0]

    # Remove leading/trailing dots
    line = line.strip(".")

    # Validate
    if DOMAIN_RE.match(line) and "." in line:
        return line
    return ""


def load_existing_domains() -> set:
    """Load all domains from all src/ rule files to deduplicate against."""
    existing = set()
    for txt_file in SRC_DIR.rglob("*.txt"):
        with open(txt_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("||") and line.endswith("^"):
                    domain = line[2:-1].split("^")[0]
                    existing.add(domain.lower())
    return existing


def load_file_domain_count(filepath: Path) -> int:
    """Count active rules in a file."""
    if not filepath.exists():
        return 0
    count = 0
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip().startswith("||"):
                count += 1
    return count


def append_domains(filepath: Path, domains: list, source_name: str):
    """Append new domains to a source file with attribution comment."""
    if not domains:
        return
    with open(filepath, "a", encoding="utf-8") as f:
        f.write(f"\n! --- Auto-fetched from {source_name} ({datetime.now(timezone.utc).strftime('%Y-%m-%d')}) ---\n")
        for domain in sorted(domains):
            f.write(f"||{domain}^                           ! auto: {source_name}\n")


# ── Source Parsers ──────────────────────────────────────────────────────────

def parse_urlhaus(content: str) -> set:
    """Parse URLhaus online URL list → extract unique domains."""
    domains = set()
    for line in content.splitlines():
        domain = extract_domain(line)
        if domain:
            domains.add(domain)
    return domains


def parse_threatfox(content: str) -> set:
    """Parse ThreatFox CSV → extract domains from IOC column."""
    domains = set()
    for line in content.splitlines():
        if line.startswith("#") or line.startswith('"'):
            continue
        parts = line.split(",")
        if len(parts) >= 3:
            ioc = parts[2].strip().strip('"')
            domain = extract_domain(ioc)
            if domain:
                domains.add(domain)
    return domains


def parse_nocoin(content: str) -> set:
    """Parse NoCoin list → extract domains."""
    domains = set()
    for line in content.splitlines():
        domain = extract_domain(line)
        if domain:
            domains.add(domain)
    return domains


def parse_phishing_database(content: str) -> set:
    """Parse Phishing.Database active list → extract domains."""
    domains = set()
    for line in content.splitlines():
        domain = extract_domain(line)
        if domain:
            domains.add(domain)
    return domains


PARSERS = {
    "urlhaus": parse_urlhaus,
    "threatfox": parse_threatfox,
    "nocoin": parse_nocoin,
    "phishing_database": parse_phishing_database,
}

# ── File mapping ────────────────────────────────────────────────────────────

TARGET_FILES = {
    "malware": SRC_DIR / "security" / "malware.txt",
    "cryptojacking": SRC_DIR / "security" / "cryptojacking.txt",
    "phishing": SRC_DIR / "security" / "phishing.txt",
}


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    log("ShieldNova Threat Intelligence Fetch")
    log("=" * 50)

    if DRY_RUN:
        log("*** DRY-RUN MODE — no files will be modified ***")

    # Load existing rules for dedup
    existing = load_existing_domains()
    log(f"Loaded {len(existing)} existing domains across all modules")

    stats = {
        "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "dry_run": DRY_RUN,
        "sources": {},
    }

    # Track new domains per target file
    new_by_target: dict[str, list] = {t: [] for t in TARGET_FILES}

    for source_name, source_config in SOURCES.items():
        url = source_config["url"]
        target = source_config["target"]
        description = source_config["description"]

        log(f"\nFetching: {description}")
        log(f"  URL: {url}")

        content = fetch_url(url)
        if not content:
            stats["sources"][source_name] = {"status": "fetch_failed", "new": 0}
            continue

        # Parse
        parser = PARSERS[source_name]
        raw_domains = parser(content)
        log(f"  Parsed: {len(raw_domains)} raw domains")

        # Deduplicate against existing
        new_domains = [d for d in raw_domains if d not in existing]
        log(f"  New (after dedup): {len(new_domains)}")

        # Check file cap
        target_file = TARGET_FILES[target]
        current_count = load_file_domain_count(target_file)
        remaining_capacity = MAX_PER_FILE - current_count

        if remaining_capacity <= 0:
            log(f"  SKIP: {target_file.name} already at cap ({current_count}/{MAX_PER_FILE})")
            stats["sources"][source_name] = {
                "status": "file_cap_reached",
                "raw": len(raw_domains),
                "new": 0,
            }
            continue

        # Cap per source per run
        cap = min(MAX_PER_SOURCE, remaining_capacity)
        if len(new_domains) > cap:
            log(f"  Capped: {len(new_domains)} → {cap}")
            new_domains = sorted(new_domains)[:cap]

        # Add to target batch
        new_by_target[target].extend(new_domains)

        # Add to existing set to prevent cross-source duplicates within same run
        for d in new_domains:
            existing.add(d)

        stats["sources"][source_name] = {
            "status": "ok",
            "raw": len(raw_domains),
            "new": len(new_domains),
            "capped_at": cap,
        }
        log(f"  Will add: {len(new_domains)} to {target_file.name}")

    # Write results
    total_added = 0
    for target, domains in new_by_target.items():
        if not domains:
            continue
        target_file = TARGET_FILES[target]
        if DRY_RUN:
            log(f"\n[DRY-RUN] Would append {len(domains)} domains to {target_file.name}")
            for d in sorted(domains)[:10]:
                log(f"  + {d}")
            if len(domains) > 10:
                log(f"  ... and {len(domains) - 10} more")
        else:
            append_domains(target_file, domains, target)
            log(f"\nAppended {len(domains)} domains to {target_file.name}")
        total_added += len(domains)

    stats["total_added"] = total_added

    # Write stats
    if not DRY_RUN:
        os.makedirs(STATS_FILE.parent, exist_ok=True)
        with open(STATS_FILE.parent / "fetch_stats.json", "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2)
        log(f"\nStats written to dist/fetch_stats.json")

    log(f"\n{'=' * 50}")
    log(f"Total new domains added: {total_added}")
    log("Done.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
