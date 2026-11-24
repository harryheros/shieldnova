# ShieldNova Changelog

Releases, newest first. The weekly threat-intelligence refreshes are listed
in [dist/updates.md](./dist/updates.md).

## 2.2.3 (2026-11-15)

- **abuse.ch terms**: abuse.ch's Terms of Use (last updated 2026-10-21)
  say that commercial or for-profit use of URLhaus and ThreatFox may require
  a paid subscription managed by Spamhaus. THIRD_PARTY_NOTICES.md said
  ThreatFox data was CC0; it now states the current terms, and
  COMMERCIAL_LICENSE.md says that neither a ShieldNova commercial license
  nor the DNSNova permission includes that subscription.
- **Builds rewrite only what changed**: every build wrote a new build time
  into all 49 lists and both stats files, so each run changed some 50 files
  whose rules were the same. A file is now rewritten only when its rules or
  counts change, and keeps the time of its last real change (also the
  AdGuard `! Version:` line).
- **Release history**: this file now lists releases only. The weekly
  refresh entries, which had buried the releases, are written to
  `dist/updates.md` (earlier ones moved there).
- Code cleanup: unused imports and variables, a duplicated pair in the
  hosting-platform list. No change to the rules.

## 2.2.2 (2026-11-12)

- **Free to use in DNSNova**: ShieldNova may be used free of charge as a
  filter list in DNSNova, commercial deployments included. Other commercial
  use still needs a license; inquiries go to
  [novaod.com/licensing](https://novaod.com/licensing).
- Use inside a company beyond research is now listed as commercial use.
- README shortened.
- The tagged commit still reported 2.2.1 in `scripts/_common.py` (used in
  the fetcher's User-Agent); corrected in the next commit.

## 2.2.1 (2026-10-27)

- **abuse.ch Auth-Key**: abuse.ch retired its keyless download URLs for
  URLhaus and ThreatFox around 2026-10-21 (HTTP 410). The fetcher now uses
  the keyed export URLs with the free Auth-Key from the Actions secret
  `ABUSECH_AUTH_KEY`. Without it both sources are skipped
  (`no_auth_key` in `dist/fetch_stats.json`) and their entries expire after
  180 days. The key is masked in logs; zipped exports are unpacked.

## 2.2.0 (2026-09-25)

- Security lists are now a rolling window of currently active threats instead
  of append-only. `malware.txt` and `phishing.txt` had reached their 500-entry
  cap on 2026-05-02, after which no new threat intelligence was added.
  Auto-fetched entries are retired when their feed no longer lists them, after
  180 days, or to make room for fresh entries; hand-curated rules are never
  touched. Truncated or failed feeds never trigger removals.
- Fixed ThreatFox parsing: the feed's comma-plus-space CSV format meant almost
  nothing was parsed. Only the IOC value column is used now (domain/URL IOCs,
  confidence >= 75), so reference links can never be mistaken for IOCs.
- New domains are selected across the whole feed instead of alphabetically.
- Threat intelligence fetch now runs weekly (was monthly).
- Auto-fetched entries are attributed to their actual source feed.
- Changelog entries report new/retired counts, and no longer repeat a
  previous fetch as "refreshed".
- CI: actions upgraded (checkout v7, setup-python v6 / Python 3.13,
  github-script v9 — v7 ran on Node 20, removed from runners on 2026-09-16),
  plus concurrency, timeout and push-with-rebase retry.

## 2.1.1 (2026-06-05)

- Clarified licensing boundaries for third-party threat-intelligence sources
- Added `THIRD_PARTY_NOTICES.md` documenting per-source attribution and licenses
  (abuse.ch URLhaus & ThreatFox, adblock-nocoin-list MIT, Phishing.Database MIT)
- README and COMMERCIAL_LICENSE now state that ShieldNova's license covers only
  its own curation, classification, allowlists, annotations, and generated
  formats — not the underlying third-party factual domain data
- No data or pipeline changes

## 2.1.0 (2026-05-26)

- **Threat feeds without false positives.** URLhaus and ThreatFox list
  malicious URLs, often on shared platforms; the feeds are now read source
  by source, so one bad page on a hosting platform does not block the
  platform.
- **False-positive gate**: every published file is checked against a list
  of critical service domains (`config/critical_domains.json`), shared by
  the fetcher, the build and an audit of existing rules
  (`audit_existing_rules.py`); the existing security rules were audited
  against it.
- Abuse-TLD patterns moved to configuration (`suspicious_patterns` in
  `config/critical_domains.json`), so they can change without code changes.
- `fetch_stats.json` counts platform subdomains that are themselves listed
  as hosting platforms separately from their parent platforms.
- Each build writes a release report: `dist/release_report.json` and
  `dist/RELEASE_NOTES.md`.
- HK/TW privacy and advertising rules expanded.
- Tests: shared helpers, false positives and version consistency.

## 2.0.0 (2026-04-30)

First tagged release.

- **Compatibility-first filter lists** for privacy, ads and security:
  high-confidence rules only, one annotated rule per service instead of
  hundreds of subdomains, about 600 rules in all.
- Profiles: Full, with editions for CN and for HK/TW; the privacy, ads and
  security modules are also published separately.
- Security rules grow monthly from public threat feeds (abuse.ch URLhaus
  and ThreatFox, Phishing.Database, a cryptojacking list), capped and
  deduplicated.
- AdGuard-format lists in `dist/`, and files for other clients in
  `formats/`.
- License: CC BY-NC-SA 4.0, with commercial licenses available.

## Before 2.0.0

Version 0.1 (2026-04-23) has no release; its changes are in the git
history.
