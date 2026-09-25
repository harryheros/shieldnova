# ShieldNova Changelog

> Security rule updates and release history.

## 2026-09-25 — v2.2.0

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

---
## 2026-07-01

- Security rules updated
- ✓ Release validation: passed

---
## 2026-06-08

- Security rules updated
- ✓ Release validation: passed

---
## 2026-06-05 — v2.1.1

- Clarified licensing boundaries for third-party threat-intelligence sources
- Added `THIRD_PARTY_NOTICES.md` documenting per-source attribution and licenses
  (abuse.ch URLhaus & ThreatFox, adblock-nocoin-list MIT, Phishing.Database MIT)
- README and COMMERCIAL_LICENSE now state that ShieldNova's license covers only
  its own curation, classification, allowlists, annotations, and generated
  formats — not the underlying third-party factual domain data
- No data or pipeline changes

---
## 2026-06-01

- Security rules updated
- ✓ Release validation: passed

---
## 2026-05-26

- Security rules updated
- ✓ Release validation: passed

---
## 2026-05-25

- Security rules updated
- ✓ Release validation: passed

---
## 2026-05-24

- Security rules updated
- ✓ Release validation: passed

---
## 2026-05-20

- Security rules updated
- ✓ Release validation: passed

---
## 2026-05-18

- Security rules updated
- ✓ Release validation: passed

---
## 2026-05-14

- Security rules updated
- ✓ Release validation: passed

---
## 2026-05-13

- Security rules updated
- ✓ Release validation: passed

---
## 2026-05-11

- Security rules updated
- ✓ Release validation: passed

---
## 2026-05-08

- Security rules updated
- ✓ Release validation: passed

---
## 2026-05-07

- Security rules updated (+15)
- ✓ Release validation: passed

---
## 2026-05-06

- Security rules updated
- ✓ Release validation: passed

---
## 2026-05-05

- Security rules updated
- ✓ Release validation: passed

---
## 2026-05-04

- Security rules updated
- ✓ Release validation: passed

---
## 2026-05-03

- Security rules updated
- ✓ Release validation: passed

---
## 2026-05-02

- Security rules updated
- ✓ Release validation: passed

---
## 2026-05-01

- Security rules updated (+0)
- Threat intelligence refreshed
- ✓ Release validation: passed

---
