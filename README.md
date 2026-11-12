# ShieldNova

[![Version](https://img.shields.io/badge/version-v2.2.1-blue)](https://github.com/harryheros/shieldnova/releases)
[![License](https://img.shields.io/badge/license-CC%20BY--NC--SA%204.0-orange)](LICENSE)

A **compatibility-first domain filter list** for privacy, ad blocking and security — conservative rules for minimal breakage, with dedicated China and HK / Taiwan editions. Subscribe in AdGuard, Clash, Surge, Shadowrocket, Loon or Quantumult X.

The goal is not maximum blocking, but **maximum usable protection**. Rule counts per list: [`dist/stats.json`](dist/stats.json).

> **License**: [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/) for ShieldNova's own curation and value-added work, in all versions. Third-party source data keeps its original licenses — see [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md). Commercial use requires a separate written license.

---

## Subscribe

Pick **one** list:

| List | Contents |
|---|---|
| `shieldnova-full.txt` | Privacy + ads + security — recommended |
| `shieldnova-full-cn.txt` | Full + China mainland trackers and ads |
| `shieldnova-full-hktw.txt` | Full + Hong Kong and Taiwan trackers and ads |
| `shieldnova-full-aggressive.txt` | Full + stricter privacy rules that may break some sites |
| `shieldnova-privacy.txt`, `-ads.txt`, `-security.txt` | One module only |

```text
AdGuard:      https://raw.githubusercontent.com/harryheros/shieldnova/main/dist/shieldnova-full.txt
Other apps:   https://raw.githubusercontent.com/harryheros/shieldnova/main/formats/<app>/shieldnova-full.txt
```

`<app>`: `adguard`, `clash`, `surge`, `shadowrocket`, `loon`, `quantumultx`.

---

## Why ShieldNova

One rule where one rule suffices. Where other lists add hundreds of subdomains of one tracker, ShieldNova blocks the domain once, with a note:

```
||actonservice.com^                       ! Act-On - marketing automation tracking
```

| | ShieldNova | Typical aggregated lists |
|---|---|---|
| Subscriptions | 1 | 10–100+ |
| Rules | ~1,300 (hand-curated privacy and ads, plus a rolling security window) | 40,000+ |
| Every rule explained | Yes — annotated or attributed to its source feed | Rarely |
| Regional editions | Yes | No |
| False positives | Near zero; checked on every build | Frequent |

---

## How it is built

```text
src/  hand-curated privacy / ads / security rules + allowlist
  +   weekly threat intel: abuse.ch URLhaus & ThreatFox, Phishing.Database, NoCoin
  →   validate → normalize → dedupe → allowlist → false-positive check
  →   dist/ (AdGuard format) and formats/ (six apps)
```

**Security lists** are rolling windows of at most 500 auto-fetched domains per file, alongside hand-curated ones. A fetched entry is retired when its feed stops listing it, after 180 days, or to make room for fresh entries (up to 100 per file per run). Hand-curated rules are never touched, and a failed or truncated feed never triggers removals. Every change is logged in `dist/fetch_stats.json`.

**Updates**: every Monday 02:00 UTC, or on demand. A failed run opens a GitHub issue.

**Allowlist**: domains in `src/allowlist/core.txt` are removed from every output.

> **Maintainers — abuse.ch Auth-Key.** abuse.ch serves URLhaus and ThreatFox only with a free Auth-Key (keyless URLs return HTTP 410 since October 2026). Create one at [auth.abuse.ch](https://auth.abuse.ch/) and add it as the Actions secret `ABUSECH_AUTH_KEY`. Without it both feeds are skipped and their entries expire after 180 days.

Release history: [CHANGELOG.md](./CHANGELOG.md).

---

## License

- **Non-commercial use**: permitted under [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/).
- **Commercial use** (SaaS, API resale, redistribution, paid products, use inside a company beyond research): requires prior written authorization — see [COMMERCIAL_LICENSE.md](./COMMERCIAL_LICENSE.md), or ask at [novaod.com/licensing](https://novaod.com/licensing).
- **In DNSNova**: free to use as a filter list in [DNSNova](https://github.com/harryheros/dnsnova), commercial deployments included; see COMMERCIAL_LICENSE.md for the exact terms.
- **Third-party data** (abuse.ch URLhaus and ThreatFox, adblock-nocoin-list, Phishing.Database) remains with its owners and licenses. ShieldNova's license covers only its own curation, classification, annotations, formatting and allowlists — see [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md).

Part of the [Nova infrastructure toolkit](https://github.com/harryheros).
