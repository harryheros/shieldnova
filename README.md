# ShieldNova

ShieldNova is a curated **domain intelligence layer** for:

- Privacy protection  
- Ad blocking  
- Security filtering  

Designed with **high compatibility and minimal breakage** in mind, ShieldNova provides a reliable default protection layer for modern applications and networks.

---

> **License Notice**: All versions of this project, including historical commits, are licensed under [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/). Commercial use of any version requires a separate written license agreement.
> **Versioning Notice**: Previous public versions of this project may have been distributed under different license terms. All current and future releases are governed solely by the LICENSE file in this repository.

## Why ShieldNova

Unlike large aggregated blocklists, ShieldNova focuses on:

- High-confidence rules only  
- Minimal impact on application functionality  
- Carefully curated domain intelligence  
- Long-term maintainability  

The goal is not maximum blocking, but **maximum usable protection**.

For current rule counts per profile, see `dist/stats.json`.

---

## Recommended Profiles

Most users only need one profile. Pick your region:

| Profile | What's included | Subscribe |
|---|---|---|
| **Full (Global)** | Privacy + Ads + Security | `dist/shieldnova-full.txt` |
| **Full (China)** | Global + China mainland trackers & ads | `dist/shieldnova-full-cn.txt` |
| **Full (HK/TW)** | Global + HK & Taiwan specific | `dist/shieldnova-full-hktw.txt` |

Subscribe URL pattern:
```
https://raw.githubusercontent.com/harryheros/shieldnova/main/dist/shieldnova-full.txt
```

For other tools (Surge, Shadowrocket, Clash, etc.), use files under `formats/`:
```
https://raw.githubusercontent.com/harryheros/shieldnova/main/formats/{tool}/shieldnova-full.txt
```

---

## What Makes ShieldNova Different

### One rule where one rule suffices

**Others do this:**
```
||a10053.actonservice.com^
||a10555.actonservice.com^
||a10640.actonservice.com^
... (500+ entries for one service)
```

**ShieldNova does this:**
```
||actonservice.com^                       ! Act-On - marketing automation tracking
```

Same coverage. One rule instead of five hundred.

### Comparison

| | ShieldNova | Typical aggregated lists |
|---|---|---|
| Subscribe | 1 link | 10-100+ links |
| Total rules | ~600 curated | 40,000+ scraped |
| Annotations | Every rule | Rarely |
| Region editions | Yes | No |
| False positives | Near zero | Frequent |
| Performance impact | Negligible | Noticeable |
| Maintenance | Manual curation | Automated scraping |

---

## Modules

- **privacy** — tracking & telemetry domains  
- **ads** — advertising infrastructure  
- **security** — phishing, malware, cryptojacking  

---

## Build & Architecture

```text
┌─────────────────────────────────────────────────┐
│  Manual Rules (src/)                            │
│  privacy / ads / security — hand-curated        │
└──────────────────┬──────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────┐
│  Threat Intel Fetch (monthly, automated)        │
│  abuse.ch URLhaus / ThreatFox                   │
│  Phishing.Database / NoCoin list                │
│  → dedup → cap → append to src/security/        │
└──────────────────┬──────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────┐
│  Build Pipeline                                 │
│  validate → normalize → dedup → allowlist       │
│  → merge combos → generate 6 client formats     │
└──────────────────┬──────────────────────────────┘
                   │
         ┌─────────┴──────────┐
         ▼                    ▼
┌─────────────────┐  ┌────────────────────┐
│  dist/           │  │  formats/          │
│  shieldnova-*   │  │  adguard / surge / │
│  (AdGuard fmt)  │  │  clash / qx / loon │
└─────────────────┘  └────────────────────┘
```

### Automated Threat Intelligence

ShieldNova's security module grows automatically via monthly feeds from:

| Source | Type | Feed |
|---|---|---|
| abuse.ch URLhaus | Malware distribution | Active malware URLs |
| abuse.ch ThreatFox | Malware C2 | Recent IOCs |
| NoCoin | Cryptojacking | Mining service domains |
| Phishing.Database | Phishing | Confirmed active phishing |

Each fetch is capped (max 50 per source, 500 per file), deduplicated against all existing rules, and appended with full attribution. Growth is controlled and auditable.

### Update Schedule

| Trigger | Frequency | Action |
|---|---|---|
| Scheduled | Every Monday 02:00 UTC | Build only |
| Scheduled | 1st of month 03:00 UTC | Threat intel fetch + build |
| Manual | On demand | Build or fetch + build |
| Failure | Automatic | Creates GitHub Issue |

---

## Design Principles

- Compatibility first  
- High-confidence filtering  
- Minimal disruption  
- Transparent and auditable rules  

---

## Allowlist

Override rules safely:

- `src/allowlist/core.txt` — domains listed here are excluded from all generated outputs

---

## Nova Toolkit

ShieldNova is part of the Nova infrastructure toolkit:

| Project | Layer | Description |
|---|---|---|
| [IPNova](https://github.com/harryheros/ipnova) | IP | Routing-aware IPv4 dataset for Asia-Pacific infrastructure classification and traffic control |
| [DomainNova](https://github.com/harryheros/domainnova) | Domain (Data) | High-precision domain dataset for proxy routing and network intelligence |
| **ShieldNova** | **Domain (Filter)** | **Compatibility-first domain intelligence for privacy, ad blocking, and security** |
| [HarryWrt](https://github.com/harryheros/harrywrt) | Device | Clean OpenWrt-based firmware for x86_64 and aarch64 (BIOS & UEFI) |
| [OSNova](https://github.com/harryheros/osnova) | System | System deployment and reinstallation engine for VPS and bare-metal servers |

---

## License

[CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/) — Attribution-NonCommercial-ShareAlike.

- **Non-commercial use**: Permitted under the terms of CC BY-NC-SA 4.0.
- **Commercial use**: Commercial use, SaaS deployment, API resale, redistribution, or integration into paid products or services requires explicit prior written authorization from the author. See [COMMERCIAL_LICENSE.md](./COMMERCIAL_LICENSE.md) or contact via [GitHub Issues](https://github.com/harryheros/shieldnova/issues).

---

Part of the [Nova infrastructure toolkit](https://github.com/harryheros).
