# ShieldNova

ShieldNova is a curated **domain intelligence layer** for:

- Privacy protection  
- Ad blocking  
- Security filtering  
- Traffic routing  

Designed with **high compatibility and minimal breakage** in mind, ShieldNova provides a reliable default protection layer for modern applications and networks.

---

## Why ShieldNova

Unlike large aggregated blocklists, ShieldNova focuses on:

- High-confidence rules only  
- Minimal impact on application functionality  
- Carefully curated domain intelligence  
- Long-term maintainability  

The goal is not maximum blocking, but **maximum usable protection**.

---

## Recommended Profiles

Most users only need one link. Pick your region:

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
| Total rules | ~100 curated | 40,000+ scraped |
| Annotations | Every rule | Rarely |
| Region editions | Yes | No |
| False positives | Near zero | Frequent |
| Performance impact | Negligible | Noticeable |
| Maintenance | Manual curation | Automated scraping |

---

## Modules

- privacy — tracking & telemetry domains  
- ads — advertising infrastructure  
- security — phishing, malware, cryptojacking  

---

## Services (Traffic Routing)

Domain sets for structured service classification.

These datasets provide domain-level intelligence, enabling network systems 
to implement routing, filtering, and policy controls based on service context.

| Service | File |
|---|---|
| Apple | `services/apple.txt` |
| ChatGPT / OpenAI | `services/chatgpt.txt` |
| Netflix | `services/netflix.txt` |
| Telegram | `services/telegram.txt` |

Subscribe URL pattern:
```
https://raw.githubusercontent.com/harryheros/shieldnova/main/dist/services/{service}.txt
```

For Surge/Shadowrocket/Clash/QX/Loon, use files under `formats/{tool}/services/`.

---

## Build & Architecture

- Source rules: `src/`  
- Generated output: `dist/`  
- Multi-client formats: `formats/`  

Features:

- Rule validation and deduplication  
- Allowlist override system  
- Structured statistics output  
- Multi-platform compatibility  

---

## Design Principles

- Compatibility first  
- High-confidence filtering  
- Minimal disruption  
- Transparent and auditable rules  

---

## Allowlist

Override rules safely:

- src/allowlist/core.txt  
- src/allowlist/custom.txt  

---

## Nova Toolkit

ShieldNova is part of the Nova infrastructure toolkit:

| Project | Layer | Description |
|---|---|---|
| [IPNova](https://github.com/harryheros/ipnova) | IP | Routing-aware IPv4 dataset for infrastructure classification and traffic control |
| [DomainNova](https://github.com/harryheros/domainnova) | Domain (Data) | High-precision Mainland China domain dataset for proxy routing and network intelligence |
| **ShieldNova** | **Domain (Filter)** | **Domain intelligence for filtering, blocking & routing** |
| [HarryWrt](https://github.com/harryheros/harrywrt) | Device | Clean OpenWrt-based firmware for x86_64 and aarch64 (BIOS & UEFI) |
| [OSNova](https://github.com/harryheros/osnova) | System | System deployment and reinstallation engine for VPS and bare-metal servers |

---

## License

[CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/)

- **Personal use**: Free, no restrictions.
- **Commercial use**: Requires a separate license. Contact via [GitHub Issues](https://github.com/harryheros/shieldnova/issues).
---

Part of the [Nova infrastructure toolkit](https://github.com/harryheros).
