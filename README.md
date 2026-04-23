# ShieldNova

A curated domain intelligence library for network filtering, privacy protection, ad blocking, security defense, and traffic routing.

One link to subscribe. Every rule annotated. Zero bloat.

---

## Why ShieldNova?

Existing domain rule projects follow a "scrape and dump" model — merging tens of thousands of rules from upstream sources without deduplication, regional filtering, or quality review. Users get bloated lists that waste device resources, cause false positives, and provide a false sense of protection. Worse, subscribing requires adding dozens or even hundreds of URLs to your proxy tool.

ShieldNova is different:

- **One link, full protection.** Subscribe to a single URL and you're done.
- **Every rule is annotated.** Each entry includes a comment explaining what it targets and why.
- **Precision over volume.** Hundreds of curated rules, not tens of thousands of unreviewed entries.
- **Region-aware.** Choose Global, China, or Hong Kong & Taiwan editions — not a global soup.
- **Zero false positives.** Every rule is verified against real-world usage before inclusion.
- **Lightweight.** Your device stays fast. Your battery stays healthy.

---

## Subscribe

### One-Click (Recommended)

Most users only need one link. Pick your region:

| Edition | What's included | Subscribe |
|---|---|---|
| **Essential (Global)** | Privacy + Advertising + Security | `shieldnova-essential.txt` |
| **Essential (China)** | Global + China mainland trackers & ads | `shieldnova-essential-cn.txt` |
| **Essential (HK/TW)** | Global + HK & Taiwan specific | `shieldnova-essential-hktw.txt` |

> These are pre-built combo files. One link gives you complete protection for your region.

### By Module (Advanced)

For users who want granular control:

| Module | Description | Subscribe |
|---|---|---|
| Privacy | Analytics, attribution, fingerprinting, telemetry | `shieldnova-privacy.txt` |
| Advertising | Ad networks, ad exchanges, ad-serving | `shieldnova-advertising.txt` |
| Security | Phishing, malware, scam, cryptojacking | `shieldnova-security.txt` |

### Traffic Routing (For proxy tools)

Domain sets for routing specific service traffic through proxy nodes:

| Service | Subscribe |
|---|---|
| Netflix | `services/netflix.txt` |
| Disney+ | `services/disney.txt` |
| Spotify | `services/spotify.txt` |
| YouTube | `services/youtube.txt` |
| Telegram | `services/telegram.txt` |
| ChatGPT | `services/chatgpt.txt` |
| GitHub | `services/github.txt` |
| WhatsApp | `services/whatsapp.txt` |
| Bilibili | `services/bilibili.txt` |

> These are NOT blocking rules. They identify service domains so your proxy tool can route them through specific nodes.

---

## Supported Tools

All editions are available in every major format:

| Tool | Platform | Format directory |
|---|---|---|
| AdGuard | iOS / Android / Desktop | `formats/adguard/` |
| Surge | iOS / macOS | `formats/surge/` |
| Shadowrocket | iOS | `formats/shadowrocket/` |
| Clash / Mihomo | Cross-platform | `formats/clash/` |
| Quantumult X | iOS | `formats/quantumultx/` |
| Loon | iOS | `formats/loon/` |

Full subscribe URLs follow this pattern:
```
https://raw.githubusercontent.com/harryheros/shieldnova/main/formats/{tool}/{filename}
```

---

## What Makes ShieldNova Different

### vs. Bloated aggregated lists

| | ShieldNova | Typical lists |
|---|---|---|
| Subscribe | 1 link | 10-100+ links |
| Total rules | Hundreds (curated) | Tens of thousands (scraped) |
| Annotations | Every rule | Rarely |
| Region editions | Yes | No |
| False positives | Near zero | Frequent |
| Performance impact | Negligible | Noticeable |
| Maintenance | Manual curation | Automated scraping |

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

Same result. One rule instead of five hundred.

---

## Repository Structure

```
shieldnova/
│
├── dist/                          # ← USERS SUBSCRIBE HERE
│   ├── shieldnova-essential.txt         # Privacy + Ads + Security (Global)
│   ├── shieldnova-essential-cn.txt      # Essential + China mainland
│   ├── shieldnova-essential-hktw.txt    # Essential + Hong Kong & Taiwan
│   ├── shieldnova-privacy.txt           # Privacy module only
│   ├── shieldnova-advertising.txt       # Advertising module only
│   ├── shieldnova-security.txt          # Security module only
│   └── services/                        # Traffic routing domain sets
│       ├── netflix.txt
│       ├── telegram.txt
│       ├── chatgpt.txt
│       └── ...
│
├── src/                           # ← SOURCE FILES (maintainer use)
│   ├── privacy/
│   │   ├── core.txt                     # Global trackers
│   │   ├── cn.txt                       # China mainland trackers
│   │   └── hktw.txt                     # HK & Taiwan trackers
│   ├── advertising/
│   │   ├── core.txt
│   │   ├── cn.txt
│   │   └── hktw.txt
│   ├── security/
│   │   ├── phishing.txt
│   │   ├── malware.txt
│   │   └── cryptojacking.txt
│   └── services/
│       ├── netflix.txt
│       ├── telegram.txt
│       ├── chatgpt.txt
│       └── ...
│
├── formats/                       # ← AUTO-GENERATED for other tools
│   ├── surge/
│   ├── shadowrocket/
│   ├── clash/
│   ├── quantumultx/
│   └── loon/
│
├── scripts/
│   ├── build.py                   # Merges src/ → dist/
│   └── convert.py                 # Converts dist/ → formats/
│
├── LICENSE                        # CC BY-NC-SA 4.0
└── README.md
```

### How it works

1. **Source rules** are maintained in `src/` — one file per category per region, fully annotated.
2. **Build script** merges source files into ready-to-use combo files in `dist/`.
3. **Convert script** generates equivalent files for Surge, Shadowrocket, Clash, etc. in `formats/`.

Users subscribe to `dist/` or `formats/`. Contributors and reviewers work in `src/`.

---

## Design Philosophy

**Simple. Transparent. Reproducible.**

1. **Users see the menu, not the kitchen.** One link to subscribe, not a hundred.
2. **Every rule earns its place.** No bulk imports. Each entry is verified and annotated.
3. **Region-aware, not region-bloated.** You get rules for your region, not the entire planet.
4. **Conservative by default.** Core modules target zero false positives. Want aggressive blocking? It's a separate, clearly labeled option.
5. **Transparent maintenance.** Every change has a git commit with a clear description. No silent additions.

---

## Ecosystem

ShieldNova is part of the Nova infrastructure toolkit:

| Project | Layer | Description |
|---|---|---|
| [IPNova](https://github.com/harryheros/ipnova) | IP | Routing-aware IPv4 dataset for infrastructure classification and traffic control |
| [DomainNova](https://github.com/harryheros/domainnova) | Domain (Data) | High-precision Mainland China domain dataset for proxy routing and network intelligence |
| **ShieldNova** | **Domain (Filter)** | **Domain intelligence for filtering, blocking & routing** |
| [HarryWrt](https://github.com/harryheros/harrywrt) | Device | Clean OpenWrt-based firmware for x86_64 (BIOS & UEFI) |
| [OSNova](https://github.com/harryheros/osnova) | System | System deployment and reinstallation engine for VPS and bare-metal servers |
---

## Roadmap

- [x] Project architecture & documentation
- [ ] Privacy module — global core (v0.1)
- [ ] Privacy module — China mainland
- [ ] Advertising module — global core
- [ ] Advertising module — China mainland
- [ ] Security module — phishing & malware
- [ ] Essential combo builds (global / cn / hktw)
- [ ] Service domain sets (Netflix, Telegram, ChatGPT, etc.)
- [ ] Build & convert scripts with CI/CD
- [ ] Surge / Shadowrocket / Clash / QX / Loon format output
- [ ] HarryWrt integration
- [ ] IPNova routing-aware filtering

---

## Contributing

Contributions are welcome via GitHub Issues and Pull Requests.

**Before submitting a rule:**

1. Confirm the domain serves the stated purpose (packet capture, documentation, or source code evidence).
2. Confirm blocking does not break normal functionality.
3. Include an inline annotation.
4. Place it in the correct `src/` file.

---

## License

[CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/)

- **Personal use**: Free, no restrictions.
- **Commercial use**: Requires a separate license. Contact via [GitHub Issues](https://github.com/harryheros/shieldnova/issues).
