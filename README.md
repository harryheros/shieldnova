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

- shieldnova-full.txt  
- shieldnova-full-cn.txt  
- shieldnova-full-hktw.txt  

Includes:
- Privacy + Ads + Security modules  

Suitable for most users as a default configuration.

---

## Modules

- privacy — tracking & telemetry domains  
- ads — advertising infrastructure  
- security — phishing, malware, cryptojacking  

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

- IPNova — routing-aware IPv4 dataset  
- DomainNova — infrastructure domain dataset  
- OSNova — system deployment engine  

---

## License

MIT License
