# ShieldNova

ShieldNova is a curated domain intelligence library for:

- Privacy protection
- Ad blocking
- Security filtering
- Traffic routing

It is designed as a **high-compatibility default protection layer**, minimizing breakage while providing meaningful protection.

---

## Recommended Subscription

- shieldnova-full.txt (Global)
- shieldnova-full-cn.txt (China Mainland)
- shieldnova-full-hktw.txt (HK/TW)

Includes:
- Privacy + Ads + Security

---

## Modules

- privacy — tracking & telemetry
- ads — advertising infrastructure
- security — phishing, malware, cryptojacking

---

## Design Philosophy

- High compatibility first
- Only high-confidence rules
- Minimal user breakage
- Maintainable & auditable rules

---

## Build System

- src/ → source rules
- dist/ → AdGuard output
- formats/ → Surge / Clash / etc

Includes:
- auto deduplication
- validation
- stats output

---

## Allowlist

Override rules safely:

- src/allowlist/core.txt
- src/allowlist/custom.txt

---

## Related Projects

Part of the Nova toolkit:

- IPNova — routing-aware IPv4 dataset
- DomainNova — mainland China infrastructure domain dataset
- OSNova — system deployment engine

---

## License

MIT
