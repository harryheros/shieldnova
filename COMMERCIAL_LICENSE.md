# Commercial Licensing — ShieldNova

ShieldNova is open for non-commercial use under [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/).

Commercial use requires a separate written license agreement.

---

## Scope — What This License Covers

Commercial licensing covers **ShieldNova's own original work**: curation,
classification, organization, annotations, allowlists, cleansing and merge
logic, enrichment, and the generated distribution formats.

It does **not** cover, and does not purport to restrict, the underlying
third-party factual data (individual malicious, tracking, or advertising
domains) obtained from upstream threat-intelligence sources. That data remains
subject to its original licenses — see [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md).
A party obtaining the same domains directly from those upstream sources does not
require a ShieldNova commercial license for that data.

In short: you license ShieldNova's curation and packaging, not the raw facts it
organizes.

---

## What Requires a Commercial License

The following uses require explicit prior written authorization from the author:

- **SaaS deployment** — hosting ShieldNova as part of a paid or freemium service
- **API resale** — exposing ShieldNova data or functionality via a commercial API
- **OEM / white-label** — bundling ShieldNova into a product sold to third parties
- **Enterprise internal use** — deploying ShieldNova within a commercial organization beyond personal or research use
- **Redistribution** — redistributing ShieldNova data or outputs as part of a paid product or service
- **Integration into paid products** — embedding ShieldNova into software or services that generate revenue

---

## What Does Not Require a Commercial License

- Personal, non-commercial use
- Academic research and education
- Open-source projects under a compatible non-commercial license
- Evaluation and testing (non-production)
- Use as a filter list in [DNSNova](https://github.com/harryheros/dnsnova), in any deployment, commercial ones included (see below)

---

## Exception: use in DNSNova

ShieldNova may be used free of charge as a filter list in DNSNova, the
Nova DNS server, including in commercial deployments: the server downloads
the list and blocks the domains on it for its clients. This permission
covers that use only. It does not allow redistributing the list, offering
it through another product or service, or using it outside DNSNova; those
still need a commercial license. Third-party data in the list keeps its own
terms (see THIRD_PARTY_NOTICES.md).

---

## Contact

For commercial licensing inquiries, including enterprise plans, OEM rights, API redistribution, and white-label deployment:

→ Use the form at https://novaod.com/licensing  
→ Or write to licensing@novaod.com

Please include a brief description of your intended use case: which data, what it is for, and roughly how widely it will be used.

---

## Note on License Upgrades

This project may transition to a stronger commercial license (such as BSL, PolyForm, or a custom proprietary license) in future versions. All versions remain subject to the license terms in effect at the time of their release, as stated in the LICENSE file.
