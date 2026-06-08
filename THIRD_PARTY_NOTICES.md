# Third-Party Notices — ShieldNova

ShieldNova aggregates and enriches domain threat-intelligence data drawn from
several third-party sources. **Rights in the underlying source data remain with
their respective owners and original licenses.** The ShieldNova license
(CC BY-NC-SA 4.0, plus the separate commercial terms) applies only to
ShieldNova's own contributions — see "Scope" at the bottom of this file.

The sources below are consumed by `scripts/fetch_threat_intel.py`. Where a
source publishes under a permissive license (e.g. MIT), that permissive license
continues to govern the underlying data even as it appears inside ShieldNova;
ShieldNova does not and cannot relicense that data.

---

## Sources

### abuse.ch — URLhaus
- **Used for:** active malware-distribution domains (`src/security/malware.txt`)
- **URL:** https://urlhaus.abuse.ch/
- **Terms:** abuse.ch datasets are published for the security community. URLhaus
  data is provided free of charge; attribution to abuse.ch / URLhaus is expected.
  Refer to https://urlhaus.abuse.ch/api/ for current usage terms.

### abuse.ch — ThreatFox
- **Used for:** recent malware indicators of compromise (`src/security/malware.txt`)
- **URL:** https://threatfox.abuse.ch/
- **Terms:** Published by abuse.ch for the security community; ThreatFox data is
  available under CC0 (public domain dedication) per abuse.ch documentation.
  Refer to https://threatfox.abuse.ch/ for current terms.

### adblock-nocoin-list (hoshsadiq)
- **Used for:** cryptojacking / in-browser mining domains (`src/security/cryptojacking.txt`)
- **URL:** https://github.com/hoshsadiq/adblock-nocoin-list
- **License:** MIT License. The MIT permission notice covers the upstream data;
  reproduce the upstream copyright and permission notice when redistributing the
  derived entries.

### Phishing.Database (mitchellkrogza)
- **Used for:** confirmed active phishing domains (`src/security/phishing.txt`)
- **URL:** https://github.com/mitchellkrogza/Phishing.Database
- **License:** MIT License. As with nocoin, the upstream MIT terms continue to
  govern these entries; they are not relicensed under ShieldNova's terms.

> The license identifications above reflect each project's stated license at the
> time of writing. They are not legal advice. Verify the current LICENSE file in
> each upstream repository before relying on it; upstream terms can change.

---

## Scope of the ShieldNova License

ShieldNova's CC BY-NC-SA 4.0 license and its separate commercial terms apply to
**ShieldNova's own value-added work only**, namely:

- manual curation and classification of domains into categories
- the allowlist and false-positive handling
- cleansing, de-duplication, and merge logic
- annotations and section organization
- the build pipeline and generated output formats

They do **not** assert ownership over, or impose new restrictions on, the raw
factual data (individual malicious/tracking/advertising domains) obtained from
the third-party sources above. A party that obtains the same domains directly
from those upstream sources is governed by the upstream licenses, not by
ShieldNova's terms.
