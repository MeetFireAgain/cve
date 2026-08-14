# CVE Disclosure Repository

Security vulnerability disclosures discovered by the FirmChain research project.

## Vulnerabilities

### D-Link DSL-3782 — Command Injection (C5)
- **Status:** Unreported, pending CVE assignment
- **Severity:** High (post-auth root RCE)
- **Directory:** [`dlink-dsl3782/`](dlink-dsl3782/)
- **Endpoint:** `/cgi-bin/New_GUI/Set/Diagnostics.asp` param `Addr` → `system()`
- **Firmware:** Build 2016-07-28 (SHA-256: c8faaffbac46...)


## Coordinated Disclosure

All vulnerabilities are reported to the respective vendors under coordinated
disclosure. This repository contains PoC details and proof evidence. Do not
use these exploits against devices you do not own or have authorization to test.

## Research

Discovered by FirmChain — autonomous dynamic-analysis pipeline for
cross-component firmware vulnerability mining.
