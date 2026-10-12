# Belkin F9K1009/F9K1010 — Hardcoded root Password "root" (CVE-2025-8730)

> **Note**: This vulnerability has been assigned **CVE-2025-8730** (August 2025, Zeropath).
> The advisory below documents independent confirmation of the same finding.

## Affected Software
- **Products:** Belkin F9K1009 v1, F9K1009 v2, F9K1010
- **Firmware:** F9K1009_WW_2.00.09, F9K1009v1_WW_1.00.09, F9K1010_WW_2.00.04
- **Vendor:** Belkin International

## Vulnerability Type
Use of Hard-coded Credentials (CWE-798) — CVE-2025-8730

## Description
The `/etc/shadow` in all three firmware images contains an **active** root entry
with the same MD5crypt hash:

```
root:$1$BOYmzSKq$ePjEPSpkQGeBcZjlEeLqI.:13796:0:99999:7:::
```

The password is `root`, verified across all three models (identical hash).
Additional findings: BusyBox v1.6.1 (2007), MiniUPnPd 1.9.

## Verification
```bash
openssl passwd -1 -salt BOYmzSKq root
# → $1$BOYmzSKq$ePjEPSpkQGeBcZjlEeLqI.  (exact match across 3 models)
```

## References
- [CVE-2025-8730 (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2025-8730)
- [Zeropath Analysis (Aug 2025)](https://zeropath.com)
