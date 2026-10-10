# Belkin F9K1009/F9K1010 — Hardcoded Active root Password "root" in /etc/shadow

## Affected Software
- **Products:** Belkin F9K1009 v1, F9K1009 v2, F9K1010
- **Firmware:** F9K1009_WW_2.00.09, F9K1009v1_WW_1.00.09, F9K1010_WW_2.00.04
- **Vendor:** Belkin International

## Vulnerability Type
Use of Hard-coded Credentials (CWE-798)

## Description
The `/etc/shadow` in all three firmware images contains an **active** root entry with
the same MD5crypt hash across all models:

```
root:$1$BOYmzSKq$ePjEPSpkQGeBcZjlEeLqI.:13796:0:99999:7:::
```

The password is the string `root` (verified by recomputation with `openssl passwd -1 -salt BOYmzSKq root`).

All units of these models ship the same hash — one crack compromises the root account
on every device (wherever root access is reachable: serial console, debug interfaces,
post-auth shell).

Additional findings: BusyBox v1.6.1 (2007 build) and MiniUPnPd 1.9 — both far past
their supported windows.

## Verification
```bash
openssl passwd -1 -salt BOYmzSKq root
# → $1$BOYmzSKq$ePjEPSpkQGeBcZjlEeLqI.  (exact match)
```

## CVSS 3.1
**8.0** (AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)

## Suggested Fix
1. Ship per-unit random root credentials (or disable the account entirely)
2. Require physical interaction for console access
3. Update BusyBox to a supported version
