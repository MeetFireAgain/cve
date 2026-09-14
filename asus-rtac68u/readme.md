# Bug Report

## Affected Software
- **Product: ASUS RT-AC68U — httpd (web management daemon)**
- **Version(s): firmware archive as tested (version string pending extraction from the image); ARM32**
- **Vendor: ASUS**

## Vulnerability Type
Stack-based Buffer Overflow via long URL (CWE-121), remote DoS confirmed

## Description
The RT-AC68U `httpd` crashes when the request line contains an over-long URL. A single `GET /AAAA…` (4000 bytes) terminates the process with SIGSEGV (core dumped) and the listening port stops accepting connections. Verified 2026-09-14 under QEMU ARM user-mode emulation with an NVRAM stub (`LD_PRELOAD=libnvfuzz_arm.so`, standard firmware-emulation practice), strict baseline-ALIVE/listener-death criterion:

```
baseline: ALIVE
GET /AAAA(4000) -> recv=b'' ; listener=DEAD (ConnectionRefusedError)
qemu: uncaught target signal 11 (Segmentation fault) - core dumped
```

The overflow is in the request-line/URL handling of the vendor httpd. Unauthenticated, single request, LAN-side.

## Proof of Concept (PoC)
`evidence/ac68u_a720r.sh` (section 1). Minimal trigger:

```python
s.connect(("router", 80)); s.send(b"GET /" + b"A"*4000 + b" HTTP/1.1\r\nHost: x\r\n\r\n")
# httpd: SIGSEGV, listener dead
```

## Reproduction Evidence
![RT-AC68U httpd listener death](evidence/ac68u_a720r_listener_death.png)

*(captured 2026-09-14; raw log `evidence/ac68u_a720r_listener_death.txt`)*

## Impact
* **Availability**: remote unauthenticated DoS of the web management interface (crash loop if watchdog restarts)
* Potential code-execution impact of the overflow itself not yet assessed (crash-only evidence)

## Note
Firmware version string to be extracted from the tested image and added here before vendor disclosure.
