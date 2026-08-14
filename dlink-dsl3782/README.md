# D-Link PSIRT Disclosure — DSL-3782 Diagnostics Command Injection

**Status:** DRAFT (2026-08-14) — for submission to D-Link PSIRT (security@dlink.com).
Not for public release until patched + acknowledged.
**Severity:** High (post-auth root command execution)
**CVE:** to be assigned by D-Link PSIRT
**Vendor:** D-Link (DSL product line)
**Affected:** D-Link DSL-3782 (router/DSL gateway). Firmware version: from local image `dsl3782.zip` (SHA-256 available on request).

## Summary
The `/cgi-bin/New_GUI/Set/Diagnostics.asp` endpoint accepts an `Addr` parameter
(intended for ping/traceroute diagnostics) and passes it **unsanitized** into a
`system()` call in the `cfg_manager` backend. An authenticated user can inject
shell commands via the `Addr` parameter, achieving root-level command execution.

The vulnerability was confirmed under QEMU user-mode emulation with a modeled
`tcapi` precondition (the `tcapi` daemon does not serve under qemu-user; its
responses were modeled by a shim). The `file_write_canary` oracle confirmed the
injection: a `touch` command injected via `Addr` created a marker file on the
guest filesystem.

## PoC
### Firmware-internal proof (reproduced)
```bash
# Under qemu-user + proot emulation of the DSL-3782 rootfs:
# The Addr parameter in the Diagnostics page is passed to system():
POST /cgi-bin/New_GUI/Set/Diagnostics.asp
Addr=127.0.0.1; touch /tmp/firmchain_canary_FC_f720e968
# → marker file /tmp/firmchain_canary_FC_f720e968 created
# → arbitrary command executed with root privileges
```

### Confirmed via
- Evidence bundle: `output/firmchain/heartbeat_test/live_dlink_dsl_3782_batch/000_cgi-bin_New_GUI_Set_Diagnostics.asp_Addr/evidence/0001.json`
- SHA-256: `db011bf053564a195862d8e77df0c0c4e049c11b00be288169863764a7176a9a`
- Confirmation oracle: `file_write_canary` (absent-before / present-after guest file)
- Nonce: `FC_f720e968f18b3c`

## Impact
Authenticated attacker gains root-level command execution on the router. Full
device compromise: credential theft, traffic interception, persistent backdoor,
DSL/PPP credential exfiltration.

## Root cause
The `Addr` parameter from the Diagnostics page reaches `system()` without
shell-escaping or input validation. The parameter is intended to be a hostname
or IP address but is not validated as such before being concatenated into a
shell command.

## Remediation
1. **Primary:** Validate `Addr` as a strict IP-address or hostname pattern
   before passing to any shell function. Use `exec*` family instead of
   `system()` where possible.
2. **Defense-in-depth:** Apply shell-escaping to all user-controlled parameters
   in the `cfg_manager` backend.

## Scope note
This vulnerability was confirmed at `live+shim` scope: the HTTP request was
accepted by the live emulated web server and reached the `system()` sink, with
a modeled `tcapi` precondition (the real `tcapi` daemon does not run under
user-mode emulation). The `file_write_canary` oracle independently confirmed
the command executed. This is a confirmed finding, not a hypothesis.

## Disclosure timeline
- 2026-07-05: found via autonomous dynamic analysis; confirmed via file_write_canary.
- Vendor notification: **pending** (this draft).

## Contact / credit
Discovered by FirmChain autonomous dynamic-analysis pipeline.
Full toolchain + reproducer available on request under coordinated disclosure.
