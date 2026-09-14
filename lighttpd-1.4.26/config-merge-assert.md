# Bug Report

## Affected Software
- **Product: lighttpd**
- **Version(s): 1.4.26 as shipped in TP-Link SR20 v1 firmware (2018-05, ARM32)**
- **Vender: TP-Link / lighttpd upstream**

## Vulnerability Type
Reachable Assertion (CWE-617); nested-regex argument also causes catastrophic backtracking (CWE-1333)

## Description
When lighttpd is given multiple `-f` configuration files together with an `-m`
module directory (or a nested-regex `-m` value), the configuration merge code
hits an assertion at `configfile.c:1065`:
`Assertion 'context.all_configs->used == 0' failed`, aborting the process
(SIGABRT). 116 unique crash signatures collected; manual reproduction is 100%
(automated reproduction failed only because the harness deleted its temp config
files after use — the PoC recreates them).

Classified as a robustness/stability defect rather than a memory-safety issue
(abort, not memory corruption).

## Proof of Concept (PoC)
```bash
export QEMU_LD_PREFIX=<SR20 squashfs-root>
echo 'server.port = 80' > /tmp/c1.txt
echo 'server.port = 81' > /tmp/c2.txt
echo x > /tmp/c3.txt
qemu-arm-static $QEMU_LD_PREFIX/usr/sbin/lighttpd -D -m /tmp/c3.txt -f /tmp/c1.txt -f /tmp/c2.txt
# → configfile.c:1065: Assertion failed → SIGABRT (rc=134)
```

## Steps to Reproduce
1. Extract the TP-Link SR20 v1 firmware squashfs-root.
2. Create the three config files and run the command above under
   `qemu-arm-static`; the process aborts with SIGABRT.

## Impact
* Denial of Service: crash of the web server process during startup/reload
  when multiple configuration sources are supplied
* Requires control over the lighttpd command line / service definition

## Reproduction Evidence

![config-merge assertion under qemu-arm-static — SIGABRT after `context.all_configs->used == 0` fails](lighttpd_assert.png)

*config-merge assertion under qemu-arm-static — SIGABRT after `context.all_configs->used == 0` fails*
