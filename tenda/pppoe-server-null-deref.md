# Bug Report

## Affected Software
- **Product: pppoe-server (rp-pppoe)**
- **Version(s): rp-pppoe 2.7 as shipped in Tenda firmware (Tenda AX1803 v2 (AX1803V2.0), firmware V1.0.0.1 (build 1382106, image_version 5027GWTR98_YD_AX1803V21382106), ARM32)**
- **Vender: Tenda**

## Vulnerability Type
NULL Pointer Dereference (CWE-476)

## Description
The `pppoe-server` binary shipped in Tenda firmware crashes with SIGSEGV when
certain command-line options receive boundary or malformed values. 346 unique
crash signatures were collected across the option families `-C` (122), `-L`
(61), `-o` (38), `-T` (34), `-p` (33), `-S` (32), `-I` (16), `-N` (15) and
others. Representative patterns:

- `-L 999.999.999.999` — out-of-range IP literal (suspected unvalidated
  `inet_aton` result followed by dereference)
- `-C <overlong string>` — strings longer than 60 characters
- `-C '%2e%2e/%2e%2e/.../etc/iss'` — double URL-encoded path traversal payloads
- Empty option values combined with otherwise valid arguments

All crashes reproduce deterministically (100%; 363 crash files, 190 unique argv
signatures, independently re-verified 2025-10 and 2026-09-08).

## Proof of Concept (PoC)
```bash
export QEMU_LD_PREFIX=<firmware squashfs-root>
qemu-arm-static $QEMU_LD_PREFIX/bin/pppoe-server -L 999.999.999.999
# → SIGSEGV (rc=139)
```

## Steps to Reproduce
1. Extract the Tenda AX1803 v2 firmware (V1.0.0.1, build 1382106) squashfs-root. Target binary MD5-12: fa2950ab55a2.
2. Run the PoC command above under `qemu-arm-static`.
3. The process terminates with SIGSEGV. Full reproducer scripts: 34
   `reproduce.sh` files in the research crash archive (available on request).

## Impact
* Denial of Service of the PPPoE server service on the device
* If any web/management interface passes user-controlled values to these
  options, the crash becomes remotely triggerable
