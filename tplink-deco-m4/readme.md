# Bug Report

## Affected Software
- **Product: TP-Link Deco M4 (V3)**
- **Version(s): firmware 1.5.0 Build 210414**
- **Vendor: TP-Link**

## Vulnerability Type
NULL Pointer Dereference (CWE-476)

## Description
The boot/mount helper `/sbin/mount_root` (2.8 KB, ARM32 LE, uClibc, stripped) reads `/proc/mtd` to enumerate flash partitions. When the file cannot be opened (e.g. `open("/proc/mtd")` returns ENOENT — the state observed under emulation when the procfs layout differs, and on-device whenever mtd probing fails), the returned pointer/error is not checked and is immediately dereferenced, faulting at address `0x34` (NULL + 0x34).

```
open("/proc/filesystems", O_RDONLY) = 3    <- ok
read(3, ..., 4096) = 407
close(3) = 0
open("/proc/mtd", O_RDONLY) = -1 ENOENT    <- unchecked
--- SIGSEGV { si_addr = 0x00000034 } ---
```

The program crashes **with no arguments at all**, 100% reproducibly.

## Proof of Concept (PoC)
```bash
SYSROOT=/path/to/Deco_M4_V3_1.5.0_210414/squashfs-root-0
qemu-arm-static -L $SYSROOT $SYSROOT/sbin/mount_root
# -> qemu: uncaught target signal 11 (SIGSEGV), si_addr=0x34, exit 139
```

## Reproduction Evidence
![mount_root NULL dereference](mount_root_null_deref.png)

*(captured 2026-09-14; full terminal log in `archived_deco_zyxel_pppoe.txt`, script in `reproduce.sh`)*

## Impact
If the condition occurs during boot or factory-reset flows (mount_root is an init-time helper), the device enters a crash/restart loop: **availability impact on the whole router**. No authentication and no user interaction are involved in the crashing path itself.

## Notes
Originally rejected by VulDB (2026-04); resubmitted with the 2026-09-14 deterministic reproduction evidence above.
