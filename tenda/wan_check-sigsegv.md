# Bug Report

## Affected Software
- **Product: wan_check**
- **Version(s): as shipped in Tenda firmware (Tenda AX1803 v2 (AX1803V2.0), firmware V1.0.0.1 (build 1382106, image_version 5027GWTR98_YD_AX1803V21382106), ARM32)**
- **Vender: Tenda**

## Vulnerability Type
NULL Pointer Dereference / out-of-bounds access (CWE-476, exact class pending disassembly)

## Description
The `wan_check` WAN health-check utility crashes with SIGSEGV when given
boundary-valued command-line arguments. 21 unique crash signatures, 100%
reproduction rate. Typical trigger patterns: port value `65535`, `-t` boundary
values combined with a long URL, `-p 0`, `-i 255.255.255.255`.

## Proof of Concept (PoC)
```bash
export QEMU_LD_PREFIX=<firmware squashfs-root>
qemu-arm-static $QEMU_LD_PREFIX/bin/wan_check \
  -t 65535 -h 'http://localhost:8080/test?query=extremelongvalue...' \
  -i 255.255.255.255 -p 0 -v DEBUG -f /dev/null -x true
# → SIGSEGV (rc=139)
```

## Steps to Reproduce
1. Extract the Tenda AX1803 v2 firmware (V1.0.0.1, build 1382106) squashfs-root.
2. Run the PoC under `qemu-arm-static`; process terminates with SIGSEGV.
3. Reproducer scripts (21) available on request.

## Impact
Denial of Service of the WAN monitoring service; availability impact on the device.
