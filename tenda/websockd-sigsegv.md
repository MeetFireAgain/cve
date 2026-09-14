# Bug Report

## Affected Software
- **Product: websockd**
- **Version(s): as shipped in Tenda firmware (reference: Tenda CNVD-2022-89236, ARM32)**
- **Vender: Tenda**

## Vulnerability Type
NULL Pointer Dereference / out-of-bounds access (CWE-476, exact class pending disassembly)

## Description
The `websockd` WebSocket daemon crashes with SIGSEGV on boundary command-line
arguments. 20 unique crash signatures, 100% reproduction rate. Typical trigger
patterns: `-a 65536` (port above uint16 range), `--max-connections 0`,
`--ip 0.0.0.0` combinations.

## Proof of Concept (PoC)
```bash
export QEMU_LD_PREFIX=<firmware squashfs-root>
qemu-arm-static $QEMU_LD_PREFIX/bin/websockd -a 65536 --max-connections 0 --ip 0.0.0.0
# → SIGSEGV (rc=139)
```

## Steps to Reproduce
1. Extract the Tenda firmware squashfs-root.
2. Run the PoC under `qemu-arm-static`; process terminates with SIGSEGV.
3. Reproducer scripts (20) available on request.

## Impact
Denial of Service of the WebSocket service on the device.
