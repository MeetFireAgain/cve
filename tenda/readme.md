# Tenda Firmware CLI Crash Advisories

Independent security research disclosures for CLI utilities in Tenda router
firmware (reference firmware: Tenda CNVD-2022-89236, ARM32). All crashes were
found with QemuLLMFuzz (LLM-assisted semantic greybox fuzzing), reproduced
under `qemu-arm-static` user-mode emulation, and have a 100% reproduction rate.

| Advisory | Program | Class | Signal | Unique signatures |
|---|---|---|---|---:|
| [pppoe-server-null-deref.md](pppoe-server-null-deref.md) | pppoe-server (rp-pppoe 2.7) | Null Pointer Dereference (CWE-476) | SIGSEGV | 346 |
| [wan_check-sigsegv.md](wan_check-sigsegv.md) | wan_check | TBD (SIGSEGV on boundary values) | SIGSEGV | 21 |
| [websockd-sigsegv.md](websockd-sigsegv.md) | websockd | TBD (SIGSEGV on boundary values) | SIGSEGV | 20 |
| [wlctdm-sigsegv.md](wlctdm-sigsegv.md) | wlctdm | TBD (SIGSEGV on boundary values) | SIGSEGV | 32 |
| [wlctdm-test-sigsegv.md](wlctdm-test-sigsegv.md) | wlctdm_test | TBD (SIGSEGV on boundary values) | SIGSEGV | 34 |

All crashes require local command-line access to the device (or an exploit
chain that reaches these binaries), so they are rated High (availability impact
on embedded services).
