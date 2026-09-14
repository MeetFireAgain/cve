# Tenda Firmware CLI Crash Advisories

Independent security research disclosures for CLI utilities in Tenda router
firmware (Tenda AX1803 v2 (AX1803V2.0), firmware V1.0.0.1 (build 1382106), ARM32). All crashes were
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

## Reproduction evidence (2026-09-08 package, re-captured 2026-09-14)

| Screenshot | Content |
|---|---|
| [pppoe_C.png](pppoe_C.png) | `-C` family — URL double-encoding traversal payloads, SIGSEGV |
| [pppoe_L.png](pppoe_L.png) | `-L` family — `999.999.999.999` IP parse, SIGSEGV |
| [attribution_pppoe.png](attribution_pppoe.png) | crash-to-root-cause attribution for the pppoe-server families |
| [wan_check.png](wan_check.png) | wan_check boundary-value crashes |
| [websockd.png](websockd.png) | websockd boundary-value crashes |
| [wlctdm.png](wlctdm.png) / [wlctdm_test.png](wlctdm_test.png) | wlctdm family crashes |

Full crash corpora (unique signatures + per-signature `reproduce.sh`):
see the `crashes/` tree of the 2026-09-08 `vuln_submission_package`.
