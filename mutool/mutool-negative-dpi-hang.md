# Bug Report

## Affected Software
- **Product: mutool draw (MuPDF)**
- **Version(s): reproduced on the official MuPDF 1.25.4 release build (2026-09-14, compiled from mupdf-1.25.4-source.tar.gz) and on Ubuntu 22.04's mupdf-tools 1.19.0; original finding was on a self-built x86-64 tree**
- **Vender: Artifex Software**

## Vulnerability Type
Infinite Loop / hang on negative DPI (CWE-835) — Denial of Service

## Description
`mutool draw` performs **no validation** of the `-r` resolution option
(`source/tools/mudraw.c`: `case 'r': resolution = fz_atof(fz_optarg);` — no
clamp, no sign check). A negative DPI flows directly into
`zoom = resolution / 72; fz_pre_scale(...)`. With a content-bearing page this
drives the renderer into a non-terminating loop; the process hangs and must be
killed.

Re-verification 2026-09-14 (MuPDF 1.25.4, official tarball build):

| Command | Result |
|---|---|
| `mutool draw -r 99 mips_extensions.pdf` | completes (exit 0) |
| `mutool draw -r -990 mips_extensions.pdf` | **hangs — killed by timeout (exit 124)** |

Note: the hang depends on page content — a trivial single-shape test PDF
completes; the original trigger document (libdwarf 0.9.2 `doc/mips_extensions.pdf`)
hangs deterministically.

## Proof of Concept (PoC)
```bash
# trigger document: libdwarf 0.9.2 release, doc/mips_extensions.pdf
# https://github.com/davea42/libdwarf-code (tag v0.9.2)
timeout 15 mutool draw -o /tmp/out%d.png -r -990 mips_extensions.pdf; echo $?
# → 124 (hung until killed); control: -r 99 exits 0
```

## Steps to Reproduce
1. Download libdwarf v0.9.2 and take `doc/mips_extensions.pdf`.
2. Run the PoC command with any mutool ≥ 1.19; the process does not terminate.

## Impact
Denial of Service: any pipeline that renders with user-controlled resolution
(document preview / thumbnail services) can be hung, tying up worker slots
indefinitely. No upstream bug report exists for this issue as of 2026-09-14
(checked bugs.ghostscript.com and GitHub).
