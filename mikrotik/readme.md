# MikroTik RouterOS Security Advisories

Independent security research disclosures for [MikroTik RouterOS](https://mikrotik.com) ([product page](https://mikrotik.com/software)).

| Advisory | Class | Affected | Fixed | PoC |
|---|---|---|---|---|
| [routeros-ipt-same-integer-overflow-brick.md](routeros-ipt-same-integer-overflow-brick.md) | Integer Overflow (CWE-190) | v6, <=7.20.x | 7.21.5 (LT) / 7.23.1 (ST) | [routeros-same-brick-poc.sh](routeros-same-brick-poc.sh) |
| [routeros-btest-kernel-uaf.md](routeros-btest-kernel-uaf.md) | Use After Free (CWE-416) | 6.x – 7.23.3 | none known | [btest-poc/](btest-poc/) |

- Kernel KASAN / panic evidence: [evidence/](evidence/)
- Coordinated disclosure to MikroTik (security@mikrotik.com) since 2026-07-02; see the timeline sections in each advisory.
- Researcher PoC environment artifacts are reproducible from the advisories; lab-internal identifiers were redacted.
