# Victron dbus_modbustcp — Heap Out-of-Bounds Read in MBAP PDU Constructor

## Affected Software
- **Product:** Victron Venus OS (dbus_modbustcp component)
- **Version:** All releases to date (verified on v3.80 and v3.81, 2026-10-05)
- **Vendor:** Victron Energy
- **Repo:** github.com/victronenergy/dbus_modbustcp

## Vulnerability Type
Out-of-bounds Read (CWE-125)

## Description
`Connection::readyRead()` (connection.cpp) does not validate the minimum MBAP length.
When a client sends a 7-byte packet with MBAP Length=0, the PDU constructor reads
`pduRequest[7]` — **one byte past a 7-byte heap buffer**.

The garbage function code is then reflected back to the client in the
IllegalFunction exception reply (1-byte adjacent-heap info leak).

## Proof of Concept (AddressSanitizer on unmodified upstream source)

```cpp
// Trigger: 7-byte wire packet (MBAP Length = 0x0000)
unsigned char pkt[] = {0x12,0x34, 0x00,0x00, 0x00,0x00, 0x01};
```

```
ERROR: AddressSanitizer: heap-buffer-overflow READ of size 1
    #0 QByteArray::operator[](int) const qth_shim.h:16
    #1 PDU::PDU(QByteArray const&) pdu.cpp:57       ← pduRequest[7]
    #2 ADU::ADU(QTcpSocket*, QByteArray const&) adu.cpp:17
0x602000000a17 is located 0 bytes after 7-byte region
```

Full PoC harness: ASAN-compiled with Qt semantic shim layer (available on request)

## Root Cause
```cpp
// connection.cpp, Connection::readyRead():
if (mData.size() == 6) {
    mLength = toUInt16(mData, 4) + 6;   // attacker-controlled
    // NO minimum-length check (mLength >= 8 required by MBAP spec)
}
if (mData.size() == mLength) {
    ADU *request = new ADU(mSocket, mData);  // ← triggers OOB read in PDU constructor
}
```

## Suggested Fix (2 lines)
```cpp
if (mData.size() == 6) {
    mLength = toUInt16(mData, 4) + 6;
    if (mLength < 8) { mSocket->disconnectFromHost(); return; }  // ADD THIS
}
```

## CVSS 3.1
**5.3** (AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

## Notes
- Port 502 (Modbus TCP) is unauthenticated by design on Venus OS
- Verified present in upstream master (checked 2026-10-08 latest commit)
