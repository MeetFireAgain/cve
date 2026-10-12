# Xiaomi BE6500 (RN02) — MQTT Credential Deterministic Derivation (CWE-330)

## Affected Software
- **Product:** Xiaomi Router BE6500 (RN02, Qualcomm IPQ5332)
- **Version(s):** miwifi_rn02_firmware_1.0.64 (other RN02 firmware likely affected)
- **Vendor:** Xiaomi Corporation

## Vulnerability Type
Use of Insufficiently Random Values (CWE-330) + Hard-coded Cryptographic Key (CWE-321)

## Description
The MQTT control plane (mosquitto 2.0.13, TLS port 8883) uses a custom
authentication plugin (`libmqtt_auth_plugin.so`) whose client password is
**entirely derived from a single static input** — no server challenge, no
temporal factor, no device entropy:

```
password = base64( sha512( username[2:16] + "_" + K + SALT16 ) )
SALT16   = b"miwifi\x00\x00" + b"\x24\x08\x23\x6e" + b"\x65\x74\x11\x00"
```

Where `K` is the mesh/WHC backhaul key (uci wireless config). Any mesh child
node holding K can compute valid MQTT credentials for any username, permanently.
After authentication there is **no ACL** — full topic publish/subscribe including
the miio device control plane (device discovery, control, cloud bridging).

## End-to-End Verification (QEMU full-system simulation)

1. Reverse-engineered the complete derivation formula from Fate-encrypted Lua plugins
2. Computed forged MQTT credentials using the extracted formula
3. Connected to broker: **CONNACK rc=6 accepted**, "New client connected"
4. Obtained full topic pub/sub permissions (same as legitimate internal clients)

Real device in standalone mode returns rc=5 (expected — K does not exist without
mesh). In mesh deployments, child nodes hold K and the forgery path is active.

## PoC
```python
# Formula (verified against broker acceptance):
import hashlib, base64
username = "XQ" + "A"*14 + "_" + "B"*10 + "_" + "C"*10
K = <mesh_backhaul_key>  # from: uci get wireless.@wifi-iface[0].key
SALT = b"miwifi\x00\x00\x24\x08\x23\x6e\x65\x74\x11\x00"
password = base64.b64encode(
    hashlib.sha512(username[2:16].encode() + b"_" + K.encode() + SALT).digest()
).decode()
# → connect to <router_ip>:8883 with TLS using username/password
```

Full PoC script available on request (includes TLS + protocol matrix).

## Impact
- Mesh child nodes can impersonate any MQTT identity (including the parent router)
- Full miio device control: discover, command, cloud-bridge IoT messages
- Permanent validity (no rotation, no challenge-response)

## CVSS 3.1
**7.4** (AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

## Suggested Fix
1. Add per-device entropy (serial number / miot did) to the derivation
2. Implement challenge-response authentication
3. Add topic-level ACL after authentication
