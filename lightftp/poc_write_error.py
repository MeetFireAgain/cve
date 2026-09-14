#!/usr/bin/env python3
"""LightFTP silent data loss PoC: LD_PRELOAD fault injector makes write() fail
with ENOSPC after 512 bytes; server must NOT return 226 success.
Run INSIDE container with server already started using fault_injector.so."""
import socket, os, sys

HOST, PORT = "127.0.0.1", 2121
FTP_ROOT = "/work/tests/ftpshare"
TARGET = "vuln_test.txt"
SIZE = 2048

def rl(s):
    data = b""
    while b"\r\n" not in data:
        chunk = s.recv(1024)
        if not chunk:
            break
        data += chunk
    return data.decode(errors="replace").strip()

s = socket.socket(); s.settimeout(5); s.connect((HOST, PORT))
print("[banner]", rl(s))
s.sendall(b"USER uploader\r\n"); print("[user ]", rl(s))
s.sendall(b"PASS Weakuploaderpassword111\r\n"); print("[pass ]", rl(s))
s.sendall(b"PASV\r\n")
resp = rl(s); print("[pasv  ]", resp)
a, b = resp[resp.find("(")+1:resp.find(")")].split(",")[-2:]
dport = int(a) * 256 + int(b)
ds = socket.socket(); ds.settimeout(5); ds.connect((HOST, dport))
s.sendall(f"STOR {TARGET}\r\n".encode()); print("[stor ]", rl(s))
ds.sendall(b"A" * SIZE); ds.close()
final = rl(s)
print(f"[*] Server final response: {final}")

path = os.path.join(FTP_ROOT, TARGET)
disk = os.path.getsize(path) if os.path.exists(path) else -1
print(f"[*] Sent {SIZE} bytes, on disk: {disk} bytes")
s.sendall(b"QUIT\r\n"); s.close()

if final.startswith("226") and 0 <= disk < SIZE:
    print("[!] VULNERABILITY CONFIRMED: 226 success returned but file truncated")
    sys.exit(0)
print("[-] Not reproduced (server reported:", final[:3] + ")")
sys.exit(1)
