#!/usr/bin/env python3
"""Upload a 100 KB file to the 8 KB tmpfs-backed FTP root (NO fault injection).
If LightFTP is correct it must answer 4xx/5xx; a 226 answer = silent data loss."""
import socket, os, sys

HOST, PORT = "127.0.0.1", 2121
FTP_ROOT = "/tmp/tinyfs/ftpshare"
SIZE = 100_000

def rl(s):
    d = b""
    while b"\r\n" not in d:
        c = s.recv(4096)
        if not c:
            break
        d += c
    return d.decode(errors="replace").strip()

s = socket.socket(); s.settimeout(10); s.connect((HOST, PORT))
print("[banner]", rl(s))
s.sendall(b"USER uploader\r\n"); rl(s)
s.sendall(b"PASS Weakuploaderpassword111\r\n"); print("[login]", rl(s))
s.sendall(b"PASV\r\n"); r = rl(s)
a, b = r[r.find("(")+1:r.find(")")].split(",")[-2:]
ds = socket.socket(); ds.settimeout(10); ds.connect((HOST, int(a)*256+int(b)))
s.sendall(b"STOR bigfile.bin\r\n"); print("[stor ]", rl(s))
ds.sendall(b"D" * SIZE); ds.close()
final = rl(s)
print(f"[*] Server final response: {final}")

path = os.path.join(FTP_ROOT, "bigfile.bin")
disk = os.path.getsize(path) if os.path.exists(path) else -1
print(f"[*] Sent {SIZE} bytes, on disk: {disk} bytes")
s.sendall(b"QUIT\r\n"); s.close()

if final.startswith("226") and 0 <= disk < SIZE:
    print("[!] VULNERABILITY CONFIRMED WITH REAL FULL DISK (tmpfs, no LD_PRELOAD)")
    sys.exit(0)
print(f"[-] Not reproduced: response={final[:3]}, disk={disk}")
sys.exit(1)
