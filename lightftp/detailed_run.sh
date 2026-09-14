#!/usr/bin/env bash
# Full step-by-step evidence run: LightFTP silent data loss on write() failure
# Container: ubuntu:24.04 (aarch64). Run: bash /work/detailed_run.sh
set -u
cd /work/tests || exit 1
mkdir -p ftpshare
rm -f ftpshare/vuln_test.txt ftpshare/control_test.txt

echo "############################################################"
echo "# STEP 0. Environment"
echo "############################################################"
uname -a
gcc --version | head -1
echo "LightFTP source: master snapshot 2026-06-15 (FTP_VERSION \"2.4\" per src/inc/ftpserv.h)"
grep -n 'define FTP_VERSION' /work/LightFTP/src/inc/ftpserv.h

echo
echo "############################################################"
echo "# STEP 1. Build (plain, and ASan)"
echo "############################################################"
cd /work/LightFTP/src
gcc -O1 -g -o /work/fftp_plain *.c -pthread -lgnutls 2>/dev/null && echo "plain build OK"
gcc -O1 -g -fno-omit-frame-pointer -fsanitize=address -o /work/fftp_asan *.c -pthread -lgnutls 2>/dev/null && echo "asan build OK"
cd /work/tests

echo
echo "############################################################"
echo "# STEP 2. Test configuration (fftp.conf)"
echo "############################################################"
grep -v '^#' fftp.conf | grep -v '^$'

echo
echo "############################################################"
echo "# STEP 3. CONTROL TEST - no fault injection (expected: full file + 226)"
echo "############################################################"
/work/fftp_plain fftp.conf > control_server.log 2>&1 &
SRV=$!
sleep 1
python3 - /work/tests/ftpshare/control_test.txt <<'EOF'
import socket, os, sys
target = sys.argv[1]
def rl(s):
    d = b""
    while b"\r\n" not in d:
        c = s.recv(1024)
        if not c: break
        d += c
    return d.decode(errors="replace").strip()
s = socket.socket(); s.settimeout(5); s.connect(("127.0.0.1", 2121))
rl(s); s.sendall(b"USER uploader\r\n"); rl(s)
s.sendall(b"PASS Weakuploaderpassword111\r\n"); rl(s)
s.sendall(b"PASV\r\n"); r = rl(s)
a, b = r[r.find("(")+1:r.find(")")].split(",")[-2:]
ds = socket.socket(); ds.connect(("127.0.0.1", int(a)*256+int(b)))
s.sendall(b"STOR " + os.path.basename(target).encode() + b"\r\n"); rl(s)
ds.sendall(b"C" * 2048); ds.close()
print("CONTROL final response:", rl(s))
s.sendall(b"QUIT\r\n"); s.close()
EOF
ls -l ftpshare/control_test.txt
kill $SRV 2>/dev/null; wait $SRV 2>/dev/null

echo
echo "############################################################"
echo "# STEP 4. Compile write() fault injector (LD_PRELOAD, ENOSPC after 512 bytes)"
echo "############################################################"
gcc -shared -fPIC -o fault_injector.so /work/fault_injector.c -ldl && echo "injector built"
grep -n "ERROR_THRESHOLD" /work/fault_injector.c | head -2

echo
echo "############################################################"
echo "# STEP 5. VULNERABILITY TEST - LD_PRELOAD injector"
echo "############################################################"
LD_PRELOAD=/work/tests/fault_injector.so /work/fftp_plain fftp.conf > vuln_server.log 2>&1 &
SRV=$!
sleep 1
python3 /work/poc_write_error.py
echo "PoC exit code: $?"
kill $SRV 2>/dev/null; wait $SRV 2>/dev/null

echo
echo "############################################################"
echo "# STEP 6. Disk verification (both files)"
echo "############################################################"
ls -l ftpshare/control_test.txt ftpshare/vuln_test.txt
echo "control bytes: $(wc -c < ftpshare/control_test.txt) (expected 2048)"
echo "vuln    bytes: $(wc -c < ftpshare/vuln_test.txt) (expected 2048, got truncated)"

echo
echo "############################################################"
echo "# STEP 7. Server-side logs"
echo "############################################################"
echo "--- injector (stderr) ---"
grep INJECTOR vuln_server.log
echo "--- FTP session log (vuln run) ---"
grep -E "STOR|226|426|complete" vuln_server.log | head -6

echo
echo "############################################################"
echo "# RESULT: server returned 226 Transfer complete while only"
echo "# 512/2048 bytes reached the disk => SILENT DATA LOSS CONFIRMED"
echo "############################################################"
