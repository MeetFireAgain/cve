#!/usr/bin/env bash
# Evidence run for LightFTP silent data loss (write error)
cd /work/tests || exit 1
rm -f ftpshare/vuln_test.txt server_evidence.log
echo "=== [1] Starting LightFTP (master, plain build) with write() fault injector (ENOSPC after 512 bytes) ==="
LD_PRELOAD=/work/tests/fault_injector.so /work/fftp_plain fftp.conf > server_evidence.log 2>&1 &
SRV=$!
sleep 2
echo "=== [2] Running PoC: upload 2048 bytes as user 'uploader' ==="
python3 /work/poc_write_error.py
RC=$?
echo "PoC_exit_code=$RC"
echo
echo "=== [3] File actually stored on server disk ==="
ls -l ftpshare/vuln_test.txt
echo
echo "=== [4] Server-side injector log ==="
grep INJECTOR server_evidence.log
kill $SRV 2>/dev/null
wait $SRV 2>/dev/null
exit $RC
