#!/usr/bin/env bash
# Real-disk-full reproduction (NO LD_PRELOAD): 8 KB tmpfs as FTP root
set -u
echo "############################################################"
echo "# REAL DISK FULL TEST - no LD_PRELOAD, no fault injector"
echo "############################################################"
echo "--- [1] create an 8 KB tmpfs filesystem ---"
umount /tmp/tinyfs 2>/dev/null
mount -t tmpfs -o size=8k tmpfs /tmp/tinyfs
mkdir -p /tmp/tinyfs/ftpshare && echo "tmpfs mounted (8 KB)"
df -h /tmp/tinyfs | tail -1

echo "--- [2] start LightFTP with FTP root on the tiny tmpfs ---"
cp /work/fftp_tmpfs.conf /tmp/tinyfs/fftp.conf
/work/fftp_plain /tmp/tinyfs/fftp.conf > /tmp/tinyfs/server.log 2>&1 &
SRV=$!
sleep 1
grep -c . /tmp/tinyfs/server.log >/dev/null && echo "server started (no LD_PRELOAD: $(grep -o 'LD_PRELOAD' /proc/$SRV/environ | wc -l) preload vars)"

echo "--- [3] upload a 100 KB file ---"
python3 /work/poc_tmpfs.py
RC=$?

echo "--- [4] disk state after upload ---"
df -h /tmp/tinyfs | tail -1
ls -l /tmp/tinyfs/ftpshare/

kill $SRV 2>/dev/null; wait $SRV 2>/dev/null
echo "PoC exit code: $RC"
exit $RC
