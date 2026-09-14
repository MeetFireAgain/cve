#!/bin/bash
# Archived vuln items #3 (Deco M4 mount_root), #4 (ZyXEL NBG2105 reload),
# #5 (Tenda CNVD-2022-88837 pppoe-server) — recipes from original apport
# crash reports in RRcov/dataset/datasetB/crash/.
QB=/home/webfuzz/Documents/qemu-rrfuzz/build
DECO=/tmp/fw_deco/Deco_M4_V3_1.5.0_210414/squashfs-root-0
ZYX=/tmp/fw_zyxel/NBG2105_V1.00_AAGU.2_C0/squashfs-root
TENDA=/tmp/fw_tenda

echo '===== #3 TP-Link Deco M4 V3 1.5.0: /sbin/mount_root NULL+0x34 deref ====='
echo '$ qemu-arm -L <deco-rootfs> sbin/mount_root   (reads /proc/mtd; absent in user-mode)'
timeout 20 $QB/qemu-arm -L "$DECO" "$DECO/sbin/mount_root"
echo "[exit=$?] (139 = SIGSEGV)"

echo
echo '===== #4 ZyXEL NBG2105: /bin/reload argument stack overrun ====='
echo '$ qemu-mips -L <zyxel-rootfs> bin/reload -u http://[::1]:65535/PATH -e $USER -d jyc... --flag on -n -1'
timeout 20 $QB/qemu-mips -L "$ZYX" "$ZYX/bin/reload" -u 'http://[::1]:65535/PATH' -e "$USER" -d 'jycCCphpui1AcnDJN7vI' --flag on -n -1
echo "[exit=$?] (139 = SIGSEGV, si_addr lands on stack guard page)"

echo
echo '===== #5 Tenda CNVD-2022-88837: pppoe-server -m 9999999999 integer overflow ====='
if [ ! -d "$TENDA" ]; then
  mkdir -p "$TENDA"
  unzip -qo /home/webfuzz/Documents/RRcov/dataset/datasetB/cnvd_2022_88837.zip -d "$TENDA" 2>/dev/null
fi
PP=$(find "$TENDA" -name pppoe-server -type f 2>/dev/null | head -1)
echo "pppoe-server binary: $PP"
if [ -n "$PP""x" ] && [ -f "$PP" ]; then
  SYSROOT=$(dirname $(dirname "$PP"))
  echo "A" > /tmp/pool.txt
  echo '$ qemu-arm -L <tenda-sysroot> pppoe-server -p pool -s pool -m 9999999999 -k -h  (original recipe)'
  timeout 20 $QB/qemu-arm -L "$SYSROOT" "$PP" -p /tmp/pool.txt -s /tmp/pool.txt -m 9999999999 -k -h
  echo "[exit=$?] (139 = SIGSEGV integer-overflow family)"
  echo
  echo '$ variant: pppoe-server pool.txt -L 999.999.999.999 -C AAAA'
  timeout 20 $QB/qemu-arm -L "$SYSROOT" "$PP" /tmp/pool.txt -L 999.999.999.999 -C AAAA
  echo "[exit=$?]"
else
  echo "!! pppoe-server binary not found after extraction"
fi
