# Advisory: RouterOS btest Kernel Module Use-After-Free → slab-out-of-bounds Write

**CVE**: 待分配（提交 MikroTik 后）
**Status**: Independently discovered via syzkaller + GPL source audit + protocol RE
**Discovery**: 2026-06-29 (syzkaller auto-found), 2026-07-01 (admin-gated reachability confirmed), 2026-07-02 (precise TOCTOU root cause)
**Affected**: RouterOS v6.40.5 + v7.20.8 (long-term)，btest.ko 存在于所有带 bandwidth-test 的版本
**Class**: CWE-416 (Use-After-Free) → CWE-787 (Out-of-bounds Write)
**Severity**: High (RCE candidate, controllable kernel memory corruption)
**Authentication**: admin-gated（需 admin 主动 `/tool bandwidth-test`，社会工程/钓鱼场景）

---

## 1. 漏洞概述

RouterOS bandwidth-test 内核模块（btest.ko）在 socket 回调注册后存在 Use-After-Free。`sk_data_ready` 回调（软中断路径）与 `sock_put` 释放之间存在 TOCTOU 竞态窗口，导致访问已释放 sock → slab-out-of-bounds Write。

**可达性修正（关键）**：之前认为 "real-but-unreachable（需 root）"。完整逆向后确认 **admin-gated 主动可达**：RouterOS `/tool bandwidth-test` 内部 open /dev/btest + ioctl 传 socket fd（admin 操作，不需 Linux root）。攻击者诱导 admin 对恶意 btest server 发起测试即可触发。

## 2. 受影响版本

| 版本 | btest.ko | /tool bandwidth-test | 受影响 |
|---|---|---|---|
| v6.40.5 | ✅ (4988B, /proc/modules 确认) | ✅ | ✅ |
| v7.20.8 (long-term) | ✅ | ✅ (实测串口确认) | ✅ |
| **v7.21.5 (long-term, 2026-07-06)** | ✅ | ✅ | **✅ 未修 (逻辑级验证)** |
| **v7.23.3 (stable, 2026-07-30 build)** | ✅ | ✅ | **✅ 未修 (逻辑级验证)** |

**⚠️ 2026-09-02 修正**: 早前 "7.20.8/7.21.5/7.23.3 逐指令 0 差异" 的结论**有误**（对比脚本漏比了位移立即数）。正确结论：
- 三个版本的 .text **指令序列与逻辑完全相同**，但存在 **27 字节的 struct 字段偏移立即数差异**（如 `0x2d8→0x2f0` 访问 struct sock 字段的位移随各版本内核的 struct 布局漂移）——每个出厂模块都是针对**各自版本内核的 ABI** 编译的
- 导入符号表（UND）三版完全相同——仍无 `synchronize_rcu` 等新增同步原语，**竞态代码逻辑在全部三版存活**
- 因此"未修"的判定不变，但证据等级从"逐字节相同"降为"逻辑级相同 + 无修复痕迹"

### 2a. 三组对照实验 (2026-09-02, syz机 内网测试机, KVM+KASAN)

方法: 自建 5.6.3 KASAN 内核 (原 syz 配置) + GPL 同源码构建模块 + 原 repro.cprog 弹幕 (15×20s), 证据: `mikrotik/evidence/` (3 份 KASAN 串口日志)

| 组 | 模块 | 结果 |
|---|---|---|
| A (阳性对照) | GPL btest.ko 未修改 | **✅ KASAN 命中 ×2 独立轮次** — `BUG: KASAN slab-out-of-bounds _raw_spin_lock_bh+0x77` / `__skb_recv_udp+0x1ee` / `btest_data_ready+0x112` (与 2026-06 原始报告逐偏移一致), boot 后 ~3s 引爆; Allocated-by/Freed-by 栈齐备 |
| C (阴性对照) | + `synchronize_rcu()` 补丁 (验证过已编译进二进制, 导入符号确证) | **❌ 仍然崩溃, 同签名** (`btest_data_ready+0x112 [btest_fixed]`) |

**🔴 重大修正 (实验证伪了我方原修复建议)**: `btest_release` 中 `cancel_work_sync` 后加 `synchronize_rcu()` **不足以修复** — data_ready 运行于 NET_RX 软中断, 不在普通 RCU 读临界区内, RCU 宽限期等不到它。且 `synchronize_rcu_bh()` 在 5.6 已移除 (RCU-bh API 5.0 消失), 无现成软中断屏障。**正确修复方向**: `btest_data_ready` 内部对 sk 持有引用 (进入时 sock_hold / 退出时 sock_put) 或等效机制 — §7 修复建议已相应更新。此发现使漏洞对 MikroTik 的修复难度评估上调 (简单屏障补丁无效)。

### 2b. 出厂二进制无法在仪器化内核动态测试的 ABI 墙 (2026-09-02, syz机实验)

尝试将出厂 btest.ko 加载入自建 KASAN 内核（vermagic 精确匹配 "5.6.3-64 SMP mod_unload"）进行动态复现，逐层失败并揭示原因：
1. **struct module 布局错位**: 出厂模块 `this_module.init` 指针在偏移 **0x178**，GPL x86_64.config 构建的内核在 **0x150** 读取 → init 永不被调用，模块"空载"（加载成功但零注册）
2. 用 MikroTik 的 configs/x86_64.config 重建内核后 init 偏移对齐 0x178，但继而 **`Unknown symbol make_kuid`** → 证明 **GPL 包里的 x86_64.config 不是他们真实构建配置**（真实构建开 USER_NS，文件里却未开）
3. 补 USER_NS 后 → **`Invalid module format`: exit 指针偏移仍不一致**（0x2c0 vs 0x308）→ 真实配置仍有更多未知差异
4. 出厂模块 .text 中的 struct sock 字段位移（0x2d8→0x2f0 等）进一步证明其编译目标的内核 ABI 与任何可复现配置不同
**结论**: 在无 MikroTik 真实内核构建配置的前提下，**出厂二进制在任何自建内核上的动态测试在技术上不可行且不安全**（错位访问会得出无效结果）。动态验证只能以 GPL 同源码构建模块为代理（§2a），出厂二进制的验证以逻辑级静态对比为准。

### 2c. 生产内核实机验证 (2026-09-01/09-02, 出厂 7.23.3 内核+模块)

**方法**: QEMU 直启出厂 bzImage + `slub_debug=FZPU` (生产内核 CONFIG_SLUB_DEBUG=y, boot 参数即激活毒化/红区/sanity/user-tracking 检测) + vmnet-host + 线程版 evil btest server (工具默认 connection-count=20 并发) + 串口 CLI `/tool bandwidth-test` 随机 duration(1-5s) 链式循环 (duration 结束时 evil server 仍在洪水 → release 发生在数据到达中 = 真实竞态窗口)。工具链存档 `btest_slub_repro_rig/`; A组在此内核弹幕 15×20s 亦未命中 (时序依赖, 见 §2a 阳性对照在 -syz 配置内核 3s 引爆)。

**结果 (两轮, 诚实记录)**:
- 攻击链路全通: 握手成功、数据流动 (st=running, local-cpu-load 100%)、release 窗口反复制造
- **两日累计 ~40 个有效竞态窗口 (单机+3机并行, 随机时长)** — **SLUB BUG/oops 未触发**; flash panic 日志三机全零 (连非 UAF panic 都无)
- **可复现行为异常 (wedge)**: 一次 bandwidth-test 后后续测试大多卡 "connecting", ~80-90s 后部分恢复 (~10% 成功率); 与 server 版本/防火墙无关, fresh boot 两连发即现 — 机制未定 (TIME_WAIT 类正常现象 vs btest 模块/工具状态残留), 可单独报 MikroTik
- **结论**: 出厂内核无 KASAN, 静默 UAF 不即时报错; TCG+CLI 节奏 (~1 有效窗口/80s) 与 syzkaller 的每秒千次 ioctl 循环差 4-5 个数量级, 竞态未命中属预期。**确定性 crash 复现必须 syz 机 (KASAN) + repro.cprog 对 shipped btest.ko** — 待 原内网测试机 可达 (今日探测: TCP 有响应但非 sshd, 疑似异网设备)

## 3. 漏洞机制（精确 TOCTOU）

### 触发架构
```
admin: /tool bandwidth-test <server>
  → RouterOS 工具: open("/dev/btest") + socketpair(AF_UNIX) + ioctl(START, {fd, BTEST_RECEIVE})
  → btest_start: sock_hold(sk); sk->sk_data_ready = btest_data_ready  [劫持回调]
```

### UAF 竞态（data_ready 路径，软中断）
```
CPU A (release/btest_stop):              CPU B (软中断, 收UDP包 → data_ready):
  state->started = false  [L535]          if(!state->started) return  [L157 检查]
  cancel_work_sync  [L536]               __skb_recv_udp(sk,...)       [L162 用 sk]
  sk->sk_data_ready = old  [L541]         spin_lock_bh(&state->lock)   [L173 越界写]
  sock_put(sk)  [L545: 释放sk]
```
**窗口**: data_ready L157 检查 started 通过后、L162 用 sk 前，release 执行 sock_put 释放 sk → UAF。
**关键**: cancel_work_sync 只同步 tx_task(work_struct)，**不保护 data_ready**（软中断回调，不在 work queue）。

### tx_task 路径实测否定
tx_task 在 unlock 后用 sk（L420-421），但 cancel_work_sync 同步等待它完整返回。fuzz VM 200 次循环 KASAN **无 UAF** → tx_task 路径**无窗口**。

## 4. KASAN 确认（syzkaller）
```
BUG: KASAN: slab-out-of-bounds in _raw_spin_lock_bh
Write of size 4 at ffff88806aeb4414
Call Trace: __skb_recv_udp ← btest_data_ready ← unix_dgram_sendmsg ← sendmsg
Allocated: unix_create1 (socketpair, 1024B UNIX slab)
Freed: unix_release_sock (close fd0)
```

## 5. RCE 可行性
- **写入可控度**: 中（UAF 可堆风中继，socketpair 喷射 UNIX 1024B slab 控制相邻对象）
- **写入语义**: spinlock atomic_try_cmpxchg（非任意指针，写 lock 值）
- **直接 RCE**: 困难，但可改相邻 slab 元数据（引用计数/length）间接利用
- **DoS**: 确定（panic）
- **结论**: **RCE 候选**（需专业内核利用），优于 SAME（SAME 算术硬约束不可 RCE）

## 6. PoC（admin-gated）
```
# 攻击者: 恶意 btest server (TCP 2000, evil_btest_server.py)
# 协议: server-first HELLO(01000000)→client HELLO→client Command(12B)→AUTH_OK→数据流

# 受害者 admin:
/tool bandwidth-test address=<attacker> direction=down
  → open /dev/btest + ioctl START + socketpair
  → 恶意 server 高速回 UDP btest 包
  → admin 停止 (Ctrl-C) → close(/dev/btest) → release
  → release vs data_ready 竞态 → UAF
```
完整 syz repro: `原内网测试机:~/syz_work/work_btest_backup/crashes/41e4ec7b.../repro.cprog`

## 7. 修复建议（2026-09-02 实验修正版）

⚠️ 原建议 (release 中 `cancel_work_sync` 后加 `synchronize_rcu()`) **已被对照实验证伪**（§2a C 组：打补丁模块同签名崩溃）——data_ready 在 NET_RX 软中断运行，不受普通 RCU 宽限期约束；`synchronize_rcu_bh()` 已在 5.6 移除。

**可行修复方向**（供 MikroTik 参考）:
```c
// 方向1 (推荐): btest_data_ready 自持引用, 从根上消除窗口
static void btest_data_ready(struct sock *sk) {
    sock_hold(sk);                    // 进入即持引用, 退出归还
    ... 原 __skb_recv_udp / spin_lock_bh 逻辑 ...
    sock_put(sk);
}
// 注意: 需保证与 btest_release 的回调摘除逻辑配对 (摘除后不得再有新调用持有)

// 方向2: release 侧在摘除回调后、sock_put 前, 用本地 bh 屏障等待在飞软中断
// (5.6 无现成 API, 需自定义; e.g. per-cpu 计数 + local_bh_enable 等待)
```
纵深: 同时审查 btest_tx_task 对 sk 的使用 (本实验未复现其窗口, cancel_work_sync 覆盖)。

## 8. 时间线
- 2026-06-29: syzkaller 自动发现 5 个 btest crash（同一根因）
- 2026-07-01: 逆向 btest 握手协议，确认 admin 主动可达
- 2026-07-02: 精确 TOCTOU 根因（data_ready），tx_task 实测否定
- 2026-09-01: 出厂二进制三版逻辑级验证未修; 生产内核攻击台实机演练 (§2c)
- 2026-09-02: syz 机三组对照 (§2a) — 阳性对照二次命中 (3s 引爆); **证伪 synchronize_rcu 修复**; ABI 墙确证 (§2b)
- 待提交: MikroTik supportsec (90 天期限 2026-09-30)

## 9. 参考
- GPL 源码: btest/btest.c
- 详细分析: kernel-gpl/btest-uaf-precise-analysis.md
- 恶意 server: evil_btest_server.py
- 协议: github.com/manawenuz/btest-rs
