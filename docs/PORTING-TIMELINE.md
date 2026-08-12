# 移植历程时间线（SM-F9360 / q4q）

> 三天五轮补档的浓缩版。完整运行历史与逐轮日志在原始工作笔记（未公开）。
> 这里只讲"为什么走这条路"——每条死路都对应一个防御机制。

## 2026-08-10：Stage 1 泄漏管线修复

基础设施：Termux github-debug APK + `run-as com.termux` = `untrusted_app` 域测试环境；
panic 会清零 F2FS 页缓存 → 每次 panic 后 MD5 核对二进制（血泪教训）。

泄漏管线三个地雷（q4q 全踩）：

1. **`APP_REQUIRE_FRESH_P0_SESSION` 必须定义**——否则构建静默走非 fresh 路径，
   MTE 参数、`KS_LEAK_ONLY`、搜索边界全被编译掉。
2. **MTE 是运行时而非配置**——`CONFIG_ARM64_MTE=y` 不代表 MTE 激活，
   设备无 `/sys/kernel/mm/kasan` → `KERNELSNITCH_MTE_ENABLED` 必须 0。
3. **搜索窗口必须覆盖设备真实内存跨度**——e2s 抄来的 2GB 窗口对 q4q 毫无希望：
   12GB 内存分散在 phys 33.8–39.5GB。`/proc/zoneinfo` 读出的真相：
   Normal zone `spanned=10485760`（40GB）、`present=3106304`（11.84GB）。
   窗口改 44GB（`0xffffff8b00000000`）→ mm leak 30/30 命中真实 zone。

futex-hash 模型源码级验证：`hashsize = roundup_pow2(256*8) = 2048`，
`hash_futex = jhash2(key,4,offset) & (hashsize-1)` 与用户态逐字一致。
→ `KERNELSNITCH_FUTEX_HASH_SIZE=2048`（b0q 默认 4096 = 16 核假设，q4q 8 核）。

## 2026-08-11：Stage 1 ROOT 达成

决定性修复链：

1. `P0_KERNEL_PHYS_LOAD=0xa8000000`（b0q/SM8450 真机值）→ CFI 写原语生效。
   （此前 uefi.elf 里读到的 0x80080000 是跨表项的未对齐假阳。）
2. `main.c` 补 `set_unbuffer()`——日志块缓冲导致 panic 时"停在 cfi write"假象，
   实际 exploit 已继续跑到 pipe 阶段。
3. tracefs slide 泄漏跨 boot 不稳定（0x170000/0x48000/0x50000/0x180000 各异，
   均非 2MB 对齐）→ 成功 boot 的 slide 稳定；坏 boot 直接重启重试（b0q README
   "clean boots" 机制）。**不要**在坏 slide boot 上 chase CFI 代码。

结果：uid 2000→0，SELinux permissive，连续 9 次成功。`cve-2026-43499-root -c 'cmd'`
= kernel 域 root 通道。

## 2026-08-11：Stage 2 KSU 加载 —— 三堵墙逐一倒塌

### 墙 1：TRIM_UNUSED_KSYMS（~40 个符号没导出）

尝试 A：**39 函数 wrapper shim**（模块内同名强符号遮蔽 + kallsyms 运行时转发）
→ modpost 过了，但撞墙 2。

尝试 B：**fake-exports ksymtab 劫持**（physrw 改写冷 `__ksymtab` 条目 + 名字串
原位覆盖 + victim 槽 CRC 对齐）→ 设计可行（29/29 符号），但：
- Samsung PREL32 `name_offset` 相对**名字字段（entry+4）**而非条目起点，off-by-4 写坏邻居字符串；
- rodata 物理写触发 KDP monitor → 中途重启；
- 32KB kcrctab 要逐字节 pipe 读（每字节一次 physrw），太慢。
→ 放弃（ksu-load.so 的 SHN_ABS 方案零内核写，见下）。

### 墙 2：modversions CRC

`CONFIG_MODULE_FORCE_LOAD=n` → `IGNORE_MODVERSIONS`/`IGNORE_VERMAGIC` 标志
全走 `try_to_force_load()` → ENOEXEC 死路（init_module 压根没有 flags 参数；
finit_module 的 flag 在 5.10 也只影响签名验证）。
尝试：kcrctab 物理 dump + ko `__versions` CRC 原位 patch → 需要 32KB 逐字节读 + rodata 写，同上放弃。

**转折：zero-`__versions` 构建**（KSU 官方风格，`check_symbol` 直过）+ SHN_ABS 重定位
→ 两堵墙同时消失。BuSung 官方方法的本地复刻。

### 墙 3：DEFEX

测绘结论（setexeccon 降域实验实锤）：DEFEX 拦的是**加载链本身**，与目标域无关；
kernel:s0 exec 新 ELF 必 Killed；`LD_PRELOAD` constructor .so 放行。
→ ksud late-load 作废，自建 `ksu-load.so`（本仓库 loader/）。

### 隐藏 BOSS：CFI jt 槽 + 编译器匹配

- **发现**：`mod->init` 唯一来源 = `__cfi_jt_init_module` 槽（`cfi_init()`）。
  无 jt 槽的 ko "Live" 但 init 从不执行——此前一切假成功的根源。
- **发现**：设备编译器 = AOSP clang 12.0.5 (r416183b)。clang-15/18 编的 ko
  CFI type-id 不兼容 → 加载即 `__cfi_check_fail` panic。
- 尝试：clang-14 手动 jt 槽 + objcopy 改名 → LTO 链接后 jt 符号被丢弃，死路。
- 正解：**clang-12 + 关 CFI**（无 `__cfi_check` → 不注册 CFI shadow）+
  clang-12 天然生成 jt 槽。init 崩溃二分（stub→打点→指令级 nop）确认
  `mrs/ldr` 本身安全后，最终根因浮出水面——

## 2026-08-12 00:35：终极根因 = LTO 拆分布局 🎉

- 现象：clang-12 自编 kernelsu **stub 版也崩**，官方 clang-12 ko stub 版能加载。
- 二分：RELA flags 相同、特殊段官方也有 → 唯一差异 = **function-sections 拆分布局**
  （自编 447 个 ALLOC 段 vs 官方 22 段；`.text` 为 0）。
- 修复：`.config` + `auto.conf` 同步关 LTO/CFI + `SECTION_MISMATCH_WARN_ONLY=y` +
  **清 `.o` 重编**（缓存不随 .config 重建！）→ 传统布局 → **一次加载成功**。

### 最终验证（全绿）

```
ksu-init.log 15/15 mark:
entry → resolver-ok → kdp-ok → cred-ok → defex-ok → syscallhook-ok
→ features-ok → supercalls-ok → rules-ok → cachesid-ok → setupcred-ok
→ escape-ok → allowlist-ok → hookmanager-ok → late-done
su -c id → uid=0(root) context=u:r:ksu:s0
KSU Manager v3.2.5 识别内核版本（supercall 通过）
```

## 探索方法论（可复用到其他设备）

1. **先找同 SoC + 同内核分支的真机 GREEN 社区移植**，比任何静态分析参考都值钱
   （b0q/S22U 救了 q4q；`0xa8000000` 是 SM8450 长寿命约定）。
2. **崩溃二分三板斧**：stub（首指令 ret）区分加载路径 vs init 内部；
   文件打点区分崩点；指令级 `bl→nop` 缩小范围。注意 ARM64 指令小端写入、
   提前返回必须配对（paciasp/SCS push/栈帧三件套）。
3. **设备事实优先于参考值**：zoneinfo、`/proc/version`、`/proc/slabinfo`、
   `/proc/config.gz`——每个数字都要能追溯到设备本身。
4. **日志无缓冲**：panic 时块缓冲 = 丢证据。
5. **系统负载是隐性变量**：fork 风暴 + futex park 线程在负载 >2.5 时被 LMKD
   静默 SIGKILL，日志停在固定字节数——等负载降，别 chase 代码。
