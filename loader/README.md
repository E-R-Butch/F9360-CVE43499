# ksu-load — KernelSU manual-relocation loader (Samsung 5.10, locked BL)

Samsung's DEFEX interceptor kills `execve()` of any new ELF from the
kernel domain (`u:r:kernel:s0`), so neither a standalone `insmod` binary nor
`ksud` can run as root. What DOES run: a shared object whose constructor is
executed by the dynamic linker when it loads into an **existing** binary —
library loading is not hooked by DEFEX.

`ksu-load.so` (built with `-DKSU_LOAD_AS_SO`) is that constructor:

1. reads the module from `$KSU_KO_PATH`;
2. parses `/proc/kallsyms` (root must first run
   `echo 0 > /proc/sys/kernel/kptr_restrict`);
3. rewrites every `SHN_UNDEF` symbol in the module's `.symtab` to
   `SHN_ABS` + `st_value = runtime absolute address` (kallsyms addresses
   already include the KASLR slide);
4. optionally patches `.modinfo` vermagic in place (only needed for
   modules whose vermagic doesn't match the device — the no-LTO build from
   this repo matches natively);
5. calls `init_module(2)`.

Why `SHN_ABS` instead of resolving via `__ksymtab`: absolute symbols are
never passed to `find_symbol()` or `check_version()`, which clears **all
three** Samsung load walls at once:

- `TRIM_UNUSED_KSYMS` stripped ~40 needed exports → `Unknown symbol (err -2)`;
- modversions CRC mismatch → `disagrees about version of symbol module_layout`;
- vermagic mismatch (mitigated at build time anyway).

Requires a module built with a **zero-length `__versions` section**
(see README §6 for the no-LTO clang-12 build recipe).

## Build

```bash
$ANDROID_NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android30-clang \
  -shared -fPIC -O2 -DKSU_LOAD_AS_SO -o ksu-load.so ksu-load.c
```

Standalone CLI mode (without `-DKSU_LOAD_AS_SO`, for shell-domain testing):
`ksu-load <module.ko> [param=value ...]`.

## Trigger

```bash
# as kernel-domain root (from the CVE exploit daemon):
KSU_KO_PATH=/data/local/tmp/kernelsu-c12-nolto.ko \
KSU_KO_PARAMS=allow_shell=1 \
LD_PRELOAD=/data/local/tmp/ksu-load.so /system/bin/true
```

Success: `patched=201 missing=0 | KernelSU loaded OK (manual relocation, 201 symbols)`
and `kernelsu ... Live (O)` in `/proc/modules`.

## Notes / traps

- kallsyms on this kernel has ~490k entries — the table cap is 600k.
  A 65536-entry cap silently truncates and reports every symbol MISSING.
- `kptr_restrict=2` on Samsung hides ALL addresses even from kernel-domain
  root — skip `addr==0` lines; flip `kptr_restrict` to 0 first.
- Output is unbuffered (`setvbuf(_IONBF)`) so a panic inside
  `init_module` still leaves a readable log.
- **Never `rmmod kernelsu` on Samsung** — the exit path restores the
  syscall table on RKP-protected memory and hard-panics the device.
