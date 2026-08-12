#!/bin/bash
# restore-root.sh — SM-F9360 (q4q, F9360ZCSAIZF1) 重启后恢复临时 root + KernelSU
# 用法: ./restore-root.sh [SERIAL]
# 前置: 设备已解锁 adb、exploit 二进制与 ko 已在 /data/local/tmp/
# 说明: 每步都验证，失败即停；root 通道丢失时不要 pkill，直接重启重来。
set -u

SERIAL="${1:-RFCW31TJJ0T}"
ADB="adb -s $SERIAL"
TMP=/data/local/tmp
KO=kernelsu-c12-nolto.ko
LOADER=ksu-load.so

say()  { echo -e "\033[1;32m[+] $*\033[0m"; }
fail() { echo -e "\033[1;31m[-] $*\033[0m"; exit 1; }

say "1/5 等待设备就绪"
$ADB wait-for-device || fail "adb 无法连接 $SERIAL"

say "2/5 等待负载降至 2.5 以下（exploit 高负载必失败）"
for i in $(seq 1 60); do
    L=$( $ADB shell 'cat /proc/loadavg' 2>/dev/null | awk '{print $1}' | tr -d '\r' )
    ok=$(awk -v l="$L" 'BEGIN{print (l<2.5)?1:0}')
    [ "$ok" = "1" ] && break
    [ "$i" -eq 60 ] && fail "60 次轮询后负载仍 >= 2.5（当前 $L），手动检查设备状态"
    sleep 10
done
say "loadavg=$L ✓"

say "3/5 运行 exploit（临时 root）"
$ADB shell "cd $TMP && KSU_LOAD_ONLY=1 EXP32_STAMP_OFF=0x58 EXPLOIT_ATTEMPTS=3 \
  LD_PRELOAD=$TMP/cve-2026-43499 nohup sh -c 'sleep 3600' > $TMP/exp.log 2>&1"
# exploit 是异步的：轮询 root 通道（最多 ~4 分钟）
ROOT_OK=0
for i in $(seq 1 48); do
    sleep 5
    OUT=$( $ADB shell "timeout 5 $TMP/cve-2026-43499-root -c 'id'" 2>/dev/null | tr -d '\r' )
    case "$OUT" in
        *uid=0*) ROOT_OK=1; say "root 通道就绪: $OUT"; break;;
        *) ;;
    esac
done
[ "$ROOT_OK" = 1 ] || { fail "exploit 未达成 root（日志: $TMP/exp.log）。可能是坏 slide boot，重启重试"; }

say "4/5 打开 kallsyms + 加载 KernelSU 模块"
$ADB shell "timeout 10 $TMP/cve-2026-43499-root -c 'echo 0 > /proc/sys/kernel/kptr_restrict'" \
    || fail "kptr_restrict 置零失败"
$ADB shell "timeout 60 $TMP/cve-2026-43499-root -c 'sh -c \"KSU_KO_PATH=$TMP/$KO \
    KSU_KO_PARAMS=allow_shell=1 LD_PRELOAD=$TMP/$LOADER \
    /system/bin/true > $TMP/ksu-load.log 2>&1\"'" || fail "加载命令执行失败"

say "5/5 验证"
LOG=$($ADB shell "cat $TMP/ksu-load.log 2>/dev/null" | tr -d '\r')
echo "$LOG"
echo "$LOG" | grep -q "KernelSU loaded OK" || fail "模块未加载（ksu-load.log 见上）"
$ADB shell "cat /proc/modules" | grep -q kernelsu || fail "/proc/modules 无 kernelsu"
$ADB shell "su -c id" | tr -d '\r' | grep -q "u:r:ksu:s0" || fail "su 未生效"
say "✓ KernelSU Live + su 可用 + Manager 应显示内核版本"
say "完成（如需 Manager 授权请打开 App）"
