#!/bin/bash
# п.6 владельца: idle поставочного config/config.yaml, старый бинарь против нового, пара ABBA.
#   w88-idle-ship.sh <SRC_BASE> <SRC_NEW> <OUT> [IDLE_S=900] [ORDER="base new new base"]
# На каждое окно: события/с (сумма ebpf_guard_events_total), CPU с/с, heap (go_memstats_heap_inuse_bytes, МиБ) на конце окна.
# Конфиг — config/config.yaml СВОЕГО дерева (file_rate: 50 в поставке у обоих) + w88-ship-cfg-patch.py (порт/токены/пути).
set -u
BASE=${1:?SRC_BASE}; NEW=${2:?SRC_NEW}; OUT=${3:?OUT}; IDLE=${4:-900}; ORDER=${5:-"base new new base"}
HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/w85-second-agent-lib.sh"
export PATH=$PATH:/usr/local/go/bin
rm -rf "$OUT"; mkdir -p "$OUT"; exec > "$OUT/driver.log" 2>&1
trap 'sa_stop 2> /dev/null; echo "агентов после: $(ps -eo cmd | grep -c "[e]bpf-guard --config")"' EXIT
die() { echo "die: $*" > "$OUT/DONE"; echo "DIE: $*"; exit 1; }
# Волна 9, ночь: рабочий агент остановлен пайплайном на время пары (ровно один агент на машине) — EXPECT_AGENTS=0.
[ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq "${EXPECT_AGENTS:-1}" ] || die "ожидалось агентов до запуска: ${EXPECT_AGENTS:-1}"
mval() { sa_metrics | grep -a "^$1 " | awk '{print $2}'; }
evsum() { sa_metrics | grep -a '^ebpf_guard_events_total' | awk '{s += $2} END {printf "%.0f", s}'; }
i=0
for r in $ORDER; do
    i=$((i+1)); case $r in base) SRC=$BASE ;; new) SRC=$NEW ;; *) die "роль $r" ;; esac
    d="$OUT/w$i-$r"; mkdir -p "$d"
    SA_CFG_FROM=config/config.yaml SA_CFG_PATCH="$HERE/w88-ship-cfg-patch.py" sa_start "$SRC" /root/w88-idle-run 19262 || die "агент $r не поднялся"
    sleep 120
    c0=$(mval process_cpu_seconds_total); e0=$(evsum); t0=$(date +%s.%N)
    sleep "$IDLE"
    c1=$(mval process_cpu_seconds_total); e1=$(evsum); t1=$(date +%s.%N)
    heap=$(mval go_memstats_heap_inuse_bytes)
    awk -v c0=$c0 -v c1=$c1 -v e0=$e0 -v e1=$e1 -v t0=$t0 -v t1=$t1 -v r=$r -v i=$i -v h=$heap 'BEGIN { dt=t1-t0; printf "w%d %-4s cpu %.3f с за %.0f с = %.4f с/с; событий %d (%.0f/с); %.1f мкс CPU на событие; heap_inuse %.1f МиБ\n", i, r, c1-c0, dt, (c1-c0)/dt, e1-e0, (e1-e0)/dt, (c1-c0)/(e1-e0)*1e6, h/1048576 }' | tee "$d/idle.txt"
    sa_stop; sleep 5
done
echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
