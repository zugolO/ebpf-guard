#!/bin/bash
# Волна 8.6, заход B, шаг 7: idle CPU второго агента, базы против нового бинаря, окна ABBA (A=base, B=new) подряд,
# без пакета атак: узел один и тот же, порядок ловит дрейф. На каждое окно: дельта process_cpu_seconds_total (с/с),
# число событий движка (сумма ebpf_guard_events_total) → CPU на событие, и профиль pprof (доля EvaluateInto).
# Рабочий ebpf-guard-test не трогается. Ориентир, не вердикт.
#   w86-b-idle-ab.sh <SRC_BASE> <SRC_NEW> <OUT> [IDLE_S=240] [ORDER="base new new base"]
set -u
BASE=${1:?SRC_BASE}; NEW=${2:?SRC_NEW}; OUT=${3:?OUT}; IDLE=${4:-240}; ORDER=${5:-"base new new base"}
HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/w85-second-agent-lib.sh"
export PATH=$PATH:/usr/local/go/bin
rm -rf "$OUT"; mkdir -p "$OUT"; exec > "$OUT/driver.log" 2>&1
trap 'sa_stop 2> /dev/null; echo "агентов после: $(ps -eo cmd | grep -c "[e]bpf-guard --config")"' EXIT
die() { echo "die: $*" > "$OUT/DONE"; echo "DIE: $*"; exit 1; }
[ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 1 ] || die "ожидался ровно один (рабочий) агент до запуска"
mval() { sa_metrics | grep -a "^$1 " | awk '{print $2}'; }
evsum() { sa_metrics | grep -a '^ebpf_guard_events_total' | awk '{s += $2} END {printf "%.0f", s}'; }
i=0
for r in $ORDER; do
    i=$((i+1)); case $r in base) SRC=$BASE ;; new) SRC=$NEW ;; *) die "роль $r" ;; esac
    d="$OUT/w$i-$r"; mkdir -p "$d"
    sa_start "$SRC" /root/w86-b-abrun 19252 || die "агент $r не поднялся"
    sleep 60
    c0=$(mval process_cpu_seconds_total); e0=$(evsum); t0=$(date +%s.%N)
    curl -s --max-time $((IDLE+60)) -H "Authorization: Bearer $SA_TOKEN" "$SA_API/debug/pprof/profile?seconds=$((IDLE-5))" > "$d/cpu.pprof"
    sleep 5
    c1=$(mval process_cpu_seconds_total); e1=$(evsum); t1=$(date +%s.%N)
    awk -v c0=$c0 -v c1=$c1 -v e0=$e0 -v e1=$e1 -v t0=$t0 -v t1=$t1 -v r=$r -v i=$i 'BEGIN { dt=t1-t0; printf "w%d %-4s cpu %.3f с за %.0f с = %.4f с/с; событий %d (%.0f/с); %.1f мкс CPU на событие\n", i, r, c1-c0, dt, (c1-c0)/dt, e1-e0, (e1-e0)/dt, (c1-c0)/(e1-e0)*1e6 }' | tee "$d/idle.txt"
    ( cd /root && go tool pprof -top -cum -focus='RuleEngine..EvaluateInto' -nodecount=2 "$SRC/build/ebpf-guard" "$d/cpu.pprof" 2> /dev/null | sed -n 1,12p > "$d/pprof-eval.txt" )
    go tool pprof -top -focus='SyscallCountReader' -nodecount=4 "$SRC/build/ebpf-guard" "$d/cpu.pprof" 2> /dev/null | sed -n 1,12p > "$d/pprof-poll.txt"
    sa_stop; sleep 5
done
echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
