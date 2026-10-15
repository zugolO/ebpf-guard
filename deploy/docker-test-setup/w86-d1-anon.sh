#!/bin/bash
# Волна 8.6, заход B, Д1 / №559: накопление anon хоста. Четыре ячейки P1 (таблица процессов) × F1 (предикаты в ядре)
# вкл/выкл — ЧЕТЫРЕ вторых агента одновременно (равные окна по построению), каждый — транзитный юнит systemd со своей
# cgroup, без рестарта в окне. Снимок раз в INTERVAL: memory.stat (anon) cgroup, Anonymous из smaps_rollup и go memstats
# агента (HeapInuse, HeapIdle−HeapReleased, StackInuse, Sys) из его /metrics.
# Рабочий ebpf-guard-test НЕ трогается. Окно не смешивать с замерами CPU/бенча (правило захода B).
#   w86-d1-anon.sh <SRC> <OUT> [HOURS=2] [INTERVAL=300]
# Выход: $OUT/<ячейка>/snap.tsv, $OUT/meta.txt, $OUT/DONE; разбор — w86-d1-report.py.
# Оговорка симметрии: каждый агент видит bpf() трёх других и рабочего (F3 исключает только свой tgid); это одинаково для
# всех ячеек, поэтому разность между ячейками остаётся приписываемой P1/F1; by_nr{321} печатается в снимке — контроль.
set -u
SRC=${1:?SRC}; OUT=${2:?OUT}; HOURS=${3:-2}; INTERVAL=${4:-300}
HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/w85-second-agent-lib.sh"
rm -rf "$OUT"; mkdir -p "$OUT"; exec > "$OUT/driver.log" 2>&1
CELLS="p1on_f1on p1on_f1off p1off_f1on p1off_f1off"
declare -A PIDS CGS APIS
cleanup() { for c in $CELLS; do systemctl stop "w86d1-$c" 2> /dev/null; done; echo "агентов после: $(ps -eo cmd | grep -c '[e]bpf-guard --config')"; }
trap cleanup EXIT
die() { echo "die: $*" > "$OUT/DONE"; echo "DIE: $*"; exit 1; }
echo "[$(date -u +%FT%TZ)] w86-d1-anon git $(cat "$SRC/GIT-HEAD" 2>/dev/null) hours=$HOURS interval=$INTERVAL"
[ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 1 ] || die "ожидался ровно один (рабочий) агент до запуска"

cat > "$OUT/f1off.py" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
# F1 выкл: предикаты в ядре (kernel_filter.arg_predicates) отключены, остальное то же
assert 'kernel_filter:' in s, 'нет секции kernel_filter'
s = s.replace('kernel_filter:\n    enabled: true\n', 'kernel_filter:\n    enabled: true\n    arg_predicates:\n      enabled: false\n', 1)
assert 'arg_predicates:\n      enabled: false' in s, 'правка F1 не применилась'
open(p, 'w').write(s)
PY
cat > "$OUT/f1on.py" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
s = s.replace('kernel_filter:\n    enabled: true\n', 'kernel_filter:\n    enabled: true\n    arg_predicates:\n      enabled: true\n', 1)
assert 'arg_predicates:\n      enabled: true' in s, 'правка F1 не применилась'
open(p, 'w').write(s)
PY

port=19240
for c in $CELLS; do
    port=$((port+1)); d="$OUT/$c"; mkdir -p "$d"
    case $c in *p1off*) export SA_PROC_TABLE=off ;; *) unset SA_PROC_TABLE ;; esac
    case $c in *f1off) export SA_CFG_PATCH="$OUT/f1off.py" ;; *) export SA_CFG_PATCH="$OUT/f1on.py" ;; esac
    export SA_UNIT=w86d1-$c
    sa_start "$SRC" "/root/w86-d1-run-$c" $port || die "ячейка $c не поднялась"
    PIDS[$c]=$SA_PID; CGS[$c]=$SA_CG; APIS[$c]=$SA_API
    st=$(curl -s -H "Authorization: Bearer $SA_TOKEN" "$SA_API/metrics" | grep -a '^ebpf_guard_proc_table_state' | grep -a ' 1$' | sed 's/.*state="\([^"]*\)".*/\1/')
    echo "cell=$c pid=$SA_PID cg=$SA_CG port=$port proc_table=$st start=$(date -u +%T)" | tee -a "$OUT/meta.txt"
    case $c in *p1on*) [ "$st" = active ] || die "ячейка $c: таблица $st, а ждали active" ;; *p1off*) [ "$st" != active ] || die "ячейка $c: таблица active при off" ;; esac
    unset SA_UNIT SA_CFG_PATCH SA_PROC_TABLE
done

snap() { # <cell>
    local c=$1 cg=${CGS[$c]} pid=${PIDS[$c]} api=${APIS[$c]}
    local m; m=$(curl -s --max-time 10 -H "Authorization: Bearer $SA_TOKEN" "$api/metrics")
    g() { echo "$m" | grep -a "^$1 " | awk '{printf "%.0f", $2}'; }
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(date +%s)" \
        "$(grep -a '^anon ' "$cg/memory.stat" | awk '{print $2}')" \
        "$(grep -a '^Anonymous:' /proc/$pid/smaps_rollup | awk '{print $2*1024}')" \
        "$(g go_memstats_heap_inuse_bytes)" "$(g go_memstats_heap_idle_bytes)" "$(g go_memstats_heap_released_bytes)" \
        "$(g go_memstats_stack_inuse_bytes)" "$(g go_memstats_sys_bytes)" "$(g go_memstats_heap_alloc_bytes)" \
        "$(echo "$m" | grep -a '^ebpf_guard_syscall_events_by_nr_total{nr="321"}' | awk '{printf "%.0f", $2}')" \
        "$(grep -a '^file ' "$cg/memory.stat" | awk '{print $2}')" >> "$OUT/$c/snap.tsv"
}
for c in $CELLS; do printf 'ts\tcg_anon\tproc_anonymous\theap_inuse\theap_idle\theap_released\tstack_inuse\tsys\theap_alloc\tby_nr_321\tcg_file\n' > "$OUT/$c/snap.tsv"; done
SA_TOKEN=${SA_TOKEN:-w85u1smoketoken0123456789abcdef012}
end=$(( $(date +%s) + HOURS*3600 ))
n=0
while [ "$(date +%s)" -lt "$end" ]; do
    for c in $CELLS; do
        kill -0 "${PIDS[$c]}" 2> /dev/null || die "ячейка $c умерла на снимке $n"
        snap "$c"
    done
    n=$((n+1)); sleep "$INTERVAL"
done
for c in $CELLS; do snap "$c"; done
echo "snapshots=$n end=$(date -u +%FT%TZ)" >> "$OUT/meta.txt"
echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
