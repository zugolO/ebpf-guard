#!/bin/bash
# w85-ab-mem.sh <SRC> <OUT> [REPEATS=3] [PACK=1] — пара A3/A4 (решение владельца 13.10, ч.2, п. 2): Go-куча, пик старта и
# memory.current ВТОРОГО агента с таблицей процессов (on) и без неё (off, тот же бинарь, SA_PROC_TABLE=off), R повторов на
# СМЕЖНЫХ окнах: порядок в повторе чередуется (on→off, off→on, on→off), чтобы дрейф узла не приписался таблице.
# Агент — транзитный юнит systemd (SA_UNIT, своя cgroup): читается memory.current, а не VmHWM процесса.
#   пик старта        — максимум memory.current по выборке 10 Гц за первые 75 с после запуска юнита;
#   после пакета      — heap_inuse/heap_alloc из /metrics и memory.current после пакета атак (максимум выборки 1 Гц за пакет).
# Рабочий агент ОСТАНАВЛИВАЕТСЯ на всю серию окон (пакет требует ровно одного агента) и поднимается обратно в любом
# исходе. PACK=0 — без пакета (отладка прибора).
# Выход: $OUT/r<k>-<mode>/{start.tsv,pack.tsv,m-start.txt,m-end.txt,meta.txt}, $OUT/DONE.
set -u
SRC=${1:?SRC}; OUT=${2:?OUT}; R=${3:-3}; PACK=${4:-1}; HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/w85-second-agent-lib.sh"
rm -rf "$OUT"; mkdir -p "$OUT"; exec > "$OUT/driver.log" 2>&1
restore() { sa_stop 2> /dev/null; systemctl start ebpf-guard-test.service; sleep 5; echo "агентов после: $(ps -eo cmd | grep -c '[e]bpf-guard --config'); рабочий: $(systemctl is-active ebpf-guard-test.service)"; }
trap restore EXIT
die() { echo "die: $*" > "$OUT/DONE"; echo "DIE: $*"; exit 1; }
echo "[$(date -u +%FT%TZ)] w85-ab-mem git $(cat "$SRC/GIT-HEAD" 2>/dev/null) R=$R PACK=$PACK"
[ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 1 ] || die "ожидался ровно один (рабочий) агент до запуска"
window() { # <k> <mode>
    local k=$1 mode=$2 d="$OUT/r$1-$2"; mkdir -p "$d"
    [ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 0 ] || die "перед окном $k-$mode есть агент (рабочий не остановлен или второй не снят)"
    if [ "$mode" = off ]; then export SA_PROC_TABLE=off; else unset SA_PROC_TABLE; fi
    export SA_UNIT=w85-mem-$mode
    local t0; t0=$(date +%s.%N)
    sa_start "$SRC" /root/w85-run-mem-$mode 19231 || die "агент ($mode) не поднялся"
    [ -r "$SA_CG/memory.current" ] || die "нет $SA_CG/memory.current"
    local st; st=$(sa_metrics | grep -a '^ebpf_guard_proc_table_state' | grep -a ' 1$' | sed 's/.*state="\([^"]*\)".*/\1/')
    { echo "mode=$mode pid=$SA_PID cg=$SA_CG state=$st"; } > "$d/meta.txt"
    [ "$mode" = on ] && [ "$st" != active ] && die "режим on, а таблица $st"
    [ "$mode" = off ] && [ "$st" = active ] && die "режим off, а таблица active"
    # выборка пика старта: 10 Гц, 75 с от запуска юнита (часть уже прошла в sa_start — пик старта обычно там)
    : > "$d/start.tsv"
    local i
    for i in $(seq 1 750); do
        printf '%s %s\n' "$(date +%s.%N)" "$(cat "$SA_CG/memory.current" 2> /dev/null)" >> "$d/start.tsv"
        [ "$i" -ge 5 ] && [ -z "$(cat "$SA_CG/memory.current" 2> /dev/null)" ] && break
        sleep 0.1
    done
    echo "t0=$t0" >> "$d/meta.txt"
    sa_metrics > "$d/m-start.txt"
    grep -aE '^(VmHWM|VmRSS):' /proc/$SA_PID/status >> "$d/meta.txt"
    : > "$d/pack.tsv"
    if [ "$PACK" = 1 ]; then
        ( while :; do printf '%s %s\n' "$(date +%s)" "$(cat "$SA_CG/memory.current" 2> /dev/null)" >> "$d/pack.tsv"; sleep 1; done ) &
        local sp=$!
        local A="$SRC/deploy/docker-test-setup/attacks"
        ( cd "$A" && EBPF_GUARD_API="$SA_API" EBPF_GUARD_TOKEN="$SA_TOKEN" SKIP_INDUCED_DROP=1 bash ./run-all-attacks.sh > "$d/attacks.log" 2>&1 )
        sleep 30
        kill "$sp" 2> /dev/null; wait "$sp" 2> /dev/null
    else
        sleep 20
    fi
    sa_metrics > "$d/m-end.txt"
    printf '%s %s\n' "$(date +%s)" "$(cat "$SA_CG/memory.current" 2> /dev/null)" > "$d/end.tsv"
    grep -aE '^(VmHWM|VmRSS):' /proc/$SA_PID/status >> "$d/meta.txt"
    sa_stop; unset SA_UNIT
    sleep 5
    echo "окно r$k-$mode: готово $(date -u +%T), агентов $(ps -eo cmd | grep -c '[e]bpf-guard --config')"
    go clean -cache > /dev/null 2>&1
}
# рабочий агент остановлен на ВСЮ серию окон (смежность окон: между ними ничего не запускается); trap его вернёт
systemctl stop ebpf-guard-test.service; sleep 3
for k in $(seq 1 "$R"); do
    if [ $((k % 2)) -eq 1 ]; then window "$k" on; window "$k" off; else window "$k" off; window "$k" on; fi
done
echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
echo "== A3/A4"
OUT=$OUT R=$R bash "$HERE/w85-mem-report.sh" | tee "$OUT/report.txt"
