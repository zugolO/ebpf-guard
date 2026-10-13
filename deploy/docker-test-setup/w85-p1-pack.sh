#!/bin/bash
# w85-p1-pack.sh <SRC> <OUT> <on|off> [BASE_INC] — пакет атак хоста против ВТОРОГО агента из SRC с таблицей процессов
# ядра (on) или на прежнем пути трекера (off, тот же бинарь): критерий 10 волны 2 (доля инцидентов с process_chain),
# чтения /proc трекером за пакет, recall по comm. Пара on/off — одно и то же поведение агента, кроме источника цепочки.
# Рабочий агент ОСТАНАВЛИВАЕТСЯ на время пакета (пакет требует ровно одного агента) и поднимается обратно в любом
# исходе; после скрипта агент один и active — проверяется и печатается.
set -u
SRC=${1:?SRC}; OUT=${2:?OUT}; MODE=${3:?on|off}; BASE_INC=${4:-}; HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/w85-second-agent-lib.sh"
rm -rf "$OUT"; mkdir -p "$OUT"; exec > "$OUT/driver.log" 2>&1
restore() { sa_stop 2> /dev/null; systemctl start ebpf-guard-test.service; sleep 5; echo "агентов после: $(ps -eo cmd | grep -c '[e]bpf-guard --config'); рабочий: $(systemctl is-active ebpf-guard-test.service)"; }
trap restore EXIT
die() { echo "die: $*" > "$OUT/DONE"; echo "DIE: $*"; exit 1; }
[ "$MODE" = on ] || [ "$MODE" = off ] || die "режим on|off"
echo "[$(date -u +%FT%TZ)] w85-p1-pack mode=$MODE git $(cat "$SRC/GIT-HEAD" 2>/dev/null)"
systemctl stop ebpf-guard-test.service; sleep 3
[ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -eq 0 ] || die "рабочий агент не остановился"
if [ "$MODE" = off ]; then export SA_PROC_TABLE=off; fi
sa_start "$SRC" /root/w85-run-pack-$MODE 19199 || die "второй агент не поднялся"
state=$(sa_metrics | grep -a '^ebpf_guard_proc_table_state' | grep -a ' 1$' | sed 's/.*state="\([^"]*\)".*/\1/')
echo "состояние таблицы: $state"
[ "$MODE" = on ] && [ "$state" != active ] && die "режим on, а таблица $state"
[ "$MODE" = off ] && [ "$state" = active ] && die "режим off, а таблица active"
sleep 60
# память агента (A3/A4): VmHWM — пик RSS процесса за жизнь, ядро ведёт сам (на 5.15 нет memory.peak у cgroup); куча Go — из /metrics
memsnap() { # <метка>
    { echo "-- $1 ($(date -u +%T)) pid=$SA_PID"; grep -aE '^(VmHWM|VmRSS):' /proc/$SA_PID/status; sa_metrics | grep -aE '^go_memstats_(heap_inuse|heap_alloc|heap_sys|heap_released|alloc)_bytes '; } >> "$OUT/mem.txt"
}
memsnap "через 60 с после старта (пик старта + idle)"
sa_metrics > "$OUT/m0.txt"; T0=$(date +%s)
A="$SRC/deploy/docker-test-setup/attacks"
ls "$A/attack-results" 2> /dev/null | sort > "$OUT/results-before.lst"
( cd "$A" && EBPF_GUARD_API="$SA_API" EBPF_GUARD_TOKEN="$SA_TOKEN" SKIP_INDUCED_DROP=1 bash ./run-all-attacks.sh > "$OUT/attacks.log" 2>&1; echo "rc=$?" > "$OUT/attacks.rc" )
sleep 30
memsnap "после пакета атак"
sa_metrics > "$OUT/m1.txt"
curl -s --max-time 60 -H "Authorization: Bearer $SA_TOKEN" "$SA_API/api/v1/incidents?limit=1000" > "$OUT/incidents.json"
cp "$A/attack-manifest.json" "$OUT/" 2> /dev/null
ls "$A/attack-results" 2> /dev/null | sort | comm -13 "$OUT/results-before.lst" - > "$OUT/results-new.lst"
for f in $(grep -E '^(baseline|final)-alerts-.*\.json$' "$OUT/results-new.lst"); do cp "$A/attack-results/$f" "$OUT/"; done
cp /root/w85-run-pack-$MODE/agent.log "$OUT/agent.log"
echo "== 8.5.5 (доля инцидентов с process_chain, чтения /proc)"
INC="$OUT/incidents.json" BASE_INC="$BASE_INC" CH_M0="$OUT/m0.txt" CH_M1="$OUT/m1.txt" bash "$HERE/w85-close-report.sh" chain | tee "$OUT/chain.txt"
echo "== recall по comm: $(ATT=$OUT bash "$HERE/w85-close-report.sh" recall)"
echo "== память агента"; cat "$OUT/mem.txt"
echo "== счётчики"
grep -aE '^ebpf_guard_(proc_chain_reads_total|lineage_proc_reads_total|proc_table_events_total|lineage_field_total)' "$OUT/m1.txt" | tee "$OUT/counters.txt"
echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
