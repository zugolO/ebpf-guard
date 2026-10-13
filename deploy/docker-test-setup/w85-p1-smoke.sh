#!/bin/bash
# w85-p1-smoke.sh <SRC> [OUT] — живой смок P1 (таблица процессов в ядре) и 8.4 на втором агенте из SRC (HEAD).
# Рабочий агент не трогается. Порядок: (0) ПЕРВЫМ делом — exec filename шебанг-скрипта (основа 8.4.2);
# (1) второй агент, состояние таблицы и счётчики хуков; (2) сверка цепочек с /proc; (3) контроль мс-цепочки
# nginx→bash→curl; (4) контроли 8.4.2 (dpkg -r и спуфы); (5) счётчик /proc-чтений трекера и F3.
# Окно — только сон и вызовы скриптов; в окнах ssh не ходит ([[waiting-loop-must-not-ssh-into-window]]).
set -u
SRC=${1:?SRC}; OUT=${2:-/var/tmp/w85-p1}; HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/w85-second-agent-lib.sh"
rm -rf "$OUT"; mkdir -p "$OUT"; exec > "$OUT/driver.log" 2>&1
die() { echo "die: $*" > "$OUT/DONE"; echo "DIE: $*"; sa_stop 2> /dev/null; exit 1; }
echo "[$(date -u +%FT%TZ)] w85-p1-smoke: SRC=$SRC git $(cat "$SRC/GIT-HEAD" 2>/dev/null) бинарь $(cut -c1-12 "$SRC/BINARY-SHA256" 2>/dev/null)"
[ "$(ps -eo cmd | grep -c '[e]bpf-guard --config')" -ge 1 ] || die "рабочий агент не найден"
echo "== 0. exec filename шебанг-скрипта (ПЕРВАЯ проверка 8.4.2)"
bash "$HERE/w84-execprobe.sh" "$OUT/execprobe" || true
sa_start "$SRC" /root/w85-run-p1 19198 || die "второй агент не поднялся"
M() { sa_metrics; }
M > "$OUT/m-start.txt"
echo "== 1. состояние таблицы"
grep -a '^ebpf_guard_proc_table_state' "$OUT/m-start.txt" | tee "$OUT/state.txt"
grep -aq '^ebpf_guard_proc_table_state{state="active"} 1' "$OUT/m-start.txt" || { grep -a "proc table" /root/w85-run-p1/agent.log | head -5; die "таблица процессов не active — P1 неизмерим"; }
grep -a "proc table" /root/w85-run-p1/agent.log | head -5
sleep 20
echo "== 2. сверка с /proc"
python3 "$HERE/w85-p1-check.py" compare "127.0.0.1:19198" "$SA_TOKEN" 60 | tee "$OUT/compare.txt"
echo "== 3. контроль мс-цепочки nginx→bash→curl (мгновенный bash)"
mkdir -p /var/tmp/w85p1; cp /bin/dash /var/tmp/w85p1/nginx; cp /bin/bash /var/tmp/w85p1/bash
python3 "$HERE/w85-p1-check.py" mcchain "127.0.0.1:19198" "$SA_TOKEN" /var/tmp/w85p1/nginx /var/tmp/w85p1/bash http://10.255.255.1/ | tee "$OUT/mcchain.txt"
rm -rf /var/tmp/w85p1
echo "== 4. контроли 8.4.2 (dpkg -r и спуфы) против второго агента"
API="$SA_API" TOKEN="$SA_TOKEN" bash "$HERE/w84-controls.sh" "$OUT/w84"
bash "$HERE/w84-close-report.sh" "$OUT/w84" | tee "$OUT/w84-verdict.txt"
M > "$OUT/m-end.txt"
echo "== 5. счётчики"
for s in ebpf_guard_proc_table_events_total ebpf_guard_proc_table_lookup_errors_total ebpf_guard_proc_table_capacity ebpf_guard_lineage_proc_reads_total ebpf_guard_proc_chain_reads_total ebpf_guard_lineage_field_total ebpf_guard_lineage_image_total ebpf_guard_syscall_self_excluded_total; do
    grep -a "^$s" "$OUT/m-end.txt"
done | tee "$OUT/counters.txt"
cp /root/w85-run-p1/agent.log "$OUT/agent.log" 2> /dev/null
sa_stop
ps -eo cmd | grep -c '[e]bpf-guard --config' | sed 's/^/агентов после смока: /'
echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
