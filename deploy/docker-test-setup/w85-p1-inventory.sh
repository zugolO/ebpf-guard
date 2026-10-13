#!/bin/bash
# w85-p1-inventory.sh <SRC> <OUT> [SECS=600] — после P1: (1) строки инвентаря A1 для карт таблицы процессов (bpftool memlock) и
# суммарный memlock карт второго агента; (2) живое число процессов узла (размер карт); (3) cmd 3 (MAP_DELETE_ELEM) и прочие
# bpf() агента за окно SECS на ПРОСТОЕ с таблицей (решение владельца 13.10, п. 3 — перепроверка на бинаре с P1).
# Второй агент из SRC; рабочий не трогается. Окно — только bpftrace; ssh внутрь не ходит.
set -u
SRC=${1:?SRC}; OUT=${2:?OUT}; SECS=${3:-600}; HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/w85-second-agent-lib.sh"
rm -rf "$OUT"; mkdir -p "$OUT"; exec > "$OUT/driver.log" 2>&1
die() { echo "die: $*" > "$OUT/DONE"; echo "DIE: $*"; sa_stop 2> /dev/null; exit 1; }
sa_start "$SRC" /root/w85-run-inv 19200 || die "второй агент не поднялся"
sleep 30
echo "== живых процессов узла: $(ls /proc | grep -c '^[0-9]') (потоков ядра и пользовательских, лидеры групп)"
echo "== карты второго агента (bpftool, memlock)"
bpftool -j map show > "$OUT/maps.json" 2>&1
jq -r '.[] | select(.name == "proc_live" or .name == "proc_exited" or .name == "proc_table_cou" or .name == "proc_table_counters") | "\(.name) type=\(.type) max_entries=\(.max_entries) memlock=\(.bytes_memlock) B (\(.bytes_memlock / 1048576 * 100 | floor / 100) МиБ)"' "$OUT/maps.json"
echo "== программы таблицы"
bpftool -j prog show > "$OUT/progs.json" 2>&1
jq -r '.[] | select(.name | test("^proc_(fork|exec|exit)")) | "\(.name) type=\(.type) loaded_at=\(.loaded_at) xlated=\(.bytes_xlated) jited=\(.bytes_jited) memlock=\(.bytes_memlock)"' "$OUT/progs.json"
echo "== cmd 3 и прочие bpf() за ${SECS} с простоя (bpftrace, ключ pid+cmd)"
timeout $((SECS + 30)) bpftrace -e "tracepoint:syscalls:sys_enter_bpf { @c[pid, args->cmd] = count(); } interval:s:$SECS { exit(); }" > "$OUT/bt.txt" 2>&1
echo "агент pid=$SA_PID"
bash "$HERE/w85-cmd3-parse.sh" "$OUT/bt.txt" "$SA_PID" "$SA_PID" "$SECS" | sed -n '1,/^ИТОГ/p' | head -20
sa_metrics > "$OUT/m-end.txt"
grep -aE '^ebpf_guard_(proc_table_events_total|proc_chain_reads_total|lineage_proc_reads_total)' "$OUT/m-end.txt"
sa_stop
echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
