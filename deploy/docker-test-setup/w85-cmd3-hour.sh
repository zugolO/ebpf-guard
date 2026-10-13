#!/bin/bash
# w85-cmd3-hour.sh <SRC> <OUT> [SECS=3600] — сколько вызовов bpf(cmd=3, MAP_DELETE_ELEM) агент делает за idle-час
# (решение владельца 13.10, п. 3). bpftrace 0.14: ОДИН зонд без предиката, ключ (pid, cmd); без BEGIN. Поднимает
# ВТОРОГО агента из SRC (порт 19197) рядом с рабочим и считает отдельно по pid каждого: рабочий (его бинарь —
# версия стенда) и второй (бинарь SRC = HEAD). Сам не опрашивает стенд внутри окна: спит и пишет итог.
# Выход: OUT/{bt.txt,summary.txt,DONE}; DONE — «done …» или «die: …».
set -u
SRC=${1:?SRC}; OUT=${2:?OUT}; SECS=${3:-3600}
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"; rm -f "$OUT/DONE"
source "$HERE/w85-second-agent-lib.sh"
die() { echo "die: $*" > "$OUT/DONE"; sa_stop; exit 1; }
WORK_PID=$(systemctl show -p MainPID --value ebpf-guard-test.service)
[ -n "$WORK_PID" ] && [ "$WORK_PID" != 0 ] || die "рабочий агент не запущен"
sa_start "$SRC" /root/w85-run-cmd3 19197 || die "второй агент не поднялся"
sa_metrics > "$OUT/m-start.txt"
T0=$(date +%s)
bpftrace -e "tracepoint:syscalls:sys_enter_bpf { @c[pid, args->cmd] = count(); } interval:s:$SECS { exit(); }" > "$OUT/bt.txt" 2>&1
T1=$(date +%s)
sa_metrics > "$OUT/m-end.txt"
{
    echo "окно $((T1 - T0)) с; рабочий агент pid=$WORK_PID; второй агент (SRC=$SRC, git $(cat "$SRC/GIT-HEAD" 2>/dev/null), бинарь $(cut -c1-12 "$SRC/BINARY-SHA256" 2>/dev/null)) pid=$SA_PID"
    bash "$HERE/w85-cmd3-parse.sh" "$OUT/bt.txt" "$WORK_PID" "$SA_PID" "$((T1 - T0))"
    echo "-- self_excluded второго агента (начало → конец):"
    for f in m-start m-end; do grep -aE '^ebpf_guard_syscall_self_excluded_total' "$OUT/$f.txt" | sed "s/^/  $f /"; done
} > "$OUT/summary.txt"
sa_stop
echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
