#!/bin/bash
# w85-cmd3-parse.sh <bt.txt> <WORK_PID> <SA_PID> <SECS> — разбор вывода bpftrace 0.14 (`@c[pid, cmd]: n`) из
# w85-cmd3-hour.sh. Многоключевую карту bpftrace 0.14 печатает С ПРОБЕЛОМ внутри ключа («@c[10, 3]: 5») —
# резать по полям нельзя, ключ нормализуется sed'ом (память bpftrace-014-…, attr-value-containing-equals…).
# Вердикт ИТОГ печатает разбор, не человек; «нет строк» ≠ 0: без единой строки @c — НЕИЗМЕРИМ.
set -u
BT=${1:?bt.txt}; WP=${2:?work pid}; SP=${3:?second pid}; SECS=${4:?secs}
rows=$(sed -nE 's/^@c\[([0-9]+), ([0-9]+)\]: ([0-9]+)[[:space:]]*$/\1 \2 \3/p' "$BT" 2>/dev/null)
if [ -z "$rows" ]; then echo "НЕИЗМЕРИМ: cmd3 НЕИЗМЕРИМ (класс НАЗВАН: в $BT нет ни одной строки @c[pid, cmd] — зонд не отработал)"; exit 0; fi
echo "-- вызовов bpf() по (pid, cmd), только эти два агента:"
printf '%s\n' "$rows" | awk -v w="$WP" -v s="$SP" '$1 == w { printf "  рабочий  pid=%s cmd=%s %s\n", $1, $2, $3 } $1 == s { printf "  второй   pid=%s cmd=%s %s\n", $1, $2, $3 }'
for who in "$WP:рабочий" "$SP:второй"; do
    p=${who%%:*}
    seen=$(printf '%s\n' "$rows" | awk -v p="$p" '$1 == p { n++ } END { print n + 0 }')
    n3=$(printf '%s\n' "$rows" | awk -v p="$p" '$1 == p && $2 == 3 { s += $3 } END { print s + 0 }')
    if [ "$seen" -eq 0 ]; then
        echo "НЕИЗМЕРИМ: cmd3 ${who#*:} агент pid=$p НЕИЗМЕРИМ (класс НАЗВАН: ни одного bpf()-вызова этого pid в окне — агент не предъявлен зонду; ноль без класса не пишется)"
    else
        echo "ИТОГ cmd=3 (MAP_DELETE_ELEM) за $SECS с: ${who#*:} агент pid=$p — $n3 вызовов ($(awk -v n="$n3" -v t="$SECS" 'BEGIN { printf "%.1f", n * 3600 / t }') в час; других cmd у него $seen строк, из них вызовов $(printf '%s\n' "$rows" | awk -v p="$p" '$1 == p { s += $3 } END { print s + 0 }'))"
    fi
done
