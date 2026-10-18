#!/bin/bash
# Метка 8.8.6h: контроль «горячий атакующий» (w88hot) под нагрузкой — алерт на чтение /etc/shadow обязателен,
# и сброс у самого атакующего должен действительно идти (иначе контроль не проверил ничего).
#   w88-hot-verdict.sh <роль> <ATT под нагрузкой>
# PASS: есть новый алерт comm=w88hot по любому правилу с «shadow» в id (cred_shadow_read, sensitive_file_read, shadow_access: часть из них дедупится соседними алертами) И shed{comm="w88hot"} за окно > 0.
# Алерт есть, сброса не было → НЕИЗМЕРИМ (контроль не вошёл в режим сброса). Сброс был, алерта нет → FAIL.
set -u
ROLE=${1:?роль}; ATT=${2:?ATT}
b=$(ls "$ATT"/baseline-alerts-*.json 2> /dev/null | tail -1); f=$(ls "$ATT"/final-alerts-*.json 2> /dev/null | tail -1)
[ -s "$ATT/hot.json" ] && [ -s "$b" ] && [ -s "$f" ] || { echo "8.8.6h $ROLE: НЕИЗМЕРИМ — нет hot.json или снимков алертов"; exit 0; }
reads=$(jq -r '.shadow_reads // 0' "$ATT/hot.json")
alerts=$(jq -r -s '(.[0] // []) as $b | (.[1] // []) as $f | ($b | map(.id) | unique) as $bids
    | [$f[] | select(.id as $id | ($bids | index($id)) | not) | select(.comm == "w88hot" and (.rule_id | test("shadow")))] | length' "$b" "$f" 2> /dev/null)
shed() { awk '/^ebpf_guard_file_hot_shed_by_comm_total\{comm="w88hot"\}/ { s += $NF } END { printf "%d", s }' "$1" 2> /dev/null; }
s0=$(shed "$ATT/a.prom"); s1=$(shed "$ATT/b.prom")
d=$((s1 - s0))
if [ "${reads:-0}" -le 0 ]; then echo "8.8.6h $ROLE: НЕИЗМЕРИМ — атакующий не прочитал /etc/shadow ни разу"; exit 0; fi
if [ "${alerts:-0}" -gt 0 ] && [ "$d" -gt 0 ]; then v=PASS
elif [ "${alerts:-0}" -gt 0 ]; then echo "8.8.6h $ROLE: НЕИЗМЕРИМ — алертов $alerts, но сброса у w88hot не было (shed=$d): режим сброса контролем не достигнут"; exit 0
else v=FAIL; fi
echo "8.8.6h $ROLE: $v — чтений /etc/shadow $reads, новых алертов cred_shadow_read/sensitive_file_read (rule_id ~ shadow) от w88hot $alerts, сброшено у w88hot за окно $d"
