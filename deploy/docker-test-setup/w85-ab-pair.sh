#!/bin/bash
# w85-ab-pair.sh <OUT> [WIN_S=3600] — пара A/B метки 8.5.3: ДВА смежных РАВНЫХ окна ОДНОГО
# бинаря, F1 переключается на ходу POST /api/v1/tuning/kernel-predicates, БЕЗ рестарта
# (рестарт между окнами измерил бы рестарт — решение владельца 12.10, п. 6).
#   A: F1 выключен  m-a0 → m-ab    (WIN_S)
#   B: F1 включён   m-ab → m-b1    (WIN_S), переключение — сразу после снимка m-ab
# Хостовый агент и API берутся из окружения: API (умолч. http://localhost:19090), TOKEN.
# Скрипт сам ничего не опрашивает внутри окон: спит и снимает /metrics на границах
# ([[waiting-loop-must-not-ssh-into-window]]). Конец окна B — состояние «F1 включён»:
# дальше пакет атак идёт с включёнными предикатами (решение 6).
# Выход: OUT/{m-a0,m-ab,m-b1}.txt, ab-meta.txt; OUT/DONE — «done …» или «die: …».
set -u
OUT=${1:?usage: w85-ab-pair.sh <OUT> [WIN_S]}; WIN=${2:-3600}
API=${API:-http://localhost:19090}; TOKEN=${TOKEN:-}
mkdir -p "$OUT"; rm -f "$OUT"/m-*.txt "$OUT/DONE"
die() { echo "die: $*" > "$OUT/DONE"; echo "die: $*" >&2; exit 1; }
M() { curl -s --max-time 30 -H "Authorization: Bearer $TOKEN" "$API/metrics"; }
state() { M | awk '/^ebpf_guard_kernel_predicate_state/ && $NF == 1 { x = $1; sub(/.*state="/, "", x); sub(/".*/, "", x); print x; exit }'; }
sw() { curl -s --max-time 15 -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "{\"enabled\":$1}" "$API/api/v1/tuning/kernel-predicates"; }

[ -n "$TOKEN" ] || die "TOKEN не задан"
sw false > "$OUT/sw-false.json"
st=$(state); [ "$st" = off_config ] || die "после POST false состояние F1 = ${st:-нет серии}, а не off_config — окно A не при выключенном F1"
t_a0=$(date +%s); M > "$OUT/m-a0.txt"; [ -s "$OUT/m-a0.txt" ] || die "m-a0 пуст"
sleep "$WIN"
M > "$OUT/m-ab.txt"; t_ab=$(date +%s); [ -s "$OUT/m-ab.txt" ] || die "m-ab пуст"
sw true > "$OUT/sw-true.json"
grep -Eq "\"changed\": *true" "$OUT/sw-true.json" || die "переключатель не сменил состояние: $(cat "$OUT/sw-true.json")"
sleep "$WIN"
M > "$OUT/m-b1.txt"; t_b1=$(date +%s); [ -s "$OUT/m-b1.txt" ] || die "m-b1 пуст"
{
    echo "window_s=$WIN"
    echo "A_s=$((t_ab - t_a0)) B_s=$((t_b1 - t_ab))"
    echo "a0=$(date -u -d @$t_a0 +%FT%TZ) ab=$(date -u -d @$t_ab +%FT%TZ) b1=$(date -u -d @$t_b1 +%FT%TZ)"
} > "$OUT/ab-meta.txt"
# окна обязаны быть равными в пределах 2% (скрипт спит одинаково, но снимок /metrics не мгновенен)
awk -v a=$((t_ab - t_a0)) -v b=$((t_b1 - t_ab)) 'BEGIN { d = a - b; if (d < 0) d = -d; exit !(d <= 0.02 * a) }' \
    || die "окна неравны: A $((t_ab - t_a0)) с, B $((t_b1 - t_ab)) с"
echo "done $(date -u +%FT%TZ)" > "$OUT/DONE"
