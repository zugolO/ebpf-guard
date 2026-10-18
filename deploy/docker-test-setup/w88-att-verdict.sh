#!/bin/bash
# Метка 8.8.6: пакет атак под нагрузкой — recall по comm и состав детекта против прогона без нагрузки.
#   w88-att-verdict.sh <роль> <ATT под нагрузкой> [ATT без нагрузки]
# ATT — каталог <OUT>/attack прогона w88-load.sh <роль> attack. recall — формула секции 7 гейта (w85-close-report.sh recall).
# Состав = множество rule_id НОВЫХ алертов (final минус baseline); выпавшие = есть без нагрузки, нет под нагрузкой.
# Типы из attacks/att-composition-timer.txt (Rego-двойники фонового таймера ноды, один отчёт на жизнь процесса) не судятся, но
# ПЕЧАТАЮТСЯ. Ось не переведена на details.base_rule_id: проверено на r4a хоста — она создаёт расхождение у близнецов, которых Rego
# переименовывает в одно имя (netintr_dns_high_entropy_query → long_dns_query), и красит прежний PASS.
# Алерты на процессы ПРИБОРА (comm e6load — генератор, w88p — зонд, w88c<N> — контрольные) в состав не входят ни с одной
# стороны: это не детект атаки, а жребий генератора (c2_high_port_outbound на e6load по случайному эфемерному порту в базе j1,
# 18.10). Ось — comm, а не rule_id: тот же rule_id на процессе атаки по-прежнему судится. w88hot (горячий атакующий) — судится.
# PASS: recall 16/16 и выпавших 0. Нет прогона без нагрузки — состав НЕИЗМЕРИМ (recall судится отдельно, но метка не PASS).
set -u
ROLE=${1:?роль}; ATT=${2:?ATT}; BASE=${3:-}
HERE=$(cd "$(dirname "$0")" && pwd)
REG=${ATT_TIMER_REG:-$HERE/attacks/att-composition-timer.txt}
ids() { # ids <каталог> — rule_id новых алертов, по строке
    local b f
    b=$(ls "$1"/baseline-alerts-*.json 2> /dev/null | tail -1); f=$(ls "$1"/final-alerts-*.json 2> /dev/null | tail -1)
    [ -s "$b" ] && [ -s "$f" ] || return 1
    jq -r -s '(.[0] // []) as $b | (.[1] // []) as $f | ($b | map(.id) | unique) as $bids
              | [$f[] | select(.id as $id | ($bids | index($id)) | not)
                 | select(((.comm // .details.comm // "") | test("^(e6load|w88p|w88c[0-9]+)$")) | not) | .rule_id] | unique | .[]' "$b" "$f" 2> /dev/null
}
rec=$(ATT=$ATT bash "$HERE/w85-close-report.sh" recall 2> /dev/null)
read -r rd rt rm <<< "$rec"
if [ -z "${rt:-}" ]; then echo "8.8.6 $ROLE: НЕИЗМЕРИМ — нет манифеста или снимков алертов в $ATT"; exit 0; fi
under=$(ids "$ATT") || { echo "8.8.6 $ROLE: НЕИЗМЕРИМ — нет снимков алертов под нагрузкой"; exit 0; }
nl=$(printf '%s\n' "$under" | grep -c .)
if [ -z "$BASE" ]; then
    echo "8.8.6 $ROLE: НЕИЗМЕРИМ — recall $rd/$rt${rm:+ (не пойманы: $rm)}, типов детекта под нагрузкой $nl, прогона без нагрузки нет (состав не судится)"; exit 0
fi
base=$(ids "$BASE") || { echo "8.8.6 $ROLE: НЕИЗМЕРИМ — нет снимков алертов без нагрузки ($BASE)"; exit 0; }
nb=$(printf '%s\n' "$base" | grep -c .)
miss_all=$(comm -23 <(printf '%s\n' "$base" | sort -u) <(printf '%s\n' "$under" | sort -u))
reg=$(grep -vE '^[[:space:]]*(#|$)' "$REG" 2> /dev/null | sort -u)
miss=$(comm -23 <(printf '%s\n' "$miss_all" | grep . | sort -u) <(printf '%s\n' "$reg" | grep . | sort -u))
skipped=$(comm -12 <(printf '%s\n' "$miss_all" | grep . | sort -u) <(printf '%s\n' "$reg" | grep . | sort -u) | tr '\n' ' ')
nm=$(printf '%s' "$miss" | grep -c .)
verdict=PASS; [ "$rd" = "$rt" ] && [ "$rt" = 16 ] && [ "$nm" -eq 0 ] || verdict=FAIL
echo "8.8.6 $ROLE: $verdict — recall $rd/$rt${rm:+ (не пойманы: $rm)}; типов детекта без нагрузки $nb, под нагрузкой $nl, выпало $nm${miss:+: $(printf '%s' "$miss" | head -8 | tr '\n' ' ')}; алерты на процессы прибора (e6load, w88p, w88c*) не судятся${skipped:+; не судится (реестр фонового таймера, attacks/att-composition-timer.txt): ${skipped% }}"
