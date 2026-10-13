#!/bin/bash
# w85-e1-identity.sh <НОВЫЙ final-alerts.json> <СТАРЫЙ final-alerts.json> <attack-manifest.json> [ПОРОГ=3] — тождество детекта на пакете атак (E1):
# наборы сработавших правил по алертам СТОРА (не по lineage-patterns). Вердикт считает скрипт:
#   правило, которое есть только в одном из прогонов, считается РАСХОЖДЕНИЕМ ДЕТЕКТА, если хотя бы один его алерт — от процесса из манифеста
#   атак (comm категории); иначе это фон узла (systemd-logind, таймеры…): он перечисляется, но тождество не ломает.
#   ДОСТИГНУТО — расхождений детекта нет; ПРОВАЛЕН — есть; НЕИЗМЕРИМ — нет/пустой снимок или манифест.
#   Правила, чей объём разошёлся более чем в ПОРОГ раз (оба ≥ 1), — тоже печатаются как фон окон.
set -u
N=${1:-}; O=${2:-}; MAN=${3:-}; K=${4:-3}
echo "== w85 8.5.E1i (тождество детекта на пакете атак): новый=${N:-—} старый=${O:-—}"
[ -s "$MAN" ] && jq -e "type == \"array\"" "$MAN" > /dev/null 2>&1 || { echo "НЕИЗМЕРИМ: 8.5.E1i НЕИЗМЕРИМ (класс НАЗВАН: нет манифеста атак ${MAN:-—})"; exit 0; }
for f in "$N" "$O"; do
    [ -s "$f" ] && jq -e 'type == "array" or type == "object"' "$f" > /dev/null 2>&1 || { echo "НЕИЗМЕРИМ: 8.5.E1i НЕИЗМЕРИМ (класс НАЗВАН: нет или не разобран снимок алертов ${f:-—})"; exit 0; }
done
cnt() { jq -r '(if type == "array" then . else .alerts // [] end)[] | (.rule_id // .RuleID)' "$1" | sort | uniq -c | awk '{ print $2, $1 }' | sort; }
cnt "$N" > /tmp/e1i-new.$$; cnt "$O" > /tmp/e1i-old.$$
tn=$(wc -l < /tmp/e1i-new.$$ | tr -d ' '); to=$(wc -l < /tmp/e1i-old.$$ | tr -d ' ')
if [ "$tn" -eq 0 ] || [ "$to" -eq 0 ]; then rm -f /tmp/e1i-*.$$; echo "НЕИЗМЕРИМ: 8.5.E1i НЕИЗМЕРИМ (класс НАЗВАН: в одном из снимков ноль правил: новый $tn, старый $to)"; exit 0; fi
comms=$(jq -r '.[].comm' "$MAN" | sort -u)
atk() { # <alerts.json> <rule> — алертов правила от процессов из манифеста
    jq -r --arg r "$2" --argjson c "$(printf '%s\n' "$comms" | jq -R . | jq -s .)" '[(if type == "array" then . else .alerts // [] end)[] | select((.rule_id // .RuleID) == $r) | select(.comm as $x | $c | index($x))] | length' "$1"
}
only_new=""; only_old=""; bg=""
for r in $(join -v1 /tmp/e1i-new.$$ /tmp/e1i-old.$$ | awk '{ print $1 }'); do
    a=$(atk "$N" "$r"); if [ "$a" -gt 0 ]; then only_new="$only_new$r(атака $a) "; else bg="$bg$r(фон, только в новом) "; fi
done
for r in $(join -v2 /tmp/e1i-new.$$ /tmp/e1i-old.$$ | awk '{ print $1 }'); do
    a=$(atk "$O" "$r"); if [ "$a" -gt 0 ]; then only_old="$only_old$r(атака $a) "; else bg="$bg$r(фон, только в старом) "; fi
done
drift=$(join /tmp/e1i-new.$$ /tmp/e1i-old.$$ | awk -v k="$K" '{ a = $2; b = $3; if (a >= 1 && b >= 1 && (a > k * b || b > k * a)) printf "%s %s→%s; ", $1, b, a }')
echo "  правил: новый $tn, старый $to; расхождения детекта — только в новом: ${only_new:-∅}; только в старом: ${only_old:-∅}; фон: ${bg:-нет}"
echo "  объём разошёлся > ${K}× (фон окон): ${drift:-нет}"
rm -f /tmp/e1i-*.$$
if [ -z "$only_new" ] && [ -z "$only_old" ]; then echo "ДОСТИГНУТО: 8.5.E1i ДОСТИГНУТО (расхождений детекта нет: правил новый $tn, старый $to; различия только в фоне узла${bg:+: ${bg% }})"
else echo "ПРОВАЛЕН: 8.5.E1i ПРОВАЛЕН (набор разошёлся: только в новом ${only_new:-∅}; только в старом ${only_old:-∅})"; fi
