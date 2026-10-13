#!/bin/bash
# w84-close-report.sh <OUT каталог w84-controls.sh> — эмиттер метки 8.4.x (8.4.1/8.4.2 на таблице процессов ядра).
# Вердикт считает ЭМИТТЕР; «нет серии/нет свидетеля» ≠ 0 — ноль без предъявленного класса не засчитывается
# (память verdict-zero-needs-its-class-presented). Сценарии — подкаталоги OUT/NN-имя/ (expect, alerts.json,
# m0.txt/m1.txt, witness.txt):
#   silent — легитимная остановка из maintainer-скрипта под dpkg (L*): алерта НЕТ. Засчитывается ТОЛЬКО если
#            (а) свидетель видел systemctl в окне (класс предъявлен), (б) исключение dpkg-maintainer-script-stop
#            ПРИМЕНИЛОСЬ (rule_exceptions_total вырос) — иначе тишина могла прийти от дедупа/лимитера.
#   alert  — спуф (X*): алерт ЕСТЬ. Засчитывается ТОЛЬКО при (а); тишина при выросших dedup/ratelimit — НЕИЗМЕРИМ
#            (другой слой подавления), а не «спуф прошёл».
#   skip   — сценарий не исполнен (названная причина) — НЕИЗМЕРИМ.
# Исход: ДОСТИГНУТО (все сценарии) / ПРОВАЛЕН (ложный алерт на легитимном или спуф ушёл в тишину) / НЕИЗМЕРИМ.
set -u
OUT=${1:-}
RULE=impact_systemd_service_disabled
EXC=dpkg-maintainer-script-stop

# val <файл> <серия с лейблами> — сумма серий, у которых есть КАЖДЫЙ названный лейбл; ПУСТО — нет серии
val() {
    awk -v spec="$2" '
        BEGIN { i = index(spec, "{"); name = substr(spec, 1, i - 1) "{"
                rest = substr(spec, i + 1); sub(/}$/, "", rest); n = split(rest, want, ",") }
        index($0, name) != 1 { next }
        { lab = substr($0, length(name) + 1); lab = "," substr(lab, 1, index(lab, "}") - 1) ","
          for (k = 1; k <= n; k++) if (index(lab, "," want[k] ",") == 0) next
          s += $NF; m++ }
        END { if (m) print s + 0; else print "" }' "$1"
}
delta() { # <m0> <m1> <серия> — дельта; «?» — нет серии в снимке
    local a b
    [ -s "$1" ] && [ -s "$2" ] || { echo "?"; return; }
    a=$(val "$1" "$3"); b=$(val "$2" "$3")
    [ -n "$b" ] || { echo "?"; return; }
    echo $(( b - ${a:-0} ))
}

echo "== w84 8.4.x: OUT=${OUT:-—}"
if [ -z "$OUT" ] || [ ! -d "$OUT" ]; then
    echo "НЕИЗМЕРИМ: 8.4.x НЕИЗМЕРИМ (класс НАЗВАН: нет каталога контролей ${OUT:-—})"; exit 0
fi
if [ ! -s "$OUT/DONE" ] || ! grep -q '^done' "$OUT/DONE" 2>/dev/null; then
    echo "НЕИЗМЕРИМ: 8.4.x НЕИЗМЕРИМ (класс НАЗВАН: контроли не доработали до конца — $(cat "$OUT/DONE" 2>/dev/null || echo 'нет DONE'))"; exit 0
fi

fail="" cls="" nsil=0 nalr=0 ok=0
shopt -s nullglob
dirs=("$OUT"/[0-9][0-9]-*/)
[ "${#dirs[@]}" -gt 0 ] || { echo "НЕИЗМЕРИМ: 8.4.x НЕИЗМЕРИМ (класс НАЗВАН: в $OUT нет ни одного сценария)"; exit 0; }
for d in "${dirs[@]}"; do
    d=${d%/}; name=$(basename "$d"); expect=$(cat "$d/expect" 2>/dev/null)
    if [ "$expect" = skip ]; then
        echo "  $name: НЕ ИСПОЛНЕН ($(cat "$d/note" 2>/dev/null))"; cls="$cls; $name не исполнен"; continue
    fi
    if [ "$expect" != silent ] && [ "$expect" != alert ]; then
        echo "  $name: нет expect"; cls="$cls; $name без expect"; continue
    fi
    if [ ! -s "$d/alerts.json" ] || ! jq -e 'type == "array" or type == "object"' "$d/alerts.json" > /dev/null 2>&1; then
        echo "  $name: снимок алертов не разобран"; cls="$cls; $name без разбираемого снимка алертов"; continue
    fi
    wit=$(grep -ac '^SYSTEMCTL' "$d/witness.txt" 2>/dev/null); wit=${wit:-0}
    na=$(jq -r --arg r "$RULE" '[(if type == "array" then . else .alerts // [] end)[] | select((.rule_id // .RuleID) == $r)] | length' "$d/alerts.json" 2>/dev/null)
    de=$(delta "$d/m0.txt" "$d/m1.txt" "ebpf_guard_rule_exceptions_total{exception_name=\"$EXC\",rule_id=\"$RULE\"}")
    dt=$(delta "$d/m0.txt" "$d/m1.txt" "ebpf_guard_alerts_total{rule_id=\"$RULE\"}")
    dd=$(delta "$d/m0.txt" "$d/m1.txt" "ebpf_guard_alerts_dedup_dropped_by_rule_total{rule_id=\"$RULE\"}")
    dr=$(delta "$d/m0.txt" "$d/m1.txt" "ebpf_guard_alerts_ratelimited_by_rule_total{rule_id=\"$RULE\"}")
    echo "  $name ($expect): systemctl у свидетеля $wit; алертов правила в API ${na:-?}; alerts_total +$dt; исключение +$de; dedup +$dd; лимитер +$dr"
    case "${na:-}" in ''|*[!0-9]*) cls="$cls; $name: снимок алертов не разобран jq"; continue ;; esac
    if [ "$wit" -eq 0 ]; then
        cls="$cls; $name: свидетель не видел systemctl в окне — команда не исполнилась (ноль без класса)"; continue
    fi
    if [ "$expect" = silent ]; then
        nsil=$((nsil + 1))
        if [ "$na" -gt 0 ]; then
            fail="$fail; $name: ЛОЖНЫЙ алерт на легитимной остановке ($na)"
        elif [ "$de" = "?" ]; then
            cls="$cls; $name: нет серии rule_exceptions_total — применение исключения не проверено"
        elif [ "$de" -lt 1 ]; then
            cls="$cls; $name: алертов нет, но исключение НЕ применялось (тишина от другого слоя: дедуп +$dd, лимитер +$dr)"
        else
            ok=$((ok + 1))
        fi
    else
        nalr=$((nalr + 1))
        if [ "$na" -gt 0 ] || { [ "$dt" != "?" ] && [ "$dt" -gt 0 ]; }; then
            ok=$((ok + 1))
        elif { [ "$dd" != "?" ] && [ "$dd" -gt 0 ]; } || { [ "$dr" != "?" ] && [ "$dr" -gt 0 ]; }; then
            cls="$cls; $name: алерта нет, но его погасили дедуп +$dd/лимитер +$dr — спуф не судится"
        else
            fail="$fail; $name: СПУФ ушёл в тишину (алертов 0, systemctl был)"
        fi
    fi
done
# X5 засчитывается, только если реюз pid реально состоялся (иначе это тот же X1 под другим именем)
x5=$(ls -d "$OUT"/*-X5-pid-reuse 2>/dev/null | head -1)
if [ -n "$x5" ]; then
    if grep -aq '^REUSED pid=' "$x5/cmd.log" 2>/dev/null; then echo "  X5: реюз pid воспроизведён ($(grep -a '^REUSED' "$x5/cmd.log" | head -1))"
    else cls="$cls; X5: реюз pid НЕ воспроизведён ($(grep -aE 'NO-REUSE' "$x5/cmd.log" | head -1))"; fi
fi
if [ -n "$fail" ]; then
    echo "ПРОВАЛЕН: 8.4.x ПРОВАЛЕН (${fail#; }${cls:+; неизмеримо также:$cls})"
elif [ -n "$cls" ]; then
    echo "НЕИЗМЕРИМ: 8.4.x НЕИЗМЕРИМ (класс НАЗВАН:${cls#;})"
else
    echo "ДОСТИГНУТО: 8.4.x ДОСТИГНУТО (легитимных остановок под dpkg без алерта $nsil, исключение применялось; спуфов с алертом $nalr; свидетель родословной видел systemctl в каждом окне)"
fi
