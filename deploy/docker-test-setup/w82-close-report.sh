#!/bin/bash
# w82-close-report.sh — эмиттер ночи закрытия волны 8.2: метки 8.2.1 и 8.2.5
# (их не печатал ни один прибор — пробел Г4 доводки), плюс сквозная печать
# 8.2.2/8.2.4 (w82-mem-report.sh по инвентарю пода на 30-й минуте) и 8.2.3
# (вывод A2, TestW82_AllocPerEvent -v).
#
# Вход — переменные (пустая/отсутствующая — НЕИЗМЕРИМ с названным классом, не 0):
#   RUN   каталог w82-pod-run.sh (samples.tsv от helm install — пик СТАРТА)
#   ATT   каталог w82-pod-attack.sh (samples.tsv, t-att1, m-pre/m-att1, манифест,
#         baseline/final-alerts-*.json, restarts.txt; heap-mid-*.top — информационно)
#   INV   каталог w82-mem-inventory.sh пода на аптайме ≥ 30 мин
#   GATE  gate.txt хостового гейта (recall по манифесту)
#   A2    вывод go test -v -run '^TestW82_AllocPerEvent' (метка 8.2.3)
#
# 8.2.1 — пик memory.current пода = max(старт, окно атак) ≤ BUDGET_MIB; старт
#   обязан покрыть ≥ 60 с от первого сэмпла cgroup, окно атак — до конца пакета;
#   рестарт контейнера — ПРОВАЛЕН (OOM на лимите пода — провал, а не неизмеримость).
# 8.2.5 — три половины, судятся НЕЗАВИСИМО и печатаются каждая
#   ([[elif-verdict-masks-independent-halves]]): (а) потери protected за окно
#   атак пода = 0; (б) ringbuf_full за окно атак пода ≤ BASE_RINGBUF_FULL (база —
#   этапы 2–4 и доводка: 0 на пакете без наведённого дропа); (в) recall по
#   манифесту = 1 у пода (на боевом наборе) И у гейта хоста.
set -u
BUDGET_MIB=${BUDGET_MIB:-150}
TARGET_MIB=${TARGET_MIB:-128}
BASE_RINGBUF_FULL=${BASE_RINGBUF_FULL:-0}
RUN=${RUN:-}; ATT=${ATT:-}; INV=${INV:-}; GATE=${GATE:-}; A2=${A2:-}
HERE=$(cd "$(dirname "$0")" && pwd)

# _m <файл> <метрика> [подстрока лейблов] — сумма серий; ПУСТО, если серии нет.
_m() {
    [ -s "$1" ] || return 0
    awk -v m="$2" -v lab="${3:-}" '
        /^#/ { next }
        { name = $1; sub(/\{.*/, "", name) }
        name == m && (lab == "" || index($1, lab) > 0) { s += $NF; seen = 1 }
        END { if (seen) printf "%.0f\n", s }' "$1" < /dev/null
}
# peak <samples.tsv> — «пик_МиБ сек_пика первый_сек последний_сек»; пусто — нет строк.
peak() {
    [ -s "$1" ] || return 0
    awk 'NF >= 2 && $2 ~ /^[0-9]+$/ {
            if (!n++) f = $1; l = $1
            if ($2 > m) { m = $2; t = $1 } }
         END { if (n) printf "%.1f %s %s %s\n", m / 1048576, t, f, l }' "$1"
}

echo "== w82 ночь закрытия: RUN=${RUN:-—} ATT=${ATT:-—} INV=${INV:-—} GATE=${GATE:-—}"
echo ""

# ── 8.2.1 ──────────────────────────────────────────────────────────────────
echo "-- 8.2.1 пик memory.current пода (старт + окно атак)"
cls=""
read -r sp st sf sl <<< "$(peak "$RUN/samples.tsv")"
if [ -z "${sp:-}" ]; then
    cls="$cls; нет сэмплов старта ($RUN/samples.tsv)"
else
    echo "  старт: пик $sp МиБ на $st с от helm install (сэмплы ${sf}…${sl} с)"
    awk -v f="$sf" -v l="$sl" 'BEGIN { exit !(l - f >= 60) }' \
        || cls="$cls; сэмплы старта покрывают $(awk -v f="$sf" -v l="$sl" 'BEGIN { printf "%.1f", l - f }') с < 60 — первые 60 с процесса не видны"
    [ -s "$RUN/peak.txt" ] && sed -n 's/^ws_/  старт: ws_/p' "$RUN/peak.txt"
fi
read -r ap at af al <<< "$(peak "$ATT/samples.tsv")"
t1=$(cat "$ATT/t-att1" 2>/dev/null)
if [ -z "${ap:-}" ]; then
    cls="$cls; нет сэмплов окна атак ($ATT/samples.tsv)"
elif [ -z "$t1" ]; then
    cls="$cls; нет t-att1 — конец пакета не записан"
else
    echo "  атаки: пик $ap МиБ на $at с (сэмплы ${af}…${al} с, конец пакета $t1 с)"
    awk -v l="$al" -v e="$t1" 'BEGIN { exit !(l >= e) }' \
        || cls="$cls; сэмплы окна атак обрываются на $al с раньше конца пакета $t1 с"
    [ -s "$ATT/peak.txt" ] && sed -n 's/^ws_/  атаки: ws_/p' "$ATT/peak.txt"
    [ -s "$ATT/per-minute-mib.txt" ] && echo "  по минутам (мин МиБ): $(tr '\n' ' ' < "$ATT/per-minute-mib.txt")"
fi
rs=$(cat "$ATT/restarts.txt" 2>/dev/null)
if [ -z "$rs" ]; then
    cls="$cls; нет restarts.txt — рестарт контейнера не исключён"
fi
if [ -n "$rs" ] && [ "$rs" != 0 ]; then
    echo "ПРОВАЛЕН: 8.2.1 ПРОВАЛЕН (рестартов контейнера $rs — $(cat "$ATT/last-state.txt" 2>/dev/null || echo 'причина не снята'))"
elif [ -n "$cls" ]; then
    echo "НЕИЗМЕРИМ: 8.2.1 НЕИЗМЕРИМ (класс НАЗВАН:${cls#;})"
else
    awk -v a="$sp" -v b="$ap" -v lim="$BUDGET_MIB" -v tgt="$TARGET_MIB" 'BEGIN {
        p = (a > b) ? a : b; w = (a > b) ? "старт" : "атаки"
        note = (p <= tgt) ? sprintf("цель %d взята", tgt) : sprintf("цель %d не взята", tgt)
        if (p <= lim) printf "ДОСТИГНУТО: 8.2.1 ДОСТИГНУТО (пик %.1f МиБ ≤ %d, на фазе «%s»; %s; учёт пода, боевой набор)\n", p, lim, w, note
        else printf "ПРОВАЛЕН: 8.2.1 ПРОВАЛЕН (пик %.1f МиБ > %d, на фазе «%s»; учёт пода, боевой набор)\n", p, lim, w }'
fi
for f in "$ATT"/heap-mid-*.top; do
    [ -s "$f" ] || continue
    v=$(awk '/buildAncestry/ { print $4, $5; exit }' "$f")
    echo "  ИНФО: $(basename "$f" .top) buildAncestry cum ${v:-нет строки}"
done
echo ""

# ── 8.2.2 / 8.2.4 — инвентарь пода на 30-й минуте ─────────────────────────
echo "-- 8.2.2 / 8.2.4 (w82-mem-report.sh, инвентарь пода)"
if [ -n "$INV" ] && [ -d "$INV" ]; then
    bash "$HERE/w82-mem-report.sh" "$INV" | grep -aE '^(ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИНФО):|memory.current|working set|учёт:'
else
    echo "НЕИЗМЕРИМ: 8.2.2 НЕИЗМЕРИМ (класс НАЗВАН: нет каталога инвентаря пода)"
    echo "НЕИЗМЕРИМ: 8.2.4 НЕИЗМЕРИМ (класс НАЗВАН: нет каталога инвентаря пода)"
fi
echo ""

# ── 8.2.3 — A2 ─────────────────────────────────────────────────────────────
echo "-- 8.2.3 (A2)"
if [ -s "$A2" ] && grep -aqE '(ДОСТИГНУТО|ПРОВАЛЕН): 8\.2\.3 ' "$A2"; then
    grep -aoE '(ДОСТИГНУТО|ПРОВАЛЕН|ИНФО): 8\.2\.3 .*' "$A2"
else
    echo "НЕИЗМЕРИМ: 8.2.3 НЕИЗМЕРИМ (класс НАЗВАН: нет вердиктной строки A2 в ${A2:-—} — тест не шёл или шёл под -short/-race)"
fi
echo ""

# ── T2: резолвер юнитов за окно атак — информационно ──────────────────────
sc0=$(_m "$ATT/m-pre.txt" ebpf_guard_systemd_unit_scans_total); sc1=$(_m "$ATT/m-att1.txt" ebpf_guard_systemd_unit_scans_total)
rv0=$(_m "$ATT/m-pre.txt" ebpf_guard_systemd_unit_lookups_total 'result="resolved"'); rv1=$(_m "$ATT/m-att1.txt" ebpf_guard_systemd_unit_lookups_total 'result="resolved"')
t1=$(cat "$ATT/t-att1" 2>/dev/null)
if [ -n "$sc0" ] && [ -n "$sc1" ] && [ -n "$t1" ]; then
    echo "ИНФО: T2 сканов system.slice за окно атак $((sc1 - sc0)) ($(awk -v n="$((sc1 - sc0))" -v t="$t1" 'BEGIN { printf "%.1f", n / (t / 60) }')/мин), resolved +$(( ${rv1:-0} - ${rv0:-0} ))"
else
    echo "ИНФО: T2 сканы НЕИЗМЕРИМ (нет серии systemd_unit_scans_total в m-pre/m-att1 или t-att1)"
fi
echo ""

# ── 8.2.5 ──────────────────────────────────────────────────────────────────
echo "-- 8.2.5 цена в детекте и потерях"
fail=""; cls=""
p0=$(_m "$ATT/m-pre.txt" ebpf_guard_events_dropped_by_queue_total 'queue="protected"')
p1=$(_m "$ATT/m-att1.txt" ebpf_guard_events_dropped_by_queue_total 'queue="protected"')
if [ -z "$p0" ] || [ -z "$p1" ]; then
    cls="$cls; (а) серии потерь protected нет в m-pre/m-att1"
    echo "  (а) потери protected за окно атак: НЕИЗМЕРИМ"
else
    echo "  (а) потери protected за окно атак: $((p1 - p0))"
    [ $((p1 - p0)) -eq 0 ] || fail="$fail; (а) потери protected $((p1 - p0))"
fi
r0=$(_m "$ATT/m-pre.txt" ebpf_guard_events_dropped_total 'reason="ringbuf_full"')
r1=$(_m "$ATT/m-att1.txt" ebpf_guard_events_dropped_total 'reason="ringbuf_full"')
if [ -z "$r0" ] || [ -z "$r1" ]; then
    cls="$cls; (б) серии ringbuf_full нет в m-pre/m-att1"
    echo "  (б) ringbuf_full за окно атак: НЕИЗМЕРИМ"
else
    echo "  (б) ringbuf_full за окно атак: $((r1 - r0)) (база $BASE_RINGBUF_FULL)"
    [ $((r1 - r0)) -le "$BASE_RINGBUF_FULL" ] || fail="$fail; (б) ringbuf_full $((r1 - r0)) > база $BASE_RINGBUF_FULL"
fi
# (в) recall пода — та же формула, что секция 7 гейта: категория поймана, если
# среди НОВЫХ (нет в baseline) алертов есть её comm.
man="$ATT/attack-manifest.json"
base=$(ls "$ATT"/baseline-alerts-*.json 2>/dev/null | tail -1)
fin=$(ls "$ATT"/final-alerts-*.json 2>/dev/null | tail -1)
if [ ! -s "$man" ] || [ -z "$base" ] || [ -z "$fin" ]; then
    cls="$cls; (в) нет манифеста или снимков алертов пакета пода"
    echo "  (в) recall пода: НЕИЗМЕРИМ"
else
    rec=$(jq -r -s --argjson c "$(jq -c '[.[] | select(.transit != true) | {category, comm}] | unique' "$man")" '
        (.[0] // []) as $b | (.[1] // []) as $f |
        ($b | map(.id) | unique) as $bids |
        ($f | map(select(.id as $id | ($bids | index($id)) | not)) | map(.comm) | unique) as $nc |
        ($c | map(. as $x | {category: $x.category, d: ($nc | index($x.comm) != null)}) | group_by(.category)
            | map({category: .[0].category, d: (map(.d) | any)})) as $pc |
        "\($pc | map(select(.d)) | length) \($pc | length) \($pc | map(select(.d | not) | .category) | join(","))"
    ' "$base" "$fin" 2>/dev/null)
    read -r rd rt rm <<< "$rec"
    if [ -z "${rt:-}" ] || [ "$rt" = 0 ]; then
        cls="$cls; (в) манифест пода пуст или jq не разобрал снимки"
        echo "  (в) recall пода: НЕИЗМЕРИМ"
    else
        echo "  (в) recall пода: $rd/$rt${rm:+ (не пойманы: $rm)}"
        [ "$rd" = "$rt" ] || fail="$fail; (в) recall пода $rd/$rt"
    fi
fi
if [ ! -s "$GATE" ]; then
    cls="$cls; (в) нет gate.txt хоста"
    echo "  (в) recall гейта хоста: НЕИЗМЕРИМ"
else
    g=$(sed 's/\x1b\[[0-9;]*m//g' "$GATE" | grep -aE '^\[(PASS|FAIL|SKIP)\] recall по манифесту' | tail -1)
    if [ -z "$g" ]; then
        cls="$cls; (в) в gate.txt нет строки recall (секция 7 не исполнилась)"
        echo "  (в) recall гейта хоста: НЕИЗМЕРИМ"
    else
        echo "  (в) гейт хоста: $g"
        case "$g" in
            "[PASS]"*) ;;
            "[FAIL]"*) fail="$fail; (в) recall гейта хоста FAIL" ;;
            *) cls="$cls; (в) recall гейта хоста SKIP" ;;
        esac
    fi
fi
if [ -n "$fail" ]; then
    echo "ПРОВАЛЕН: 8.2.5 ПРОВАЛЕН (${fail#; }${cls:+; неизмеримо также:$cls})"
elif [ -n "$cls" ]; then
    echo "НЕИЗМЕРИМ: 8.2.5 НЕИЗМЕРИМ (класс НАЗВАН:${cls#;})"
else
    echo "ДОСТИГНУТО: 8.2.5 ДОСТИГНУТО (потери protected 0, ringbuf_full ≤ базы, recall пода и гейта хоста 1)"
fi
