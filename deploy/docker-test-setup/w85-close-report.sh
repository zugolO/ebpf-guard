#!/bin/bash
# w85-close-report.sh <режим> — эмиттер волны 8.5. Вердикт считает ЭМИТТЕР, не человек:
# «нет серии» ≠ 0 — отсутствие входа даёт НЕИЗМЕРИМ с названным классом.
#
# Режим d1 — метка 8.5.7 по ОДНОМУ прогону пода (w85-podonly.sh):
#   RUN  каталог w82-pod-run.sh (старт: samples.tsv, f1.txt)
#   ATT  каталог w82-pod-attack.sh (samples.tsv, t-att1, m-pre/m-att1, f1.txt, манифест,
#        baseline/final-alerts-*.json)
#   Три половины судятся НЕЗАВИСИМО и печатаются каждая:
#   (а) recall пода по comm = RECALL_TOTAL/RECALL_TOTAL (16/16);
#   (б) fileaccess ringbuf_to_router за окно атак (m-pre → m-att1) ≤ R2R_FRAC × BASE_R2R
#       (база ночи 8.2 — 15 196, доля 0,5 — владелец);
#   (в) пик memory.current пода (старт и окно атак) ≤ PEAK_MAX_MIB (147,1 — верх ночи 8.2 и
#       повторов 11.10) — условие метки, а не её замена: 8.2.1 судится своим эмиттером.
#   Условие: F1 был active в начале и в конце окна атак (f1.txt) — иначе прогон не про F1,
#   НЕИЗМЕРИМ, а не «достигнуто на выключенном F1».
set -u
MODE=${1:-}
BASE_R2R=${BASE_R2R:-15196}
R2R_FRAC=${R2R_FRAC:-0.5}
PEAK_MAX_MIB=${PEAK_MAX_MIB:-147.1}
RECALL_TOTAL=${RECALL_TOTAL:-16}
RUN=${RUN:-}; ATT=${ATT:-}

# _m <файл> <метрика> [подстрока лейблов] — сумма серий; ПУСТО, если серии нет.
_m() {
    [ -s "$1" ] || return 0
    awk -v m="$2" -v lab="${3:-}" '
        /^#/ { next }
        { name = $1; sub(/\{.*/, "", name) }
        name == m && (lab == "" || index($1, lab) > 0) { s += $NF; seen = 1 }
        END { if (seen) printf "%.0f\n", s }' "$1" < /dev/null
}
_peak() {
    [ -s "$1" ] || return 0
    awk 'NF >= 2 && $2 ~ /^[0-9]+$/ { if ($2 > m) m = $2; n++ } END { if (n) printf "%.1f\n", m / 1048576 }' "$1"
}
# состояние F1 на снимке: «pre»/«att1»/«post» в первой колонке f1.txt, пусто — нет серии
_f1() {
    [ -s "$ATT/f1.txt" ] || return 0
    awk -v s="$1" '$1 == s && $2 ~ /^ebpf_guard_kernel_predicate_state/ && $NF == 1 { x = $2; sub(/.*state="/, "", x); sub(/".*/, "", x); print x; exit }' "$ATT/f1.txt"
}

d1() {
    echo "== w85 D1 (8.5.7): RUN=${RUN:-—} ATT=${ATT:-—}"
    local cls="" fail=""
    local s0 s1
    s0=$(_f1 pre); s1=$(_f1 post)
    echo "  F1: состояние в начале окна атак=${s0:-НЕТ СЕРИИ}, в конце=${s1:-НЕТ СЕРИИ}"
    if [ "$s0" != active ] || [ "$s1" != active ]; then
        cls="$cls; F1 не active на обоих концах окна атак (pre=${s0:-нет серии} post=${s1:-нет серии}) — прогон не про F1"
    fi
    local kf0 kf1
    kf0=$(_m "$ATT/m-pre.txt" ebpf_guard_syscall_events_kernel_filtered_total)
    kf1=$(_m "$ATT/m-att1.txt" ebpf_guard_syscall_events_kernel_filtered_total)
    if [ -n "$kf0" ] && [ -n "$kf1" ]; then echo "  kernel_filtered за окно атак: $((kf1 - kf0))"
    else echo "  kernel_filtered за окно атак: НЕТ СЕРИИ"; cls="$cls; нет серии kernel_filtered в m-pre/m-att1"; fi

    # (а) recall по comm — формула секции 7 гейта (как w82-close-report.sh)
    local man="$ATT/attack-manifest.json" base fin rec rd rt rm
    base=$(ls "$ATT"/baseline-alerts-*.json 2>/dev/null | tail -1)
    fin=$(ls "$ATT"/final-alerts-*.json 2>/dev/null | tail -1)
    if [ ! -s "$man" ] || [ -z "$base" ] || [ -z "$fin" ]; then
        cls="$cls; (а) нет манифеста или снимков алертов пакета пода"; echo "  (а) recall пода по comm: НЕИЗМЕРИМ"
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
        if [ -z "${rt:-}" ] || [ "$rt" != "$RECALL_TOTAL" ]; then
            cls="$cls; (а) в манифесте ${rt:-?} категорий, ожидалось $RECALL_TOTAL — знаменатель не тот"
            echo "  (а) recall пода по comm: НЕИЗМЕРИМ (категорий ${rt:-?} из ожидаемых $RECALL_TOTAL)"
        else
            echo "  (а) recall пода по comm: $rd/$rt${rm:+ (не пойманы: $rm)} (цель $RECALL_TOTAL/$RECALL_TOTAL)"
            [ "$rd" = "$rt" ] || fail="$fail; (а) recall $rd/$rt"
        fi
    fi
    # (б) fileaccess ringbuf_to_router за окно атак
    local r0 r1 lim
    r0=$(_m "$ATT/m-pre.txt" ebpf_guard_events_dropped_total 'collector="fileaccess",reason="ringbuf_to_router"')
    r1=$(_m "$ATT/m-att1.txt" ebpf_guard_events_dropped_total 'collector="fileaccess",reason="ringbuf_to_router"')
    lim=$(awk -v b="$BASE_R2R" -v f="$R2R_FRAC" 'BEGIN { printf "%.0f", b * f }')
    if [ -z "$r0" ] || [ -z "$r1" ]; then
        cls="$cls; (б) нет серии fileaccess/ringbuf_to_router в m-pre/m-att1"; echo "  (б) fileaccess ringbuf_to_router за окно атак: НЕТ СЕРИИ"
    else
        echo "  (б) fileaccess ringbuf_to_router за окно атак: $((r1 - r0)) (база ночи 8.2 $BASE_R2R, предел $lim = ${R2R_FRAC} базы)"
        [ $((r1 - r0)) -le "$lim" ] || fail="$fail; (б) ringbuf_to_router $((r1 - r0)) > $lim"
    fi
    # (в) пик memory.current
    local pa pb pm
    pa=$(_peak "$RUN/samples.tsv"); pb=$(_peak "$ATT/samples.tsv")
    if [ -z "$pa" ] || [ -z "$pb" ]; then
        cls="$cls; (в) нет сэмплов memory.current старта или окна атак"; echo "  (в) пик memory.current пода: НЕИЗМЕРИМ"
    else
        pm=$(awk -v a="$pa" -v b="$pb" 'BEGIN { print (a > b) ? a : b }')
        echo "  (в) пик memory.current пода: $pm МиБ (старт $pa, атаки $pb; предел $PEAK_MAX_MIB)"
        awk -v p="$pm" -v l="$PEAK_MAX_MIB" 'BEGIN { exit !(p <= l) }' || fail="$fail; (в) пик $pm > $PEAK_MAX_MIB"
    fi
    if [ -n "$fail" ]; then
        echo "ПРОВАЛЕН: 8.5.7 ПРОВАЛЕН (${fail#; }${cls:+; неизмеримо также:$cls})"
    elif [ -n "$cls" ]; then
        echo "НЕИЗМЕРИМ: 8.5.7 НЕИЗМЕРИМ (класс НАЗВАН:${cls#;})"
    else
        echo "ДОСТИГНУТО: 8.5.7 ДОСТИГНУТО (F1 active, recall $RECALL_TOTAL/$RECALL_TOTAL, ringbuf_to_router ≤ $lim, пик ≤ $PEAK_MAX_MIB МиБ)"
    fi
}

case "$MODE" in
    d1) d1 ;;
    *) echo "usage: w85-close-report.sh d1" >&2; exit 2 ;;
esac
