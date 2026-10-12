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

# ── 8.5.1 / 8.5.3 (первый час) / 8.5.3 (пара A/B) ─────────────────────────────
#
# flow — метка 8.5.1: syscall-событий в userspace за idle-час (сумма by_nr) ≤ FLOW_FRAC базы
#   ночи 8.2. Печатает by_nr, kernel_filtered и их сумму по номерам и по часам (решение 12).
#   Единица — СОБЫТИЯ; enter и exit — отдельными событиями, как в by_nr (разреза по фазе в
#   метриках нет — печатается как факт, а не угадывается). «До отбора» = by_nr + kernel_filtered.
#   Вход: IDLE (каталог idle-run.sh: snapshots/metrics-NNNN.txt), BASE_IDLE (то же у ночи 8.2),
#   SNAP_INTERVAL (с между снимками, 300), FLOW_FRAC (0,2 — владелец).
# anomaly-hour — строка решения 9: объём anomaly_detection за ПЕРВЫЙ час против базы; ИНФО.
# ab — метка 8.5.3: пара A/B смежных равных окон одного бинаря (w85-ab-pair.sh):
#   AB_DIR с m-a0.txt, m-ab.txt, m-b1.txt, ab-meta.txt (длина окон, моменты переключения).
#   B ≤ A + 2·√A (2σ пуассоновского шума счёта; полоса — предложение исполнителя) — ДОСТИГНУТО.
SNAP_INTERVAL=${SNAP_INTERVAL:-300}
FLOW_FRAC=${FLOW_FRAC:-0.2}
IDLE=${IDLE:-}; BASE_IDLE=${BASE_IDLE:-}; AB_DIR=${AB_DIR:-}

# _sumall <файл> <метрика> — сумма всех серий метрики; ПУСТО, если серии нет (нет серии ≠ 0)
_sumall() { _m "$1" "$2"; }
_snaps() { ls "$1"/snapshots/metrics-*.txt 2>/dev/null | sort; }

# _hourly <idle-dir> <метрика> — построчно «час значение» (дельта за полный час, 12 снимков);
# первая строка «ERR причина» при отсутствии серии/сбросе счётчика/нехватке снимков.
_hourly() {
    local dir=$1 metric=$2 snaps n per h va vb out=""
    mapfile -t snaps < <(_snaps "$dir")
    n=${#snaps[@]}
    per=$((3600 / SNAP_INTERVAL))
    [ "$n" -gt "$per" ] || { echo "ERR снимков $n — меньше часа ($((per + 1)) нужно)"; return; }
    for ((h = 0; (h + 1) * per < n; h++)); do
        va=$(_sumall "${snaps[$((h * per))]}" "$metric"); vb=$(_sumall "${snaps[$(((h + 1) * per))]}" "$metric")
        [ -n "$va" ] && [ -n "$vb" ] || { echo "ERR нет серии $metric в снимке часа $h"; return; }
        [ "$vb" -ge "$va" ] || { echo "ERR счётчик $metric упал в часе $h ($va → $vb) — рестарт агента внутри окна"; return; }
        out="$out$h $((vb - va))"$'\n'
    done
    printf '%s' "$out"
}
_mean() { awk '{ s += $2; n++ } END { if (n) printf "%.0f", s / n }'; }

# _by_nr_table <файл-начала> <файл-конца> — «nr by kf» по номерам (дельты); пусто, если нет серий by_nr
_by_nr_table() {
    awk -v f0="$1" '
        /^#/ { next }
        { name = $1; sub(/\{.*/, "", name) }
        name != "ebpf_guard_syscall_events_by_nr_total" && name != "ebpf_guard_syscall_events_kernel_filtered_total" { next }
        { nr = $1; sub(/.*nr="/, "", nr); sub(/".*/, "", nr)
          if (FILENAME == f0) { if (name ~ /by_nr/) b0[nr] = $NF; else k0[nr] = $NF }
          else { if (name ~ /by_nr/) { b1[nr] = $NF; seen[nr] = 1 } else { k1[nr] = $NF; seen[nr] = 1 } } }
        END { for (nr in seen) printf "%s %.0f %.0f\n", nr, b1[nr] - b0[nr], k1[nr] - k0[nr] }' "$1" "$2" | sort -k2,2nr
}

flow() {
    echo "== w85 8.5.1: IDLE=${IDLE:-—} BASE_IDLE=${BASE_IDLE:-—}"
    local cls="" snaps nlast first last hrs_new hrs_base mn mb kfm st
    echo "-- 8.5.1 syscall-поток в userspace за idle-час (единица — события; enter и exit отдельными событиями, разреза по фазе в метриках нет)"
    mapfile -t snaps < <(_snaps "$IDLE")
    if [ "${#snaps[@]}" -lt 2 ]; then cls="$cls; нет снимков метрик в $IDLE/snapshots"; fi
    if [ -z "$BASE_IDLE" ] || [ "$(_snaps "$BASE_IDLE" | wc -l)" -lt 2 ]; then cls="$cls; нет базы ночи 8.2 (BASE_IDLE=${BASE_IDLE:-—})"; fi
    if [ -n "$cls" ]; then echo "НЕИЗМЕРИМ: 8.5.1 НЕИЗМЕРИМ (класс НАЗВАН:${cls#;})"; return; fi
    first=${snaps[0]}; last=${snaps[$((${#snaps[@]} - 1))]}
    st=$(awk '/^ebpf_guard_kernel_predicate_state/ && $NF == 1 { x = $1; sub(/.*state="/, "", x); sub(/".*/, "", x); print x; exit }' "$last")
    echo "  F1 в конце ночи: ${st:-НЕТ СЕРИИ}"
    [ "$st" = active ] || cls="$cls; F1 не active в конце ночи (${st:-нет серии}) — ночь не про F1"
    echo "  по номерам за ночь (событий): nr by_nr kernel_filtered до_отбора"
    _by_nr_table "$first" "$last" | awk '{ printf "    nr=%-6s %12d %12d %12d\n", $1, $2, $3, $2 + $3 }'
    local rows_by rows_kf
    rows_by=$(_hourly "$IDLE" ebpf_guard_syscall_events_by_nr_total)
    rows_kf=$(_hourly "$IDLE" ebpf_guard_syscall_events_kernel_filtered_total)
    case "$rows_by" in ERR*) cls="$cls; by_nr: ${rows_by#ERR }"; rows_by="" ;; esac
    case "$rows_kf" in ERR*) cls="$cls; kernel_filtered: ${rows_kf#ERR }"; rows_kf="" ;; esac
    echo "  по часам (событий): час by_nr kernel_filtered до_отбора"
    if [ -n "$rows_by" ] && [ -n "$rows_kf" ]; then
        paste -d' ' <(echo "$rows_by") <(echo "$rows_kf" | awk '{ print $2 }') | awk '{ printf "    %2d %12d %12d %12d\n", $1, $2, $3, $2 + $3 }'
    elif [ -n "$rows_by" ]; then
        echo "$rows_by" | awk '{ printf "    %2d %12d %12s %12s\n", $1, $2, "нет серии", "—" }'
    fi
    local rows_base
    rows_base=$(_hourly "$BASE_IDLE" ebpf_guard_syscall_events_by_nr_total)
    case "$rows_base" in ERR*) cls="$cls; база: ${rows_base#ERR }"; rows_base="" ;; esac
    if [ -n "$rows_by" ] && [ -n "$rows_base" ]; then
        mn=$(echo "$rows_by" | _mean); mb=$(echo "$rows_base" | _mean)
        kfm=$(echo "$rows_kf" | _mean)
        echo "  среднее за час: сейчас by_nr $mn, kernel_filtered ${kfm:-—}, до отбора $(( mn + ${kfm:-0} )); база ночи 8.2 by_nr $mb"
        if [ -n "$cls" ]; then
            echo "НЕИЗМЕРИМ: 8.5.1 НЕИЗМЕРИМ (класс НАЗВАН:${cls#;})"
        else
            awk -v n="$mn" -v b="$mb" -v k="${kfm:-0}" -v f="$FLOW_FRAC" 'BEGIN {
                r = n / b
                if (r <= f) printf "ДОСТИГНУТО: 8.5.1 ДОСТИГНУТО (by_nr %d/ч = %.1f%% базы %d/ч ≤ %.0f%%; до отбора %d/ч = %.1f%% базы — тождество потока, не цель)\n", n, 100 * r, b, 100 * f, n + k, 100 * (n + k) / b
                else printf "ПРОВАЛЕН: 8.5.1 ПРОВАЛЕН (by_nr %d/ч = %.1f%% базы %d/ч > %.0f%%; до отбора %d/ч = %.1f%% базы)\n", n, 100 * r, b, 100 * f, n + k, 100 * (n + k) / b }'
        fi
    else
        echo "НЕИЗМЕРИМ: 8.5.1 НЕИЗМЕРИМ (класс НАЗВАН:${cls#;})"
    fi
}

# _anomaly <файл> — сумма anomaly_detection по всем event_type; ПУСТО, если серии нет
_anomaly() {
    [ -s "$1" ] || return 0
    awk '/^ebpf_guard_alert_volume_by_event_type_total\{/ && index($1, "rule_id=\"anomaly_detection\"") { s += $NF; seen = 1 } END { if (seen) printf "%.0f\n", s }' "$1" < /dev/null
}

anomaly_hour() {
    local cls="" s0 s1 b0 b1 snaps bsnaps per=$((3600 / SNAP_INTERVAL))
    mapfile -t snaps < <(_snaps "$IDLE"); mapfile -t bsnaps < <(_snaps "$BASE_IDLE")
    [ "${#snaps[@]}" -gt "$per" ] || cls="$cls; снимков ночи ${#snaps[@]} — нет первого часа"
    [ "${#bsnaps[@]}" -gt "$per" ] || cls="$cls; снимков базы ${#bsnaps[@]} — нет первого часа"
    if [ -z "$cls" ]; then
        s0=$(_anomaly "${snaps[0]}"); s1=$(_anomaly "${snaps[$per]}")
        b0=$(_anomaly "${bsnaps[0]}"); b1=$(_anomaly "${bsnaps[$per]}")
        [ -n "$s0" ] && [ -n "$s1" ] || cls="$cls; нет серии alert_volume_by_event_type{rule_id=anomaly_detection} в снимках ночи"
        [ -n "$b0" ] && [ -n "$b1" ] || cls="$cls; нет серии anomaly_detection в базе"
    fi
    if [ -n "$cls" ]; then
        echo "НЕИЗМЕРИМ: 8.5.3a НЕИЗМЕРИМ (класс НАЗВАН:${cls#;})"
    else
        local note="хост стартовал с profiler-state.json до F1 — отдельного контроля «рестарт на профиле до F1» нет, им служит эта ночь (решение 9)"
        [ "${PROFILE_BEFORE:-}" = absent ] && note="профиля до F1 на старте НЕ БЫЛО — контроль решения 9 в этой ночи НЕ ИСПОЛНЕН, число — со стартом без профиля"
        echo "ИЗМЕРЕНО: 8.5.3a объём anomaly_detection за ПЕРВЫЙ час ночи $((s1 - s0)) (база ночи 8.2: $((b1 - b0))); $note"
    fi
}

ab() {
    echo "== w85 8.5.3 (пара A/B): AB_DIR=${AB_DIR:-—}"
    local cls="" a0 ab_ b1 A B band meta
    for f in m-a0.txt m-ab.txt m-b1.txt ab-meta.txt; do [ -s "$AB_DIR/$f" ] || cls="$cls; нет $f"; done
    if [ -n "$cls" ]; then echo "НЕИЗМЕРИМ: 8.5.3 НЕИЗМЕРИМ (класс НАЗВАН:${cls#;})"; return; fi
    meta=$AB_DIR/ab-meta.txt
    echo "  окна: $(tr '\n' ' ' < "$meta")"
    # A — F1 выключен в начале окна и в его конце (переключение — ПОСЛЕ m-ab); B — включён в конце
    local sa sb
    sa=$(awk '/^ebpf_guard_kernel_predicate_state/ && $NF == 1 { x = $1; sub(/.*state="/, "", x); sub(/".*/, "", x); print x; exit }' "$AB_DIR/m-ab.txt")
    sb=$(awk '/^ebpf_guard_kernel_predicate_state/ && $NF == 1 { x = $1; sub(/.*state="/, "", x); sub(/".*/, "", x); print x; exit }' "$AB_DIR/m-b1.txt")
    sa0=$(awk '/^ebpf_guard_kernel_predicate_state/ && $NF == 1 { x = $1; sub(/.*state="/, "", x); sub(/".*/, "", x); print x; exit }' "$AB_DIR/m-a0.txt")
    echo "  состояние F1: начало A=${sa0:-нет серии}, конец A=${sa:-нет серии}, конец B=${sb:-нет серии}"
    [ "$sa0" = off_config ] && [ "$sa" = off_config ] || cls="$cls; окно A не при выключенном F1 (A: ${sa0:-нет}/${sa:-нет})"
    [ "$sb" = active ] || cls="$cls; окно B не при включённом F1 (${sb:-нет серии})"
    a0=$(_anomaly "$AB_DIR/m-a0.txt"); ab_=$(_anomaly "$AB_DIR/m-ab.txt"); b1=$(_anomaly "$AB_DIR/m-b1.txt")
    [ -n "$a0" ] && [ -n "$ab_" ] && [ -n "$b1" ] || cls="$cls; нет серии anomaly_detection в снимках пары"
    if [ -n "$cls" ]; then echo "НЕИЗМЕРИМ: 8.5.3 НЕИЗМЕРИМ (класс НАЗВАН:${cls#;})"; return; fi
    A=$((ab_ - a0)); B=$((b1 - ab_))
    band=$(awk -v a="$A" 'BEGIN { printf "%.0f", 2 * sqrt(a) }')
    echo "  anomaly_detection: A (F1 выкл) $A, B (F1 вкл) $B, полоса шума 2·√A = $band"
    if [ "$B" -le $((A + band)) ]; then
        echo "ДОСТИГНУТО: 8.5.3 ДОСТИГНУТО (B $B ≤ A $A + полоса $band; смежные равные окна одного бинаря, переключатель без рестарта)"
    else
        echo "ПРОВАЛЕН: 8.5.3 ПРОВАЛЕН (B $B > A $A + полоса $band)"
    fi
}

# controls — метка 8.5.2: положительные контроли трёх номеров ПРИ ВКЛЮЧЁННОМ F1 (w85-ctl.py
#   сырым syscall: mmap RWX anonymous, mprotect → RWX, arch_prctl(ARCH_GET_CPUID)) + состав
#   детекта на пакете атак (прокси — recall гейта хоста по манифесту = база 1; полного
#   сравнения состава с базой в приборе нет — не заявляется).
#   CTL_ALERTS — alerts.json API после контролей, CTL_STATE — metrics с состоянием F1 на момент
#   контролей, GATE — gate.txt. Контроль считается пойманным, если есть алерт правила от comm CTL_COMM.
CTL_ALERTS=${CTL_ALERTS:-}; CTL_STATE=${CTL_STATE:-}; GATE=${GATE:-}; CTL_COMM=${CTL_COMM:-python3}
controls() {
    echo "== w85 8.5.2: CTL_ALERTS=${CTL_ALERTS:-—} GATE=${GATE:-—}"
    local cls="" fail="" st rid hit n=0 want=3
    st=$(awk '/^ebpf_guard_kernel_predicate_state/ && $NF == 1 { x = $1; sub(/.*state="/, "", x); sub(/".*/, "", x); print x; exit }' "${CTL_STATE:-/dev/null}" 2>/dev/null)
    echo "  F1 на момент контролей: ${st:-НЕТ СЕРИИ}"
    [ "$st" = active ] || cls="$cls; F1 не active на контролях (${st:-нет серии}) — контроли не про F1"
    if [ ! -s "$CTL_ALERTS" ]; then
        cls="$cls; нет снимка алертов контролей"
    else
        for rid in rootkit_anonymous_exec_memory sigma_mprotect_exec_heap mitre_sandbox_detect_cpuid; do
            hit=$(jq -r --arg r "$rid" --arg c "$CTL_COMM" '[(.alerts // .)[] | select((.rule_id // .RuleID) == $r and ((.comm // .Comm) == $c))] | length' "$CTL_ALERTS" 2>/dev/null)
            echo "  контроль $rid (comm $CTL_COMM): ${hit:-?} алертов"
            case "${hit:-}" in ''|*[!0-9]*) cls="$cls; снимок алертов не разобран jq ($rid)" ;; 0) fail="$fail; контроль $rid не сработал" ;; *) n=$((n + 1)) ;; esac
        done
        hit=$(jq -r --arg c xmrig '[(.alerts // .)[] | select((.rule_id // .RuleID) == "cryptominer_binary_name" and ((.comm // .Comm) == $c))] | length' "$CTL_ALERTS" 2>/dev/null)
        echo "  ИНФО: суженное comm-правило cryptominer_binary_name (comm xmrig): ${hit:-?} алертов"
    fi
    local g
    if [ ! -s "$GATE" ]; then
        cls="$cls; нет gate.txt — состав детекта на пакете не судится"
    else
        g=$(sed 's/\x1b\[[0-9;]*m//g' "$GATE" | grep -aE '^\[(PASS|FAIL|SKIP)\] recall по манифесту' | tail -1)
        echo "  гейт хоста: ${g:-нет строки recall}"
        case "$g" in "[PASS]"*) ;; "[FAIL]"*) fail="$fail; recall гейта FAIL" ;; *) cls="$cls; в gate.txt нет строки recall" ;; esac
    fi
    if [ -n "$fail" ]; then
        echo "ПРОВАЛЕН: 8.5.2 ПРОВАЛЕН (${fail#; }${cls:+; неизмеримо также:$cls})"
    elif [ -n "$cls" ]; then
        echo "НЕИЗМЕРИМ: 8.5.2 НЕИЗМЕРИМ (класс НАЗВАН:${cls#;})"
    else
        echo "ДОСТИГНУТО: 8.5.2 ДОСТИГНУТО (контроли $n/$want при F1 active, recall гейта хоста PASS)"
    fi
}

case "$MODE" in
    controls) controls ;;
    d1) d1 ;;
    flow) flow ;;
    anomaly-hour) anomaly_hour ;;
    ab) ab ;;
    *) echo "usage: w85-close-report.sh d1|flow|anomaly-hour|ab|controls" >&2; exit 2 ;;
esac
