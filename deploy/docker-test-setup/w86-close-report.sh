#!/bin/bash
# w86-close-report.sh <режим> — эмиттеры ночи закрытия волны 8.6. Вердикт считает ЭМИТТЕР, не человек:
# «нет серии» ≠ 0, отсутствие входа даёт НЕИЗМЕРИМ с названным классом. База CPU и потока — архив ночи 8.5
# (BASE_*), числа базы читаются из архива тем же кодом, а не вписываются руками; константы порогов названы ниже.
#
# Режимы и метки:
#   cpu-idle    8.6.1   CPU idle с/с (дельта process_cpu_seconds_total) ≤ 0,6 × ночь 8.5 (0,0529)
#   cpu-event   8.6.2   CPU на событие под пакетом атак (поды этой ночи, медиана ≥ 5) ≤ 0,6 × ночь 8.5
#   rule-eval   8.6.3а  секунды RuleEngine.EvaluateInto в idle-профилях ночи на 270 с ≤ 3,96
#   bench       8.6.3б  бенч G0 на дампе w86-b ≤ 0,42 × базы; файл результата, sha бинаря сверяется
#   detect      8.6.4   состав детекта алерт-в-алерт против ночи 8.5 (реестр new-rules.txt по ДАТЕ) + 14 живых
#                       контролей трёх поправленных правил + тождество на дампе (C0)
#   pod-median  8.6.5   ringbuf_to_router fileaccess пода, медиана ≥ 5 прогонов ЭТОЙ ночи ≤ 7 122,5
#   pod-peak    8.6.6   пик пода (медиана пиков прогонов) и BPF карты+кольца ≤ ночи 8.5
#   chain       8.5.5   доля инцидентов с process_chain: хост ≥ базы И контроль цепочки ≥ 5 инцидентов, доля ≥ базы
#   memsplit    8.1.1r  разрез anon/file/memstats по снимкам (ИЗМЕРЕНО; вердикт 8.1.1 даёт night-report.sh)
#   dlist       8.6.Д   строки части Д со статусом из plan.md; «открыта» → ПРОВАЛЕН
set -u
MODE=${1:-}
SETUP=${SETUP:-$(cd "$(dirname "$0")" && pwd)}

# ── общее ──────────────────────────────────────────────────────────────────────
_m() {   # <файл> <метрика> [подстрока лейблов] — сумма серий; ПУСТО, если серии нет
    [ -s "$1" ] || return 0
    awk -v m="$2" -v lab="${3:-}" '
        /^#/ { next }
        { name = $1; sub(/\{.*/, "", name) }
        name == m && (lab == "" || index($1, lab) > 0) { s += $NF; seen = 1 }
        END { if (seen) printf "%.6f\n", s }' "$1" < /dev/null
}
_pcpu() { awk '/^process_cpu_seconds_total / { print $2; exit }' "$1" 2>/dev/null; }
_pstart() { awk '/^process_start_time_seconds / { print $2; exit }' "$1" 2>/dev/null; }
_snaps() { ls "$1"/snapshots/metrics-*.txt 2>/dev/null | sort; }
_median() { sort -n | awk '{ a[NR] = $1 } END { if (!NR) exit; if (NR % 2) printf "%.10g\n", a[(NR + 1) / 2]; else printf "%.10g\n", (a[NR / 2] + a[NR / 2 + 1]) / 2 }'; }
# verdict <метка> <fail> <cls> <строка_успеха> — ПРОВАЛЕН при fail, НЕИЗМЕРИМ при cls, иначе ДОСТИГНУТО
verdict() {
    local lbl=$1 fail=$2 cls=$3 okline=$4
    if [ -n "$fail" ]; then echo "ПРОВАЛЕН: $lbl ПРОВАЛЕН (${fail#; }${cls:+; неизмеримо также:$cls})"
    elif [ -n "$cls" ]; then echo "НЕИЗМЕРИМ: $lbl НЕИЗМЕРИМ (класс НАЗВАН:${cls#;})"
    else echo "ДОСТИГНУТО: $lbl ДОСТИГНУТО ($okline)"; fi
}

# ── 8.6.1: CPU idle ────────────────────────────────────────────────────────────
SNAP_INTERVAL=${SNAP_INTERVAL:-300}
IDLE=${IDLE:-}; BASE_IDLE=${BASE_IDLE:-}
CPU_FRAC=${CPU_FRAC:-0.6}; BASE_CPS_EXPECT=${BASE_CPS_EXPECT:-0.0529}
_idle_cps() {   # <idle-dir> → «с/с cpu_с окно_с» | «ERR причина»
    local snaps n c0 c1 s0 s1 secs
    mapfile -t snaps < <(_snaps "$1")
    n=${#snaps[@]}
    [ "$n" -ge 2 ] || { echo "ERR снимков $n < 2 в $1/snapshots"; return; }
    c0=$(_pcpu "${snaps[0]}"); c1=$(_pcpu "${snaps[$((n - 1))]}")
    s0=$(_pstart "${snaps[0]}"); s1=$(_pstart "${snaps[$((n - 1))]}")
    [ -n "$c0" ] && [ -n "$c1" ] && [ -n "$s0" ] && [ -n "$s1" ] || { echo "ERR нет серии process_cpu_seconds_total/process_start_time_seconds в крайних снимках $1"; return; }
    [ "$s0" = "$s1" ] || { echo "ERR рестарт агента внутри окна $1 (process_start_time_seconds $s0 → $s1)"; return; }
    secs=$(( (n - 1) * SNAP_INTERVAL ))
    awk -v a="$c0" -v b="$c1" -v t="$secs" 'BEGIN { if (b < a) { print "ERR process_cpu_seconds_total убыл"; exit } printf "%.5f %.2f %d\n", (b - a) / t, b - a, t }'
}
cpu_idle() {
    echo "== w86 8.6.1: IDLE=${IDLE:-—} BASE_IDLE=${BASE_IDLE:-—}"
    local cls="" fail="" ni bi
    ni=$(_idle_cps "$IDLE"); bi=$(_idle_cps "$BASE_IDLE")
    case "$ni" in ERR*) cls="$cls; idle ночи: ${ni#ERR }"; ni="" ;; esac
    case "$bi" in ERR*) cls="$cls; idle базы (ночь 8.5): ${bi#ERR }"; bi="" ;; esac
    if [ -n "$bi" ]; then
        awk -v b="${bi%% *}" -v e="$BASE_CPS_EXPECT" 'BEGIN { d = (b - e) / e; if (d < 0) d = -d; exit !(d <= 0.01) }' \
            || { cls="$cls; база из архива ${bi%% *} с/с не сходится с объявленной $BASE_CPS_EXPECT (±1%) — архив не ночи 8.5"; bi=""; }
    fi
    if [ -n "$ni" ] && [ -n "$bi" ]; then
        awk -v n="${ni%% *}" -v b="${bi%% *}" -v f="$CPU_FRAC" 'BEGIN { printf "  idle ночи %.5f с/с, база %.5f с/с, отношение %.3f, порог %.2f\n", n, b, n / b, f }'
        awk -v n="${ni%% *}" -v b="${bi%% *}" -v f="$CPU_FRAC" 'BEGIN { exit !(n <= f * b * (1 + 1e-9)) }' \
            || fail="$fail; idle ${ni%% *} с/с = $(awk -v n="${ni%% *}" -v b="${bi%% *}" 'BEGIN { printf "%.0f", 100 * n / b }')% базы ${bi%% *} > $(awk -v f="$CPU_FRAC" 'BEGIN { printf "%.0f", 100 * f }')%"
    fi
    if [ -n "$ni" ] && [ -n "$bi" ]; then
        verdict 8.6.1 "$fail" "$cls" "idle ${ni%% *} с/с = $(awk -v n="${ni%% *}" -v b="${bi%% *}" 'BEGIN { printf "%.0f", 100 * n / b }')% базы ${bi%% *} ≤ $(awk -v f="$CPU_FRAC" 'BEGIN { printf "%.0f", 100 * f }')%; CPU ${ni#* } с за окно $(echo "$ni" | awk '{ print $3 }') с"
    else
        verdict 8.6.1 "" "$cls" ""
    fi
}

# ── 8.6.2: CPU на событие под пакетом ──────────────────────────────────────────
POD_RUNS=${POD_RUNS:-}; BASE_ATT=${BASE_ATT:-}; POD_MIN_RUNS=${POD_MIN_RUNS:-5}
_att_ucpe() {   # <att-dir> → «мкс_на_событие cpu_с события окно_с» | «ERR причина»
    local d=$1 c0 c1 s0 s1 e0 e1 t
    c0=$(_pcpu "$d/m-pre.txt"); c1=$(_pcpu "$d/m-att1.txt"); s0=$(_pstart "$d/m-pre.txt"); s1=$(_pstart "$d/m-att1.txt")
    e0=$(_m "$d/m-pre.txt" ebpf_guard_events_total); e1=$(_m "$d/m-att1.txt" ebpf_guard_events_total)
    t=$(cat "$d/t-att1" 2>/dev/null)
    [ -n "$c0" ] && [ -n "$c1" ] && [ -n "$s0" ] && [ -n "$s1" ] || { echo "ERR нет process_cpu_seconds_total/start_time в m-pre/m-att1 ($d)"; return; }
    [ -n "$e0" ] && [ -n "$e1" ] || { echo "ERR нет серии ebpf_guard_events_total в m-pre/m-att1 ($d)"; return; }
    [ "$s0" = "$s1" ] || { echo "ERR рестарт агента внутри окна атак ($d)"; return; }
    awk -v a="$c0" -v b="$c1" -v x="$e0" -v y="$e1" -v t="${t:-0}" 'BEGIN { if (b < a || y <= x) { print "ERR счётчик убыл или событий нет"; exit } printf "%.3f %.2f %.0f %.0f\n", (b - a) / (y - x) * 1e6, b - a, y - x, t }'
}
cpu_event() {
    echo "== w86 8.6.2: POD_RUNS=${POD_RUNS:-—} BASE_ATT=${BASE_ATT:-—}"
    local cls="" fail="" pair att k=0 n=0 vals="" r base
    for pair in $POD_RUNS; do
        att=${pair#*:}; k=$((k + 1))
        r=$(_att_ucpe "$att")
        case "$r" in
            ERR*) cls="$cls; прогон $k: ${r#ERR }" ;;
            *) n=$((n + 1)); vals="$vals${r%% *}"$'\n'
               echo "  прогон $k ($att): $(echo "$r" | awk '{ printf "%.1f мкс CPU на событие (CPU %.1f с на %d событий за %d с)", $1, $2, $3, $4 }')" ;;
        esac
    done
    base=$(_att_ucpe "$BASE_ATT")
    case "$base" in ERR*) cls="$cls; база (ночь 8.5): ${base#ERR }"; base="" ;; esac
    if [ "$n" -lt "$POD_MIN_RUNS" ]; then cls="$cls; прогонов пода с измеренным CPU на событие $n < $POD_MIN_RUNS"; fi
    if [ -n "$base" ] && [ "$n" -ge "$POD_MIN_RUNS" ]; then
        local med lim
        med=$(printf '%s' "$vals" | _median); lim=$(awk -v b="${base%% *}" -v f="$CPU_FRAC" 'BEGIN { printf "%.3f", b * f }')
        echo "  база ночи 8.5: $(echo "$base" | awk '{ printf "%.1f мкс на событие (CPU %.1f с на %d событий за %d с)", $1, $2, $3, $4 }'); медиана ночи $med мкс; предел $lim = $CPU_FRAC базы"
        awk -v m="$med" -v l="$lim" 'BEGIN { exit !(m <= l) }' || fail="$fail; медиана $med мкс на событие > $lim"
        verdict 8.6.2 "$fail" "$cls" "медиана $med мкс на событие по $n прогонам ≤ $lim = ${CPU_FRAC} × база ${base%% *}"
    else
        verdict 8.6.2 "$fail" "$cls" ""
    fi
}

# ── 8.6.3а: секунды EvaluateInto в idle-профилях ────────────────────────────────
NORM_SECS=${NORM_SECS:-270}; EVAL_LIMIT=${EVAL_LIMIT:-3.96}; PROF_MIN=${PROF_MIN:-6}
rule_eval() {
    echo "== w86 8.6.3а: IDLE=${IDLE:-—} норма ${NORM_SECS} с, предел ${EVAL_LIMIT} с"
    local cls="" fail="" profs n out dur cum
    mapfile -t profs < <(ls "$IDLE"/snapshots/cpu-*.pprof 2>/dev/null | sort)
    n=${#profs[@]}
    command -v go > /dev/null 2>&1 || cls="$cls; нет go в PATH — профиль не разобрать"
    [ "$n" -ge "$PROF_MIN" ] || cls="$cls; профилей $n < $PROF_MIN (30 с каждый, снимает idle-run.sh при CPU_PROFILE_EVERY)"
    if [ -z "$cls" ]; then
        out=$(go tool pprof -top -cum -nodecount=400 "${profs[@]}" 2> /dev/null)
        dur=$(printf '%s\n' "$out" | sed -n 's/^Duration: *\([0-9.]*\)s.*/\1/p' | head -1)
        cum=$(printf '%s\n' "$out" | awk '/correlator\.\(\*RuleEngine\)\.EvaluateInto$/ { v = $4; if (v ~ /ms$/) { sub(/ms/, "", v); v = v / 1000 } else sub(/s$/, "", v); print v; exit }')
        if [ -z "$dur" ] || [ -z "$cum" ]; then
            cls="$cls; в сведённом профиле нет длительности (${dur:-—}) или узла RuleEngine.EvaluateInto (${cum:-—}) — профиль не от агента 8.6 или pprof не разобрал"
        else
            local norm
            norm=$(awk -v c="$cum" -v d="$dur" -v n="$NORM_SECS" 'BEGIN { printf "%.2f", c * n / d }')
            echo "  профилей $n, суммарная длительность ${dur} с, EvaluateInto cum ${cum} с; на ${NORM_SECS} с: ${norm} с (ночь 8.5: 9,43 с)"
            awk -v v="$norm" -v l="$EVAL_LIMIT" 'BEGIN { exit !(v <= l) }' || fail="$fail; EvaluateInto ${norm} с на ${NORM_SECS} с > ${EVAL_LIMIT}"
            verdict 8.6.3а "$fail" "$cls" "EvaluateInto ${norm} с на ${NORM_SECS} с ≤ ${EVAL_LIMIT} по $n профилям (${dur} с)"
            return
        fi
    fi
    verdict 8.6.3а "$fail" "$cls" ""
}

# ── 8.6.3б: бенч на дампе (файл результата + сверка sha бинаря) ─────────────────
BENCH_FILE=${BENCH_FILE:-}; IDENT=${IDENT:-}; BENCH_FRAC=${BENCH_FRAC:-0.42}
BENCH_BASE_STAND=${BENCH_BASE_STAND:-47600}; BENCH_BASE_MAC=${BENCH_BASE_MAC:-14630}; BENCH_MIN_EVENTS=${BENCH_MIN_EVENTS:-1000000}
_kv() { sed -n "s/^$2=//p" "$1" 2>/dev/null | head -1; }
bench() {
    echo "== w86 8.6.3б: BENCH_FILE=${BENCH_FILE:-—} IDENT=${IDENT:-—}"
    local cls="" fail="" bsha nsha ns nm ev lim
    if [ ! -s "$BENCH_FILE" ]; then verdict 8.6.3б "" "; нет файла результата бенча (${BENCH_FILE:-—}) — считается офлайн до ночи на бинаре ночи (w86-bench-night.sh)" ""; return; fi
    if [ ! -s "$IDENT" ]; then verdict 8.6.3б "" "; нет тождества бинаря ночи (${IDENT:-—})" ""; return; fi
    bsha=$(_kv "$BENCH_FILE" binary_sha256); nsha=$(_kv "$IDENT" sha256)
    if [ -z "$bsha" ] || [ -z "$nsha" ]; then cls="$cls; в файле бенча или тождестве нет sha бинаря"
    elif [ "$bsha" != "$nsha" ]; then cls="$cls; sha бинаря бенча ${bsha:0:12} ≠ sha бинаря ночи ${nsha:0:12} — бенч считался не на бинаре ночи"; fi
    ns=$(_kv "$BENCH_FILE" ns_stand); nm=$(_kv "$BENCH_FILE" ns_mac); ev=$(_kv "$BENCH_FILE" dump_events)
    [ -n "$ns" ] || cls="$cls; в файле бенча нет ns_stand"
    case "${ev:-0}" in ''|*[!0-9]*) ev=0 ;; esac
    [ "$ev" -ge "$BENCH_MIN_EVENTS" ] || cls="$cls; дамп в бенче $ev событий < $BENCH_MIN_EVENTS (не дамп w86-b)"
    if [ -n "$ns" ]; then
        lim=$(awk -v b="$BENCH_BASE_STAND" -v f="$BENCH_FRAC" 'BEGIN { printf "%.0f", b * f }')
        echo "  стенд: $ns ns/событие, база $BENCH_BASE_STAND, предел $lim = $BENCH_FRAC базы (отношение $(awk -v n="$ns" -v b="$BENCH_BASE_STAND" 'BEGIN { printf "%.3f", n / b }'))"
        awk -v n="$ns" -v l="$lim" 'BEGIN { exit !(n <= l) }' || fail="$fail; стенд $ns ns > $lim"
    fi
    if [ -n "$nm" ]; then
        local mg; mg=$(_kv "$BENCH_FILE" mac_git); local ng; ng=$(_kv "$IDENT" git)
        if [ -n "$mg" ] && [ -n "$ng" ] && [ "${mg:0:12}" = "${ng:0:12}" ]; then
            lim=$(awk -v b="$BENCH_BASE_MAC" -v f="$BENCH_FRAC" 'BEGIN { printf "%.0f", b * f }')
            echo "  мак (тот же коммит ${mg:0:12}): $nm ns/событие, база $BENCH_BASE_MAC, предел $lim"
            awk -v n="$nm" -v l="$lim" 'BEGIN { exit !(n <= l) }' || fail="$fail; мак $nm ns > $lim"
        else
            echo "  мак: $nm ns/событие записан для коммита ${mg:-?}, коммит ночи ${ng:-?} — НЕ судится (справочно)"
        fi
    fi
    verdict 8.6.3б "$fail" "$cls" "стенд ${ns} ns ≤ $(awk -v b="$BENCH_BASE_STAND" -v f="$BENCH_FRAC" 'BEGIN { printf "%.0f", b * f }') = ${BENCH_FRAC} × ${BENCH_BASE_STAND} на дампе ${ev} событий; sha бинаря ${nsha:0:12} совпал"
}

# ── 8.6.4: состав детекта ──────────────────────────────────────────────────────
DET_NEW=${DET_NEW:-}; DET_OLD=${DET_OLD:-}; DET_MAN=${DET_MAN:-}; NEW_RULES=${NEW_RULES:-}
NIGHT_DATE=${NIGHT_DATE:-}; BASE_DATE=${BASE_DATE:-}; RULE_CTL=${RULE_CTL:-}; C0_IDENT=${C0_IDENT:-}; DRIFT_K=${DRIFT_K:-3}
# _registry <rule> → дата заведения из new-rules.txt (пусто — нет записи)
_registry() { [ -s "$NEW_RULES" ] || return 0; awk -F'\t' -v r="$1" '$1 == r && $2 ~ /^[0-9]{8}$/ { print $2; exit }' "$NEW_RULES"; }
detect() {
    echo "== w86 8.6.4: новый=${DET_NEW:-—} база=${DET_OLD:-—} реестр=${NEW_RULES:-—} ночь=${NIGHT_DATE:-—} база-дата=${BASE_DATE:-—}"
    local cls="" fail="" rid a d only_new="" only_old="" expected="" bg=""
    [ -s "$DET_MAN" ] && jq -e 'type == "array"' "$DET_MAN" > /dev/null 2>&1 || cls="$cls; нет манифеста атак (${DET_MAN:-—})"
    for f in "$DET_NEW" "$DET_OLD"; do
        [ -s "$f" ] && jq -e 'type == "array" or type == "object"' "$f" > /dev/null 2>&1 || cls="$cls; нет или не разобран снимок алертов ${f:-—}"
    done
    case "$NIGHT_DATE" in [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;; *) cls="$cls; дата ночи не задана (YYYYMMDD)" ;; esac
    case "$BASE_DATE" in [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;; *) cls="$cls; дата базы не задана (YYYYMMDD)" ;; esac
    [ -s "$NEW_RULES" ] || cls="$cls; нет реестра new-rules.txt (${NEW_RULES:-—})"
    if [ -z "$cls" ]; then
        local T; T=$(mktemp -d)
        cnt() { jq -r '(if type == "array" then . else .alerts // [] end)[] | (.rule_id // .RuleID)' "$1" | sort | uniq -c | awk '{ print $2, $1 }' | sort; }
        cnt "$DET_NEW" > "$T/new"; cnt "$DET_OLD" > "$T/old"
        if [ ! -s "$T/new" ] || [ ! -s "$T/old" ]; then cls="$cls; в одном из снимков ноль правил (новый $(wc -l < "$T/new" | tr -d ' '), база $(wc -l < "$T/old" | tr -d ' '))"
        else
            local comms; comms=$(jq -r '.[].comm' "$DET_MAN" | sort -u | jq -R . | jq -s .)
            atk() { jq -r --arg r "$2" --argjson c "$comms" '[(if type == "array" then . else .alerts // [] end)[] | select((.rule_id // .RuleID) == $r) | select(.comm as $x | $c | index($x))] | length' "$1"; }
            for rid in $(join -v1 "$T/new" "$T/old" | awk '{ print $1 }'); do
                a=$(atk "$DET_NEW" "$rid")
                if [ "$a" -gt 0 ]; then
                    d=$(_registry "$rid")
                    # ожидаемое расширение: правило заведено ПОСЛЕ даты базы и НЕ позже даты ночи (иначе на ночи его не могло быть)
                    if [ -n "$d" ] && [ "$d" -gt "$BASE_DATE" ] && [ "$d" -le "$NIGHT_DATE" ]; then expected="$expected$rid(атака $a, реестр $d) "
                    elif [ -n "$d" ]; then only_new="$only_new$rid(атака $a, реестр $d вне окна $BASE_DATE<d≤$NIGHT_DATE) "
                    else only_new="$only_new$rid(атака $a, нет в реестре) "; fi
                else bg="$bg$rid(фон, только в новом) "; fi
            done
            for rid in $(join -v2 "$T/new" "$T/old" | awk '{ print $1 }'); do
                a=$(atk "$DET_OLD" "$rid")
                if [ "$a" -gt 0 ]; then only_old="$only_old$rid(атака $a) "; else bg="$bg$rid(фон, только в базе) "; fi
            done
            local drift; drift=$(join "$T/new" "$T/old" | awk -v k="$DRIFT_K" '{ a = $2; b = $3; if (a >= 1 && b >= 1 && (a > k * b || b > k * a)) printf "%s %s→%s; ", $1, b, a }')
            echo "  правил: новый $(wc -l < "$T/new" | tr -d ' '), база $(wc -l < "$T/old" | tr -d ' '); ожидаемое расширение по реестру: ${expected:-∅}"
            echo "  расхождения детекта — только в новом: ${only_new:-∅}; только в базе: ${only_old:-∅}; фон окон: ${bg:-нет}"
            echo "  объём разошёлся > ${DRIFT_K}× (фон окон): ${drift:-нет}"
            [ -z "$only_new" ] || fail="$fail; только в новом: ${only_new% }"
            [ -z "$only_old" ] || fail="$fail; только в базе: ${only_old% }"
        fi
        rm -rf "$T"
    fi
    # (б) живые контроли трёх поправленных правил в окне атак
    local okn failn
    if [ -s "$RULE_CTL" ]; then
        okn=$(sed -n 's/^ИТОГ: \([0-9]*\) OK, \([0-9]*\) FAIL.*/\1/p' "$RULE_CTL" | tail -1); failn=$(sed -n 's/^ИТОГ: \([0-9]*\) OK, \([0-9]*\) FAIL.*/\2/p' "$RULE_CTL" | tail -1)
        if [ -z "$okn" ]; then cls="$cls; в выводе контролей правил нет строки ИТОГ"
        else
            echo "  живые контроли трёх правил (в окне атак): $okn OK, $failn FAIL"
            grep -a '^FAIL' "$RULE_CTL" | sed 's/^/    /' | head -8
            [ "$failn" = 0 ] || fail="$fail; контроли правил: $failn FAIL"
            [ "$okn" -ge 14 ] || cls="$cls; контролей OK $okn < 14 (положительные 5 + отрицательные 5 по 14 проверок)"
        fi
    else cls="$cls; нет вывода живых контролей правил (${RULE_CTL:-—})"; fi
    # (в) тождество алертов на дампе (C0) на коде ночи
    if [ -s "$C0_IDENT" ]; then
        if grep -aq -- '--- PASS: TestDispatch_ShippedRulesetSameAlerts' "$C0_IDENT"; then
            local evn; evn=$(sed -n 's/.*событий \([0-9]*\), алертов.*/\1/p' "$C0_IDENT" | head -1)
            echo "  тождество алертов индекса G3 на дампе w86-b: PASS (событий ${evn:-?})"
            [ "${evn:-0}" -ge 1000000 ] || cls="$cls; тождество G3 шло на ${evn:-0} событий < 1 000 000 — не на дампе w86-b"
        else fail="$fail; тождество индекса G3 на дампе не PASS ($(grep -a -m1 -- '--- FAIL\|^FAIL' "$C0_IDENT" | cut -c1-120))"; fi
    else cls="$cls; нет вывода тождества G3 на дампе (${C0_IDENT:-—})"; fi
    verdict 8.6.4 "$fail" "$cls" "состав детекта = база с ожидаемым расширением по реестру (${expected:-∅}); живые контроли ${okn:-?} OK, 0 FAIL; тождество G3 на дампе PASS"
}

# ── 8.6.5 / 8.6.6: прогоны пода ночи ──────────────────────────────────────────
POD_SHA=${POD_SHA:-}; BASE_R2R=${BASE_R2R:-7122.5}
_rec() { # <run> <att> → строка REC эмиттера d1 волны 8.5
    RUN="$1" ATT="$2" bash "$SETUP/w85-close-report.sh" d1 2>&1 | grep -a '^REC ' | tail -1
}
pod_median() {
    echo "== w86 8.6.5: POD_RUNS=${POD_RUNS:-—} POD_SHA=${POD_SHA:-—} предел медианы $BASE_R2R"
    local cls="" fail="" pair run att k=0 vals="" rec r2r afail pcls sha n=0 seen=""
    [ -n "$POD_SHA" ] || cls="$cls; sha пода ночи не задан"
    for pair in $POD_RUNS; do
        run=${pair%%:*}; att=${pair#*:}; k=$((k + 1))
        [ -d "$att" ] || { cls="$cls; прогон $k: нет каталога $att"; continue; }
        local key; key=$(cd "$att" && pwd -P)
        case " $seen " in *" $key "*) cls="$cls; прогон $k повторяет уже учтённый каталог"; continue ;; esac
        seen="$seen $key"
        sha=$(cat "$run/pod-sha.txt" 2>/dev/null)
        if [ -z "$sha" ]; then cls="$cls; прогон $k: нет pod-sha.txt — бинарь прогона не предъявлен"; continue; fi
        if [ -n "$POD_SHA" ] && [ "$sha" != "$POD_SHA" ]; then cls="$cls; прогон $k: sha пода $sha ≠ ночи $POD_SHA — прогон не этого бинаря, не засчитан"; continue; fi
        rec=$(_rec "$run" "$att")
        [ -n "$rec" ] || { cls="$cls; прогон $k: эмиттер d1 не выдал REC"; continue; }
        r2r=$(printf '%s' "$rec" | sed -n 's/^REC r2r=\([^ ]*\) .*/\1/p')
        afail=$(printf '%s' "$rec" | sed -n 's/.* afail=\(.*\) cls=.*/\1/p'); pcls=$(printf '%s' "$rec" | sed -n 's/.* cls=\(.*\)$/\1/p')
        case "$r2r" in ''|-|*[!0-9]*) cls="$cls; прогон $k: ringbuf_to_router не измерен:${pcls:- нет серии}"; continue ;; esac
        # F1 active на концах окна и recall 16/16 — условия «прогон про тот продукт»; провал (а)/(в) судят свои метки
        case "$pcls" in *"F1 не active"*) cls="$cls; прогон $k: F1 не active — прогон не про F1"; continue ;; esac
        n=$((n + 1)); vals="$vals$r2r"$'\n'
        echo "  прогон $k: ringbuf_to_router $r2r (sha пода $sha)$(printf '%s' "$rec" | sed -n 's/.* rec=\([^ ]*\) peak=\([^ ]*\) .*/; recall \1, пик \2 МиБ/p')"
    done
    if [ "$n" -lt "$POD_MIN_RUNS" ]; then cls="$cls; засчитанных прогонов $n < $POD_MIN_RUNS"
    else
        local med; med=$(printf '%s' "$vals" | _median)
        echo "  отсортировано: $(printf '%s' "$vals" | sort -n | tr '\n' ' ')— медиана $med, предел $BASE_R2R (ночь 8.5)"
        awk -v m="$med" -v l="$BASE_R2R" 'BEGIN { exit !(m <= l) }' || fail="$fail; медиана ringbuf_to_router $med > $BASE_R2R"
        verdict 8.6.5 "$fail" "$cls" "медиана $med ≤ $BASE_R2R по $n прогонам одного бинаря ${POD_SHA}"
        return
    fi
    verdict 8.6.5 "$fail" "$cls" ""
}
_peak() { [ -s "$1" ] || return 0; awk 'NF >= 2 && $2 ~ /^[0-9]+$/ { if ($2 > m) m = $2; n++ } END { if (n) printf "%.1f\n", m / 1048576 }' "$1"; }
_bpf_mib() { # <inv-dir> → МиБ карт+колец по bpftool (как w85 mem) | пусто
    local inv=$1 ml rn rsz mn
    [ -s "$inv/maps.json" ] && jq -e 'type == "array"' "$inv/maps.json" > /dev/null 2>&1 || return 0
    read -r ml rn rsz mn < <(jq -r '[ (map(select(.type != "ringbuf") | .bytes_memlock // 0) | add // 0),
        (map(select(.type == "ringbuf")) | length),
        (map(select(.type == "ringbuf") | (if (.bytes_memlock // 0) > 0 then .bytes_memlock else .max_entries end)) | add // 0), length ] | @tsv' "$inv/maps.json")
    awk -v a="$ml" -v b="$rsz" 'BEGIN { printf "%.1f\n", (a + b) / 1048576 }'
}
BASE_RUN=${BASE_RUN:-}; BASE_INV=${BASE_INV:-}; INV=${INV:-}
pod_peak() {
    echo "== w86 8.6.6: POD_RUNS=${POD_RUNS:-—} INV=${INV:-—} база: RUN=${BASE_RUN:-—} ATT=${BASE_ATT:-—} INV=${BASE_INV:-—}"
    local cls="" fail="" pair run att k=0 n=0 peaks="" pa pb pm bp bb nb
    for pair in $POD_RUNS; do
        run=${pair%%:*}; att=${pair#*:}; k=$((k + 1))
        pa=$(_peak "$run/samples.tsv"); pb=$(_peak "$att/samples.tsv")
        if [ -z "$pa" ] || [ -z "$pb" ]; then cls="$cls; прогон $k: нет сэмплов memory.current (старт/атаки)"; continue; fi
        pm=$(awk -v a="$pa" -v b="$pb" 'BEGIN { print (a > b) ? a : b }'); n=$((n + 1)); peaks="$peaks$pm"$'\n'
        echo "  прогон $k: пик memory.current $pm МиБ (старт $pa, атаки $pb)"
    done
    pa=$(_peak "$BASE_RUN/samples.tsv"); pb=$(_peak "$BASE_ATT/samples.tsv")
    if [ -z "$pa" ] || [ -z "$pb" ]; then cls="$cls; нет сэмплов memory.current базы (ночь 8.5)"; bp=""
    else bp=$(awk -v a="$pa" -v b="$pb" 'BEGIN { print (a > b) ? a : b }'); fi
    bb=$(_bpf_mib "$BASE_INV"); nb=$(_bpf_mib "$INV")
    [ -n "$bb" ] || cls="$cls; нет разбираемого maps.json базы (ночь 8.5)"
    [ -n "$nb" ] || cls="$cls; нет разбираемого maps.json ночи"
    [ "$n" -ge "$POD_MIN_RUNS" ] || cls="$cls; прогонов с пиком $n < $POD_MIN_RUNS"
    if [ -n "$bp" ] && [ "$n" -ge "$POD_MIN_RUNS" ]; then
        local med mx; med=$(printf '%s' "$peaks" | _median); mx=$(printf '%s' "$peaks" | sort -n | tail -1)
        echo "  пик: медиана $med МиБ, наибольший $mx МиБ; база ночи 8.5 $bp МиБ (судится медиана пиков прогонов; наибольший — справочно)"
        awk -v m="$med" -v b="$bp" 'BEGIN { exit !(m <= b) }' || fail="$fail; медиана пиков $med МиБ > базы $bp"
    fi
    if [ -n "$bb" ] && [ -n "$nb" ]; then
        echo "  BPF карты+кольца по bpftool: ночь $nb МиБ, база $bb МиБ"
        awk -v n="$nb" -v b="$bb" 'BEGIN { exit !(n <= b) }' || fail="$fail; BPF карты+кольца $nb МиБ > базы $bb"
    fi
    verdict 8.6.6 "$fail" "$cls" "медиана пиков пода ≤ ${bp:-?} МиБ (ночь 8.5), BPF карты+кольца ${nb:-?} ≤ ${bb:-?} МиБ"
}

# ── 8.5.5 на N ≥ 5: хост + контроль цепочки ────────────────────────────────────
INC=${INC:-}; BASE_INC=${BASE_INC:-}; CTL_INC=${CTL_INC:-}; CTL_ROOT=${CTL_ROOT:-nginx}; CTL_MIN=${CTL_MIN:-5}
_share() { [ -s "$1" ] || return 0; jq -r 'if type == "array" then . else (.incidents // []) end | "\([.[] | select((.process_chain // []) | length > 0)] | length) \(length)"' "$1" 2> /dev/null; }
_ctl_share() { # <incidents.json> <корень> → «с_цепочкой всего»
    [ -s "$1" ] || return 0
    jq -r --arg r "$2" 'if type == "array" then . else (.incidents // []) end | map(select(.root_comm == $r or ((.process_chain // []) | index($r) != null))) | "\([.[] | select((.process_chain // []) | length > 0)] | length) \(length)"' "$1" 2> /dev/null
}
chain() {
    echo "== w86 8.5.5 на N ≥ ${CTL_MIN}: INC=${INC:-—} BASE_INC=${BASE_INC:-—} CTL_INC=${CTL_INC:-—} корень контроля ${CTL_ROOT}"
    local cls="" fail="" w t bw bt cw ct old
    old=$(INC="$INC" BASE_INC="$BASE_INC" CH_M0="${CH_M0:-}" CH_M1="${CH_M1:-}" bash "$SETUP/w85-close-report.sh" chain 2>&1)
    printf '%s\n' "$old" | grep -av '^\(ДОСТИГНУТО\|ПРОВАЛЕН\|НЕИЗМЕРИМ\): ' | sed 's/^/  [хост] /'
    local ov; ov=$(printf '%s\n' "$old" | grep -aE '^(ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ): 8\.5\.5' | head -1)
    case "$ov" in
        ДОСТИГНУТО*) ;;
        ПРОВАЛЕН*) fail="$fail; хост (пакет атак): ${ov#*(}" ;;
        *) cls="$cls; хост: ${ov:-эмиттер 8.5.5 не выдал вердикт}" ;;
    esac
    read -r bw bt <<< "$(_share "$BASE_INC")"
    read -r cw ct <<< "$(_ctl_share "$CTL_INC" "$CTL_ROOT")"
    if [ -z "${ct:-}" ]; then cls="$cls; нет снимка инцидентов контроля цепочки (${CTL_INC:-—})"
    elif [ -z "${bt:-}" ] || [ "$bt" -eq 0 ]; then cls="$cls; нет базы доли (BASE_INC)"
    elif [ "$ct" -lt "$CTL_MIN" ]; then cls="$cls; инцидентов контроля цепочки $ct < $CTL_MIN (корень $CTL_ROOT) — N мало, доля не судится"
    else
        echo "  контроль цепочки ${CTL_ROOT}→bash→curl: инцидентов с process_chain $cw из $ct ($(awk -v a="$cw" -v b="$ct" 'BEGIN { printf "%.1f", 100 * a / b }')%), база $bw из $bt"
        [ $((cw * bt)) -ge $((bw * ct)) ] || fail="$fail; контроль цепочки: доля $cw/$ct ниже базы $bw/$bt"
    fi
    verdict 8.5.5 "$fail" "$cls" "хост: пакет атак и чтения /proc — как 8.5.5; контроль цепочки ${CTL_ROOT}→bash→curl: $cw/$ct инцидентов с process_chain ≥ база $bw/$bt при N ≥ $CTL_MIN"
}

# ── 8.1.1r: разрез anon/file и memstats ────────────────────────────────────────
memsplit() {
    echo "== w86 8.1.1r (разрез для Д1): IDLE=${IDLE:-—}"
    local tsv="$IDLE/snapshots/cgroup-mem.tsv" snaps n cls=""
    [ -s "$tsv" ] || { echo "НЕИЗМЕРИМ: 8.1.1r НЕИЗМЕРИМ (класс НАЗВАН: нет cgroup-mem.tsv — CGROUP_MEM=0 или cgroup агента не определён)"; return; }
    mapfile -t snaps < <(_snaps "$IDLE"); n=${#snaps[@]}
    local T; T=$(mktemp -d)
    # memstats по снимкам: n → heap_inuse heap_idle heap_released stack_inuse sys
    local i f; : > "$T/ms"
    for ((i = 0; i < n; i++)); do
        f=${snaps[$i]}
        awk -v i="$i" '
            /^go_memstats_heap_inuse_bytes / { hi = $2 } /^go_memstats_heap_idle_bytes / { hd = $2 }
            /^go_memstats_heap_released_bytes / { hr = $2 } /^go_memstats_stack_inuse_bytes / { si = $2 } /^go_memstats_sys_bytes / { sy = $2 }
            END { if (hi != "") printf "%d %.0f %.0f %.0f %.0f %.0f\n", i, hi, hd, hr, si, sy; else printf "%d NA NA NA NA NA\n", i }' "$f" >> "$T/ms"
    done
    local have; have=$(grep -vc 'NA' "$T/ms")
    [ "$have" -ge 2 ] || cls="$cls; в снимках нет go_memstats_* ($have из $n)"
    # колонки tsv: timestamp n current anon file slab pagetables kernel_stack sock max
    awk -F'\t' -v ms="$T/ms" -v warm=12 '
        BEGIN { while ((getline l < ms) > 0) { split(l, a, " "); idx = a[1]; hi[idx] = a[2]; hd[idx] = a[3]; hr[idx] = a[4]; si[idx] = a[5]; sy[idx] = a[6] } }
        NR == 1 { next }
        { k = $2 + 0; cur[k] = $3; an[k] = $4; fi[k] = $5; if (k > mk) mk = k }
        function slope(arr, kind,   n, sx, sy2, sxy, sxx, k2, x, y, den) {
            n = 0; sx = sy2 = sxy = sxx = 0
            for (k2 = warm; k2 <= mk; k2++) { if (!(k2 in arr) || arr[k2] == "NA") continue; x = k2 * 300 / 3600; y = arr[k2] / 1048576; n++; sx += x; sy2 += y; sxy += x * y; sxx += x * x }
            den = n * sxx - sx * sx; if (n < 3 || den == 0) return "NA"
            return sprintf("%+.2f", (n * sxy - sx * sy2) / den)
        }
        END {
            printf "  %5s %9s %9s %9s %10s %10s %9s %9s\n", "час", "current", "anon", "file", "heap_inuse", "heap_idle-rel", "stack", "go_sys"
            for (h = 0; h * 12 <= mk; h++) { k = h * 12; if (!(k in cur)) continue
                hv = (k in hi && hi[k] != "NA") ? sprintf("%.1f", hi[k] / 1048576) : "NA"
                hl = (k in hd && hd[k] != "NA") ? sprintf("%.1f", (hd[k] - hr[k]) / 1048576) : "NA"
                sv = (k in si && si[k] != "NA") ? sprintf("%.1f", si[k] / 1048576) : "NA"
                yv = (k in sy && sy[k] != "NA") ? sprintf("%.1f", sy[k] / 1048576) : "NA"
                printf "  %5d %9.1f %9.1f %9.1f %10s %10s %9s %9s\n", h, cur[k] / 1048576, an[k] / 1048576, fi[k] / 1048576, hv, hl, sv, yv }
            printf "SLOPES current=%s anon=%s file=%s heap_inuse=%s heap_idle_minus_released=%s stack_inuse=%s go_sys=%s\n", slope(cur), slope(an), slope(fi), slope(hi), slope2(), slope(si), slope(sy)
        }
        function slope2(   k3, tmp, n2) { delete tmpa; for (k3 = 0; k3 <= mk; k3++) if ((k3 in hd) && hd[k3] != "NA") tmpa[k3] = hd[k3] - hr[k3]; return slope(tmpa) }
    ' "$tsv" > "$T/out"
    grep -v '^SLOPES' "$T/out"
    local sl; sl=$(grep '^SLOPES' "$T/out" | sed 's/^SLOPES //')
    rm -rf "$T"
    if [ -n "$cls" ]; then echo "НЕИЗМЕРИМ: 8.1.1r НЕИЗМЕРИМ (класс НАЗВАН:${cls#;}; наклоны МиБ/ч после 1 ч: $sl)"
    else echo "ИЗМЕРЕНО: 8.1.1r ИЗМЕРЕНО (наклоны МиБ/ч после 1 ч прогрева: $sl; снимков $n по 300 с; вердикт 8.1.1 — night-report.sh)"; fi
}

# ── 8.6.Д: статус части Д из plan.md ───────────────────────────────────────────
PLAN=${PLAN:-}; REPORTS=${REPORTS:-}; DEFER_ALLOWED=${DEFER_ALLOWED:-"Д4b Д15 Д17 Д18"}
dlist() {
    echo "== w86 8.6.Д: PLAN=${PLAN:-—} REPORTS=${REPORTS:-—} отложить можно только: $DEFER_ALLOWED"
    [ -s "$PLAN" ] || { verdict 8.6.Д "" "; нет plan.md (${PLAN:-—})" ""; return; }
    local blk; blk=$(awk '/<!-- D-STATUS-BEGIN -->/ { p = 1; next } /<!-- D-STATUS-END -->/ { p = 0 } p' "$PLAN" | grep -a '^| Д')
    [ -n "$blk" ] || { verdict 8.6.Д "" "; в plan.md нет таблицы статусов D-STATUS" ""; return; }
    local fail="" cls="" row id st why n=0 closed=0 deferred=0 lbl lv
    while IFS='|' read -r _ id st why _; do
        id=$(echo "$id" | xargs); st=$(echo "$st" | xargs); why=$(echo "$why" | xargs)
        [ "$id" = "Д" ] && continue   # строка заголовка таблицы
        n=$((n + 1))
        case "$st" in
            закрыт) echo "  $id: закрыт — $why"; closed=$((closed + 1)) ;;
            ночь:*)
                lbl=${st#ночь:}
                lv=""; [ -s "$REPORTS" ] && lv=$(grep -aE "^(ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО): ${lbl//./\\.}( |$)" "$REPORTS" | head -1 | cut -d: -f1)
                case "$lv" in
                    ДОСТИГНУТО) echo "  $id: закрыт ночью — метка $lbl ДОСТИГНУТО ($why)"; closed=$((closed + 1)) ;;
                    "") echo "  $id: ОТКРЫТА — метка $lbl без вердикта в отчётах ночи"; fail="$fail; $id открыта (метка $lbl без вердикта)" ;;
                    *) echo "  $id: ОТКРЫТА — метка $lbl: $lv"; fail="$fail; $id открыта (метка $lbl: $lv)" ;;
                esac ;;
            отложено)
                case " $DEFER_ALLOWED " in
                    *" $id "*) echo "  $id: отложено решением владельца — $why"; deferred=$((deferred + 1)) ;;
                    *) echo "  $id: ОТЛОЖЕНО БЕЗ ПРАВА — «отложено» допустимо только для: $DEFER_ALLOWED"; fail="$fail; $id отложено без решения владельца" ;;
                esac ;;
            открыта) echo "  $id: ОТКРЫТА — $why"; fail="$fail; $id открыта" ;;
            *) echo "  $id: статус «${st}» не из перечня"; cls="$cls; $id: статус «${st}» не из перечня (закрыт|ночь:<метка>|отложено|открыта)" ;;
        esac
    done <<< "$blk"
    [ "$n" -gt 0 ] || cls="$cls; таблица статусов пуста"
    verdict 8.6.Д "$fail" "$cls" "строк части Д $n: закрыто $closed, отложено решением владельца $deferred (${DEFER_ALLOWED}), открытых 0"
}

case "$MODE" in
    cpu-idle) cpu_idle ;;
    cpu-event) cpu_event ;;
    rule-eval) rule_eval ;;
    bench) bench ;;
    detect) detect ;;
    pod-median) pod_median ;;
    pod-peak) pod_peak ;;
    chain) chain ;;
    memsplit) memsplit ;;
    dlist) dlist ;;
    *) echo "usage: w86-close-report.sh cpu-idle|cpu-event|rule-eval|bench|detect|pod-median|pod-peak|chain|memsplit|dlist" >&2; exit 2 ;;
esac
