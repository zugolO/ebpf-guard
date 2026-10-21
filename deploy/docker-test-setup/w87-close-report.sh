#!/bin/bash
# w87-close-report.sh <режим> — эмиттеры ночи закрытия волны 8.7. Вердикт считает ЭМИТТЕР, не человек:
# «нет серии» ≠ 0, отсутствие входа даёт НЕИЗМЕРИМ с названным классом. Базы читаются из архивов тем же кодом,
# а не вписываются руками; константы порогов названы ниже. Собран из w86-close-report.sh (ночь 8.6).
#
# Режимы и метки:
#   cpu-idle    8.7.2   CPU idle с/с ≤ 0,8 × ночь 8.6 (0,03058 → 0,0245)
#   cpu-idle86  8.6.1   сторож «не хуже ночи 8.6»: idle ≤ 0,6 × ночь 8.5 (0,0529), прежняя формула
#   cpu-event   8.7.1   CPU на событие под пакетом (поды этой ночи, медиана ≥ 5) ≤ 0,6 × ночь 8.5 (82,3 мкс), без смягчения
#                       (решение 6 владельца 16.10); цена раскладывается по event_type из cpu-*.pprof (справочно)
#   sched       8.7.3   с волны 9 (В2): секунды планировщика Go (findRunnable cum) на 270 с ≤ 1,14 (0,8 × 1,43 ночи 8.6); доля — справка
#   rule-eval   8.6.3а  секунды RuleEngine.EvaluateInto в idle-профилях ночи на 270 с ≤ 3,96 (сторож «не хуже ночи 8.6»)
#   bench       8.6.3б  бенч G0 на дампе w86-b ≤ 0,42 × базы; sha бинаря сверяется
#   detect      8.7.4   состав детекта алерт-в-алерт против ночи 8.6 (реестр new-rules.txt по ДАТЕ) + 14 живых контролей
#                       + тождество на дампе (список тестов IDENT_TESTS)
#   pod-median  8.7.5   ringbuf_to_router fileaccess пода, медиана ≥ 5 прогонов ЭТОЙ ночи ≤ 7 122,5
#   pod-peak    8.6.6   Д6′: пик пода (медиана пиков) ≤ медианы пиков пяти прогонов ночи 8.6 (143,5), считается из архива
#   pod-peak128 9.2     (волна 9, Д15) цель Д2: медиана пиков пода core (rego_active=0) ≤ 128 МиБ; прогон с Rego в зачёт не идёт
#   mem-slice   8.2.2   Д3′: memory.current − карты P1 на 30-й минуте КАЖДОГО прогона пода, медиана ≥ 5 ≤ 120
#   chain       8.5.5   Д12′: доля инцидентов с process_chain БЕЗ root_pid == 1, одинаково в базе и в ночи (прежняя — справочно)
#   prof        8.7.6   профили под пакетом (хост и каждый под) и block/mutex-профиль в архиве, ≥ 1000 сэмплов CPU на прогон
#   memsplit    8.1.1r  разрез anon/file/memstats по снимкам (ИЗМЕРЕНО)
#   ref-811     —       справочно к 8.1.1 (Д1′): прыжки next_gc > 1 МиБ за срез и набор event_type алертов на краях окна;
#                       класс 8.1.1 не меняет (вердикт — night-report.sh)
#   dlist       8.7.Д   строки части Д со статусом из plan.md; «открыта» → ПРОВАЛЕН
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

# ── 8.7.2: CPU idle ────────────────────────────────────────────────────────────
SNAP_INTERVAL=${SNAP_INTERVAL:-300}
IDLE=${IDLE:-}; BASE_IDLE=${BASE_IDLE:-}
CPU_FRAC=${CPU_FRAC:-0.8}; BASE_CPS_EXPECT=${BASE_CPS_EXPECT:-0.03058}; EVENT_FRAC=${EVENT_FRAC:-0.6}; BASE_EVENT_CPS_EXPECT=${BASE_EVENT_CPS_EXPECT:-137.2}
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
CPU_LABEL=${CPU_LABEL:-8.7.2}; BASE_NAME=${BASE_NAME:-ночь 8.6}
cpu_idle() {
    echo "== w87 $CPU_LABEL: IDLE=${IDLE:-—} BASE_IDLE=${BASE_IDLE:-—}"
    local cls="" fail="" ni bi
    ni=$(_idle_cps "$IDLE"); bi=$(_idle_cps "$BASE_IDLE")
    case "$ni" in ERR*) cls="$cls; idle ночи: ${ni#ERR }"; ni="" ;; esac
    case "$bi" in ERR*) cls="$cls; idle базы ($BASE_NAME): ${bi#ERR }"; bi="" ;; esac
    if [ -n "$bi" ]; then
        awk -v b="${bi%% *}" -v e="$BASE_CPS_EXPECT" 'BEGIN { d = (b - e) / e; if (d < 0) d = -d; exit !(d <= 0.01) }' \
            || { cls="$cls; база из архива ${bi%% *} с/с не сходится с объявленной $BASE_CPS_EXPECT (±1%) — архив не $BASE_NAME"; bi=""; }
    fi
    if [ -n "$ni" ] && [ -n "$bi" ]; then
        awk -v n="${ni%% *}" -v b="${bi%% *}" -v f="$CPU_FRAC" 'BEGIN { printf "  idle ночи %.5f с/с, база %.5f с/с, отношение %.3f, порог %.2f\n", n, b, n / b, f }'
        awk -v n="${ni%% *}" -v b="${bi%% *}" -v f="$CPU_FRAC" 'BEGIN { exit !(n <= f * b * (1 + 1e-9)) }' \
            || fail="$fail; idle ${ni%% *} с/с = $(awk -v n="${ni%% *}" -v b="${bi%% *}" 'BEGIN { printf "%.0f", 100 * n / b }')% базы ${bi%% *} > $(awk -v f="$CPU_FRAC" 'BEGIN { printf "%.0f", 100 * f }')%"
    fi
    if [ -n "$ni" ] && [ -n "$bi" ]; then
        verdict "$CPU_LABEL" "$fail" "$cls" "idle ${ni%% *} с/с = $(awk -v n="${ni%% *}" -v b="${bi%% *}" 'BEGIN { printf "%.0f", 100 * n / b }')% базы ${bi%% *} ≤ $(awk -v f="$CPU_FRAC" 'BEGIN { printf "%.0f", 100 * f }')%; CPU ${ni#* } с за окно $(echo "$ni" | awk '{ print $3 }') с"
    else
        verdict "$CPU_LABEL" "" "$cls" ""
    fi
}

# ── 8.7.1: CPU на событие под пакетом ──────────────────────────────────────────
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
    echo "== w87 8.7.1: POD_RUNS=${POD_RUNS:-—} BASE_ATT=${BASE_ATT:-—}"
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
    if [ -n "$base" ]; then
        awk -v b="${base%% *}" -v e="$BASE_EVENT_CPS_EXPECT" 'BEGIN { d = (b - e) / e; if (d < 0) d = -d; exit !(d <= 0.01) }' \
            || { cls="$cls; база из архива ${base%% *} мкс не сходится с объявленной $BASE_EVENT_CPS_EXPECT (±1%) — архив не ночи 8.5"; base=""; }
    fi
    if [ "$n" -lt "$POD_MIN_RUNS" ]; then cls="$cls; прогонов пода с измеренным CPU на событие $n < $POD_MIN_RUNS"; fi
    if [ -n "$base" ] && [ "$n" -ge "$POD_MIN_RUNS" ]; then
        local med lim
        med=$(printf '%s' "$vals" | _median); lim=$(awk -v b="${base%% *}" -v f="$EVENT_FRAC" 'BEGIN { printf "%.3f", b * f }')
        echo "  база ночи 8.5: $(echo "$base" | awk '{ printf "%.1f мкс на событие (CPU %.1f с на %d событий за %d с)", $1, $2, $3, $4 }'); медиана ночи $med мкс; предел $lim = $EVENT_FRAC базы"
        awk -v m="$med" -v l="$lim" 'BEGIN { exit !(m <= l) }' || fail="$fail; медиана $med мкс на событие > $lim"
        cpu_split
        verdict 8.7.1 "$fail" "$cls" "медиана $med мкс на событие по $n прогонам ≤ $lim = ${EVENT_FRAC} × база ${base%% *}"
    else
        cpu_split
        verdict 8.7.1 "$fail" "$cls" ""
    fi
}

# ── CPU под пакетом по типу события (П0(а), справочно к 8.7.1) ──────────────────
# _secs <10s|120ms|1.5s|0> → секунды
_secs() { awk -v v="$1" 'BEGIN { if (v ~ /ms$/) { sub(/ms/, "", v); v = v / 1000 } else if (v ~ /us$/) { sub(/us/, "", v); v = v / 1e6 } else sub(/s$/, "", v); printf "%.6f", v }'; }
# _total_s <pprof…> → сумма CPU-секунд сведённых профилей («Total samples = Xs»)
_total_s() { local t; t=$(go tool pprof -top "$@" 2> /dev/null | sed -n 's/^Duration: .*Total samples = \([0-9.]*[a-z]*\).*/\1/p' | head -1); [ -n "$t" ] && _secs "$t"; }
# _event_split <pprof…> → «тип секунды» по строке
_event_split() {
    go tool pprof -tags "$@" 2> /dev/null | awk '
        /^ *event_type: Total/ { on = 1; next }
        on && /^ *[a-zA-Z0-9_.]+: Total/ { on = 0 }
        on && /\([0-9.]+%\): / { v = $1; t = $NF; if (v ~ /ms$/) { sub(/ms/, "", v); v = v / 1000 } else if (v ~ /us$/) { sub(/us/, "", v); v = v / 1e6 } else sub(/s$/, "", v); printf "%s %.4f\n", t, v }'
}
# cpu_split — по cpu-*.pprof каталогов атак пода (POD_RUNS) и хоста (HOST_CPU_DIR); справочно, на вердикт не влияет.
cpu_split() {
    local pair att files=() f tot lab t row
    for pair in $POD_RUNS; do att=${pair#*:}; for f in "$att"/cpu-*.pprof; do [ -s "$f" ] && files+=("$f"); done; done
    if [ "${#files[@]}" -eq 0 ]; then
        echo "  СПРАВОЧНО: разложение цены по event_type НЕ СНЯТО — в каталогах атак подов нет cpu-*.pprof (прибор П0(а)); 8.7.6 судит наличие"
        return
    fi
    command -v go > /dev/null 2>&1 || { echo "  СПРАВОЧНО: разложение по event_type — нет go в PATH"; return; }
    tot=$(_total_s "${files[@]}"); [ -n "$tot" ] || { echo "  СПРАВОЧНО: разложение по event_type — профили не разобраны"; return; }
    row=$(_event_split "${files[@]}" | awk '{ a[$1] += $2; l += $2 } END { for (k in a) printf "%s %.3f\n", k, a[k] }' | sort -k2 -nr)
    lab=$(printf '%s\n' "$row" | awk '{ s += $2 } END { printf "%.3f", s }')
    echo "  СПРАВОЧНО: цена под пакетом по event_type (cpu-*.pprof ${#files[@]} файлов, всего CPU ${tot} с; метка стоит на проходе RuleEngine.EvaluateInto, остальное — без метки):"
    printf '%s\n' "$row" | awk -v tot="$tot" 'NF == 2 { printf "      %-14s %8.2f с  %5.1f%%\n", $1, $2, 100 * $2 / tot }'
    awk -v l="${lab:-0}" -v tot="$tot" 'BEGIN { printf "      %-14s %8.2f с  %5.1f%%  (читатель колец, роутер, алерты/стор/Rego/инциденты, GC, планировщик)\n", "без метки", tot - l, 100 * (tot - l) / tot }'
}

# ── 8.7.3: доля планировщика Go в idle-профилях ──────────────────────────────────
NORM_SECS=${NORM_SECS:-270}; PROF_MIN=${PROF_MIN:-6}
SCHED_MAX=${SCHED_MAX:-15}; SCHED_FN=${SCHED_FN:-runtime.findRunnable}
# _sched_abs <idle-dir> → «доля% cum_с длительность_с профилей» | пусто. Один прибор для ночи и для базы: сведённые
# idle-профили, `pprof -top -cum`, узел $SCHED_FN. Заход Е3 (волна 8.7): доля ВРЁТ там, где падает знаменатель
# (ночь 8.7: findRunnable −32% в секундах, а доля 24,7% → 23,0%), поэтому рядом печатаются секунды.
_sched_abs() {
    local profs out dur pct cum
    mapfile -t profs < <(ls "$1"/snapshots/cpu-*.pprof 2>/dev/null | sort)
    [ "${#profs[@]}" -ge "$PROF_MIN" ] || return 0
    out=$(go tool pprof -top -cum -nodecount=600 "${profs[@]}" 2> /dev/null)
    dur=$(printf '%s\n' "$out" | sed -n 's/^Duration: *\([0-9.]*\)s.*/\1/p' | head -1)
    printf '%s\n' "$out" | awk -v fn="$SCHED_FN" -v d="$dur" -v n="${#profs[@]}" '
        $NF == fn { p = $5; sub(/%/, "", p); v = $4; if (v ~ /ms$/) { sub(/ms/, "", v); v = v / 1000 } else sub(/s$/, "", v); printf "%s %s %s %s\n", p, v, d, n; exit }'
}
# sched_abs — справочная строка (вердикта не меняет): секунды на NORM_SECS и отношение к базе ТОГО ЖЕ прибора.
sched_abs() {
    local cur base cp cs cd cn bp bs bd bn
    cur=$(_sched_abs "$IDLE"); [ -n "$cur" ] || return 0
    read -r cp cs cd cn <<< "$cur"
    local cn_s; cn_s=$(awk -v c="$cs" -v d="$cd" -v n="$NORM_SECS" 'BEGIN { printf "%.2f", c * n / d }')
    if [ -z "${BASE_IDLE:-}" ]; then
        echo "  СПРАВОЧНО (Е3): $SCHED_FN cum ${cs} с за ${cd} с профилей = ${cn_s} с на ${NORM_SECS} с (доля ${cp}%); базы того же прибора не задано (BASE_IDLE)"
        return 0
    fi
    base=$(_sched_abs "$BASE_IDLE")
    if [ -z "$base" ]; then
        echo "  СПРАВОЧНО (Е3): $SCHED_FN cum ${cs} с за ${cd} с = ${cn_s} с на ${NORM_SECS} с (доля ${cp}%); база $BASE_IDLE — меньше $PROF_MIN idle-профилей или нет узла, отношение НЕ СЧИТАЕТСЯ"
        return 0
    fi
    read -r bp bs bd bn <<< "$base"
    local bn_s; bn_s=$(awk -v c="$bs" -v d="$bd" -v n="$NORM_SECS" 'BEGIN { printf "%.2f", c * n / d }')
    awk -v cs="$cn_s" -v bs="$bn_s" -v cp="$cp" -v bp="$bp" -v fn="$SCHED_FN" -v n="$NORM_SECS" 'BEGIN {
        printf "  СПРАВОЧНО (Е3): %s на %d с: ночь %.2f с (доля %s%%), база того же прибора %.2f с (доля %s%%); секунды к базе %.2f, доля к базе %.2f\n", fn, n, cs, cp, bs, bp, cs / bs, cp / bp }'
}
# Волна 9, В2 (решение владельца 18.10.2026): 8.7.3 судится СЕКУНДАМИ findRunnable cum на 270 с, не долей. Доля врёт там,
# где падает знаменатель (Е3: ночь 8.7 — секунды −32%, доля 24,7% → 23,0%). Порог SEC_MAX = SEC_FRAC × BASE_SEC_EXPECT
# = 0,8 × 1,43 = 1,14 с; 1,43 — секунды ТОГО ЖЕ прибора на idle-профилях ночи 8.6. База из архива (BASE_IDLE) сверяется с
# объявленной константой (±2%): не сошлась — НЕИЗМЕРИМ (порог считан от другой базы). Доля печатается справкой.
SEC_FRAC=${SEC_FRAC:-0.8}; BASE_SEC_EXPECT=${BASE_SEC_EXPECT:-1.43}; SEC_MAX=${SEC_MAX:-1.14}
sched() {
    echo "== w87 8.7.3 (волна 9, В2): IDLE=${IDLE:-—} предел секунд $SCHED_FN cum на ${NORM_SECS} с ≤ ${SEC_MAX} (= ${SEC_FRAC} × ${BASE_SEC_EXPECT} базы ночи 8.6); доля — справкой (прежний предел ${SCHED_MAX}%)"
    local cls="" fail="" cur cp cs cd cn cn_s
    command -v go > /dev/null 2>&1 || cls="$cls; нет go в PATH — профиль не разобрать"
    local nprof; nprof=$(ls "$IDLE"/snapshots/cpu-*.pprof 2>/dev/null | wc -l | tr -d ' ')
    [ "$nprof" -ge "$PROF_MIN" ] || cls="$cls; профилей $nprof < $PROF_MIN (снимает idle-run.sh при CPU_PROFILE_EVERY)"
    if [ -z "$cls" ]; then
        cur=$(_sched_abs "$IDLE")
        if [ -z "$cur" ]; then
            cls="$cls; в сведённом профиле нет узла $SCHED_FN — профиль не от агента или pprof не разобрал"
        else
            read -r cp cs cd cn <<< "$cur"
            cn_s=$(awk -v c="$cs" -v d="$cd" -v n="$NORM_SECS" 'BEGIN { printf "%.2f", c * n / d }')
            echo "  профилей $cn, $SCHED_FN cum ${cs} с за ${cd} с профилей = ${cn_s} с на ${NORM_SECS} с (доля ${cp}% — справка)"
            if [ -n "${BASE_IDLE:-}" ]; then
                sched_abs
                local base bp bs bd bn bn_s
                base=$(_sched_abs "$BASE_IDLE")
                if [ -z "$base" ]; then cls="$cls; база $BASE_IDLE — меньше $PROF_MIN idle-профилей или нет узла, объявленная база $BASE_SEC_EXPECT с не сверена"
                else
                    read -r bp bs bd bn <<< "$base"
                    bn_s=$(awk -v c="$bs" -v d="$bd" -v n="$NORM_SECS" 'BEGIN { printf "%.2f", c * n / d }')
                    awk -v b="$bn_s" -v e="$BASE_SEC_EXPECT" 'BEGIN { d = (b - e) / e; if (d < 0) d = -d; exit !(d <= 0.02) }' \
                        || cls="$cls; база из архива $bn_s с не сходится с объявленной $BASE_SEC_EXPECT с (±2%) — порог $SEC_MAX считан не от ночи 8.6"
                fi
            else
                echo "  СПРАВОЧНО: базы того же прибора не задано (BASE_IDLE) — судит объявленная константа $SEC_MAX с = $SEC_FRAC × $BASE_SEC_EXPECT"
            fi
            awk -v v="$cn_s" -v l="$SEC_MAX" 'BEGIN { exit !(v <= l + 1e-9) }' || fail="$fail; $SCHED_FN cum ${cn_s} с на ${NORM_SECS} с > ${SEC_MAX} с (доля ${cp}%)"
            verdict 8.7.3 "$fail" "$cls" "$SCHED_FN cum ${cn_s} с на ${NORM_SECS} с ≤ ${SEC_MAX} с = ${SEC_FRAC} × ${BASE_SEC_EXPECT}; доля ${cp}% — справка; по ${cn} профилям"
            return
        fi
    fi
    verdict 8.7.3 "$fail" "$cls" ""
}

# ── 8.7.6: приборы П0 — профили под пакетом и block/mutex в архиве ────────────────
PROF_MIN_SAMPLES=${PROF_MIN_SAMPLES:-1000}; HOST_CPU_DIR=${HOST_CPU_DIR:-}; BLOCK_DIR=${BLOCK_DIR:-}
_samples_n() { go tool pprof -sample_index=samples -top "$@" 2> /dev/null | sed -n 's/^Duration: .*Total samples = \([0-9]*\).*/\1/p' | head -1; }
prof() {
    echo "== w87 8.7.6: POD_RUNS=${POD_RUNS:-—} HOST_CPU_DIR=${HOST_CPU_DIR:-—} BLOCK_DIR=${BLOCK_DIR:-—} ≥ ${PROF_MIN_SAMPLES} сэмплов CPU на прогон"
    local cls="" fail="" pair att k=0 files f nsm labs
    command -v go > /dev/null 2>&1 || { verdict 8.7.6 "" "; нет go в PATH — профили не разобрать" ""; return; }
    chk() { # <имя> <каталог>
        files=(); for f in "$2"/cpu-*.pprof; do [ -s "$f" ] && files+=("$f"); done
        if [ "${#files[@]}" -eq 0 ]; then fail="$fail; $1: нет cpu-*.pprof в $2"; return; fi
        nsm=$(_samples_n "${files[@]}")
        if [ -z "$nsm" ]; then fail="$fail; $1: профили не разобраны pprof"; return; fi
        labs=$(_event_split "${files[@]}" | awk '{ s += $2 } END { printf "%.1f", s }')
        echo "  $1: ${#files[@]} файлов, $nsm сэмплов CPU, с меткой event_type ${labs:-0} с"
        [ "$nsm" -ge "$PROF_MIN_SAMPLES" ] || fail="$fail; $1: сэмплов $nsm < $PROF_MIN_SAMPLES"
    }
    chk "хост (окно пакета)" "${HOST_CPU_DIR:-/нет}"
    for pair in $POD_RUNS; do k=$((k + 1)); att=${pair#*:}; chk "под $k" "$att"; done
    [ "$k" -gt 0 ] || cls="$cls; прогонов пода нет"
    # block/mutex: отдельное окно после idle, переключатель вернулся в 0
    if [ -s "$BLOCK_DIR/block.pprof" ] && [ -s "$BLOCK_DIR/mutex.pprof" ] && grep -aq '^done' "$BLOCK_DIR/DONE" 2> /dev/null; then
        echo "  block/mutex: block.pprof $(wc -c < "$BLOCK_DIR/block.pprof" | tr -d ' ') Б, mutex.pprof $(wc -c < "$BLOCK_DIR/mutex.pprof" | tr -d ' ') Б, окно закрыто ($(cat "$BLOCK_DIR/DONE"))"
    else
        fail="$fail; block/mutex-профиль не снят (${BLOCK_DIR:-—}: $(cat "$BLOCK_DIR/DONE" 2> /dev/null || echo 'нет DONE'))"
    fi
    verdict 8.7.6 "$fail" "$cls" "профили под пакетом у хоста и $k подов ≥ ${PROF_MIN_SAMPLES} сэмплов CPU, block/mutex-профиль в архиве"
}

# ── 8.2.2 (Д3′): память idle пода на 30-й минуте КАЖДОГО прогона ─────────────────
POD_INVS=${POD_INVS:-}; IDLE_MAX_MIB=${IDLE_MAX_MIB:-120}
mem_slice() {
    echo "== w87 8.2.2 (Д3′): POD_INVS=${POD_INVS:-—} предел медианы $IDLE_MAX_MIB МиБ (memory.current − карты P1, срез на 30-й минуте)"
    local cls="" fail="" inv k=0 n=0 vals="" line v
    for inv in $POD_INVS; do
        k=$((k + 1))
        [ -d "$inv" ] || { cls="$cls; прогон $k: нет каталога среза $inv"; continue; }
        line=$(bash "$SETUP/w82-mem-report.sh" "$inv" 2>&1 | grep -aE '^(ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ): 8\.2\.2 ' | head -1)
        case "$line" in
            НЕИЗМЕРИМ*) cls="$cls; прогон $k: ${line#*(класс НАЗВАН: }"; continue ;;
            "") cls="$cls; прогон $k: w82-mem-report.sh не выдал 8.2.2"; continue ;;
        esac
        v=$(printf '%s' "$line" | sed -n 's/.*= \([0-9.]*\) МиБ.*/\1/p')
        [ -n "$v" ] || { cls="$cls; прогон $k: в строке 8.2.2 нет числа"; continue; }
        n=$((n + 1)); vals="$vals$v"$'\n'
        echo "  прогон $k: $v МиБ ($(printf '%s' "$line" | sed -n 's/^[^:]*: 8\.2\.2 \([^ ]*\).*/\1/p'))"
    done
    if [ "$n" -lt "$POD_MIN_RUNS" ]; then cls="$cls; срезов на 30-й минуте $n < $POD_MIN_RUNS"
    else
        local med; med=$(printf '%s' "$vals" | _median)
        echo "  отсортировано: $(printf '%s' "$vals" | sort -n | tr '\n' ' ')— медиана $med, предел $IDLE_MAX_MIB; разброс $(printf '%s' "$vals" | sort -n | awk 'NR == 1 { lo = $1 } { hi = $1 } END { printf "%.1f", hi - lo }') МиБ"
        awk -v m="$med" -v l="$IDLE_MAX_MIB" 'BEGIN { exit !(m <= l) }' || fail="$fail; медиана $med МиБ > $IDLE_MAX_MIB"
        verdict 8.2.2 "$fail" "$cls" "медиана $med МиБ ≤ $IDLE_MAX_MIB по $n срезам на 30-й минуте"
        return
    fi
    verdict 8.2.2 "$fail" "$cls" ""
}

# ── справочно к 8.1.1 (Д1′): ступеньки next_gc и event_type алертов на краях окна ─────────
# Печать не меняет класс 8.1.1 (его даёт night-report.sh): называет ступеньку Rego (№564) там, где классификатор
# по anon её не видит (anon догонял кучу ≈ 75 мин, ночь 8.6).
STEP_MIB=${STEP_MIB:-1}; EDGE_ALERTS=${EDGE_ALERTS:-}; EDGE_N=${EDGE_N:-2}
ref_811() {
    echo "== w87 справочно к 8.1.1: IDLE=${IDLE:-—} прыжок next_gc > ${STEP_MIB} МиБ за срез; алерты краёв окна: ${EDGE_ALERTS:-—}"
    local snaps n i prev cur steps="" nst=0 d
    mapfile -t snaps < <(_snaps "$IDLE"); n=${#snaps[@]}
    if [ "$n" -lt 2 ]; then echo "СПРАВОЧНО: 8.1.1 прыжки next_gc НЕИЗМЕРИМЫ (снимков $n < 2)"; else
        prev=""; local nse=0
        for ((i = 0; i < n; i++)); do
            cur=$(awk '/^go_memstats_next_gc_bytes / { printf "%.0f", $2; exit }' "${snaps[$i]}")
            if [ -z "$cur" ]; then nse=$((nse + 1)); continue; fi
            if [ -n "$prev" ]; then
                d=$(awk -v a="$prev" -v b="$cur" 'BEGIN { printf "%.2f", (b - a) / 1048576 }')
                if awk -v d="$d" -v t="$STEP_MIB" 'BEGIN { exit !(d > t || d < -t) }'; then
                    nst=$((nst + 1)); steps="$steps снимок $i: $(awk -v a="$prev" 'BEGIN { printf "%.1f", a / 1048576 }')→$(awk -v b="$cur" 'BEGIN { printf "%.1f", b / 1048576 }') МиБ (${d:0:6});"
                fi
            fi
            prev=$cur
        done
        if [ "$nse" -ge "$n" ]; then echo "СПРАВОЧНО: 8.1.1 прыжки next_gc НЕИЗМЕРИМЫ (в снимках нет go_memstats_next_gc_bytes)"
        else echo "СПРАВОЧНО: 8.1.1 прыжков next_gc больше ${STEP_MIB} МиБ за срез: $nst${steps:+ —$steps} (снимков $n; без серии $nse)"; fi
    fi
    if [ -s "$EDGE_ALERTS" ] && jq -e 'type == "array" or type == "object"' "$EDGE_ALERTS" > /dev/null 2>&1; then
        # Алерт API не несёт event_type (память alert-has-no-event-type-axis): тип берётся из загруженных правил по rule_id.
        local map ets T; T=$(mktemp -d)
        # правила — простой YAML (`- id: X` … `event_type: Y`): awk, без pyyaml (мак его не имеет)
        cat "${RULES_DIR:-$SETUP/../../rules}"/*.yaml 2> /dev/null | awk '
            /^[[:space:]]*-[[:space:]]+id:[[:space:]]*/ { id = $0; sub(/^[[:space:]]*-[[:space:]]+id:[[:space:]]*/, "", id); gsub(/["'"'"']/, "", id); sub(/[[:space:]]+#.*/, "", id); sub(/[[:space:]]+$/, "", id); seen[id] = 0; cur = id; next }
            /^[[:space:]]+event_type:[[:space:]]*/ && cur != "" && !seen[cur] { t = $0; sub(/^[[:space:]]+event_type:[[:space:]]*/, "", t); gsub(/["'"'"']/, "", t); sub(/[[:space:]]+#.*/, "", t); sub(/[[:space:]]+$/, "", t); print cur "\t" t; seen[cur] = 1 }' > "$T/map.tsv"
        ets=$(jq -r --argjson k "$EDGE_N" '(if type == "array" then . else .alerts // [] end) | sort_by(.timestamp // .Timestamp // "")
            | (.[:$k] + .[-$k:]) | map(.rule_id // .RuleID // "?") | unique | .[]' "$EDGE_ALERTS" 2> /dev/null \
            | while read -r rid; do t=$(awk -F'\t' -v r="$rid" '$1 == r { print $2; exit }' "$T/map.tsv"); echo "${t:-?}"; done | sort -u | paste -sd, -)
        rm -rf "$T"
        echo "СПРАВОЧНО: 8.1.1 набор event_type алертов на краях окна (первые и последние $EDGE_N, тип — по правилу): ${ets:-∅}"
        echo "$ets" | grep -qE '(^|,)tls(,|$)' && echo "СПРАВОЧНО: 8.1.1 на краях окна есть tls-алерт — ступенька Rego (№564) возможна; после П5 прыжок > 1 МиБ не ожидается"
    else
        echo "СПРАВОЧНО: 8.1.1 набор event_type алертов на краях окна НЕ СНЯТ (нет снимка алертов ${EDGE_ALERTS:-—})"
    fi
}

# ── 8.6.3а: секунды EvaluateInto в idle-профилях ────────────────────────────────
EVAL_LIMIT=${EVAL_LIMIT:-3.96}
rule_eval() {
    echo "== w87 8.6.3а: IDLE=${IDLE:-—} норма ${NORM_SECS} с, предел ${EVAL_LIMIT} с"
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
    echo "== w87 8.6.3б: BENCH_FILE=${BENCH_FILE:-—} IDENT=${IDENT:-—}"
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

# ── 8.7.4: состав детекта ──────────────────────────────────────────────────────
DET_NEW=${DET_NEW:-}; DET_OLD=${DET_OLD:-}; DET_MAN=${DET_MAN:-}; NEW_RULES=${NEW_RULES:-}
NIGHT_DATE=${NIGHT_DATE:-}; BASE_DATE=${BASE_DATE:-}; RULE_CTL=${RULE_CTL:-}; C0_IDENT=${C0_IDENT:-}; DRIFT_K=${DRIFT_K:-3}
# Волна 9: RENAMED — attacks/renamed-rules.txt («старое<TAB>новое<TAB>основание»): rule_id БАЗЫ переводятся на новое имя до
# сравнения (Д18: web_path_traversal_process → owasp_path_traversal иначе печатался бы «только в базе»). Пусто — без перевода.
RENAMED=${RENAMED:-}
IDENT_TESTS=${IDENT_TESTS:-TestDispatch_ShippedRulesetSameAlerts}
# _registry <rule> → дата заведения из new-rules.txt (пусто — нет записи)
_registry() { [ -s "$NEW_RULES" ] || return 0; awk -F'\t' -v r="$1" '$1 == r && $2 ~ /^[0-9]{8}$/ { print $2; exit }' "$NEW_RULES"; }
detect() {
    echo "== w87 8.7.4: новый=${DET_NEW:-—} база=${DET_OLD:-—} реестр=${NEW_RULES:-—} ночь=${NIGHT_DATE:-—} база-дата=${BASE_DATE:-—}"
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
        if [ -s "$RENAMED" ]; then
            local side ren; ren=""
            for side in new old; do
                awk -F'\t' 'NR == FNR { if ($0 !~ /^#/ && NF >= 2) m[$1] = $2; next } { split($0, f, " "); r = (f[1] in m) ? m[f[1]] : f[1]; c[r] += f[2] }
                             END { for (r in c) print r, c[r] }' "$RENAMED" "$T/$side" | sort > "$T/$side.r"
                ren="$ren$(join "$T/$side" <(awk -F'\t' '$0 !~ /^#/ && NF >= 2 { print $1 }' "$RENAMED" | sort) | awk -v s="$side" '{ printf "%s(%s) ", $1, s }')"
                mv "$T/$side.r" "$T/$side"
            done
            [ -n "$ren" ] && echo "  переведено по реестру переименований: $ren"
        fi
        if [ ! -s "$T/new" ] || [ ! -s "$T/old" ]; then cls="$cls; в одном из снимков ноль правил (новый $(wc -l < "$T/new" | tr -d ' '), база $(wc -l < "$T/old" | tr -d ' '))"
        else
            local comms; comms=$(jq -r '.[].comm' "$DET_MAN" | sort -u | jq -R . | jq -s .)
            atk1() { jq -r --arg r "$2" --argjson c "$comms" '[(if type == "array" then . else .alerts // [] end)[] | select((.rule_id // .RuleID) == $r) | select(.comm as $x | $c | index($x))] | length' "$1"; }
            atk() { local n o; n=$(atk1 "$1" "$2")
                    if [ -s "$RENAMED" ]; then for o in $(awk -F'\t' -v n="$2" '$0 !~ /^#/ && $2 == n { print $1 }' "$RENAMED"); do n=$((n + $(atk1 "$1" "$o"))); done; fi
                    echo "$n"; }
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
    # (в) тождество алертов на дампе на коде ночи: каждый тест из IDENT_TESTS обязан быть PASS (G3 + индексы 8.7)
    if [ -s "$C0_IDENT" ]; then
        local t evn tnot=""
        for t in $IDENT_TESTS; do
            grep -aq -- "--- PASS: $t " "$C0_IDENT" || grep -aq -- "--- PASS: $t\$" "$C0_IDENT" || tnot="$tnot $t"
        done
        if [ -z "$tnot" ]; then
            evn=$(sed -n 's/.*событий \([0-9]*\), алертов.*/\1/p' "$C0_IDENT" | head -1)
            echo "  тождество алертов на дампе w86-b: PASS ($IDENT_TESTS; событий ${evn:-?})"
            [ "${evn:-0}" -ge 1000000 ] || cls="$cls; тождество шло на ${evn:-0} событий < 1 000 000 — не на дампе w86-b"
        else fail="$fail; тождество на дампе не PASS:$tnot ($(grep -a -m1 -- '--- FAIL\|^FAIL' "$C0_IDENT" | cut -c1-120))"; fi
    else cls="$cls; нет вывода тождества на дампе (${C0_IDENT:-—})"; fi
    verdict 8.7.4 "$fail" "$cls" "состав детекта = база с ожидаемым расширением по реестру (${expected:-∅}); живые контроли ${okn:-?} OK, 0 FAIL; тождество на дампе PASS ($IDENT_TESTS)"
}

# ── 8.7.5 / 8.6.6: прогоны пода ночи ──────────────────────────────────────────
POD_SHA=${POD_SHA:-}; BASE_R2R=${BASE_R2R:-7122.5}
_rec() { # <run> <att> → строка REC эмиттера d1 волны 8.5
    RUN="$1" ATT="$2" bash "$SETUP/w85-close-report.sh" d1 2>&1 | grep -a '^REC ' | tail -1
}
pod_median() {
    echo "== w87 8.7.5: POD_RUNS=${POD_RUNS:-—} POD_SHA=${POD_SHA:-—} предел медианы $BASE_R2R"
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
        verdict 8.7.5 "$fail" "$cls" "медиана $med ≤ $BASE_R2R по $n прогонам одного бинаря ${POD_SHA}"
        return
    fi
    verdict 8.7.5 "$fail" "$cls" ""
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
BASE_PODS=${BASE_PODS:-}; BASE_INV=${BASE_INV:-}; INV=${INV:-}; BASE_PEAK_EXPECT=${BASE_PEAK_EXPECT:-143.5}
# _pod_peaks <пары run:att> → «пик_МиБ» по строке на прогон (max(старт, атаки)); пары без сэмплов пропускаются молча,
# число засчитанных считает вызывающий.
_pod_peaks() {
    local pair run att pa pb
    for pair in $1; do
        run=${pair%%:*}; att=${pair#*:}
        pa=$(_peak "$run/samples.tsv"); pb=$(_peak "$att/samples.tsv")
        [ -n "$pa" ] && [ -n "$pb" ] && awk -v a="$pa" -v b="$pb" 'BEGIN { print (a > b) ? a : b }'
    done
}
# Д6′ (решение 2 владельца 16.10): база 8.6.6 — медиана пиков пяти прогонов ночи 8.6 (143,5), не единичный пик ночи 8.5.
pod_peak() {
    echo "== w87 8.6.6 (Д6′): POD_RUNS=${POD_RUNS:-—} INV=${INV:-—} база: BASE_PODS=${BASE_PODS:-—} INV=${BASE_INV:-—}"
    local cls="" fail="" k=0 n=0 peaks="" bpeaks pair bb nb bn bp
    for pair in $POD_RUNS; do
        k=$((k + 1))
        local pm; pm=$(_pod_peaks "$pair")
        if [ -z "$pm" ]; then cls="$cls; прогон $k: нет сэмплов memory.current (старт/атаки)"; continue; fi
        n=$((n + 1)); peaks="$peaks$pm"$'\n'
        echo "  прогон $k: пик memory.current $pm МиБ"
    done
    bpeaks=$(_pod_peaks "$BASE_PODS"); bn=$(printf '%s' "$bpeaks" | grep -c .)
    bp=""
    if [ "$bn" -lt "$POD_MIN_RUNS" ]; then cls="$cls; прогонов базы (ночь 8.6) с пиком $bn < $POD_MIN_RUNS"
    else
        bp=$(printf '%s' "$bpeaks" | _median)
        echo "  база: пики пяти прогонов ночи 8.6: $(printf '%s' "$bpeaks" | sort -n | tr '\n' ' ')— медиана $bp (разброс $(printf '%s' "$bpeaks" | sort -n | awk 'NR == 1 { lo = $1 } { hi = $1 } END { printf "%.1f", hi - lo }') МиБ)"
        awk -v b="$bp" -v e="$BASE_PEAK_EXPECT" 'BEGIN { d = b - e; if (d < 0) d = -d; exit !(d <= 0.1) }' \
            || { cls="$cls; база из архива $bp МиБ не сходится с объявленной $BASE_PEAK_EXPECT (±0,1) — архив не ночи 8.6"; bp=""; }
    fi
    bb=$(_bpf_mib "$BASE_INV"); nb=$(_bpf_mib "$INV")
    [ -n "$bb" ] || cls="$cls; нет разбираемого maps.json базы (ночь 8.6)"
    [ -n "$nb" ] || cls="$cls; нет разбираемого maps.json ночи"
    [ "$n" -ge "$POD_MIN_RUNS" ] || cls="$cls; прогонов с пиком $n < $POD_MIN_RUNS"
    if [ -n "$bp" ] && [ "$n" -ge "$POD_MIN_RUNS" ]; then
        local med mx; med=$(printf '%s' "$peaks" | _median); mx=$(printf '%s' "$peaks" | sort -n | tail -1)
        echo "  пик: медиана $med МиБ, наибольший $mx МиБ, разброс $(printf '%s' "$peaks" | sort -n | awk 'NR == 1 { lo = $1 } { hi = $1 } END { printf "%.1f", hi - lo }') МиБ; база $bp МиБ (судится медиана пиков; наибольший — справочно)"
        awk -v m="$med" -v b="$bp" 'BEGIN { exit !(m <= b) }' || fail="$fail; медиана пиков $med МиБ > базы $bp"
    fi
    if [ -n "$bb" ] && [ -n "$nb" ]; then
        echo "  BPF карты+кольца по bpftool: ночь $nb МиБ, база $bb МиБ"
        awk -v n="$nb" -v b="$bb" 'BEGIN { exit !(n <= b) }' || fail="$fail; BPF карты+кольца $nb МиБ > базы $bb"
    fi
    verdict 8.6.6 "$fail" "$cls" "медиана пиков пода ≤ ${bp:-?} МиБ (медиана пяти прогонов ночи 8.6), BPF карты+кольца ${nb:-?} ≤ ${bb:-?} МиБ"
}

# ── 9.2 (волна 9, В1/Д15): цель Д2 «пик пода 128 МиБ» возвращается строкой критерия при Rego off ──
# Решение владельца 18.10.2026: Rego — опция сборки full, core (умолчание образа и чарта) идёт без движка и с policy.rego
# выключенным; 14.10 цель 128 была снята «пока», вернуться — если Д15 сделает Rego опциональным (plan.md, Д2). Судится
# МЕДИАНА пиков пяти прогонов пода (как 8.6.6: max(старт, атаки) по memory.current), предел POD_PEAK_MAX = 128 МиБ.
# Прогон засчитывается ТОЛЬКО при выключенном Rego, и это читается из РАНТАЙМА, не из конфига: серия
# ebpf_guard_runtime_flag{flag="rego_active"} в m-att1.txt прогона (0 — core; 1 — Rego считан и память пода
# другая; нет серии — бинарь до волны 9, состояние неизвестно). Прогон с Rego в зачёт не идёт и называется:
# 128 МиБ с Rego цель не про него (его память судит 8.6.6 против базы 8.6).
POD_PEAK_MAX=${POD_PEAK_MAX:-128}
pod_peak128() {
    echo "== w9 9.2 (Д2 при Д15): POD_RUNS=${POD_RUNS:-—}; медиана пиков пяти прогонов core (rego_active=0) ≤ ${POD_PEAK_MAX} МиБ"
    local cls="" fail="" k=0 n=0 peaks="" pair att rf pm
    for pair in $POD_RUNS; do
        k=$((k + 1)); att=${pair#*:}
        rf=$(_m "$att/m-att1.txt" ebpf_guard_runtime_flag 'flag="rego_active"')
        if [ -z "$rf" ]; then cls="$cls; прогон $k: нет серии runtime_flag{flag=\"rego_active\"} (бинарь до волны 9 — Rego выключен или нет, не известно)"; continue; fi
        if awk -v v="$rf" 'BEGIN { exit !(v != 0) }'; then cls="$cls; прогон $k: Rego ВКЛЮЧЁН (rego_active=1) — цель 128 судится на core (Д15), прогон не засчитан"; continue; fi
        pm=$(_pod_peaks "$pair")
        if [ -z "$pm" ]; then cls="$cls; прогон $k: нет сэмплов memory.current (старт/атаки)"; continue; fi
        n=$((n + 1)); peaks="$peaks$pm"$'\n'
        echo "  прогон $k (rego_active=0): пик memory.current $pm МиБ"
    done
    [ "$n" -ge "$POD_MIN_RUNS" ] || cls="$cls; засчитанных прогонов core $n < $POD_MIN_RUNS"
    if [ "$n" -ge "$POD_MIN_RUNS" ]; then
        local med mx; med=$(printf '%s' "$peaks" | _median); mx=$(printf '%s' "$peaks" | sort -n | tail -1)
        echo "  пик: медиана $med МиБ, наибольший $mx МиБ, разброс $(printf '%s' "$peaks" | sort -n | awk 'NR == 1 { lo = $1 } { hi = $1 } END { printf "%.1f", hi - lo }') МиБ; предел $POD_PEAK_MAX МиБ (судится медиана; наибольший — справочно)"
        awk -v m="$med" -v l="$POD_PEAK_MAX" 'BEGIN { exit !(m <= l) }' || fail="$fail; медиана пиков $med МиБ > ${POD_PEAK_MAX}"
        verdict 9.2 "$fail" "$cls" "медиана пиков пода $med МиБ ≤ ${POD_PEAK_MAX} МиБ по $n прогонам core (rego_active=0)"
        return
    fi
    verdict 9.2 "$fail" "$cls" ""
}

# ── 8.5.5 (Д12′): доля с process_chain БЕЗ инцидентов root_pid == 1 ────────────
# Решение 2 владельца 16.10: у pid 1 нет предка по построению (память chain-share-denominator-holds-pid1), он
# в знаменателе и базы, и ночи одинаково держит долю ниже 100%. Фильтр один и тот же в базе и в ночи; прежняя доля
# (со всеми инцидентами) печатается справочно и вердикта не меняет.
INC=${INC:-}; BASE_INC=${BASE_INC:-}; CTL_INC=${CTL_INC:-}; CTL_ROOT=${CTL_ROOT:-nginx}; CTL_MIN=${CTL_MIN:-5}
CH_M0=${CH_M0:-}; CH_M1=${CH_M1:-}
# _share <incidents.json> [no1] — «с_цепочкой всего»; no1 исключает root_pid == 1
_share() {
    [ -s "$1" ] || return 0
    jq -r --arg no1 "${2:-}" 'if type == "array" then . else (.incidents // []) end
        | map(select($no1 != "no1" or ((.root_pid // -1) != 1)))
        | "\([.[] | select((.process_chain // []) | length > 0)] | length) \(length)"' "$1" 2> /dev/null
}
_ctl_share() { # <incidents.json> <корень> → «с_цепочкой всего»
    [ -s "$1" ] || return 0
    jq -r --arg r "$2" 'if type == "array" then . else (.incidents // []) end | map(select((.root_pid // -1) != 1)) | map(select(.root_comm == $r or ((.process_chain // []) | index($r) != null))) | "\([.[] | select((.process_chain // []) | length > 0)] | length) \(length)"' "$1" 2> /dev/null
}
chain() {
    echo "== w87 8.5.5 (Д12′) на N ≥ ${CTL_MIN}: INC=${INC:-—} BASE_INC=${BASE_INC:-—} CTL_INC=${CTL_INC:-—} корень контроля ${CTL_ROOT}; без root_pid == 1"
    local cls="" fail="" w t bw bt cw ct w1 t1 bw1 bt1
    read -r w t <<< "$(_share "$INC" no1)"; read -r bw bt <<< "$(_share "$BASE_INC" no1)"
    read -r w1 t1 <<< "$(_share "$INC")"; read -r bw1 bt1 <<< "$(_share "$BASE_INC")"
    if [ -n "${t1:-}" ] && [ -n "${bt1:-}" ]; then
        echo "  СПРАВОЧНО (прежняя формула, со всеми инцидентами, вердикта не меняет): ночь $w1/$t1, база $bw1/$bt1"
    fi
    if [ -z "${t:-}" ] || [ "$t" -eq 0 ]; then cls="$cls; нет инцидентов ночи без root_pid == 1 (${t:-нет снимка}) — доля не определена"
    elif [ -z "${bt:-}" ] || [ "$bt" -eq 0 ]; then cls="$cls; нет базы без root_pid == 1 (${bt:-нет снимка})"
    else
        echo "  инцидентов без root_pid == 1 с process_chain: ночь $w из $t ($(awk -v a="$w" -v b="$t" 'BEGIN { printf "%.1f", 100 * a / b }')%), база $bw из $bt ($(awk -v a="$bw" -v b="$bt" 'BEGIN { printf "%.1f", 100 * a / b }')%)"
        [ $((w * bt)) -ge $((bw * t)) ] || fail="$fail; (а) доля с process_chain без pid 1 $w/$t ниже базы $bw/$bt"
    fi
    # (б) чтения /proc трекером при active таблице — как в w85 chain
    local r0 r1 e0 e1 st
    r0=$(_m "$CH_M0" ebpf_guard_lineage_proc_reads_total); r1=$(_m "$CH_M1" ebpf_guard_lineage_proc_reads_total)
    e0=$(_m "$CH_M0" ebpf_guard_events_total); e1=$(_m "$CH_M1" ebpf_guard_events_total)
    st=$(awk '/^ebpf_guard_proc_table_state/ && $NF == 1 { x = $1; sub(/.*state="/, "", x); sub(/".*/, "", x); print x; exit }' "${CH_M1:-/dev/null}" 2> /dev/null)
    if [ -z "$r0" ] || [ -z "$r1" ] || [ -z "$e0" ] || [ -z "$e1" ]; then
        cls="$cls; нет серии lineage_proc_reads_total/events_total в снимках окна"
    elif awk -v a="$e1" -v b="$e0" 'BEGIN { exit !(a <= b) }'; then
        cls="$cls; событий за окно не прибавилось — на событие делить нечего"
    elif awk -v a="$r1" -v b="$r0" 'BEGIN { exit !(a < b) }'; then
        cls="$cls; счётчик чтений /proc упал ($r0 → $r1) — рестарт внутри окна"
    elif [ "$st" != active ]; then
        cls="$cls; таблица процессов не active в конце окна (${st:-нет серии})"
    elif awk -v a="$r1" -v b="$r0" 'BEGIN { exit !(a != b) }'; then
        fail="$fail; (б) чтений /proc при активной таблице: $(awk -v a="$r1" -v b="$r0" 'BEGIN { printf "%.0f", a - b }') (цель 0)"
    fi
    read -r cw ct <<< "$(_ctl_share "$CTL_INC" "$CTL_ROOT")"
    if [ -z "${ct:-}" ]; then cls="$cls; нет снимка инцидентов контроля цепочки (${CTL_INC:-—})"
    elif [ -z "${bt:-}" ] || [ "$bt" -eq 0 ]; then :
    elif [ "$ct" -lt "$CTL_MIN" ]; then cls="$cls; инцидентов контроля цепочки $ct < $CTL_MIN (корень $CTL_ROOT) — N мало, доля не судится"
    else
        echo "  контроль цепочки ${CTL_ROOT}→bash→curl: инцидентов с process_chain $cw из $ct ($(awk -v a="$cw" -v b="$ct" 'BEGIN { printf "%.1f", 100 * a / b }')%), база $bw из $bt"
        [ $((cw * bt)) -ge $((bw * ct)) ] || fail="$fail; контроль цепочки: доля $cw/$ct ниже базы $bw/$bt"
    fi
    verdict 8.5.5 "$fail" "$cls" "без root_pid == 1: ночь ${w:-?}/${t:-?} ≥ база ${bw:-?}/${bt:-?}; контроль цепочки ${CTL_ROOT}→bash→curl: ${cw:-?}/${ct:-?} при N ≥ $CTL_MIN; чтений /proc трекером 0 при active таблице"
}

# ── 8.1.1r: разрез anon/file и memstats ────────────────────────────────────────
memsplit() {
    echo "== w87 8.1.1r (разрез для Д1): IDLE=${IDLE:-—}"
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
            # В3 (волна 9): anon − верхняя граница резидентной памяти Go (go_sys − heap_released) по КАЖДОМУ срезу; ≤ 0 —
            # anon целиком внутри рантайма Go (C-куча cgo не растёт)
            nb = 0; pos = 0; mx = ""
            for (k = 0; k <= mk; k++) { if (!(k in an) || !(k in sy) || sy[k] == "NA" || hr[k] == "NA") continue
                d = (an[k] - (sy[k] - hr[k])) / 1048576; nb++; if (d > 0) pos++; if (mx == "" || d > mx) mx = d }
            if (nb > 0) printf "ANONGO n=%d pos=%d max=%+.1f\n", nb, pos, mx; else print "ANONGO n=0"
        }
        function slope2(   k3, tmp, n2) { delete tmpa; for (k3 = 0; k3 <= mk; k3++) if ((k3 in hd) && hd[k3] != "NA") tmpa[k3] = hd[k3] - hr[k3]; return slope(tmpa) }
    ' "$tsv" > "$T/out"
    grep -v '^SLOPES\|^ANONGO' "$T/out"
    local sl; sl=$(grep '^SLOPES' "$T/out" | sed 's/^SLOPES //')
    local ag; ag=$(grep '^ANONGO' "$T/out")
    case "$ag" in
        *"n=0"|"") echo "  8.1.1b: СПРАВКА anon − Go-резидентное — не считается (нет go_memstats_sys/heap_released в срезах)" ;;
        *) echo "$ag" | awk '{ split($2, a, "="); split($3, b, "="); split($4, c, "=");
               printf "  8.1.1b: СПРАВКА anon − Go-резидентное (go_sys − heap_released): макс %s МиБ, срезов с anon > Go: %d из %d%s\n", c[2], b[2], a[2],
                   (b[2] == 0 ? " — anon целиком внутри рантайма Go (В3)" : " — часть anon вне рантайма Go") }' ;;
    esac
    rm -rf "$T"
    case "$sl" in *current=NA*|*anon=NA*|*file=NA*) cls="$cls; снимков после часа прогрева меньше трёх (всего $n) — наклон не считается" ;; esac
    if [ -n "$cls" ]; then echo "НЕИЗМЕРИМ: 8.1.1r НЕИЗМЕРИМ (класс НАЗВАН:${cls#;}; наклоны МиБ/ч после 1 ч: $sl)"
    else echo "ИЗМЕРЕНО: 8.1.1r ИЗМЕРЕНО (наклоны МиБ/ч после 1 ч прогрева: $sl; снимков $n по 300 с; вердикт 8.1.1 — night-report.sh)"; fi
}

# ── 8.7.Д: статус части Д из plan.md ───────────────────────────────────────────
PLAN=${PLAN:-}; REPORTS=${REPORTS:-}; # пустое DEFER_ALLOWED="" — «отложить нельзя ничего» (9.Д); не задано — перечень 8.7.Д
DEFER_ALLOWED=${DEFER_ALLOWED-"Д4b Д15 Д17 Д18"}
# Волна 9: тот же эмиттер судит 9.Д по своей таблице (DTAG=D9-STATUS DLABEL=9.Д).
DTAG=${DTAG:-D-STATUS}; DLABEL=${DLABEL:-8.7.Д}
dlist() {
    echo "== w87 $DLABEL: PLAN=${PLAN:-—} REPORTS=${REPORTS:-—} таблица $DTAG, отложить можно только: $DEFER_ALLOWED"
    [ -s "$PLAN" ] || { verdict "$DLABEL" "" "; нет plan.md (${PLAN:-—})" ""; return; }
    local blk; blk=$(awk -v b="<!-- $DTAG-BEGIN -->" -v e="<!-- $DTAG-END -->" 'index($0, b) { p = 1; next } index($0, e) { p = 0 } p' "$PLAN" | grep -a '^| Д')
    [ -n "$blk" ] || { verdict "$DLABEL" "" "; в plan.md нет таблицы статусов $DTAG" ""; return; }
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
    verdict "$DLABEL" "$fail" "$cls" "строк части Д $n: закрыто $closed, отложено решением владельца $deferred (${DEFER_ALLOWED}), открытых 0"
}

case "$MODE" in
    cpu-idle) cpu_idle ;;
    cpu-idle86) CPU_LABEL=8.6.1 CPU_FRAC=0.6 BASE_CPS_EXPECT=0.0529 BASE_NAME="ночь 8.5" cpu_idle ;;   # сторож «не хуже ночи 8.6»: прежний 8.6.1 (база ночи 8.5)
    cpu-event) cpu_event ;;
    sched) sched ;;
    rule-eval) rule_eval ;;
    bench) bench ;;
    detect) detect ;;
    pod-median) pod_median ;;
    pod-peak) pod_peak ;;
    pod-peak128) pod_peak128 ;;
    mem-slice) mem_slice ;;
    chain) chain ;;
    prof) prof ;;
    memsplit) memsplit ;;
    ref-811) ref_811 ;;
    dlist) dlist ;;
    *) echo "usage: w87-close-report.sh cpu-idle|cpu-event|sched|rule-eval|bench|detect|pod-median|pod-peak|pod-peak128|mem-slice|chain|prof|memsplit|ref-811|dlist" >&2; exit 2 ;;
esac
