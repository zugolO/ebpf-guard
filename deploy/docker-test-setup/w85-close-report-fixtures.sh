#!/bin/bash
# Фикстуры эмиттера волны 8.5 (режим d1) и мутации, которые их красят.
#   w85-close-report-fixtures.sh            — фикстуры против настоящего эмиттера
#   w85-close-report-fixtures.sh --mutate   — каждая мутация эмиттера ОБЯЗАНА покраснить фикстуры
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
EMIT=${EMITTER:-$HERE/w85-close-report.sh}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
source "$HERE/w85-fixture-lib.sh"
fails=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fails=$((fails + 1)); }

run() { # run <имя> [mk-аргументы] — печатает вывод эмиттера
    local n=$1; shift
    local dirs; dirs=$(mk "$n" "$@")
    RUN=${dirs% *} ATT=${dirs#* } bash "$EMIT" d1 2>&1
}
want() { # want <имя> <шаблон>
    local n=$1 pat=$2; shift 2
    local out; out=$(run "$n" "$@")
    if echo "$out" | grep -aqE "$pat"; then ok "$n"; else bad "$n — нет «${pat}»"; echo "$out" | sed 's/^/    | /' | head -12; fi
}

want good        '^ДОСТИГНУТО: 8\.5\.7r ' 
want f1-off      '^НЕИЗМЕРИМ: 8\.5\.7r .*F1 не active' state=off_no_rules
want f1-noseries '^НЕИЗМЕРИМ: 8\.5\.7r .*F1 не active' state=none
want recall-15   '^ПРОВАЛЕН: 8\.5\.7r .*\(а\) recall 15/16' missed=1
want cats-15     '^НЕИЗМЕРИМ: 8\.5\.7r .*знаменатель не тот' cats=15
want r2r-high    '^ПРОВАЛЕН: 8\.5\.7r .*\(б\) ringbuf_to_router 9000 > 7598' r2r=9000
want r2r-edge    '^ДОСТИГНУТО: 8\.5\.7r ' r2r=7598
want r2r-absent  '^НЕИЗМЕРИМ: 8\.5\.7r .*нет серии fileaccess/ringbuf_to_router' r2r=none
want peak-high   '^ПРОВАЛЕН: 8\.5\.7r .*\(в\) пик' peak=160
want kf-absent   '^НЕИЗМЕРИМ: 8\.5\.7r .*нет серии kernel_filtered' kf=no
# провал не маскируется неизмеримостью другой половины и наоборот
want fail-and-unmeasurable '^ПРОВАЛЕН: 8\.5\.7r .*неизмеримо также' missed=2 r2r=none


# ── d1-median (8.5.7): решение владельца 13.10 — медиана ≥ 5 прогонов, ни один не выше базы ──
runs() { # runs <префикс> <r2r1> <r2r2> … — строит прогоны, печатает D1_RUNS; "r2r:ключ=знач" добавляет ключи mk
    local pre=$1; shift
    local i=0 spec out="" dirs extra
    for spec in "$@"; do
        i=$((i + 1))
        extra=""
        case "$spec" in *:*) extra=${spec#*:}; spec=${spec%%:*} ;; esac
        dirs=$(mk "$pre$i" r2r="$spec" $extra)
        out="$out ${dirs% *}:${dirs#* }"
    done
    printf '%s' "${out# }"
}
wantm() { # wantm <имя> <D1_RUNS> <шаблон>
    local out; out=$(D1_RUNS=$2 bash "$EMIT" d1-median 2>&1)
    if echo "$out" | grep -aqE "$3"; then ok "$1"; else bad "$1 — нет «${3}»"; echo "$out" | sed 's/^/    | /' | head -14; fi
}
# три прогона этапа 2 (3 817 / 7 393 / 8 370) + два добранных: медиана 5 — ≤ 7 598, ни один не выше 15 196
wantm med-good        "$(runs mg 3817 7393 8370 5000 6000)"        '^ДОСТИГНУТО: 8\.5\.7 .*медиана 6000 ≤ 7598 по 5 прогонам'
# один прогон выше предела медианы, но медиана ниже — как раз случай владельца: это не провал
wantm med-one-high    "$(runs mh 3817 7393 8370 5000 6000)"        '^ДОСТИГНУТО: 8\.5\.7 '
wantm med-six-even    "$(runs m6 3817 7393 8370 5000 6000 7000)"   '^ДОСТИГНУТО: 8\.5\.7 .*медиана 6500\.0 ≤ 7598 по 6 прогонам'
wantm med-over        "$(runs mo 8000 9000 8370 5000 9500)"        '^ПРОВАЛЕН: 8\.5\.7 .*\(б\) медиана ringbuf_to_router 8370 > 7598'
wantm med-edge        "$(runs me 1 2 7598 8000 9000)"              '^ДОСТИГНУТО: 8\.5\.7 .*медиана 7598 '
wantm med-above-base  "$(runs mb 100 200 300 400 15197)"          '^ПРОВАЛЕН: 8\.5\.7 .*прогон 5: ringbuf_to_router 15197 выше базы ночи 8\.2 15196'
wantm med-at-base     "$(runs mc 100 200 300 400 15196)"          '^ДОСТИГНУТО: 8\.5\.7 '
wantm med-three       "$(runs mt 3817 7393 8370)"                  '^НЕИЗМЕРИМ: 8\.5\.7 .*прогонов с измеренным ringbuf_to_router 3 < 5'
wantm med-none        ""                                            '^НЕИЗМЕРИМ: 8\.5\.7 .*прогонов с измеренным ringbuf_to_router 0 < 5'
# повтор одного прогона не добирает минимум
R1=$(runs md 3817 7393 8370 5000)
wantm med-dup-run     "$R1 ${R1##* }"                              '^НЕИЗМЕРИМ: 8\.5\.7 .*повторяет уже учтённый каталог'
# нет серии у одного прогона: «нет серии» ≠ 0 — в медиану не идёт, прогонов меньше минимума
wantm med-no-series   "$(runs mn 3817 7393 8370 5000 none)"       '^НЕИЗМЕРИМ: 8\.5\.7 .*нет серии fileaccess/ringbuf_to_router'
# F1 выключен в одном прогоне — прогон не про F1
wantm med-f1-off      "$(runs mf 3817 7393 8370 5000 "6000:state=off_no_rules")" '^НЕИЗМЕРИМ: 8\.5\.7 .*F1 не active'
# recall 15/16 в одном прогоне при хорошей медиане — провал (а) не маскируется медианой
wantm med-recall      "$(runs mr 3817 7393 8370 5000 "6000:missed=1")" '^ПРОВАЛЕН: 8\.5\.7 .*прогон 5:.*\(а\) recall 15/16'
wantm med-peak        "$(runs mp 3817 7393 8370 5000 "6000:peak=160")" '^ПРОВАЛЕН: 8\.5\.7 .*\(в\) пик'
# каталога нет
wantm med-no-dir      "$(runs mx 3817 7393 8370 5000) $T/нет:$T/нет-такого" '^НЕИЗМЕРИМ: 8\.5\.7 .*нет каталога атак'
# медиана не среднее: хвост 14000 тянет среднее выше предела, медиана остаётся 6000
wantm med-not-mean    "$(runs mm 1000 2000 6000 14000 14000)"      '^ДОСТИГНУТО: 8\.5\.7 .*медиана 6000 '

runf() { # runf <режим> <IDLE> <BASE_IDLE>
    IDLE=$2 BASE_IDLE=$3 bash "$EMIT" "$1" 2>&1
}
wantf() { # wantf <имя> <режим> <idle> <base> <шаблон>
    local n=$1 mode=$2 idle=$3 base=$4 pat=$5
    local out; out=$(runf "$mode" "$idle" "$base")
    if echo "$out" | grep -aqE "$pat"; then ok "$n"; else bad "$n — нет «${pat}»"; echo "$out" | sed 's/^/    | /' | head -14; fi
}
BASE=$(mkidle base by=1000 kf=none state=none)
wantf flow-good      flow "$(mkidle f-good by=150)"            "$BASE" '^ДОСТИГНУТО: 8\.5\.1 .*15\.0% базы'
wantf flow-edge-20   flow "$(mkidle f-edge by=200)"            "$BASE" '^ДОСТИГНУТО: 8\.5\.1 '
wantf flow-over-20   flow "$(mkidle f-over by=250)"            "$BASE" '^ПРОВАЛЕН: 8\.5\.1 .*25\.0% базы'
wantf flow-f1-off    flow "$(mkidle f-off by=150 state=off_config)" "$BASE" '^НЕИЗМЕРИМ: 8\.5\.1 .*F1 не active'
wantf flow-no-state  flow "$(mkidle f-nost by=150 state=none)" "$BASE" '^НЕИЗМЕРИМ: 8\.5\.1 .*F1 не active'
wantf flow-no-kf     flow "$(mkidle f-nokf by=150 kf=none)"    "$BASE" '^НЕИЗМЕРИМ: 8\.5\.1 .*нет серии ebpf_guard_syscall_events_kernel_filtered_total'
wantf flow-reset     flow "$(mkidle f-reset by=150 reset=14)"  "$BASE" '^НЕИЗМЕРИМ: 8\.5\.1 .*рестарт агента внутри окна'
wantf flow-short     flow "$(mkidle f-short by=150 snaps=8)"   "$BASE" '^НЕИЗМЕРИМ: 8\.5\.1 .*меньше часа'
wantf flow-no-base   flow "$(mkidle f-nobase by=150)"          "$T/нет-такого" '^НЕИЗМЕРИМ: 8\.5\.1 .*нет базы ночи 8\.2'
wantf flow-prints-parts flow "$(mkidle f-parts by=150 kf=9000)" "$BASE" 'nr=9 +[0-9]+ +[0-9]+ +[0-9]+'
wantf anomaly-good   anomaly-hour "$(mkidle a-good anomhr=33)" "$(mkidle a-base anomhr=20)" '^ИЗМЕРЕНО: 8\.5\.3a .*ПЕРВЫЙ час ночи 33 \(база ночи 8\.2: 20\)'
out=$(PROFILE_BEFORE=absent IDLE=$(mkidle a-np anomhr=33) BASE_IDLE=$(mkidle a-npb anomhr=20) bash "$EMIT" anomaly-hour 2>&1)
echo "$out" | grep -aq 'НЕ ИСПОЛНЕН' && ok "anomaly-no-profile" || bad "anomaly: старт без профиля до F1 не назван"
wantf anomaly-absent anomaly-hour "$(mkidle a-abs anomhr=none)" "$(mkidle a-base2 anomhr=20)" '^НЕИЗМЕРИМ: 8\.5\.3a .*нет серии'

wantab() { # wantab <имя> <AB_DIR> <шаблон>
    local out; out=$(AB_DIR=$2 bash "$EMIT" ab 2>&1)
    if echo "$out" | grep -aqE "$3"; then ok "$1"; else bad "$1 — нет «${3}»"; echo "$out" | sed 's/^/    | /' | head -12; fi
}
wantab ab-good       "$(mkab ab-good)"                          '^ДОСТИГНУТО: 8\.5\.3 '
wantab ab-b-lower    "$(mkab ab-lower b1=135)"                  '^ДОСТИГНУТО: 8\.5\.3 '
wantab ab-in-band    "$(mkab ab-band a0=100 ab=200 b1=319)"     '^ДОСТИГНУТО: 8\.5\.3 .*полоса 20'
wantab ab-over-band  "$(mkab ab-over a0=100 ab=200 b1=330)"     '^ПРОВАЛЕН: 8\.5\.3 .*B 130 > A 100 \+ полоса 20'
wantab ab-a-not-off  "$(mkab ab-anot sta=active)"              '^НЕИЗМЕРИМ: 8\.5\.3 .*окно A не при выключенном F1'
wantab ab-b-not-on   "$(mkab ab-bnot stb=off_no_rules)"         '^НЕИЗМЕРИМ: 8\.5\.3 .*окно B не при включённом F1'
wantab ab-no-series  "$(mkab ab-nos b1=none)"                   '^НЕИЗМЕРИМ: 8\.5\.3 .*нет серии anomaly_detection'
wantab ab-no-file    "$(mkab ab-nof drop=m-ab.txt)"             '^НЕИЗМЕРИМ: 8\.5\.3 .*нет m-ab\.txt'

wantctl() { # wantctl <имя> <каталог> <шаблон>
    local d=$2 out
    out=$(CTL_ALERTS=$d/alerts.json CTL_STATE=$d/state.txt GATE=$d/gate.txt bash "$EMIT" controls 2>&1)
    if echo "$out" | grep -aqE "$3"; then ok "$1"; else bad "$1 — нет «${3}»"; echo "$out" | sed 's/^/    | /' | head -12; fi
}
wantctl ctl-good      "$(mkctl c-good)"                                   '^ДОСТИГНУТО: 8\.5\.2 .*контроли 3/3'
wantctl ctl-miss-one  "$(mkctl c-miss miss=sigma_mprotect_exec_heap)"     '^ПРОВАЛЕН: 8\.5\.2 .*контроль sigma_mprotect_exec_heap не сработал'
wantctl ctl-f1-off    "$(mkctl c-off state=off_no_rules)"                 '^НЕИЗМЕРИМ: 8\.5\.2 .*F1 не active'
wantctl ctl-gate-fail "$(mkctl c-gf gate=FAIL)"                           '^ПРОВАЛЕН: 8\.5\.2 .*recall гейта FAIL'
wantctl ctl-no-gate   "$(mkctl c-ng gate=none)"                           '^НЕИЗМЕРИМ: 8\.5\.2 .*нет gate\.txt'
wantctl ctl-no-alerts "$(mkctl c-na alerts=none)"                         '^НЕИЗМЕРИМ: 8\.5\.2 .*нет снимка алертов'
wantctl ctl-wrong-comm "$(mkctl c-wc)"                                    '^ДОСТИГНУТО'
out=$(CTL_COMM=bash CTL_ALERTS=$T/c-wc/alerts.json CTL_STATE=$T/c-wc/state.txt GATE=$T/c-wc/gate.txt bash "$EMIT" controls 2>&1)
echo "$out" | grep -aqE '^ПРОВАЛЕН: 8\.5\.2 ' && ok "ctl-comm-must-match" || bad "контроль засчитан на чужом comm"

if [ "${1:-}" = "--mutate" ]; then
    echo "== мутации: каждая обязана покраснить фикстуры"
    mut() { # mut <имя> <sed-выражение>
        local n=$1 expr=$2 m=$T/mut-$1.sh
        sed -e "$expr" "$EMIT" > "$m"
        if cmp -s "$m" "$EMIT"; then bad "мутация $n не изменила эмиттер (выражение устарело)"; return; fi
        if EMITTER=$m bash "$0" 2>&1 | grep -q '^FAIL'; then ok "мутация $n покраснила фикстуры"; else bad "мутация $n ПРОШЛА фикстуры — прибор не ловит"; fi
    }
    mut f1-guard-off     's/if \[ "\$s0" != active \] || \[ "\$s1" != active \]; then/if false; then/'
    mut recall-any       's/\[ "\$rd" = "\$rt" \] || fail=/true || fail=/'
    mut r2r-no-limit     's/\[ "\$r2rd" -le "\$lim" \] || failb=/true || failb=/'
    mut absent-as-zero   's/if \[ -z "\$r0" \] || \[ -z "\$r1" \]; then/r0=${r0:-0}; r1=${r1:-0}; if false; then/'
    mut denominator      's/\[ "\$rt" != "\$RECALL_TOTAL" \]/false/'
    mut flow-frac        's/FLOW_FRAC=\${FLOW_FRAC:-0.2}/FLOW_FRAC=${FLOW_FRAC:-0.9}/'
    mut flow-f1-guard    's/\[ "\$st" = active \] || cls=/true || cls=/'
    mut flow-kf-as-zero  's/\[ -n "\$va" \] \&\& \[ -n "\$vb" \] || { echo "ERR нет серии/va=${va:-0}; vb=${vb:-0}; [ -n "$va" ] || true; false || { echo "ERR нет серии/'
    mut flow-reset-guard 's/\[ "\$vb" -ge "\$va" \] || {/true || {/'
    mut ab-band          's/band=\$(awk -v a="\$A" .BEGIN { printf "%.0f", 2 \* sqrt(a) }.)/band=0/'
    mut ab-state-a       's/\[ "\$sa0" = off_config \] \&\& \[ "\$sa" = off_config \] || cls=/true || cls=/'
    mut ctl-f1-guard     's/\[ "\$st" = active \] || cls="\$cls; F1 не active на контролях/true || cls="$cls; F1 не active на контролях/'
    mut ctl-hit-zero     's/0) fail="\$fail; контроль \$rid не сработал" ;;/0) true ;;/'
    mut median-as-mean   's/med=\$(printf .%s. "\$vals" | _median)/med=$(printf "%s" "$vals" | awk "{ s += \\$1 } END { printf \\"%.0f\\", s \/ NR }")/'
    mut median-as-max    's/sort -n | awk .{ a\[NR\] = \$1 } END { if (!NR) exit; if (NR % 2)/sort -n | awk '"'"'{ a[NR] = $1 } END { if (!NR) exit; if (1)/'
    mut median-min-runs  's/D1_MIN_RUNS=\${D1_MIN_RUNS:-5}/D1_MIN_RUNS=${D1_MIN_RUNS:-1}/'
    mut median-no-base   's/\[ "\$r2r" -le "\$BASE_R2R" \] || fail=/true || fail=/'
    mut median-no-dup    's/case " \$seen " in \*" \$key "\*)/case " $seen " in *"ZZZ"*)/'
    mut median-no-limit  's/awk -v m="\$med" -v l="\$lim" .BEGIN { exit !(m <= l) }. || fail=/true || fail=/'
    mut median-peak-per-run 's/\[ -z "\$afail" \] || fail=/true || fail=/'
    mut median-cls-per-run  's/\[ -z "\$pcls" \] || cls=/true || cls=/'
    mut anomaly-absent   's/\[ -n "\$s0" \] \&\& \[ -n "\$s1" \] || cls=/true || cls=/'
fi
echo "-- fails=$fails"
[ "$fails" = 0 ]
