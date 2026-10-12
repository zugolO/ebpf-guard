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

want good        '^ДОСТИГНУТО: 8\.5\.7 ' 
want f1-off      '^НЕИЗМЕРИМ: 8\.5\.7 .*F1 не active' state=off_no_rules
want f1-noseries '^НЕИЗМЕРИМ: 8\.5\.7 .*F1 не active' state=none
want recall-15   '^ПРОВАЛЕН: 8\.5\.7 .*\(а\) recall 15/16' missed=1
want cats-15     '^НЕИЗМЕРИМ: 8\.5\.7 .*знаменатель не тот' cats=15
want r2r-high    '^ПРОВАЛЕН: 8\.5\.7 .*\(б\) ringbuf_to_router 9000 > 7598' r2r=9000
want r2r-edge    '^ДОСТИГНУТО: 8\.5\.7 ' r2r=7598
want r2r-absent  '^НЕИЗМЕРИМ: 8\.5\.7 .*нет серии fileaccess/ringbuf_to_router' r2r=none
want peak-high   '^ПРОВАЛЕН: 8\.5\.7 .*\(в\) пик' peak=160
want kf-absent   '^НЕИЗМЕРИМ: 8\.5\.7 .*нет серии kernel_filtered' kf=no
# провал не маскируется неизмеримостью другой половины и наоборот
want fail-and-unmeasurable '^ПРОВАЛЕН: 8\.5\.7 .*неизмеримо также' missed=2 r2r=none

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
    mut r2r-no-limit     's/\[ \$((r1 - r0)) -le "\$lim" \] || fail=/true || fail=/'
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
    mut anomaly-absent   's/\[ -n "\$s0" \] \&\& \[ -n "\$s1" \] || cls=/true || cls=/'
fi
echo "-- fails=$fails"
[ "$fails" = 0 ]
