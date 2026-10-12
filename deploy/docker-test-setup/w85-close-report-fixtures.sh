#!/bin/bash
# Фикстуры эмиттера волны 8.5 (режим d1) и мутации, которые их красят.
#   w85-close-report-fixtures.sh            — фикстуры против настоящего эмиттера
#   w85-close-report-fixtures.sh --mutate   — каждая мутация эмиттера ОБЯЗАНА покраснить фикстуры
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
EMIT=${EMITTER:-$HERE/w85-close-report.sh}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fails=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fails=$((fails + 1)); }

# mk <имя> [ключ=значение…] — каталог RUN/ATT; ключи: state=active|off_no_rules|none r2r=<дельта>|none
#                              cats=<число категорий> missed=<число непойманных> peak=<МиБ старта/атак> kf=yes|no
mk() {
    local n=$1; shift
    local state=active r2r=1200 cats=16 missed=0 peak=140 kf=yes
    for kv in "$@"; do eval "${kv%%=*}='${kv#*=}'"; done
    local R=$T/$n/run A=$T/$n/att; mkdir -p "$R" "$A"
    # memory.current: байты, 2 колонки
    awk -v p="$peak" 'BEGIN { for (i = 0; i < 700; i++) printf "%.1f %.0f\n", i / 10, p * 1048576 * (0.8 + 0.2 * (i % 7) / 6) }' > "$R/samples.tsv"
    cp "$R/samples.tsv" "$A/samples.tsv"
    for s in pre att1; do : > "$A/m-$s.txt"; done
    if [ "$r2r" != none ]; then
        echo 'ebpf_guard_events_dropped_total{collector="fileaccess",reason="ringbuf_to_router"} 100' >> "$A/m-pre.txt"
        echo "ebpf_guard_events_dropped_total{collector=\"fileaccess\",reason=\"ringbuf_to_router\"} $((100 + r2r))" >> "$A/m-att1.txt"
    fi
    if [ "$kf" = yes ]; then
        echo 'ebpf_guard_syscall_events_kernel_filtered_total{nr="9"} 1000' >> "$A/m-pre.txt"
        echo 'ebpf_guard_syscall_events_kernel_filtered_total{nr="9"} 90000' >> "$A/m-att1.txt"
    fi
    : > "$A/f1.txt"
    if [ "$state" != none ]; then
        for s in pre post; do echo "$s ebpf_guard_kernel_predicate_state{state=\"$state\"} 1" >> "$A/f1.txt"; done
    fi
    # манифест: cats категорий, у каждой своя comm; baseline пуст, final содержит всех кроме missed
    local i first=1
    {
        echo '['
        for i in $(seq 1 "$cats"); do [ $first = 1 ] || echo ','; first=0; echo "{\"category\":\"cat$i\",\"comm\":\"c$i\"}"; done
        echo ']'
    } > "$A/attack-manifest.json"
    echo '[]' > "$A/baseline-alerts-1.json"
    {
        echo '['
        first=1
        for i in $(seq 1 "$cats"); do
            [ "$i" -le $((cats - missed)) ] || continue
            [ $first = 1 ] || echo ','; first=0; echo "{\"id\":\"a$i\",\"comm\":\"c$i\"}"
        done
        echo ']'
    } > "$A/final-alerts-1.json"
    echo "$R $A"
}
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
fi
echo "-- fails=$fails"
[ "$fails" = 0 ]
