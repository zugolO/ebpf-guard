#!/bin/bash
# Фикстуры эмиттера w85-mem-report.sh и мутации.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
EMIT=${EMITTER:-$HERE/w85-mem-report.sh}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fails=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fails=$((fails + 1)); }
MB=1048576
# mk <имя> [R=3] [<метрика><k>_<режим>=<МиБ> …] — база: старт 100, пакет 140, inuse 40, alloc 30 у обоих режимов; done=yes
#   переопределения: start2_on=105  mem1_off=150  inuse3_on=44  alloc1_on=31.5  drop=<файл>  done=no
mk() {
    local n=$1; shift
    local R=3 done=yes drop="" k mode
    declare -A O
    for kv in "$@"; do case "${kv%%=*}" in R|done|drop) eval "${kv%%=*}='${kv#*=}'" ;; *) O[${kv%%=*}]=${kv#*=} ;; esac; done
    local d=$T/$n; mkdir -p "$d"
    [ "$done" = yes ] && echo "done x" > "$d/DONE" || echo "die: x" > "$d/DONE"
    for k in $(seq 1 "$R"); do for mode in on off; do
        local D=$d/r$k-$mode; mkdir -p "$D"
        local s=${O[start${k}_$mode]:-100} m=${O[mem${k}_$mode]:-140} hi=${O[inuse${k}_$mode]:-40} ha=${O[alloc${k}_$mode]:-30}
        awk -v s="$s" -v mb=$MB 'BEGIN { for (i = 0; i < 20; i++) printf "%d %.0f\n", 1000 + i, mb * s * (0.5 + 0.5 * i / 19) }' > "$D/start.tsv"
        awk -v s="$m" -v mb=$MB 'BEGIN { for (i = 0; i < 20; i++) printf "%d %.0f\n", 2000 + i, mb * s * (0.8 + 0.2 * i / 19) }' > "$D/pack.tsv"
        echo "3000 $(awk -v s="$m" -v mb=$MB 'BEGIN { printf "%.0f", s * mb * 0.9 }')" > "$D/end.tsv"
        printf 'go_memstats_heap_inuse_bytes %.0f\ngo_memstats_heap_alloc_bytes %.0f\n' "$(awk -v x="$hi" -v mb=$MB 'BEGIN{print x*mb}')" "$(awk -v x="$ha" -v mb=$MB 'BEGIN{print x*mb}')" > "$D/m-end.txt"
        echo "mode=$mode pid=1 cg=/x state=$([ $mode = on ] && echo active || echo off_config)" > "$D/meta.txt"
    done; done
    [ -z "$drop" ] || rm -rf "$d/$drop"
    echo "$d"
}
want() { # <имя> <каталог> <шаблон> [ENV…]
    local name=$1 dir=$2 pat=$3; shift 3
    local out; out=$(env OUT="$dir" "$@" bash "$EMIT" 2>&1)
    if echo "$out" | grep -aqE "$pat"; then ok "$name"; else bad "$name — нет «${pat}»"; echo "$out" | sed 's/^/    | /' | head -20; fi
}
want identical     "$(mk same)"                                                            '^ИЗМЕРЕНО: 8\.5\.A34 разницы вне ±4% во всех 3 повторах нет'
want real-inuse    "$(mk real inuse1_on=44 inuse2_on=44 inuse3_on=44)"                     '^ИЗМЕРЕНО: 8\.5\.A34 разница РЕАЛЬНА, с P1 БОЛЬШЕ: heap_inuse \(\+10\.0% \+10\.0% \+10\.0%\).*убрать декодирование Filename'
want two-of-three  "$(mk two inuse1_on=44 inuse2_on=44 inuse3_on=40.4)"                   '^ИЗМЕРЕНО: 8\.5\.A34 разницы вне ±4%'
want edge-4pct     "$(mk edge inuse1_on=41.6 inuse2_on=41.6 inuse3_on=41.6)"               '^ИЗМЕРЕНО: 8\.5\.A34 разницы вне ±4%'
want just-over     "$(mk over inuse1_on=41.7 inuse2_on=41.7 inuse3_on=41.7)"               '^ИЗМЕРЕНО: 8\.5\.A34 разница РЕАЛЬНА, с P1 БОЛЬШЕ: heap_inuse'
want sign-flips    "$(mk flip inuse1_on=44 inuse2_off=44 inuse3_on=44)"                    '^ИЗМЕРЕНО: 8\.5\.A34 разницы вне ±4%'
want lower-is-real "$(mk lower alloc1_on=27 alloc2_on=27 alloc3_on=27)"                    '^ИЗМЕРЕНО: 8\.5\.A34 разница РЕАЛЬНА, с P1 МЕНЬШЕ: heap_alloc \(-10\.0% -10\.0% -10\.0%\).*правка Filename не требуется'
want start-peak    "$(mk sp start1_on=110 start2_on=110 start3_on=110)"                    '^ИЗМЕРЕНО: 8\.5\.A34 разница РЕАЛЬНА, с P1 БОЛЬШЕ: пик старта memory.current'
want mem-peak      "$(mk mp mem1_on=160 mem2_on=160 mem3_on=160)"                          '^ИЗМЕРЕНО: 8\.5\.A34 разница РЕАЛЬНА, с P1 БОЛЬШЕ: пик memory.current \('
want mixed-up-down "$(mk mixed inuse1_on=44 inuse2_on=44 inuse3_on=44 alloc1_on=27 alloc2_on=27 alloc3_on=27)" '^ИЗМЕРЕНО: 8\.5\.A34 разница РЕАЛЬНА, с P1 БОЛЬШЕ: heap_inuse .*; с P1 меньше: heap_alloc'
want not-done      "$(mk nd done=no)"                                                      '^НЕИЗМЕРИМ: 8\.5\.A34 .*серия не завершена'
want no-dir-pair   "$(mk nodir drop=r2-off)"                                               '^НЕИЗМЕРИМ: 8\.5\.A34 .*нет каталога r2-off'
want no-heap       "$(mk noheap R=3 drop=r1-on/m-end.txt)"                                 '^НЕИЗМЕРИМ: 8\.5\.A34 .*r1-on: нет go_memstats_heap_'
out=$(OUT="$T/нет" bash "$EMIT" 2>&1); echo "$out" | grep -aq '^НЕИЗМЕРИМ: 8\.5\.A34 .*нет каталога' && ok no-dir || bad no-dir

if [ "${1:-}" = --mutate ]; then
    mut() {
        local f; f=$(mktemp); sed "$2" "$EMIT" > "$f"
        if cmp -s "$f" "$EMIT"; then bad "мутация $1 не применилась"; rm -f "$f"; return; fi
        if EMITTER=$f bash "$0" 2>/dev/null | grep -q '^FAIL'; then ok "мутация $1 покраснила фикстуры"; else bad "мутация $1 НЕ покраснила фикстуры"; fi
        rm -f "$f"
    }
    mut noise-default 's/NOISE_PCT=\${NOISE_PCT:-4}/NOISE_PCT=${NOISE_PCT:-9}/'
    mut all-repeats   's/\[ "\$sign" = "\$sg" \] || allout=0/true/'
    mut abs-only      "s/if (d < 0) d = -d; //"
    mut done-guard    's/if ! grep -q .\^done. "\$OUT\/DONE" 2>\/dev\/null; then/if false; then/'
    mut direction      's/if \[ "\$sign" = "+" \]; then real_up=/if true; then real_up=/'
    mut strict-gt     's/exit !(d > n) }/exit !(d >= n) }/'
    mut missing-heap  's/\[ -n "\$hi" \] \&\& \[ -n "\$ha" \] || cls=/true || cls=/'
fi
echo "-- fails=$fails"
[ "$fails" = 0 ]
