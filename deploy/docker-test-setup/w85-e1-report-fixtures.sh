#!/bin/bash
# Фикстуры эмиттера w85-e1-report.sh и мутации. --mutate: каждая мутация ОБЯЗАНА покраснить фикстуры.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
EMIT=${EMITTER:-$HERE/w85-e1-report.sh}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fails=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fails=$((fails + 1)); }
R=mitre_vm_detect_dmi_read; X=virt-detect-self

# mk <имя> [ub=… rb=… ua=… ra=… eb=… ea=… img=… sp="copy 3 exec-a 2 comm 4" stb=off_config sta=active done=yes]
mk() {
    local n=$1; shift
    local ub=250 rb=50 ua=10 ra=290 eb=0 ea=280 img=290 sp="copy-same-name 3|exec-a 2|comm-spoof 4" stb=off_config sta=active done=yes dropm="" dropser=""
    for kv in "$@"; do eval "${kv%%=*}='${kv#*=}'"; done
    local d=$T/$n; mkdir -p "$d/before" "$d/after"
    [ "$done" = yes ] && echo "done 2026-10-13T00:00:00Z" > "$d/DONE" || echo "die: x" > "$d/DONE"
    echo "$stb" > "$d/before/proc_table_state.txt"; echo "$sta" > "$d/after/proc_table_state.txt"
    echo 3 > "$d/before/alerts.txt"; echo 0 > "$d/after/alerts.txt"
    echo "$sp" | tr '|' '\n' > "$d/spoof.txt"
    local ph
    for ph in before after; do
        local u r e
        if [ $ph = before ]; then u=$ub; r=$rb; e=$eb; else u=$ua; r=$ra; e=$ea; fi
        {
            echo "ebpf_guard_exe_path_lookups_total{field=\"exe_path\",result=\"unresolved\"} 100"
            echo "ebpf_guard_exe_path_lookups_total{field=\"exe_path\",result=\"resolved\"} 100"
            echo "ebpf_guard_exe_path_lookups_total{field=\"parent_exe_path\",result=\"unresolved\"} 7"
            echo "ebpf_guard_rule_exceptions_total{exception_name=\"$X\",rule_id=\"$R\"} 4"
            echo "ebpf_guard_exe_path_image_total{result=\"filename\"} 0"
            echo "ebpf_guard_exe_path_image_total{result=\"cached\"} 0"
            echo "ebpf_guard_exe_path_image_total{result=\"proc\"} 0"
            echo "ebpf_guard_exe_path_readlink_fallback_total{result=\"resolved\"} 0"
            echo "ebpf_guard_exe_path_readlink_fallback_total{result=\"unresolved\"} 0"
        } > "$d/$ph/m0.txt"
        {
            echo "ebpf_guard_exe_path_lookups_total{field=\"exe_path\",result=\"unresolved\"} $((100 + u))"
            echo "ebpf_guard_exe_path_lookups_total{field=\"exe_path\",result=\"resolved\"} $((100 + r))"
            echo "ebpf_guard_exe_path_lookups_total{field=\"parent_exe_path\",result=\"unresolved\"} 900"
            echo "ebpf_guard_rule_exceptions_total{exception_name=\"$X\",rule_id=\"$R\"} $((4 + e))"
            if [ $ph = after ]; then
                echo "ebpf_guard_exe_path_image_total{result=\"filename\"} $((img / 2))"
                echo "ebpf_guard_exe_path_image_total{result=\"cached\"} $((img - img / 2))"
            else
                echo "ebpf_guard_exe_path_image_total{result=\"filename\"} 0"
                echo "ebpf_guard_exe_path_image_total{result=\"cached\"} 0"
            fi
            echo "ebpf_guard_exe_path_image_total{result=\"proc\"} 0"
            echo "ebpf_guard_exe_path_readlink_fallback_total{result=\"resolved\"} 3"
            echo "ebpf_guard_exe_path_readlink_fallback_total{result=\"unresolved\"} 1"
        } > "$d/$ph/m1.txt"
    done
    [ -z "$dropm" ] || rm -f "$d/$dropm"
    [ -z "$dropser" ] || { grep -av "$dropser" "$d/after/m1.txt" > "$d/after/m1.tmp"; mv "$d/after/m1.tmp" "$d/after/m1.txt"; }
    echo "$d"
}
want() { # <имя> <каталог> <шаблон>
    local out; out=$(OUT=$2 bash "$EMIT" 2>&1)
    if echo "$out" | grep -aqE "$3"; then ok "$1"; else bad "$1 — нет «$3»"; echo "$out" | sed 's/^/    | /' | head -14; fi
}
want good            "$(mk good)"                                   '^ДОСТИГНУТО: 8\.5\.E1 .*unresolved 250/300 → 10/300; подавлений 0 → 280; образ из таблицы 290; спуфов 3/3'
want no-improvement  "$(mk no-impr ua=240 ra=60)"                   '^ПРОВАЛЕН: 8\.5\.E1 .*доля unresolved «после»'
want half-edge       "$(mk edge ub=200 rb=100 ua=100 ra=200)"       '^ДОСТИГНУТО: 8\.5\.E1 '
want over-half       "$(mk over ub=200 rb=100 ua=101 ra=199)"       '^ПРОВАЛЕН: 8\.5\.E1 .*доля unresolved'
want no-exceptions   "$(mk noexc ea=0)"                             '^ПРОВАЛЕН: 8\.5\.E1 .*подавлений «после» \(0\)'
want exceptions-equal "$(mk exceq eb=280 ea=280)"                   '^ПРОВАЛЕН: 8\.5\.E1 .*подавлений «после»'
want image-silent    "$(mk imgsil img=0)"                            '^ПРОВАЛЕН: 8\.5\.E1 .*образ из таблицы ни разу'
want spoof-silent    "$(mk spoof sp="copy-same-name 3|exec-a 0|comm-spoof 4")" '^ПРОВАЛЕН: 8\.5\.E1 .*контроль exec-a не сработал'
want spoof-none      "$(mk spnone sp="copy-same-name 3|exec-a none|comm-spoof 4")" '^ПРОВАЛЕН: 8\.5\.E1 .*контроль exec-a: счёт алертов не получен'
want spoof-short     "$(mk spshort sp="copy-same-name 3")"           '^ПРОВАЛЕН: 8\.5\.E1 .*спуф-контролей 1 < 3'
want class-absent    "$(mk few ub=10 rb=5 ua=1 ra=2)"                '^НЕИЗМЕРИМ: 8\.5\.E1 .*не дошли до оценки exe_path'
want before-active   "$(mk bact stb=active)"                         '^НЕИЗМЕРИМ: 8\.5\.E1 .*«до» с активной таблицей'
want after-off       "$(mk aoff sta=off_load_failed)"                '^НЕИЗМЕРИМ: 8\.5\.E1 .*«после» без активной таблицы'
want not-done        "$(mk nd done=no)"                              '^НЕИЗМЕРИМ: 8\.5\.E1 .*прогон не завершён'
want no-snapshot     "$(mk nosnap dropm=after/m1.txt)"               '^НЕИЗМЕРИМ: 8\.5\.E1 .*after: нет снимков метрик'
want no-series       "$(mk noser dropser=exception_name)"            '^НЕИЗМЕРИМ: 8\.5\.E1 .*нет серии'
want no-series-lookups "$(mk noserl dropser='field="exe_path",result="unresolved"')" '^НЕИЗМЕРИМ: 8\.5\.E1 .*нет серии'
out=$(OUT="$T/нет" bash "$EMIT" 2>&1); echo "$out" | grep -aq '^НЕИЗМЕРИМ: 8\.5\.E1 .*нет каталога' && ok no-dir || bad "no-dir"

if [ "${1:-}" = --mutate ]; then
    mut() { # <имя> <sed-выражение>
        local f; f=$(mktemp); sed "$2" "$EMIT" > "$f"
        if cmp -s "$f" "$EMIT"; then bad "мутация $1 не применилась"; rm -f "$f"; return; fi
        if EMITTER=$f bash "$0" 2>/dev/null | grep -q '^FAIL'; then ok "мутация $1 покраснила фикстуры"; else bad "мутация $1 НЕ покраснила фикстуры"; fi
        rm -f "$f"
    }
    mut half-gate     's/\[ \$((2 \* ua \* tb)) -le \$((ub \* ta)) \] || fail=/true || fail=/'
    mut exc-gate      's/\[ "\$ea" -gt "\$eb" \] || fail=/true || fail=/'
    mut img-gate      's/\[ "\$img" -gt 0 \] || fail=/true || fail=/'
    mut spoof-zero    's/0) fail="\$fail; контроль \$name не сработал (исключение применилось к спуфу)" ;;/0) true ;;/'
    mut spoof-count   's/\[ "\$nsp" -ge 3 \] || fail=/true || fail=/'
    mut min-lookups   's/E1_MIN_LOOKUPS=\${E1_MIN_LOOKUPS:-50}/E1_MIN_LOOKUPS=${E1_MIN_LOOKUPS:-0}/'
    mut before-guard  's/\[ "\$(cat "\$OUT\/before\/proc_table_state.txt" 2>\/dev\/null)" != active \] || cls=/true || cls=/'
    mut after-guard   's/\[ "\$(cat "\$OUT\/after\/proc_table_state.txt" 2>\/dev\/null)" = active \] || cls=/true || cls=/'
    mut done-guard    's/if ! grep -q .\^done. "\$OUT\/DONE" 2>\/dev\/null; then/if false; then/'
    mut absent-zero   "s/case \"\$v\" in ''|'?'|-\\*|\\*\\[!0-9\\]\\*)/case \"\$v\" in ZZZ)/"
fi
echo "-- fails=$fails"
[ "$fails" = 0 ]
