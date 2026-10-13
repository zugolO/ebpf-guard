#!/bin/bash
# w85-e1-report.sh — вердикт E1 (волна 8.5, этап 4) по каталогу OUT w85-e1-smoke.sh. Считает ЭМИТТЕР.
#   OUT=<каталог> bash w85-e1-report.sh
# Метка 8.5.E1 (в REQUIRED_LABELS ночи не входит — суд этапа 4):
#   класс предъявлен: в обеих фазах мс-процессы дошли до оценки exe_path (lookups ≥ E1_MIN_LOOKUPS), N запусков;
#   ДОСТИГНУТО: доля unresolved по exe_path «после» ≤ половины «до», подавлений virt-detect-self «после» > «до»,
#               все спуф-контроли дали ≥ 1 алерт;
#   образ из таблицы: ebpf_guard_exe_path_image_total{cached+proc+filename} «после» > 0;
#   нет серии / нет каталога — НЕИЗМЕРИМ с названным классом, не ноль.
set -u
OUT=${OUT:-}
E1_MIN_LOOKUPS=${E1_MIN_LOOKUPS:-50}
RULE=mitre_vm_detect_dmi_read; EXC=virt-detect-self

val() { # <файл> <имя метрики> <label=value>… — значение серии, содержащей ВСЕ перечисленные пары (порядок лейблов не важен)
    local f=$1 n=$2; shift 2
    awk -v n="$n" -v pairs="$*" 'BEGIN { k = split(pairs, P, " ") }
        index($0, n "{") == 1 || index($0, n " ") == 1 {
            ok = 1; for (i = 1; i <= k; i++) { split(P[i], kv, "="); if (index($0, kv[1] "=\"" kv[2] "\"") == 0) ok = 0 }
            if (ok) { print $NF; exit }
        }' "$f"
}
delta() { # <m0> <m1> <имя> <пары…> — «?» нет серии
    local m0=$1 m1=$2 n=$3; shift 3
    [ -s "$m0" ] && [ -s "$m1" ] || { echo "?"; return; }
    local a b; a=$(val "$m0" "$n" "$@"); b=$(val "$m1" "$n" "$@")
    [ -n "$b" ] || { echo "?"; return; }
    awk -v a="${a:-0}" -v b="$b" 'BEGIN { printf "%.0f", b - a }'
}

echo "== w85 8.5.E1: OUT=${OUT:-—}"
if [ -z "$OUT" ] || [ ! -d "$OUT" ]; then echo "НЕИЗМЕРИМ: 8.5.E1 НЕИЗМЕРИМ (класс НАЗВАН: нет каталога ${OUT:-—})"; exit 0; fi
if ! grep -q '^done' "$OUT/DONE" 2>/dev/null; then echo "НЕИЗМЕРИМ: 8.5.E1 НЕИЗМЕРИМ (класс НАЗВАН: прогон не завершён: $(cat "$OUT/DONE" 2>/dev/null || echo нет DONE))"; exit 0; fi
cls=""
for ph in before after; do
    d=$OUT/$ph
    [ -s "$d/m0.txt" ] && [ -s "$d/m1.txt" ] || cls="$cls; $ph: нет снимков метрик"
    [ -s "$d/alerts.txt" ] || cls="$cls; $ph: нет alerts.txt"
done
[ -s "$OUT/spoof.txt" ] || cls="$cls; нет spoof.txt"
[ "$(cat "$OUT/before/proc_table_state.txt" 2>/dev/null)" != active ] || cls="$cls; «до» с активной таблицей"
[ "$(cat "$OUT/after/proc_table_state.txt" 2>/dev/null)" = active ] || cls="$cls; «после» без активной таблицы"
if [ -n "$cls" ]; then echo "НЕИЗМЕРИМ: 8.5.E1 НЕИЗМЕРИМ (класс НАЗВАН:${cls#;})"; exit 0; fi

L=ebpf_guard_exe_path_lookups_total
ub=$(delta "$OUT/before/m0.txt" "$OUT/before/m1.txt" $L field=exe_path result=unresolved)
rb=$(delta "$OUT/before/m0.txt" "$OUT/before/m1.txt" $L field=exe_path result=resolved)
ua=$(delta "$OUT/after/m0.txt" "$OUT/after/m1.txt" $L field=exe_path result=unresolved)
ra=$(delta "$OUT/after/m0.txt" "$OUT/after/m1.txt" $L field=exe_path result=resolved)
eb=$(delta "$OUT/before/m0.txt" "$OUT/before/m1.txt" ebpf_guard_rule_exceptions_total rule_id=$RULE exception_name=$EXC)
ea=$(delta "$OUT/after/m0.txt" "$OUT/after/m1.txt" ebpf_guard_rule_exceptions_total rule_id=$RULE exception_name=$EXC)
echo "  до:    exe_path resolved $rb, unresolved $ub; подавлений $EXC $eb; алертов $RULE от systemd-detect-* $(cat "$OUT/before/alerts.txt")"
echo "  после: exe_path resolved $ra, unresolved $ua; подавлений $EXC $ea; алертов $RULE от systemd-detect-* $(cat "$OUT/after/alerts.txt")"
for v in "$ub" "$rb" "$ua" "$ra" "$eb" "$ea"; do case "$v" in ''|'?'|-*|*[!0-9]*) echo "НЕИЗМЕРИМ: 8.5.E1 НЕИЗМЕРИМ (класс НАЗВАН: нет серии/отрицательная дельта в снимках метрик)"; exit 0 ;; esac; done
tb=$((ub + rb)); ta=$((ua + ra))
if [ "$tb" -lt "$E1_MIN_LOOKUPS" ] || [ "$ta" -lt "$E1_MIN_LOOKUPS" ]; then
    echo "НЕИЗМЕРИМ: 8.5.E1 НЕИЗМЕРИМ (класс НАЗВАН: мс-процессы не дошли до оценки exe_path: до $tb, после $ta < $E1_MIN_LOOKUPS)"; exit 0
fi
img=0; for r in cached proc filename; do
    x=$(delta "$OUT/after/m0.txt" "$OUT/after/m1.txt" ebpf_guard_exe_path_image_total result=$r); case "$x" in ''|'?') x=0 ;; esac
    img=$((img + x)); echo "  после: exe_path_image{$r} +$x"
done
for r in resolved unresolved; do
    x=$(delta "$OUT/after/m0.txt" "$OUT/after/m1.txt" ebpf_guard_exe_path_readlink_fallback_total result=$r)
    echo "  после: readlink запасной {$r} +$x"
done
fail=""
# доли по целым: unresolved_after / total_after ≤ ½ · unresolved_before / total_before
[ $((2 * ua * tb)) -le $((ub * ta)) ] || fail="$fail; доля unresolved «после» ($ua/$ta) больше половины «до» ($ub/$tb)"
[ "$ea" -gt "$eb" ] || fail="$fail; подавлений «после» ($ea) не больше «до» ($eb)"
[ "$img" -gt 0 ] || fail="$fail; образ из таблицы ни разу не ответил"
nsp=0
while read -r name cnt; do
    [ -n "$name" ] || continue; nsp=$((nsp + 1))
    echo "  спуф-контроль $name: алертов $cnt"
    case "$cnt" in ''|none|*[!0-9]*) fail="$fail; контроль $name: счёт алертов не получен" ;; 0) fail="$fail; контроль $name не сработал (исключение применилось к спуфу)" ;; esac
done < "$OUT/spoof.txt"
[ "$nsp" -ge 3 ] || fail="$fail; спуф-контролей $nsp < 3"
if [ -z "$fail" ]; then
    echo "ДОСТИГНУТО: 8.5.E1 ДОСТИГНУТО (unresolved $ub/$tb → $ua/$ta; подавлений $eb → $ea; образ из таблицы $img; спуфов $nsp/$nsp)"
else
    echo "ПРОВАЛЕН: 8.5.E1 ПРОВАЛЕН (${fail#;})"
fi
