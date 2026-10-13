#!/bin/bash
# w85-mem-report.sh — пара A3/A4 (волна 8.5; решение владельца 13.10 ч.2, п. 2) по каталогу w85-ab-mem.sh. Считает эмиттер.
#   OUT=<каталог> R=<повторов, по умолчанию 3> [NOISE_PCT=4] bash w85-mem-report.sh
# Метрики на повтор (on = таблица процессов, off = без неё; один бинарь): пик memory.current старта (выборка 10 Гц), пик
# memory.current за пакет атак, heap_inuse и heap_alloc после пакета. Разница РЕАЛЬНА по метрике, если во ВСЕХ R повторах
# |on − off| / off > NOISE_PCT% и знак один и тот же (решение: «вне ±4% во всех трёх»). Критерия по памяти от P1 нет —
# эмиттер только называет, нужна ли правка (убрать декодирование Filename из чтения дерева) и перемер. Правка нужна ТОЛЬКО если
# реальная разница в сторону БОЛЬШЕ памяти с P1 (знак «+»): разница «P1 дешевле» (знак «−») правки не требует, но печатается.
# Нет файла/серии — НЕИЗМЕРИМ с названным классом.
set -u
OUT=${OUT:-}; R=${R:-3}; NOISE_PCT=${NOISE_PCT:-4}
echo "== w85 A3/A4 (8.5.A34): OUT=${OUT:-—} повторов $R, шум пары ±${NOISE_PCT}%"
if [ -z "$OUT" ] || [ ! -d "$OUT" ]; then echo "НЕИЗМЕРИМ: 8.5.A34 НЕИЗМЕРИМ (класс НАЗВАН: нет каталога ${OUT:-—})"; exit 0; fi
if ! grep -q '^done' "$OUT/DONE" 2>/dev/null; then echo "НЕИЗМЕРИМ: 8.5.A34 НЕИЗМЕРИМ (класс НАЗВАН: серия не завершена: $(cat "$OUT/DONE" 2>/dev/null || echo нет DONE))"; exit 0; fi
mx() { awk 'NF >= 2 && $2 ~ /^[0-9]+$/ { if ($2 > m) m = $2; seen = 1 } END { if (seen) printf "%.2f", m / 1048576 }' "$1" 2> /dev/null; }
last() { awk 'NF >= 2 && $2 ~ /^[0-9]+$/ { v = $2; seen = 1 } END { if (seen) printf "%.2f", v / 1048576 }' "$1" 2> /dev/null; }
gm() { awk -v n="$2" '$1 == n { v = $2; seen = 1 } END { if (seen) printf "%.2f", v / 1048576 }' "$1" 2> /dev/null; }
cls=""
declare -A V
for k in $(seq 1 "$R"); do
    for mode in on off; do
        d=$OUT/r$k-$mode
        [ -d "$d" ] || { cls="$cls; нет каталога r$k-$mode"; continue; }
        sp=$(mx "$d/start.tsv"); pp=$(mx "$d/pack.tsv"); en=$(last "$d/end.tsv")
        hi=$(gm "$d/m-end.txt" go_memstats_heap_inuse_bytes); ha=$(gm "$d/m-end.txt" go_memstats_heap_alloc_bytes)
        [ -n "$sp" ] || cls="$cls; r$k-$mode: нет выборки старта memory.current"
        [ -n "$pp" ] || pp=$en
        [ -n "$pp" ] || cls="$cls; r$k-$mode: нет memory.current после пакета"
        [ -n "$hi" ] && [ -n "$ha" ] || cls="$cls; r$k-$mode: нет go_memstats_heap_* в m-end.txt"
        V[$k,$mode,start]=$sp; V[$k,$mode,mem]=$pp; V[$k,$mode,inuse]=$hi; V[$k,$mode,alloc]=$ha
        echo "  r$k $mode: пик старта $sp МиБ, пик memory.current $pp МиБ, heap_inuse $hi МиБ, heap_alloc $ha МиБ ($(sed -n 's/^mode=.*state=//p' "$d/meta.txt"))"
    done
done
if [ -n "$cls" ]; then echo "НЕИЗМЕРИМ: 8.5.A34 НЕИЗМЕРИМ (класс НАЗВАН:${cls#;})"; exit 0; fi
real_up=""; real_down=""
for m in start mem inuse alloc; do
    case $m in start) nm="пик старта memory.current";; mem) nm="пик memory.current";; inuse) nm="heap_inuse";; alloc) nm="heap_alloc";; esac
    allout=1; sign=""; diffs=""
    for k in $(seq 1 "$R"); do
        on=${V[$k,on,$m]}; off=${V[$k,off,$m]}
        dp=$(awk -v a="$on" -v b="$off" 'BEGIN { if (b == 0) { print "nan"; exit } printf "%+.1f", 100 * (a - b) / b }')
        diffs="$diffs $dp%"
        case "$dp" in nan) allout=0 ;; *)
            awk -v d="$dp" -v n="$NOISE_PCT" 'BEGIN { if (d < 0) d = -d; exit !(d > n) }' || allout=0
            sg=$(awk -v d="$dp" 'BEGIN { print (d > 0) ? "+" : "-" }')
            [ -z "$sign" ] && sign=$sg; [ "$sign" = "$sg" ] || allout=0 ;;
        esac
    done
    if [ "$allout" = 1 ]; then
        if [ "$sign" = "+" ]; then real_up="$real_up; $nm (${diffs# })"; else real_down="$real_down; $nm (${diffs# })"; fi
    fi
    echo "  разница on−off, $nm:${diffs}$([ "$allout" = 1 ] && echo '  ← ВНЕ ±'$NOISE_PCT'% во всех повторах')"
done
if [ -n "$real_up" ]; then
    echo "ИЗМЕРЕНО: 8.5.A34 разница РЕАЛЬНА, с P1 БОЛЬШЕ: ${real_up#; }${real_down:+; с P1 меньше: ${real_down#; }} — по решению 2: убрать декодирование Filename из чтения дерева и перемерить"
elif [ -n "$real_down" ]; then
    echo "ИЗМЕРЕНО: 8.5.A34 разница РЕАЛЬНА, с P1 МЕНЬШЕ: ${real_down#; } — таблица процессов памяти не добавляет, правка Filename не требуется; остальные величины вне ±${NOISE_PCT}% во всех $R повторах не выходят"
else
    echo "ИЗМЕРЕНО: 8.5.A34 разницы вне ±${NOISE_PCT}% во всех $R повторах нет ни по одной из четырёх величин — правка Filename не требуется"
fi
