#!/bin/bash
# night-report.sh — отчёт ЗАМЕРА №3 (ночной idle) и вход волны 8.1.
#
# Читает каталог idle-run.sh (snapshots/metrics-NNNN.txt каждые INTERVAL секунд,
# snapshots/store-size.tsv, snapshots/heap-NNNN.pprof) и печатает почасовую
# таблицу и вердиктные строки. Сам ничего не снимает — реплеится офлайн по архиву.
#
# ВЕЛИЧИНЫ И ИХ ЕДИНИЦЫ (каждая строка называет единицу рядом с осью, №480):
#   объём ЗА ЧАС — сумма трёх слоёв, АЛЕРТОВ: выпущено (alerts_total) + срезал
#     лимитер (ratelimited_by_rule) + срезал дедуп (dedup_dropped). Напечатанное
#     «выпущено» одно — это потолок лимитера, а не объём ([[gate-value-is-limiter-reading]]);
#   память — RSS и go_memstats на КОНЕЦ часа, МиБ;
#   серии — число строк /metrics без комментариев на конец часа;
#   стор — размер файла SQLite (+WAL) stat'ом, МиБ.
#
# ЧТО НЕ ЕСТЬ НОЛЬ (каждое — НЕИЗМЕРИМ с классом, а не 0):
#   - снимок отсутствует или пуст ([[empty-metric-snapshot-is-silently-zero]]);
#   - process_start_time_seconds сменился внутри часа — рестарт, дельта через него
#     бессмысленна;
#   - полных часов меньше, чем требует критерий.
#
# Вердикты:
#   3.P1-19  объём часа 8 не выше часа 2 более чем на 20% (сумма трёх слоёв);
#   3.MEM    стационарность памяти: ИЗМЕРЕНО с наклоном МиБ/ч по часам 2..8 и
#            классом «монотонный рост / не монотонный» — порог не назначается
#            (первое измерение порога не несёт, правило 5.9.6);
#   3.ATTACK инциденты verdict="attack" за ночь: 0 → ДОСТИГНУТО;
#   3.STORE  приёмка 4.5: рост файла стора МиБ/ч и потолок к ретенции 168 ч;
#            ретенция за окно не срабатывает — вердикт НЕИЗМЕРИМ по построению.
#   8.1.1    траектория cgroup-памяти (ночь №4, этап D волны 8.1): ИЗМЕРЕНО с
#            классом «прогрев / накопление / промежуточный» по anon и с пиком
#            memory.current против лимита чарта. ВЕРДИКТА по item 5 эта метка не
#            несёт и ДОСТИГНУТО не печатает НИКОГДА: лимит судится под атаками
#            (этап F), а не на idle — здесь только вход;
#   8.1.2    потери очереди protected на idle: 0 → ДОСТИГНУТО, но ТОЛЬКО если
#            предъявлен прибор очередей (ebpf_guard_queue_depth_hwm). Ноль без
#            прибора — НЕИЗМЕРИМ: ровно это требует пункт 4 критерия выхода
#            волны 8.1 («ноль с предъявленным прибором, а не отсутствие серии»).
#
# Использование: night-report.sh <каталог idle-run> [интервал_с=300]
set -u
D="${1:?каталог idle-run не задан}"
INTERVAL="${2:-${NIGHT_INTERVAL:-300}}"
PER_H=$(( 3600 / INTERVAL ))
S="$D/snapshots"
[ -d "$S" ] || { echo "НЕИЗМЕРИМ: 3.* НЕИЗМЕРИМ (класс НАЗВАН: нет каталога снимков $S)"; exit 0; }

# _val <файл> <метрика> [фильтр лейблов] — сумма серий метрики; ПУСТО, если
# файла нет, он пуст или серии нет вовсе (пустота — не ноль).
_val() {
    local f="$1" m="$2" lab="${3:-}"
    [ -s "$f" ] || { echo ""; return; }
    awk -v m="$m" -v lab="$lab" '
        /^#/ { next }
        { name = $1; sub(/\{.*/, "", name) }
        name == m && (lab == "" || index($1, lab) > 0) { s += $NF; seen = 1 }
        END { if (seen) printf "%.0f\n", s }' "$f" < /dev/null
}
_series() { [ -s "$1" ] && grep -vc '^#' "$1" || echo ""; }
_mib() { [ -n "$1" ] && awk -v b="$1" 'BEGIN { printf "%.1f", b / 1048576 }' || echo "?"; }
_snap() { printf '%s/metrics-%04d.txt' "$S" "$1"; }

last=$(ls "$S"/metrics-*.txt 2>/dev/null | sed 's/.*metrics-0*\([0-9][0-9]*\)\.txt/\1/' | sort -n | tail -1)
[ -n "$last" ] || { echo "НЕИЗМЕРИМ: 3.* НЕИЗМЕРИМ (класс НАЗВАН: ни одного снимка metrics в $S)"; exit 0; }
hours=$(( last / PER_H ))
echo "=== ЗАМЕР №3: ночной idle по часам (снимков $((last + 1)), интервал ${INTERVAL} с, полных часов $hours) ==="
printf '%-4s %10s %10s %10s %10s %8s %8s %8s %8s %8s %7s %8s %s\n' \
    час "выпущено" "лимитер" "дедуп" "объём" "attack" "RSS" "heap" "inuse" "удерж" "серии" "стор" "класс часа"

declare -A VOL RSS HEAP ATT
bad_hours=""
for h in $(seq 1 "$hours"); do
    a=$(_snap $(( (h - 1) * PER_H ))); b=$(_snap $(( h * PER_H )))
    sa=$(_val "$a" process_start_time_seconds); sb=$(_val "$b" process_start_time_seconds)
    cls="ok"
    if [ ! -s "$a" ] || [ ! -s "$b" ]; then cls="снимок_пуст"
    elif [ -z "$sa" ] || [ "$sa" != "$sb" ]; then cls="рестарт"
    fi
    e0=$(_val "$a" ebpf_guard_alerts_total); e1=$(_val "$b" ebpf_guard_alerts_total)
    r0=$(_val "$a" ebpf_guard_alerts_ratelimited_by_rule_total); r1=$(_val "$b" ebpf_guard_alerts_ratelimited_by_rule_total)
    d0=$(_val "$a" ebpf_guard_alerts_dedup_dropped_total); d1=$(_val "$b" ebpf_guard_alerts_dedup_dropped_total)
    k0=$(_val "$a" ebpf_guard_incidents_total 'verdict="attack"'); k1=$(_val "$b" ebpf_guard_incidents_total 'verdict="attack"')
    if [ "$cls" = ok ]; then
        e=$(( ${e1:-0} - ${e0:-0} )); r=$(( ${r1:-0} - ${r0:-0} )); d=$(( ${d1:-0} - ${d0:-0} )); k=$(( ${k1:-0} - ${k0:-0} ))
        if [ "$e" -lt 0 ] || [ "$r" -lt 0 ] || [ "$d" -lt 0 ] || [ "$k" -lt 0 ]; then cls="счётчик_убыл"; fi
    fi
    rss=$(_val "$b" process_resident_memory_bytes); heap=$(_val "$b" go_memstats_heap_alloc_bytes)
    inuse=$(_val "$b" go_memstats_heap_inuse_bytes); idle=$(_val "$b" go_memstats_heap_idle_bytes)
    rel=$(_val "$b" go_memstats_heap_released_bytes)
    ret=""; [ -n "$idle" ] && [ -n "$rel" ] && ret=$(( idle - rel ))
    st=$(awk -F'\t' -v n=$(( h * PER_H )) '$2 == n { print $3 + $4 }' "$S/store-size.tsv" 2>/dev/null)
    if [ "$cls" = ok ]; then
        v=$(( e + r + d )); VOL[$h]=$v; ATT[$h]=$k
        printf '%-4s %10s %10s %10s %10s %8s %8s %8s %8s %8s %7s %8s %s\n' "$h" "$e" "$r" "$d" "$v" "$k" \
            "$(_mib "$rss")" "$(_mib "$heap")" "$(_mib "$inuse")" "$(_mib "$ret")" "$(_series "$b")" "$(_mib "$st")" "$cls"
    else
        bad_hours="$bad_hours $h:$cls"
        printf '%-4s %10s %10s %10s %10s %8s %8s %8s %8s %8s %7s %8s %s\n' "$h" - - - - - \
            "$(_mib "$rss")" "$(_mib "$heap")" "$(_mib "$inuse")" "$(_mib "$ret")" "$(_series "$b")" "$(_mib "$st")" "$cls"
    fi
    [ -n "$rss" ] && RSS[$h]=$rss; [ -n "$heap" ] && HEAP[$h]=$heap
done
echo "  (объём — АЛЕРТОВ за час, сумма трёх слоёв; память — МиБ на конец часа; стор — МиБ файла SQLite+WAL)"
echo

# ── 3.P1-19 ────────────────────────────────────────────────────────────────
if [ "$hours" -lt 8 ]; then
    echo "НЕИЗМЕРИМ: 3.P1-19 НЕИЗМЕРИМ (класс НАЗВАН: полных часов $hours, критерию нужен 8-й)"
elif [ -z "${VOL[2]:-}" ] || [ -z "${VOL[8]:-}" ]; then
    echo "НЕИЗМЕРИМ: 3.P1-19 НЕИЗМЕРИМ (класс НАЗВАН: час 2 или 8 неизмерим —${bad_hours})"
elif [ "${VOL[2]}" -eq 0 ]; then
    echo "НЕИЗМЕРИМ: 3.P1-19 НЕИЗМЕРИМ (класс НАЗВАН: объём часа 2 = 0 алертов, отношение не определено; час 8 = ${VOL[8]} алертов)"
else
    ratio=$(awk -v a="${VOL[8]}" -v b="${VOL[2]}" 'BEGIN { printf "%.3f", a / b }')
    if awk -v r="$ratio" 'BEGIN { exit !(r <= 1.20) }'; then
        echo "ДОСТИГНУТО: 3.P1-19 ДОСТИГНУТО (объём часа 8 = ${VOL[8]} алертов против часа 2 = ${VOL[2]} алертов, отношение $ratio ≤ 1.20; сумма трёх слоёв)"
    else
        echo "ПРОВАЛЕН: 3.P1-19 ПРОВАЛЕН (объём часа 8 = ${VOL[8]} алертов против часа 2 = ${VOL[2]} алертов, отношение $ratio > 1.20; сумма трёх слоёв — шум нарастает)"
    fi
fi

# ── 3.MEM ──────────────────────────────────────────────────────────────────
# Наклон — МНК по часам 2..min(8,hours) (час 1 — прогрев после рестарта).
_slope() {
    local -n arr=$1; local h xs=""
    for h in $(seq 2 "$(( hours < 8 ? hours : 8 ))"); do [ -n "${arr[$h]:-}" ] && xs="$xs $h:${arr[$h]}"; done
    printf '%s\n' $xs | awk -F: 'NF == 2 { n++; x += $1; y += $2 / 1048576; xy += $1 * $2 / 1048576; xx += $1 * $1; v[n] = $2 }
        END { if (n < 3) { print "?"; exit } m = (n * xy - x * y) / (n * xx - x * x)
              mono = 1; for (i = 2; i <= n; i++) if (v[i] <= v[i-1]) mono = 0
              printf "%.2f %s %d\n", m, (mono ? "монотонный_рост" : "не_монотонный"), n }'
}
if [ "$hours" -lt 4 ]; then
    echo "НЕИЗМЕРИМ: 3.MEM НЕИЗМЕРИМ (класс НАЗВАН: полных часов $hours — наклону нужно ≥3 часа после прогрева)"
else
    read -r rs rc rn <<< "$(_slope RSS)"; read -r hs hc hn <<< "$(_slope HEAP)"
    if [ "$rs" = "?" ] || [ "$hs" = "?" ]; then
        echo "НЕИЗМЕРИМ: 3.MEM НЕИЗМЕРИМ (класс НАЗВАН: меньше 3 часов с непустыми снимками памяти)"
    else
        echo "ИЗМЕРЕНО: 3.MEM ИЗМЕРЕНО (часы 2..$((hn + 1)): RSS наклон $rs МиБ/ч, $rc; heap_alloc наклон $hs МиБ/ч, $hc; RSS конец часа 2 = $(_mib "${RSS[2]:-}") МиБ, последнего = $(_mib "${RSS[$hours]:-}") МиБ — порог не назначается, правило 5.9.6)"
    fi
fi

# ── 3.ATTACK ───────────────────────────────────────────────────────────────
a0=$(_val "$(_snap 0)" ebpf_guard_incidents_total 'verdict="attack"')
aN=$(_val "$(_snap "$last")" ebpf_guard_incidents_total 'verdict="attack"')
s0=$(_val "$(_snap 0)" process_start_time_seconds); sN=$(_val "$(_snap "$last")" process_start_time_seconds)
if [ -z "$s0" ] || [ "$s0" != "$sN" ]; then
    echo "НЕИЗМЕРИМ: 3.ATTACK НЕИЗМЕРИМ (класс НАЗВАН: рестарт агента между первым и последним снимком, или снимок пуст)"
elif [ -z "$a0" ] && [ -z "$aN" ]; then
    echo "НЕИЗМЕРИМ: 3.ATTACK НЕИЗМЕРИМ (класс НАЗВАН: серии incidents_total{verdict=\"attack\"} нет ни в первом, ни в последнем снимке — нет серии ≠ 0)"
else
    da=$(( ${aN:-0} - ${a0:-0} ))
    if [ "$da" -eq 0 ]; then
        echo "ДОСТИГНУТО: 3.ATTACK ДОСТИГНУТО (инцидентов verdict=\"attack\" за ночь 0)"
    else
        echo "ПРОВАЛЕН: 3.ATTACK ПРОВАЛЕН (инцидентов verdict=\"attack\" за ночь $da — на idle их быть не должно)"
    fi
fi

# ── 3.STORE (приёмка 4.5) ──────────────────────────────────────────────────
if [ ! -s "$S/store-size.tsv" ]; then
    echo "НЕИЗМЕРИМ: 3.STORE НЕИЗМЕРИМ (класс НАЗВАН: store-size.tsv не снят — STORE_DB не задан)"
else
    awk -F'\t' -v per="$PER_H" '
        $3 >= 0 { n++; if (n == 1) { t0 = $2; b0 = $3 + $4 } t1 = $2; b1 = $3 + $4 }
        END {
            if (n < 2 || t1 == t0) { print "НЕИЗМЕРИМ: 3.STORE НЕИЗМЕРИМ (класс НАЗВАН: меньше двух замеров размера файла стора)"; exit }
            h = (t1 - t0) / per; g = (b1 - b0) / 1048576 / h
            printf "НЕИЗМЕРИМ: 3.STORE НЕИЗМЕРИМ по построению (ретенция 168 ч за окно %.1f ч не срабатывает); величина: файл стора %.1f → %.1f МиБ, рост %.2f МиБ/ч, потолок к ретенции ≈ %.0f МиБ\n", h, b0 / 1048576, b1 / 1048576, g, b0 / 1048576 + g * 168
        }' "$S/store-size.tsv" < /dev/null
fi

# ── 8.1: что приложено ─────────────────────────────────────────────────────
nheap=$(ls "$S"/heap-*.pprof 2>/dev/null | grep -c . || true)
echo "  8.1: heap-профилей в архиве $nheap (без gc=1); разность первого и последнего — go tool pprof -base"
ncpu=$(ls "$S"/cpu-*.pprof 2>/dev/null | grep -c . || true)
echo "  8.1: CPU-профилей в архиве $ncpu (30 с каждый час, снят в фоне); разбор — go tool pprof -top, разность — -base"
# item 9: пик глубины каждой очереди за ночь = максимум скользящего 5-мин окна по
# всем срезам (шаг среза = окно, дыр нет); ёмкость — из последнего среза. Это
# ВХОД для items 9/10, вердикта нет; нулевой пик = «не виден при 1 Гц», не «не
# заполнялась» — заполнение судится счётчиками потерь очереди.
if ls "$S"/metrics-*.txt >/dev/null 2>&1; then
    awk '
        /^ebpf_guard_queue_depth_hwm\{/ { q = $1; sub(/.*queue="/, "", q); sub(/".*/, "", q); if ($NF + 0 > pk[q]) pk[q] = $NF + 0; seen[q] = 1 }
        /^ebpf_guard_queue_capacity\{/   { q = $1; sub(/.*queue="/, "", q); sub(/".*/, "", q); cap[q] = $NF + 0 }
        END {
            n = 0; for (q in seen) n++
            if (!n) { print "  8.1: очереди: серии ebpf_guard_queue_depth_hwm НЕ НАПЕЧАТАНЫ (бинарь без item 9?)"; exit }
            for (q in seen) printf "  8.1: очередь %s: пик %d из %d (%.1f%%)\n", q, pk[q], cap[q], (cap[q] > 0 ? 100 * pk[q] / cap[q] : 0)
        }' "$S"/metrics-*.txt < /dev/null 2>/dev/null | sort
fi

# ── 8.1.1: траектория cgroup-памяти (вход item 5, вопрос «прогрев или накопление») ──
# Прибор — snapshots/cgroup-mem.tsv из idle-run.sh (CGROUP_MEM=1). RSS и heap для
# этого вопроса не годятся: 03.10.2026 RSS 276 МиБ стоял при memory.current 290,
# то есть по RSS прогон «уложился» бы в 256Mi, а в поде это OOM-kill.
CG="$S/cgroup-mem.tsv"
CHART_LIMIT=$(( 256 * 1048576 ))
if [ ! -s "$CG" ]; then
    echo "НЕИЗМЕРИМ: 8.1.1 НЕИЗМЕРИМ (класс НАЗВАН: cgroup-mem.tsv не снят — CGROUP_MEM=0 или cgroup агента не определён; по RSS этот вопрос не решается)"
else
    printf '%-4s %12s %12s %12s %12s %s\n' час "current" "anon" "file" "неназв." "(МиБ, конец часа)"
    for h in $(seq 1 "$hours"); do
        awk -F'\t' -v n=$(( h * PER_H )) -v h="$h" '
            $2 == n {
                un = $3 - ($4 + $5 + $6 + $7 + $8 + $9)
                printf "%-4s %12.1f %12.1f %12.1f %12.1f\n", h, $3/1048576, $4/1048576, $5/1048576, un/1048576
                found = 1
            }
            END { if (!found) printf "%-4s %12s %12s %12s %12s  срез отсутствует\n", h, "-", "-", "-", "-" }' "$CG" < /dev/null
    done
    # Класс считает ЭМИТТЕР: таблица исходов в руках человека разъезжается с
    # величиной прогона ([[verdict-input-must-be-computed-by-emitter]]). Час 1 —
    # прогрев после рестарта, он из наклонов исключён. Отношение, а не порог:
    # первое измерение порога не несёт (правило 5.9.6).
    awk -F'\t' -v per="$PER_H" -v hours="$hours" -v lim="$CHART_LIMIT" '
        NR > 1 && $2 ~ /^[0-9]+$/ {
            n = $2 + 0; cur[n] = $3 + 0; an[n] = $4 + 0; mx = $10
            if ($3 + 0 > pk) { pk = $3 + 0; pkn = n }
            if (n > lastn) lastn = n
        }
        END {
            if (hours < 4) {
                printf "НЕИЗМЕРИМ: 8.1.1 НЕИЗМЕРИМ (класс НАЗВАН: полных часов %d — классу «прогрев или накопление» нужно ≥4, чтобы сравнить первые три с последними тремя); пик memory.current %.1f МиБ\n", hours, pk / 1048576
                exit
            }
            h1 = per; h4 = 4 * per; hl3 = (hours - 3) * per; hl = hours * per
            for (k in an) ;
            miss = ""
            if (!(h1 in an)) miss = miss " час1"
            if (!(h4 in an)) miss = miss " час4"
            if (!(hl3 in an)) miss = miss " час" (hours - 3)
            if (!(hl in an)) miss = miss " час" hours
            if (miss != "") {
                printf "НЕИЗМЕРИМ: 8.1.1 НЕИЗМЕРИМ (класс НАЗВАН: нет срезов cgroup на границах часов:%s)\n", miss
                exit
            }
            d_first = (an[h4] - an[h1]) / 1048576
            d_last  = (an[hl] - an[hl3]) / 1048576
            if (d_first > 0 && d_last <= d_first / 4)      cls = "прогрев (рост anon затух)"
            else if (d_last > 0 && d_last >= d_first / 2)   cls = "НАКОПЛЕНИЕ (рост anon не затухает)"
            else if (d_last <= 0)                           cls = "прогрев (anon перестал расти)"
            else                                            cls = "промежуточный"
            over = (pk - lim) / 1048576
            printf "ИЗМЕРЕНО: 8.1.1 ИЗМЕРЕНО (anon: часы 1→4 %+.1f МиБ, часы %d→%d %+.1f МиБ, класс %s; пик memory.current %.1f МиБ на срезе %d против лимита чарта 256.0 МиБ — %s %.1f МиБ; memory.max cgroup стенда = %s; порог не назначается, правило 5.9.6)\n", \
                d_first, hours - 3, hours, d_last, cls, pk / 1048576, pkn, (over > 0 ? "перебор" : "запас"), (over > 0 ? over : -over), mx
        }' "$CG" < /dev/null
fi

# ── 8.1.2: потери очереди protected на idle (пункт 4 критерия выхода волны 8.1) ──
# Ноль обязан быть ПОКАЗАНИЕМ: при отсутствии серий очередного прибора
# (ebpf_guard_queue_depth_hwm, item 9) «потерь 0» неотличимо от «бинарь про
# очереди не знает» ([[gated-metric-cannot-carry-product-verdict]]).
f0=$(_snap 0); fN=$(_snap "$last")
p0=$(_val "$f0" ebpf_guard_events_dropped_by_queue_total 'queue="protected"')
pN=$(_val "$fN" ebpf_guard_events_dropped_by_queue_total 'queue="protected"')
hop0=$(_val "$f0" ebpf_guard_events_dropped_total 'reason="ringbuf_to_router"')
hopN=$(_val "$fN" ebpf_guard_events_dropped_total 'reason="ringbuf_to_router"')
hwm=$(_val "$fN" ebpf_guard_queue_depth_hwm)
st0=$(_val "$f0" process_start_time_seconds); stN=$(_val "$fN" process_start_time_seconds)
if [ -z "$st0" ] || [ "$st0" != "$stN" ]; then
    echo "НЕИЗМЕРИМ: 8.1.2 НЕИЗМЕРИМ (класс НАЗВАН: рестарт агента между первым и последним снимком — дельта счётчиков через рестарт бессмысленна)"
elif [ -z "$p0" ] && [ -z "$pN" ]; then
    echo "НЕИЗМЕРИМ: 8.1.2 НЕИЗМЕРИМ (класс НАЗВАН: серии events_dropped_by_queue_total{queue=\"protected\"} нет ни в первом, ни в последнем снимке — нет серии ≠ 0)"
elif [ -z "$hwm" ]; then
    echo "НЕИЗМЕРИМ: 8.1.2 НЕИЗМЕРИМ (класс НАЗВАН: потери protected за ночь $(( ${pN:-0} - ${p0:-0} )), но прибор очередей не предъявлен — серий ebpf_guard_queue_depth_hwm в снимке нет; ноль без прибора пункт 4 критерия не берёт)"
else
    dp=$(( ${pN:-0} - ${p0:-0} )); dh=$(( ${hopN:-0} - ${hop0:-0} ))
    if [ "$dp" -lt 0 ] || [ "$dh" -lt 0 ]; then
        echo "НЕИЗМЕРИМ: 8.1.2 НЕИЗМЕРИМ (класс НАЗВАН: счётчик потерь убыл за ночь — protected $dp, хоп ringbuf_to_router $dh)"
    elif [ "$dp" -eq 0 ]; then
        echo "ДОСТИГНУТО: 8.1.2 ДОСТИГНУТО (потерь очереди protected за ночь 0; хоп ringbuf_to_router $dh; прибор очередей предъявлен — серии ebpf_guard_queue_depth_hwm в снимке есть, пики выше)"
    else
        echo "ПРОВАЛЕН: 8.1.2 ПРОВАЛЕН (потерь очереди protected за ночь $dp, хоп ringbuf_to_router $dh — на ПУСТОЙ ноде сигнал безопасности терять нельзя; разрез по часам ниже)"
        for h in $(seq 1 "$hours"); do
            a=$(_snap $(( (h - 1) * PER_H ))); b=$(_snap $(( h * PER_H )))
            x0=$(_val "$a" ebpf_guard_events_dropped_by_queue_total 'queue="protected"')
            x1=$(_val "$b" ebpf_guard_events_dropped_by_queue_total 'queue="protected"')
            [ -n "$x0" ] && [ -n "$x1" ] && echo "    час $h: protected +$(( x1 - x0 ))"
        done
    fi
fi
