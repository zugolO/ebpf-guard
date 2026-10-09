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
#   3.P1-19  нарастание шума по ФОНОВЫМ часам — часам без стартов юнитов ноды
#            (журнал PID 1, node-units.tsv; №549, решение владельца 08.10.2026):
#            последний фоновый час против первого, сумма трёх слоёв. Вердиктное
#            слово несёт класс — НАРАСТАНИЕ → ПРОВАЛЕН, ПЛАТО → ДОСТИГНУТО;
#            фоновых часов меньше двух или нет журнала юнитов — НЕИЗМЕРИМ.
#            Рядом печатается ЦЕНА каждого события ноды (три слоя за его срезы
#            минус фон) и цена того же юнита прошлой ночи (NIGHT_PREV). До
#            09.10.2026 метка сравнивала час 8 с часом 2 — на стенде это час
#            unattended-upgrades против часа apt-daily, о нарастании оно не
#            говорило ничего (ночь H2: 1,05 «ДОСТИГНУТО»);
#   3.MEM    стационарность памяти: ИЗМЕРЕНО с наклоном МиБ/ч по часам 2..8 и
#            классом «монотонный рост / не монотонный» — порог не назначается
#            (первое измерение порога не несёт, правило 5.9.6);
#   3.ATTACK инциденты verdict="attack" за ночь: 0 → ДОСТИГНУТО;
#   3.STORE  приёмка 4.5: рост файла стора МиБ/ч и потолок к ретенции 168 ч;
#            ретенция за окно не срабатывает — вердикт НЕИЗМЕРИМ по построению.
#   8.1.1    траектория cgroup-памяти (ночь №4, этап D волны 8.1): класс по anon
#            — ПЛАТО/ПРОГРЕВ → ДОСТИГНУТО, НАКОПЛЕНИЕ → ПРОВАЛЕН — и пик
#            memory.current против лимита чарта (печатается, не судится). С
#            07.10.2026 вердиктное слово несёт КЛАСС, а не «ИЗМЕРЕНО»: лимит чарта
#            и item 5 судит волна 8.2 (решение владельца 06.10), за 8.1 остался
#            один вопрос — копится ли память на idle. Ступенька от события ноды
#            (ночь H: dpkg-шторм, anon +55 МиБ за три среза) из класса вынесена и
#            названа отдельно: размах остатков, раздутый ею, давал «плато/колебание»
#            по неверной причине;
#   8.1.2    потери очереди protected на idle: 0 → ДОСТИГНУТО, но ТОЛЬКО если
#            предъявлен прибор очередей (ebpf_guard_queue_depth_hwm). Ноль без
#            прибора — НЕИЗМЕРИМ: ровно это требует пункт 4 критерия выхода
#            волны 8.1 («ноль с предъявленным прибором, а не отсутствие серии»).
#
# Использование: night-report.sh <каталог idle-run> [интервал_с=300]
#   NIGHT_UNITS — старты юнитов ноды (умолчание <каталог>/node-units.tsv,
#                 строки «start_epoch<TAB>end_epoch<TAB>unit», node-units-extract.py);
#   NIGHT_PREV  — каталог idle-run прошлой ночи для сравнения цен по юнитам.
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

# ── 3.P1-19: нарастание по фоновым часам и цена события ноды (№549) ─────────
# Час — пара снимков (h-1)·PER_H и h·PER_H; его границы во времени берутся из
# первой колонки store-size.tsv (иначе cgroup-mem.tsv). Час НЕ фоновый, если его
# пересекает событие юнита [start, end + P119_GRACE]: хвост — один срез, алерты
# процесса доходят до счётчиков с задержкой агрегации. Час 1 — прогрев после
# рестарта, в фон не идёт (старая метка по той же причине брала час 2).
#
# Нарастание: последний фоновый час L против первого F. Отношение > 1.20 само по
# себе на ночной тишине ничего не значит — фоновые часы ночи H2 несут 3…27
# алертов, и 3 → 10 было бы «×3,3». Поэтому НАРАСТАНИЕ требует ещё и разности
# сверх счётного шума: L − F > 2·√(F + L) (≈ 2σ пуассоновского счёта). Это не
# порог на величину (правило 5.9.6), а различимость, как тренд против остатков
# у 8.1.1; оба числа печатаются.
#
# Цена события: события юнитов, лежащие ближе P119_GRACE, — одно событие ноды
# (unattended-upgrades тянет man-db, snapd, motd-news). Срезы — от последнего
# снимка не позже старта до первого не раньше конца + хвост; цена = три слоя за
# эти срезы минус фон (медиана фоновых часов × длительность). Цена — АЛЕРТОВ;
# к дереву процесса не приписана (снимки метрик дерева не знают): чужой фон
# внутри срезов вычтен медианой, а не исключён.
P119_GRACE="${P119_GRACE:-300}"
UNITS="${NIGHT_UNITS:-$D/node-units.tsv}"
# _p119_slices <каталог idle> — «n epoch выпущено лимитер дедуп старт» по снимкам с временем.
_p119_slices() {
    local s="$1/snapshots" tsf n ts f
    tsf="$s/store-size.tsv"; [ -s "$tsf" ] || tsf="$s/cgroup-mem.tsv"
    [ -s "$tsf" ] || return 0
    awk -F'\t' '$2 ~ /^[0-9]+$/ && !seen[$2]++ { print $2, $1 }' "$tsf" < /dev/null | while read -r n ts; do
        f=$(printf '%s/metrics-%04d.txt' "$s" "$n")
        [ -s "$f" ] || continue
        awk -v n="$n" -v ts="$ts" '
            function ep(t,   y, m, d) {
                if (length(t) != 16 || substr(t, 9, 1) != "T") return -1
                y = substr(t, 1, 4) + 0; m = substr(t, 5, 2) + 0; d = substr(t, 7, 2) + 0
                if (m <= 2) { y--; m += 12 }
                return (365 * y + int(y / 4) - int(y / 100) + int(y / 400) + int((153 * (m - 3) + 2) / 5) + d - 719469) * 86400 \
                    + substr(t, 10, 2) * 3600 + substr(t, 12, 2) * 60 + substr(t, 14, 2)
            }
            /^#/ { next }
            { nm = $1; sub(/\{.*/, "", nm) }
            nm == "ebpf_guard_alerts_total" { e += $NF }
            nm == "ebpf_guard_alerts_ratelimited_by_rule_total" { r += $NF }
            nm == "ebpf_guard_alerts_dedup_dropped_total" { d += $NF }
            nm == "process_start_time_seconds" { st = $NF }
            END { t = ep(ts); if (t >= 0) printf "%d %d %.0f %.0f %.0f %s\n", n, t, e, r, d, (st == "" ? "-" : st) }' "$f" < /dev/null
    done
}
# _p119 <mode> <slices> <units> <per_h> [цены прошлой ночи]
#   mode=report — строки отчёта и вердикт; mode=prices — «unit<TAB>цена<TAB>метка события».
_p119() {
    awk -v mode="$1" -v per="$4" -v grace="$P119_GRACE" -v prevf="${5:-}" '
        function hm(t) { t = t % 86400; return sprintf("%02d:%02d:%02d", int(t / 3600), int(t % 3600 / 60), t % 60) }
        function med(a, n,   i, j, x) {
            for (i = 2; i <= n; i++) { x = a[i]; for (j = i - 1; j >= 1 && a[j] > x; j--) a[j + 1] = a[j]; a[j + 1] = x }
            return (n % 2) ? a[(n + 1) / 2] : (a[n / 2] + a[n / 2 + 1]) / 2
        }
        FILENAME == ARGV[1] { N[$1] = 1; T[$1] = $2; E[$1] = $3; R[$1] = $4; DD[$1] = $5; ST[$1] = $6; if ($1 > last) last = $1; next }
        FILENAME == ARGV[2] {
            if (NF < 3 || $1 !~ /^[0-9]+$/) next
            nu++; us[nu] = $1; ue[nu] = ($2 >= $1 ? $2 : $1); un[nu] = $3; next
        }
        FILENAME == prevf { split($0, f, "\t"); pp[f[1]] = (pp[f[1]] == "" ? "" : pp[f[1]] "; ") f[2] " (" f[3] ")"; next }
        END {
            if (!(0 in N)) { if (mode == "report") print "НЕИЗМЕРИМ: 3.P1-19 НЕИЗМЕРИМ (класс НАЗВАН: у снимков нет времени — store-size.tsv и cgroup-mem.tsv не сняты, час не сопоставить журналу юнитов)"; exit }
            # события ноды: юниты по старту, слитые при зазоре ≤ хвоста
            for (i = 2; i <= nu; i++) for (j = i; j > 1 && us[j - 1] > us[j]; j--) {
                x = us[j]; us[j] = us[j - 1]; us[j - 1] = x; x = ue[j]; ue[j] = ue[j - 1]; ue[j - 1] = x; x = un[j]; un[j] = un[j - 1]; un[j - 1] = x }
            nc = 0
            for (i = 1; i <= nu; i++) {
                if (nc > 0 && us[i] <= ce[nc] + grace) {
                    if (ue[i] > ce[nc]) ce[nc] = ue[i]
                    if (index(" " cu[nc] " ", " " un[i] " ") == 0) cu[nc] = cu[nc] " " un[i]
                } else { nc++; cs[nc] = us[i]; ce[nc] = ue[i]; cu[nc] = un[i] }
            }
            hours = int(last / per)
            nb = 0
            for (h = 1; h <= hours; h++) {
                a = (h - 1) * per; b = h * per
                if (!(a in N) || !(b in N)) { hc[h] = "снимок_пуст"; continue }
                if (ST[a] == "-" || ST[a] != ST[b]) { hc[h] = "рестарт"; continue }
                v = (E[b] - E[a]) + (R[b] - R[a]) + (DD[b] - DD[a]); hv[h] = v
                ev = ""
                for (c = 1; c <= nc; c++) if (cs[c] < T[b] && ce[c] + grace > T[a]) ev = ev (ev == "" ? "" : " ") cu[c]
                if (h == 1)       hc[h] = "прогрев"
                else if (ev != "") hc[h] = "событие[" ev "]"
                else { hc[h] = "фон"; nb++; bh[nb] = h; bv[nb] = v }
            }
            for (i = 1; i <= nb; i++) bm[i] = bv[i]
            bmed = (nb > 0) ? med(bm, nb) : 0
            # цена каждого события
            for (c = 1; c <= nc; c++) {
                pa = -1; pb = -1
                for (n = 0; n <= last; n++) if (n in N) {
                    if (T[n] <= cs[c]) pa = n
                    if (pb < 0 && T[n] >= ce[c] + grace) pb = n
                }
                lbl = hm(cs[c]) "–" hm(ce[c])
                if (pa < 0 || pb < 0) { cp[c] = "вне окна снимков"; cn[c] = ""; continue }
                if (ST[pa] == "-" || ST[pa] != ST[pb]) { cp[c] = "рестарт внутри срезов — неизмеримо"; cn[c] = ""; continue }
                re = E[pb] - E[pa]; rr = R[pb] - R[pa]; rd = DD[pb] - DD[pa]; raw = re + rr + rd
                bg = (nb > 0) ? bmed * (T[pb] - T[pa]) / 3600 : 0
                cn[c] = sprintf("%.0f", raw - bg)
                cp[c] = sprintf("срезы %d…%d (%d с), выпущено %d / лимитер %d / дедуп %d = %d, фон %s → цена %s алертов", pa, pb, T[pb] - T[pa], re, rr, rd, raw, (nb > 0 ? sprintf("≈%.0f", bg) : "не вычтен (фоновых часов нет)"), cn[c])
                # Цена прошлой ночи — цена СОБЫТИЯ, а не юнита: у события из
                # нескольких юнитов это сказано, иначе man-db H3 (310) читался
                # бы против всего unattended-upgrades H2 (16 292).
                if (mode == "prices") { m = split(cu[c], uu, " "); for (k = 1; k <= m; k++) printf "%s\t%s\t%s\n", uu[k], cn[c], lbl (m > 1 ? sprintf(", событие из %d юнитов", m) : "") }
            }
            if (mode == "prices") exit
            hl = ""
            for (h = 1; h <= hours; h++) hl = hl sprintf("%s%d %s%s", (h > 1 ? "; " : ""), h, hc[h], (h in hv ? " " hv[h] : ""))
            printf "  3.P1-19: часы (объём — сумма трёх слоёв, АЛЕРТОВ): %s\n", hl
            if (nu == 0) printf "  3.P1-19: стартов юнитов ноды за окно 0 (журнал снят, но пуст — на ноде с apt/logrotate это само по себе подозрительно)\n"
            for (c = 1; c <= nc; c++) {
                prev = ""
                if (prevf != "") {
                    m = split(cu[c], uu, " ")
                    for (k = 1; k <= m; k++) prev = prev sprintf("%s%s=%s", (k > 1 ? ", " : ""), uu[k], (uu[k] in pp ? pp[uu[k]] : "нет"))
                    prev = "; прошлая ночь: " prev
                } else prev = "; прошлая ночь не задана (NIGHT_PREV)"
                printf "  3.P1-19: цена события ноды %s [%s]: %s%s\n", hm(cs[c]) "–" hm(ce[c]), cu[c], cp[c], prev
            }
            if (nb < 2) {
                printf "НЕИЗМЕРИМ: 3.P1-19 НЕИЗМЕРИМ (класс НАЗВАН: фоновых часов %d — нарастанию нужно не меньше двух часов без стартов юнитов ноды; таймерные часы метку не решают)\n", nb
                exit
            }
            F = bv[1]; L = bv[nb]
            ratio = (F > 0) ? sprintf("%.3f", L / F) : "не определено (первый фоновый час 0)"
            noise = 2 * sqrt(F + L)
            grow = (L > 1.2 * F) && (L - F > noise)
            tail = sprintf("последний фоновый час %d = %d алертов против первого %d = %d, отношение %s, разность %+d против счётного шума 2·√(F+L) = %.1f; фоновых часов %d, медиана %.0f; сумма трёх слоёв", bh[nb], L, bh[1], F, ratio, L - F, noise, nb, bmed)
            if (grow)                  printf "ПРОВАЛЕН: 3.P1-19 ПРОВАЛЕН (класс НАРАСТАНИЕ: %s — шум фона нарастает)\n", tail
            else if (L > 1.2 * F)      printf "ДОСТИГНУТО: 3.P1-19 ДОСТИГНУТО (класс ПЛАТО — рост в пределах счётного шума: %s)\n", tail
            else                       printf "ДОСТИГНУТО: 3.P1-19 ДОСТИГНУТО (класс ПЛАТО: %s)\n", tail
        }' "$2" "$3" ${5:+"$5"} < /dev/null
}
if [ ! -f "$UNITS" ]; then
    echo "НЕИЗМЕРИМ: 3.P1-19 НЕИЗМЕРИМ (класс НАЗВАН: журнал стартов юнитов ноды не снят — нет $UNITS; без него час таймера неотличим от фонового)"
else
    # Во временный файл вне архива: эмиттер реплеится по чужим каталогам и
    # писать в них не вправе.
    P119_TMP=$(mktemp); _p119_slices "$D" > "$P119_TMP"
    prevp=""
    if [ -n "${NIGHT_PREV:-}" ]; then
        if [ -f "$NIGHT_PREV/node-units.tsv" ]; then
            prevs=$(mktemp); prevp=$(mktemp)
            _p119_slices "$NIGHT_PREV" > "$prevs"
            _p119 prices "$prevs" "$NIGHT_PREV/node-units.tsv" "$PER_H" > "$prevp"
            rm -f "$prevs"
        else
            echo "  3.P1-19: прошлая ночь $NIGHT_PREV без node-units.tsv — цены не сравниваются"
        fi
    fi
    _p119 report "$P119_TMP" "$UNITS" "$PER_H" "$prevp"
    rm -f "$P119_TMP" ${prevp:+"$prevp"}
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
    # Класс считает ЭМИТТЕР, и считает ПО ВСЕМ СРЕЗАМ, а не по двум точкам на
    # границах часов. Первая версия брала anon на часах 1, 4, hours-3 и hours и
    # сравнивала две разности — на пиле это даёт класс, противоположный данным:
    # ночь №4 напечатала «НАКОПЛЕНИЕ (+1.0 против +3.0 МиБ)» на траектории,
    # которая КОНЧИЛА НИЖЕ, чем начала (129.0 → 128.5 МиБ при размахе 7.7 и пяти
    # разворотах знака). Обе точки просто попали: час 1 около впадины, час 8
    # около гребня (находка №524).
    #
    # Поэтому класс даёт тренд ПРОТИВ ОСТАТОЧНОГО разброса: наклон МНК по всем
    # срезам после часа прогрева, умноженный на длину окна, сравнивается с
    # размахом ОСТАТКОВ вокруг линии тренда. Сравнивать с полным размахом нельзя
    # — у монотонного роста размах РАВЕН тренду, и класс «НАКОПЛЕНИЕ» стал бы
    # недостижим по построению (поймано фикстурой линейного роста сразу после
    # первой починки). Остаток же у монотонного роста около нуля, а у пилы —
    # вся её амплитуда. Это не порог на величину (правило 5.9.6), а требование,
    # чтобы тренд был различим на фоне собственного шума сигнала; все числа
    # печатаются рядом, чтобы вердикт пересчитывался руками.
    # Ступенька (07.10.2026, ночь H). Скачок anon за ОДИН срез больше
    # max(5 МиБ, 4 × средний |Δ| ночи) — событие ноды (обновление пакетов,
    # всплеск потока), а не траектория; на пиле ночи №4 |Δ| ≤ 1,1 МиБ, на
    # линейном росте фикстуры 0,35. Ряд режется по ступенькам, класс считается
    # по САМОМУ ДЛИННОМУ участку без них, ступеньки печатаются поимённо с
    # уровнем на конец окна — это вход 8.2, а не класс 8.1.
    awk -F'\t' -v per="$PER_H" -v hours="$hours" -v lim="$CHART_LIMIT" '
        NR > 1 && $2 ~ /^[0-9]+$/ {
            n = $2 + 0
            if ($3 + 0 > pk) { pk = $3 + 0; pkn = n }
            mx = $10
            if (n < per) next            # час 1 — прогрев после рестарта
            K++; X[K] = n; Y[K] = $4 / 1048576
        }
        END {
            if (K < 12) {
                printf "НЕИЗМЕРИМ: 8.1.1 НЕИЗМЕРИМ (класс НАЗВАН: срезов cgroup после часа прогрева %d — наклону нужно не меньше часа точек); пик memory.current %.1f МиБ\n", K, pk / 1048576
                exit
            }
            for (i = 2; i <= K; i++) { d = Y[i] - Y[i-1]; sad += (d < 0 ? -d : d) }
            stepmin = 4 * sad / (K - 1); if (stepmin < 5) stepmin = 5
            nsteps = 0; steps = ""; bs = 1; best_s = 1; best_e = 0
            for (i = 2; i <= K + 1; i++) {
                isstep = 0
                if (i <= K) { d = Y[i] - Y[i-1]; isstep = (d > stepmin || d < -stepmin) }
                if (i > K || isstep) {
                    if (i - bs > best_e - best_s + 1) { best_s = bs; best_e = i - 1 }
                    if (isstep) {
                        nsteps++
                        steps = steps sprintf("%sсрез %d: %+.1f МиБ", (nsteps > 1 ? ", " : ""), X[i], d)
                        bs = i
                    }
                }
            }
            k = 0
            for (i = best_s; i <= best_e; i++) { k++; x[k] = X[i]; y[k] = Y[i] }
            if (k < 12) {
                printf "НЕИЗМЕРИМ: 8.1.1 НЕИЗМЕРИМ (класс НАЗВАН: ступенек %d (%s), самый длинный участок без них — %d срезов, наклону нужно не меньше часа точек); пик memory.current %.1f МиБ\n", nsteps, steps, k, pk / 1048576
                exit
            }
            for (i = 1; i <= k; i++) {
                if (i == 1 || y[i] > ymax) ymax = y[i]
                if (i == 1 || y[i] < ymin) ymin = y[i]
            }
            for (i = 1; i <= k; i++) { sx += x[i]; sy += y[i]; sxy += x[i] * y[i]; sxx += x[i] * x[i] }
            slope = (k * sxy - sx * sy) / (k * sxx - sx * sx)   # МиБ на срез
            inter = (sy - slope * sx) / k
            per_h = slope * per
            span = x[k] - x[1]
            trend = slope * span                                 # МиБ за окно
            band = ymax - ymin                                   # полный размах
            net = y[k] - y[1]
            for (i = 1; i <= k; i++) {
                r = y[i] - (slope * x[i] + inter)
                if (i == 1 || r > rmax) rmax = r
                if (i == 1 || r < rmin) rmin = r
            }
            resid = rmax - rmin                                  # размах остатков
            # Прогрев от накопления отличает ЗАМЕДЛЕНИЕ, а линия его не видит:
            # у насыщающейся кривой остатки тоже малы, и один лишь тест
            # «тренд против остатков» назвал бы её накоплением (поймано
            # фикстурой прогрева). Поэтому считаются наклоны половин окна.
            h = int(k / 2)
            for (i = 1; i <= h; i++)      { ax += x[i]; ay += y[i]; axy += x[i] * y[i]; axx += x[i] * x[i]; an1++ }
            for (i = h + 1; i <= k; i++)  { bx += x[i]; by += y[i]; bxy += x[i] * y[i]; bxx += x[i] * x[i]; bn++ }
            s1 = (an1 * axy - ax * ay) / (an1 * axx - ax * ax) * per
            s2 = (bn * bxy - bx * by) / (bn * bxx - bx * bx) * per
            turns = 0; prev = 0
            for (i = 2; i <= k; i++) {
                d = y[i] - y[i-1]
                s = (d > 0.05) ? 1 : ((d < -0.05) ? -1 : 0)
                if (s != 0 && prev != 0 && s != prev) turns++
                if (s != 0) prev = s
            }
            word = "ДОСТИГНУТО"
            if (trend <= 0)          cls = "ПЛАТО (тренда вверх нет)"
            else if (trend <= resid) cls = "ПЛАТО/колебание (тренд за окно меньше разброса остатков, накоплением не называется)"
            else if (s2 <= s1 / 2)   cls = "ПРОГРЕВ (рост замедляется: наклон второй половины вдвое с лишним ниже первой)"
            else                   { cls = "НАКОПЛЕНИЕ (тренд больше разброса остатков и не замедляется)"; word = "ПРОВАЛЕН" }
            if (nsteps == 0) stepnote = "ступенек нет"
            else stepnote = sprintf("ступенек %d (%s; порог скачка %.1f МиБ за срез) — класс считан по участку срезов %d…%d, уровень anon на конец окна %.1f МиБ против %.1f на конце участка; ступенька — вход 8.2, не класс", nsteps, steps, stepmin, x[1], x[k], Y[K], y[k])
            over = (pk - lim) / 1048576
            printf "%s: 8.1.1 %s (класс %s; anon после прогрева: наклон %+.2f МиБ/ч, тренд за окно %+.1f МиБ против разброса остатков %.1f МиБ (полный размах %.1f), чистое изменение %+.1f МиБ, разворотов знака %d, точек %d; наклоны половин %+.2f и %+.2f МиБ/ч; %s; пик memory.current %.1f МиБ на срезе %d против лимита чарта 256.0 МиБ — %s %.1f МиБ (судит 8.2); memory.max cgroup стенда = %s; порог не назначается, правило 5.9.6)\n", \
                word, word, cls, per_h, trend, resid, band, net, turns, k, s1, s2, stepnote, pk / 1048576, pkn, (over > 0 ? "перебор" : "запас"), (over > 0 ? over : -over), mx
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

# ── 8.1.3: CPU на событие за ночь (пункт 3 критерия выхода волны 8.1) ──
# База — 226 мкс/событие ночи №3, разброс срезов той ночи ±9%. Величину считает
# ЭМИТТЕР одной формулой для любой ночи: Δprocess_cpu_seconds_total /
# Δevents_total между первым и последним снимком ([[verdict-input-must-be-computed-by-emitter]]).
# ДОСТИГНУТО — сдвиг вниз больше разброса базы (≤ 205,7 мкс); меньше — правки
# волны от нуля не отличимы, ПРОВАЛЕН. Рядом печатается доля ядра против
# 28,6% ночи №3: после item 11 (сброс read/write без пути) уходят ДЕШЁВЫЕ
# события, и CPU на событие растёт при вдвое меньшем CPU в целом.
c0=$(awk '/^process_cpu_seconds_total /{print $2}' "$f0" 2>/dev/null)
cN=$(awk '/^process_cpu_seconds_total /{print $2}' "$fN" 2>/dev/null)
e0=$(_val "$f0" ebpf_guard_events_total); eN=$(_val "$fN" ebpf_guard_events_total)
if [ -z "$st0" ] || [ "$st0" != "$stN" ]; then
    echo "НЕИЗМЕРИМ: 8.1.3 НЕИЗМЕРИМ (класс НАЗВАН: рестарт агента между первым и последним снимком)"
elif [ -z "$c0" ] || [ -z "$cN" ] || [ -z "$e0" ] || [ -z "$eN" ]; then
    echo "НЕИЗМЕРИМ: 8.1.3 НЕИЗМЕРИМ (класс НАЗВАН: нет серии process_cpu_seconds_total или ebpf_guard_events_total в первом/последнем снимке)"
else
    awk -v c0="$c0" -v cN="$cN" -v e0="$e0" -v eN="$eN" -v secs="$(( ${last:-0} * INTERVAL ))" 'BEGIN {
        core = (secs > 0) ? sprintf("; доля ядра %.1f%% против 28,6%% ночи №3", 100 * (cN - c0) / secs) : ""
        de = eN - e0; dc = cN - c0
        if (de <= 0 || dc < 0) { printf "НЕИЗМЕРИМ: 8.1.3 НЕИЗМЕРИМ (класс НАЗВАН: событий за ночь %d, CPU %+.1f с)\n", de, dc; exit }
        us = 1e6 * dc / de
        if (us <= 226 * 0.91)
            printf "ДОСТИГНУТО: 8.1.3 ДОСТИГНУТО (CPU на событие %.1f мкс против базы 226 мкс ночи №3, сдвиг %+.0f%% за пределами разброса базы ±9%%; CPU %.0f с на %d событий%s)\n", us, 100 * (us - 226) / 226, dc, de, core
        else
            printf "ПРОВАЛЕН: 8.1.3 ПРОВАЛЕН (CPU на событие %.1f мкс против базы 226 мкс, сдвиг %+.0f%% в пределах разброса ±9%% или выше — от нуля не отличим%s)\n", us, 100 * (us - 226) / 226, core
    }' < /dev/null
fi

# ── 8.1.4: ось file.op жива (item 7: unlink/rename/truncate/rmdir) ──
# Продюсер оси предъявляется событиями за ночь, а не конфигом: на любой ноде с
# постоянным журналом systemd-journald делает ftruncate (зонд Ц1 волны 7 — 34/мин).
# Нет серии — бинарь без прибора, НЕИЗМЕРИМ; хуки не привязались — ПРОВАЛЕН.
m0=0; mN=0; seen=""
for op in unlink rename truncate rmdir; do
    a=$(_val "$f0" ebpf_guard_file_events_by_op_total "op=\"$op\""); b=$(_val "$fN" ebpf_guard_file_events_by_op_total "op=\"$op\"")
    [ -n "$b" ] && seen=1
    m0=$(( m0 + ${a:-0} )); mN=$(( mN + ${b:-0} ))
done
hooks_ok=$(awk '/^ebpf_guard_file_hook_attach_total\{/ && /result="ok"/ && /hook="sys_enter_(unlink|unlinkat|rmdir|truncate|ftruncate|rename|renameat|renameat2)"/ && $NF > 0 { n++ } END { print n + 0 }' "$fN" 2>/dev/null)
if [ -z "$st0" ] || [ "$st0" != "$stN" ]; then
    echo "НЕИЗМЕРИМ: 8.1.4 НЕИЗМЕРИМ (класс НАЗВАН: рестарт агента между первым и последним снимком)"
elif [ -z "$seen" ]; then
    echo "НЕИЗМЕРИМ: 8.1.4 НЕИЗМЕРИМ (класс НАЗВАН: серии ebpf_guard_file_events_by_op_total нет — бинарь без прибора оси, нет серии ≠ 0)"
elif [ "${hooks_ok:-0}" -eq 0 ]; then
    echo "ПРОВАЛЕН: 8.1.4 ПРОВАЛЕН (ни один из восьми хуков unlink/rename/truncate/rmdir не привязан — правила оси file.op немы)"
elif [ $(( mN - m0 )) -le 0 ]; then
    echo "ПРОВАЛЕН: 8.1.4 ПРОВАЛЕН (хуков привязано $hooks_ok из 8, но событий оси за ночь 0 — продюсер не доказан)"
else
    echo "ДОСТИГНУТО: 8.1.4 ДОСТИГНУТО (событий unlink/rename/truncate/rmdir за ночь $(( mN - m0 )); хуков привязано $hooks_ok из 8)"
fi
