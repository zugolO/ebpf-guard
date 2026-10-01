#!/usr/bin/env bash
# w7-pair-report.sh <архив A> <архив B> <порция> — ОДНО чтение результата пары A/B порции
# оси `nr`, одним кодом для всех порций (раньше величины выписывались руками и
# расходились: правило 2 постановки, №515 — объём правила есть СУММА ТРЁХ СЛОЁВ).
#
# Печатает:
#   1. цену в СОБЫТИЯХ — дельту собственной оси {nr=…} за окно по каждому открываемому
#      номеру роли B (из манифеста АРХИВА, не дерева) и сумму оси на обеих ролях;
#   2. объём АЛЕРТОВ по правилам порции СУММОЙ ТРЁХ СЛОЁВ: выпущено + срез лимитера +
#      срез дедупа, с переименованиями Rego (серия alert_rule_id_renamed_total);
#   3. ПОСЛЕДСТВИЕ объёма на обеих ролях (единица судит последствием, порога нет,
#      [[event-price-is-judged-by-consequence-not-threshold]]): дропы событий
#      БЕЗ path_denylist и С ним (denylist — проектное ядерное отсечение, оно было
#      «+695» у обеих половин порции 3 и ничего не значит для цены) и аллокации Go;
#   4. вердиктные строки меток 6.6.9 и 6.7.1 из run-6.4.log обеих ролей.
# Окно — W7_WINDOW (умолчание 600 с). Читает ТОЛЬКО файлы архивов.
set -u
A="${1:?архив роли A}"; B="${2:?архив роли B}"; POR="${3:?порция}"
WIN="${W7_WINDOW:-600}"
ART() { echo "$1/controls/artifacts"; }
for d in "$A" "$B"; do
    for f in metrics-window-start.txt metrics-window-end.txt wave7-nr-portions.txt; do
        [ -s "$(ART "$d")/$f" ] || { echo "class=нет_входа_${f}_в_$(basename "$d")"; exit 0; }
    done
done
MAN="$(ART "$B")/wave7-nr-portions.txt"

echo "== порция $POR: пара $(basename "$A") / $(basename "$B"), окно ${WIN} с =="
NRS=$(awk -v p="P$POR" '$1 == p && $2 == "NR" { n[$3] = 1 } $1 == p && $2 == "REJECTED" { r[$3] = 1 } END { for (k in n) if (!(k in r)) print k }' "$MAN" | sort -n | tr '\n' ' ')
REJ=$(awk -v p="P$POR" '$1 == p && $2 == "REJECTED" { print $3 }' "$MAN" | sort -n | tr '\n' ' ')
RULES=$(awk -v p="P$POR" '$1 == p && $2 == "RULE" { print $3 }' "$MAN" | tr '\n' ' ')
echo "открываются: ${NRS:-—} | отвергнуты (не открывались): ${REJ:-—} | правила порции: ${RULES:-—}"

echo "-- 1. цена в СОБЫТИЯХ (дельта оси {nr} за окно) --"
for role in A B; do
    d=$A; [ "$role" = B ] && d=$B
    awk -v role="$role" -v nrs="$NRS" '
        FNR == 1 { f++ }
        index($1, "ebpf_guard_syscall_events_by_nr_total{nr=\"") == 1 {
            v = $1; sub(/.*nr="/, "", v); sub(/".*/, "", v); val[f, v] = $NF + 0; seen[v] = 1
        }
        END {
            n = split(nrs, a, " ")
            for (k in seen) { tot += val[2, k] - val[1, k] }
            printf "  роль %s: сумма оси за окно = %d; ", role, tot
            for (i = 1; i <= n; i++) printf "nr=%s:%s ", a[i], ((a[i] in seen) ? val[2, a[i]] - val[1, a[i]] : "нет-в-оси")
            printf "\n"
        }' "$(ART "$d")/metrics-window-start.txt" "$(ART "$d")/metrics-window-end.txt"
done

echo "-- 2. объём АЛЕРТОВ по правилам порции, СУММА ТРЁХ СЛОЁВ (роль B) --"
awk -v rules="$RULES" -v win="$WIN" '
    BEGIN { n = split(rules, a, " "); for (i = 1; i <= n; i++) want[a[i]] = 1 }
    FNR == 1 { f++ }
    function rid(s,   r) { r = s; sub(/.*rule_id="/, "", r); sub(/".*/, "", r); return r }
    index($1, "ebpf_guard_alert_rule_id_renamed_total{") == 1 {
        b = $1; sub(/.*base_rule_id="/, "", b); sub(/".*/, "", b)
        r = $1; sub(/.*,rule_id="/, "", r); sub(/".*/, "", r)
        if (b in want && r != b) ren[r] = b
    }
    index($1, "ebpf_guard_alert_volume_by_event_type_total{") == 1 && index($0, "event_type=\"syscall\"") > 0 { rel[f, rid($1)] = $NF + 0; ids[rid($1)] = 1 }
    index($1, "ebpf_guard_alerts_ratelimited_by_rule_total{") == 1 { lim[f, rid($1)] = $NF + 0; ids[rid($1)] = 1 }
    index($1, "ebpf_guard_alerts_dedup_dropped_by_rule_total{") == 1 { ded[f, rid($1)] = $NF + 0; ids[rid($1)] = 1 }
    END {
        for (k in ids) {
            base = (k in want) ? k : ((k in ren) ? ren[k] : "")
            if (base == "") continue
            R[base] += rel[2, k] - rel[1, k]; L[base] += lim[2, k] - lim[1, k]; D[base] += ded[2, k] - ded[1, k]
            names[base] = 1
        }
        m = 0
        for (b in want) {
            tot = R[b] + L[b] + D[b]
            printf "  %-34s выпущено %d + лимитер %d + дедуп %d = %d за окно = %d/ч\n", b, R[b], L[b], D[b], tot, tot * 3600.0 / win
            T += tot
        }
        printf "  ИТОГО по правилам порции: %d за окно = %d/ч\n", T, T * 3600.0 / win
    }' "$(ART "$B")/metrics-window-start.txt" "$(ART "$B")/metrics-window-end.txt"

echo "-- 3. ПОСЛЕДСТВИЕ объёма (обе роли) --"
for role in A B; do
    d=$A; [ "$role" = B ] && d=$B
    awk -v role="$role" '
        FNR == 1 { f++ }
        /^ebpf_guard_(events|event_queue)_dropped/ { all[f] += $NF; if ($1 !~ /path_denylist/) real[f] += $NF }
        /^go_memstats_alloc_bytes_total / { al[f] = $2 }
        END { printf "  роль %s: дропы событий БЕЗ path_denylist %+d, С ним %+d; аллокации Go за окно %.3f ГБ\n", role, real[2] - real[1], all[2] - all[1], (al[2] - al[1]) / 1e9 }' \
        "$(ART "$d")/metrics-window-start.txt" "$(ART "$d")/metrics-window-end.txt"
done
ba=$(awk '/^go_memstats_alloc_bytes_total /{print $2}' "$(ART "$A")/metrics-window-end.txt"); sa=$(awk '/^go_memstats_alloc_bytes_total /{print $2}' "$(ART "$A")/metrics-window-start.txt")
bb=$(awk '/^go_memstats_alloc_bytes_total /{print $2}' "$(ART "$B")/metrics-window-end.txt"); sb=$(awk '/^go_memstats_alloc_bytes_total /{print $2}' "$(ART "$B")/metrics-window-start.txt")
awk -v a="$ba" -v sa="$sa" -v b="$bb" -v sb="$sb" 'BEGIN { if ((a - sa) > 0) printf "  аллокации B относительно A: %+.2f%%\n", ((b - sb) / (a - sa) - 1) * 100 }'

echo "-- 4. вердиктные строки меток --"
for role in A B; do
    d=$A; [ "$role" = B ] && d=$B
    for l in "6\\.6\\.9" "6\\.7\\.1"; do
        line=$(grep -a -E "(^|[^0-9.])${l}[[:space:]]+(ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО)" "$d/run-6.4.log" 2>/dev/null | grep -avE "фикстура|реплей" | tail -1)
        if [ -n "$line" ]; then echo "  роль $role ${l//\\/}: $(printf '%s' "$line" | sed 's/^[[:space:]]*//' | cut -c1-230)"; else echo "  роль $role ${l//\\/}: метки в логе нет"; fi
    done
done
