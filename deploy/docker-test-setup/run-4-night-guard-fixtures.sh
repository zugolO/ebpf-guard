#!/bin/bash
# Фикстуры сторожа полноты меток ночи №4 (этап D волны 8.1).
#
# Таблица меток и цикл ВЫРЕЗАЮТСЯ из run-4-night-pipeline.sh между GUARD-BEGIN и
# GUARD-END и исполняются как есть: сторож с не совпадающей регуляркой печатает
# «0 расхождений» на любом отчёте, то есть делает критерий недостижимым и при
# этом выглядит зелёным ([[verdict-line-that-can-only-say-unmeasurable]]).
# Отчёт берётся НАСТОЯЩИЙ — его печатает night-report.sh по синтетической ночи,
# а не пишется руками: сторож, проверенный на выдуманном тексте, знает форму
# строки, которой в живом логе нет ([[self-test-fixtures-miss-live-log-shape]]).
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
FAIL=0
ok()  { echo "  OK    $*"; }
bad() { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); }

awk '/# GUARD-BEGIN/ { p = 1; next } /# GUARD-END/ { exit } p' "$HERE/run-4-night-pipeline.sh" > "$T/guard.sh"
grep -q 'REQUIRED_LABELS=' "$T/guard.sh" || { echo "  FAIL  таблица меток не вырезана (маркеры GUARD-BEGIN/END переехали)"; exit 1; }
grep -q 'label_completeness()' "$T/guard.sh" || { echo "  FAIL  функция сторожа не вырезана"; exit 1; }
source "$T/guard.sh"
echo "[вырезано ${#REQUIRED_LABELS[@]} меток: ${REQUIRED_LABELS[*]}]"

# Настоящая ночь: 9 часов, cgroup и очереди на месте — отчёт обязан вынести все метки.
bash "$HERE/night-report-fixtures.sh" >/dev/null 2>&1   # смок самого эмиттера
mkdir -p "$T/n/snapshots"
# Синтетическую ночь строит та же функция, что и фикстуры эмиттера: _night живёт
# в night-report-fixtures.sh, поэтому вызываем его собственным путём.
# С 09.10.2026 _night зовёт _FIX_T0/_fix_ts (время снимков для 3.P1-19) —
# вырезаются вместе с ней, иначе синтетическая ночь без времени и 3.P1-19
# зеленеет НЕИЗМЕРИМОМ, а не вердиктом.
awk '/^_FIX_T0=/ { p = 1 } p { print } p && $0 == "}" && seen_night { exit } /^_night\(\) \{/ { seen_night = 1 }' "$HERE/night-report-fixtures.sh" > "$T/night.sh"
grep -q '^_night() {' "$T/night.sh" || { bad "_night не вырезан из фикстур эмиттера"; exit 1; }
grep -q '^_fix_ts() {' "$T/night.sh" || { bad "_fix_ts не вырезан из фикстур эмиттера"; exit 1; }
source "$T/night.sh"
_night "$T/n" 9 120 0 600 cg=plateau
bash "$HERE/night-report.sh" "$T/n" 300 > "$T/report.txt" 2>&1

grep -q '^ДОСТИГНУТО: 3.P1-19' "$T/report.txt" && ok "синтетическая ночь даёт 3.P1-19 вердиктом, не НЕИЗМЕРИМОМ" \
    || bad "синтетическая ночь: 3.P1-19 без вердикта ($(grep -a '3.P1-19' "$T/report.txt" | tail -1 | cut -c1-120))"
m=$(label_completeness "$T/report.txt")
[ -z "$m" ] && ok "полный отчёт — расхождений нет (все ${#REQUIRED_LABELS[@]} меток найдены)" \
            || bad "полный отчёт, а сторож не нашёл:$m"

# Каждая метка по очереди вымарывается из отчёта: сторож обязан назвать именно её.
for lbl in "${REQUIRED_LABELS[@]}"; do
    grep -av -- "$lbl" "$T/report.txt" > "$T/cut.txt"
    m=$(label_completeness "$T/cut.txt")
    case " $m " in
        *" $lbl "*) ok "метка $lbl вымарана — сторож её назвал" ;;
        *)          bad "метка $lbl вымарана, а сторож молчит (нашёл:${m:-ничего})" ;;
    esac
done

# Освобождение по моменту доставки (LABELS_SINCE): обе половины кодом
# ([[label-since-day-granularity-frees-first-run]]).
grep -av -- '8.1.3' "$T/report.txt" > "$T/no813.txt"
m=$(label_completeness "$T/no813.txt" "2026-10-03T19:18:59Z")
case " $m " in *" 8.1.3 "*) bad "прогон ночи №4 (до доставки 8.1.3) не освобождён: $m" ;; *) ok "прогон до момента доставки — 8.1.3 освобождена" ;; esac
case "$(label_exempt "2026-10-03T19:18:59Z")" in *"8.1.3(с "*) ok "освобождение напечатано вслух" ;; *) bad "освобождение не названо" ;; esac
m=$(label_completeness "$T/no813.txt" "2026-10-09T22:58:00Z")
case " $m " in *" 8.1.3 "*) ok "прогон после момента доставки — 8.1.3 требуется" ;; *) bad "прогон после доставки освобождён: ${m:-ничего}" ;; esac
m=$(label_completeness "$T/no813.txt")
case " $m " in *" 8.1.3 "*) ok "без старта прогона — 8.1.3 требуется (закрытый отказ)" ;; *) bad "без старта освобождён: ${m:-ничего}" ;; esac
grep -av -- '3.P1-19' "$T/report.txt" > "$T/no119.txt"
m=$(label_completeness "$T/no119.txt" "2026-10-03T19:18:59Z")
case " $m " in *" 3.P1-19 "*) ok "3.P1-19 освобождения не имеет — требуется и у старого прогона" ;; *) bad "3.P1-19 освобождена: ${m:-ничего}" ;; esac
# Настоящие архивы ночей: каждый своим отчётом и своим стартом (если лежат рядом).
for a in "$HERE"/../../server-logs/collect-4-night "$HERE"/../../server-logs/collect-8.1-H/night-8.1H "$HERE"/../../server-logs/collect-8.1-H2/night-8.1H2; do
    [ -f "$a/night-report.txt" ] || continue
    st=$(cat "$a"/agent-start-*.txt 2>/dev/null | head -1)
    m=$(label_completeness "$a/night-report.txt" "$st")
    [ -z "$m" ] && ok "архив $(basename "$a") (старт $st) — своим отчётом полон" || bad "архив $(basename "$a") красный:$m"
done

# Ложный PASS: слово вердикта есть, а метки нет — сторож не вправе зачесть.
printf 'ДОСТИГНУТО: что-то ДОСТИГНУТО (величина 0)\n' > "$T/vacuum.txt"
m=$(label_completeness "$T/vacuum.txt")
# wc -w на BSD выравнивает пробелами — число берётся через арифметику, а не
# сравнением строк, иначе фикстура красит сторож за формат чужой утилиты.
[ "$(( $(printf '%s' "$m" | wc -w) ))" = "${#REQUIRED_LABELS[@]}" ] \
    && ok "отчёт без меток — все ${#REQUIRED_LABELS[@]} названы отсутствующими" \
    || bad "отчёт без меток зачтён частично: ${m:-ничего}"

echo
[ "$FAIL" -eq 0 ] && { echo "run-4-night-guard-fixtures: расхождений 0"; exit 0; }
echo "run-4-night-guard-fixtures: ЕСТЬ РАСХОЖДЕНИЯ ($FAIL)"; exit 1
