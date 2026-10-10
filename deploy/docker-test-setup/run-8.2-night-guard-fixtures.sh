#!/bin/bash
# Фикстуры сторожа полноты меток ночи закрытия 8.2 (run-8.2-night-pipeline.sh).
#
# Блок сторожа ВЫРЕЗАЕТСЯ из пайплайна между GUARD-BEGIN и GUARD-END и
# исполняется как есть. Отчёты — НАСТОЯЩИЕ: night-report.sh по синтетической
# ночи (функция _night из его фикстур) и w82-close-report.sh по случаю «ок» его
# фикстур, склеенные так же, как в пайплайне (all-reports.txt).
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
FAIL=0
ok()  { echo "  OK    $*"; }
bad() { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); }

awk '/# GUARD-BEGIN/ { p = 1; next } /# GUARD-END/ { exit } p' "$HERE/run-8.2-night-pipeline.sh" > "$T/guard.sh"
grep -q 'REQUIRED_LABELS=' "$T/guard.sh" || { echo "  FAIL  таблица меток не вырезана"; exit 1; }
grep -q 'label_completeness()' "$T/guard.sh" || { echo "  FAIL  функция сторожа не вырезана"; exit 1; }
source "$T/guard.sh"
echo "[вырезано ${#REQUIRED_LABELS[@]} меток: ${REQUIRED_LABELS[*]}]"

# Отчёт хоста — night-report.sh по синтетической ночи (как run-4-night-guard-fixtures.sh).
awk '/^_FIX_T0=/ { p = 1 } p { print } p && $0 == "}" && seen_night { exit } /^_night\(\) \{/ { seen_night = 1 }' \
    "$HERE/night-report-fixtures.sh" > "$T/night.sh"
grep -q '^_night() {' "$T/night.sh" || { bad "_night не вырезан из фикстур night-report"; exit 1; }
source "$T/night.sh"
mkdir -p "$T/n/snapshots"
_night "$T/n" 9 120 0 600 cg=plateau
bash "$HERE/night-report.sh" "$T/n" 300 > "$T/night-report.txt" 2>&1

# Отчёт 8.2 — w82-close-report.sh по случаю «ок» его фикстур (mkcase вырезается).
sed -n '/^samples() {/,/^run() /p' "$HERE/w82-close-report-fixtures.sh" | sed '$d' > "$T/close.sh"
grep -q '^mkcase() {' "$T/close.sh" || { bad "mkcase не вырезан из фикстур close-report"; exit 1; }
source "$T/close.sh"
mkcase ok
RUN="$T/ok/run" ATT="$T/ok/att" INV="" GATE="$T/ok/gate.txt" A2="$T/ok/a2.txt" \
    bash "$HERE/w82-close-report.sh" > "$T/close-report.txt" 2>&1
cat "$T/night-report.txt" "$T/close-report.txt" > "$T/all.txt"

m=$(label_completeness "$T/all.txt" "2026-10-12T22:00:00Z")
[ -z "$m" ] && ok "полный отчёт — все ${#REQUIRED_LABELS[@]} меток найдены" || bad "полный отчёт, а сторож не нашёл:$m"
m=$(label_completeness "$T/night-report.txt" "2026-10-12T22:00:00Z")
case " $m " in *" 8.2.1 "*" 8.2.5 "*) ok "без отчёта 8.2 — метки 8.2.x названы отсутствующими" ;; *) bad "без отчёта 8.2 сторож молчит: ${m:-ничего}" ;; esac

for lbl in "${REQUIRED_LABELS[@]}"; do
    grep -avF -- "$lbl " "$T/all.txt" > "$T/cut.txt"
    m=$(label_completeness "$T/cut.txt" "2026-10-12T22:00:00Z")
    case " $m " in
        *" $lbl "*) ok "метка $lbl вымарана — сторож её назвал" ;;
        *)          bad "метка $lbl вымарана, а сторож молчит (нашёл:${m:-ничего})" ;;
    esac
done

# Точка в метке — литерал: «8x2x1» не засчитывается за 8.2.1.
grep -avF -- '8.2.1 ' "$T/all.txt" > "$T/dot.txt"; echo 'ДОСТИГНУТО: 8x2x1 ДОСТИГНУТО' >> "$T/dot.txt"
m=$(label_completeness "$T/dot.txt")
case " $m " in *" 8.2.1 "*) ok "точка в метке — литерал" ;; *) bad "«8x2x1» зачтена за 8.2.1" ;; esac

echo
[ "$FAIL" -eq 0 ] && { echo "run-8.2-night-guard-fixtures: расхождений 0"; exit 0; }
echo "run-8.2-night-guard-fixtures: ЕСТЬ РАСХОЖДЕНИЯ ($FAIL)"; exit 1
