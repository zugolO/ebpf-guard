#!/bin/bash
# Фикстуры сторожа полноты меток ночи закрытия 8.5 (run-8.5-night-pipeline.sh).
#
# Блок сторожа ВЫРЕЗАЕТСЯ из пайплайна между GUARD-BEGIN и GUARD-END и исполняется как есть.
# Отчёты — НАСТОЯЩИЕ: night-report.sh по синтетической ночи, w82-close-report.sh по случаю «ок»
# его фикстур, w85-close-report.sh (flow, anomaly-hour, ab, controls, d1) по случаям «хорошо» своих
# фикстур и вердиктная строка A1 из настоящего go test, склеенные так же, как в пайплайне.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
FAIL=0
ok()  { echo "  OK    $*"; }
bad() { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); }

awk '/# GUARD-BEGIN/ { p = 1; next } /# GUARD-END/ { exit } p' "$HERE/run-8.5-night-pipeline.sh" > "$T/guard.sh"
grep -q 'REQUIRED_LABELS=' "$T/guard.sh" || { echo "  FAIL  таблица меток не вырезана"; exit 1; }
grep -q 'label_completeness()' "$T/guard.sh" || { echo "  FAIL  функция сторожа не вырезана"; exit 1; }
source "$T/guard.sh"
echo "[вырезано ${#REQUIRED_LABELS[@]} меток: ${REQUIRED_LABELS[*]}]"

# Метки волны 8.5, у которых ЕСТЬ эмиттер, обязаны стоять в таблице сторожа — иначе цикл ниже,
# идущий по самой таблице, не заметил бы вычеркнутую метку.
for lbl in 8.5.1 8.5.2 8.5.3 8.5.3a 8.5.7 8.5.8; do
    case " ${REQUIRED_LABELS[*]} " in *" $lbl "*) ;; *) bad "метка $lbl с эмиттером не стоит в REQUIRED_LABELS"; esac
done

# отчёт хоста
awk '/^_FIX_T0=/ { p = 1 } p { print } p && $0 == "}" && seen_night { exit } /^_night\(\) \{/ { seen_night = 1 }' \
    "$HERE/night-report-fixtures.sh" > "$T/night.sh"
grep -q '^_night() {' "$T/night.sh" || { bad "_night не вырезан из фикстур night-report"; exit 1; }
source "$T/night.sh"
mkdir -p "$T/n/snapshots"
_night "$T/n" 9 120 0 600 cg=plateau
bash "$HERE/night-report.sh" "$T/n" 300 > "$T/night-report.txt" 2>&1

# отчёт 8.2
sed -n '/^samples() {/,/^run() /p' "$HERE/w82-close-report-fixtures.sh" | sed '$d' > "$T/close.sh"
grep -q '^mkcase() {' "$T/close.sh" || { bad "mkcase не вырезан из фикстур close-report"; exit 1; }
source "$T/close.sh"
mkcase ok
RUN="$T/ok/run" ATT="$T/ok/att" INV="" GATE="$T/ok/gate.txt" A2="$T/ok/a2.txt" \
    bash "$HERE/w82-close-report.sh" > "$T/close-report.txt" 2>&1

# отчёты 8.5 — из построителей фикстур эмиттера
EMIT=$HERE/w85-close-report.sh
source "$HERE/w85-fixture-lib.sh"
BASE=$(mkidle base by=1000 kf=none state=none)
NEW=$(mkidle new by=150)
dirs=$(mk d1good); D1RUN=${dirs% *}; D1ATT=${dirs#* }
CTL=$(mkctl ctlgood)
{
    IDLE=$NEW BASE_IDLE=$BASE bash "$EMIT" flow
    IDLE=$NEW BASE_IDLE=$BASE bash "$EMIT" anomaly-hour
    AB_DIR=$(mkab abgood) bash "$EMIT" ab
    CTL_ALERTS=$CTL/alerts.json CTL_STATE=$CTL/state.txt GATE=$CTL/gate.txt bash "$EMIT" controls
    RUN=$D1RUN ATT=$D1ATT bash "$EMIT" d1
    ( cd "$ROOT" && go test -count=1 -v -run '^TestW85_A1_AllocPerEventPostF1Mix' ./internal/correlator/ 2>&1 | grep -aoE '(ДОСТИГНУТО|ПРОВАЛЕН): 8\.5\.8 .*' | head -1 )
} > "$T/close-report-85.txt" 2>&1
cat "$T/night-report.txt" "$T/close-report.txt" "$T/close-report-85.txt" > "$T/all.txt"

START="2026-10-12T22:00:00Z"
m=$(label_completeness "$T/all.txt" "$START")
[ -z "$m" ] && ok "полный отчёт — все ${#REQUIRED_LABELS[@]} меток найдены" || { bad "полный отчёт, а сторож не нашёл:$m"; grep -aE '8\.5\.' "$T/close-report-85.txt" | head -20; }
m=$(label_completeness "$T/night-report.txt" "$START")
case " $m " in *" 8.5.1 "*" 8.5.8 "*) ok "без отчётов 8.5 — метки 8.5.x названы отсутствующими" ;; *) bad "без отчётов 8.5 сторож молчит: ${m:-ничего}" ;; esac

for lbl in "${REQUIRED_LABELS[@]}"; do
    grep -avF -- "$lbl " "$T/all.txt" > "$T/cut.txt"
    m=$(label_completeness "$T/cut.txt" "$START")
    case " $m " in
        *" $lbl "*) ok "метка $lbl вымарана — сторож её назвал" ;;
        *)          bad "метка $lbl вымарана, а сторож молчит (нашёл:${m:-ничего})" ;;
    esac
done

# 8.5.3 и 8.5.3a — разные метки: «8.5.3a» не засчитывается за 8.5.3 и наоборот.
grep -avE '(ДОСТИГНУТО|ПРОВАЛЕН|НЕИЗМЕРИМ|ИЗМЕРЕНО): 8\.5\.3 ' "$T/all.txt" > "$T/ab3.txt"
m=$(label_completeness "$T/ab3.txt" "$START")
case " $m " in *" 8.5.3 "*) ok "8.5.3 вымарана, 8.5.3a осталась — сторож назвал 8.5.3" ;; *) bad "8.5.3a засчитана за 8.5.3 (${m:-ничего})" ;; esac
# Точка в метке — литерал.
grep -avF -- '8.5.1 ' "$T/all.txt" > "$T/dot.txt"; echo 'ДОСТИГНУТО: 8x5x1 ДОСТИГНУТО' >> "$T/dot.txt"
m=$(label_completeness "$T/dot.txt")
case " $m " in *" 8.5.1 "*) ok "точка в метке — литерал" ;; *) bad "«8x5x1» зачтена за 8.5.1" ;; esac

echo
[ "$FAIL" -eq 0 ] && { echo "run-8.5-night-guard-fixtures: расхождений 0"; exit 0; }
echo "run-8.5-night-guard-fixtures: ЕСТЬ РАСХОЖДЕНИЯ ($FAIL)"; exit 1
