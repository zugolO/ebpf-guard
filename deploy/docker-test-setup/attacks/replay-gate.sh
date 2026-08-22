#!/bin/bash
# replay-gate.sh — 5.9.7c (№85, P0): 5.9.6b/5.9.6c/5.9.7a воспроизводятся на
# архиве ДО стенда.
#
# Риск №1 постановки повторялся три волны подряд (5.9.5/5.9.6/5.9.7 —
# plan.md, «Риск №1») и три раза не исполнялся: план обещал реплей на
# архивах collect-2.9.5/collect-2.9.6, разбор делался руками уже ПОСЛЕ
# прогона, а не машинным шагом ДО него. Этот скрипт переносит риск №1 из
# текста постановки в исполняемую проверку: он гоняет секции 19 (баланс
# событий, 5.9.6b) и 20 (контроль счётности, 5.9.7a) текущего run-gate.sh
# против СОХРАНЁННЫХ baseline/final-metrics и counting-control-*.txt чужого
# прошлого прогона — офлайн, без сети и без живого агента — и сверяет вывод
# с исходами, зашитыми в сам скрипт как проверки (awk/grep по тексту), а не
# просто печатает результат на глаз (постановка явно требует «проверки, а не
# печать»).
#
# Четыре обязательных ожидания (числа получены прогоном текущего run-gate.sh
# против этих же архивов на этой сессии, см. plan.md 5.9.7c/5.9.8e):
#   1. collect-2.9.5 (до 5.9.6a/b): events_emitted_kernel_total в архиве нет
#      вовсе — секция 19 обязана SKIP'нуть по отсутствующей серии, а не
#      печатать невязку по несуществующей левой части.
#   2. collect-2.9.6: секция 19 сходится PASS по всем трём коллекторам. С
#      подложенным синтетическим null-маркером (фон 547/с — та же величина,
#      что разбор №2.9.6 дал вручную) секция 20 даёт idle: остаток 130
#      (PASS, допуск ±135) и drop: остаток −86 (SKIP по «ringbuf_full=0 на
#      этом стенде», не FAIL) — то есть старая формула валила оба режима
#      (17087/±4495 и 18512/±6171, см. gate-2.9.6.txt), новая — нет.
#   3. Синтетическая потеря 1000 событий на emitted_kernel{collector=
#      "syscall"} без роста правой части — секция 19 обязана упасть FAIL
#      именно на syscall (допуск там ±500, невязка станет 1012).
#   4. collect-2.9.7 (5.9.8e, №90): секция 6 (гейт называет её "критерий 9"
#      в тексте постановки) обязана дать PASS 88.6/мин, а не SKIP по
#      «сборка харнесса старее 5.9.7d» — маркер окна атаки на этом архиве
#      есть и разобран правильно, SKIP до правки был ложным (OFMT awk
#      усекал дробный unix-эпох first/last до одинакового значения).
#
# Использование: replay-gate.sh [collect-2.9.5-dir] [collect-2.9.6-dir] [collect-2.9.7-dir]
# По умолчанию — server-logs/collect-2.9.5, server-logs/collect-2.9.6 и
# server-logs/collect-2.9.7 относительно корня репозитория. Любое
# несовпадение — ненулевой код возврата (преflight-стоп); печатает
# REPLAY-GATE: PASS/FAIL в конце.
set -u

# Реплей зовёт run-gate.sh через "${BASH:-bash}", то есть ТЕМ ЖЕ
# интерпретатором, каким запущен сам. Если это bash 3.2 (штатный /bin/bash в
# macOS — а шебанг этого файла указывает именно на /bin/bash), секция 19
# гейта падает на `declare -A`, и реплей печатает REPLAY-GATE: FAIL по
# причине, не имеющей отношения к архивам. Стоп с отдельным кодом 4 — иначе
# преflight №2.9.7 остановился бы «по несовпадению исхода», а несовпадения
# не было: был не тот bash.
if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
    echo "REPLAY-GATE: неподходящий интерпретатор — bash ${BASH_VERSION:-?}, требуется 4+ (run-gate.sh, секция 19, использует declare -A). Запускать как: bash5 replay-gate.sh ..." >&2
    exit 4
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
GATE="$SCRIPT_DIR/run-gate.sh"

C295_DIR="${1:-$REPO_ROOT/server-logs/collect-2.9.5}"
C296_DIR="${2:-$REPO_ROOT/server-logs/collect-2.9.6}"
# 5.9.8e (№90, P1): четвёртый реплей — collect-2.9.7, крит. 9 (темп алертов
# от атакующих, гейт называет его "6") обязан дать 88.6/мин, а не SKIP. До
# правки OFMT (см. run-gate.sh, окно атаки) "first"/"last" усекались до
# одинакового значения "1.78741e+09" и окно обнулялось — гейт печатал SKIP с
# причиной "сборка харнесса старее 5.9.7d", хотя маркер был на месте и
# разобран правильно почти до самого конца.
C297_DIR="${3:-$REPO_ROOT/server-logs/collect-2.9.7}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

REPLAY_FAILED=0
ok()  { echo -e "${GREEN}[REPLAY-OK]${NC} $1"; }
bad() { echo -e "${RED}[REPLAY-MISMATCH]${NC} $1"; REPLAY_FAILED=1; }

if [ ! -x "$GATE" ]; then
    echo "run-gate.sh не найден рядом ($GATE) — реплей невозможен" >&2
    exit 2
fi
if ! command -v jq &> /dev/null; then
    echo "jq не найден — run-gate.sh не может отработать, реплей невозможен" >&2
    exit 2
fi

# detection-baseline-diff-state.txt (5.9.6f) лежит рядом с run-gate.sh и
# переживает запуски — секция 6 гейта сравнивает сигнатуру added/lost с
# прошлым прогоном, чтобы поймать заброшенную базу. Реплей на архиве не
# должен считаться «прошлым прогоном» для этого сравнения: он гоняет старые,
# уже разобранные данные, а не текущий стенд. Снимок/восстановление вокруг
# каждого вызова гейта — иначе реплей тихо портит состояние, которое видит
# следующий настоящий прогон.
DIFF_STATE="$SCRIPT_DIR/detection-baseline-diff-state.txt"
DIFF_STATE_BACKUP=""
save_diff_state() {
    DIFF_STATE_BACKUP=""
    if [ -f "$DIFF_STATE" ]; then
        DIFF_STATE_BACKUP=$(mktemp)
        cp "$DIFF_STATE" "$DIFF_STATE_BACKUP"
    fi
}
restore_diff_state() {
    if [ -n "$DIFF_STATE_BACKUP" ]; then
        cp "$DIFF_STATE_BACKUP" "$DIFF_STATE"
        rm -f "$DIFF_STATE_BACKUP"
    else
        rm -f "$DIFF_STATE"
    fi
}

# attack-manifest.json (5.9.8e, реплей 4/4) — run-gate.sh читает его
# из своего собственного каталога ($GATE_SCRIPT_DIR/attack-manifest.json),
# не из results_dir, и файл регенерируется каждым прогоном (.gitignore) —
# в рабочем дереве его обычно нет вовсе. Без него крит. 6 не считает темп
# и SKIP'ает по другой причине ("нет attack-manifest.json"), что для этого
# реплея неотличимо от прохождения; манифест архива подкладывается на время
# вызова и снимается сразу после, тем же приёмом, что save/restore_diff_state.
MANIFEST_FILE_LIVE="$SCRIPT_DIR/attack-manifest.json"
MANIFEST_BACKUP=""
save_manifest() {
    MANIFEST_BACKUP=""
    if [ -f "$MANIFEST_FILE_LIVE" ]; then
        MANIFEST_BACKUP=$(mktemp)
        cp "$MANIFEST_FILE_LIVE" "$MANIFEST_BACKUP"
    fi
}
restore_manifest() {
    if [ -n "$MANIFEST_BACKUP" ]; then
        cp "$MANIFEST_BACKUP" "$MANIFEST_FILE_LIVE"
        rm -f "$MANIFEST_BACKUP"
    else
        rm -f "$MANIFEST_FILE_LIVE"
    fi
}

find_ts() {
    local dir="$1"
    local latest
    latest=$(find "$dir" -maxdepth 1 -name 'baseline-state-*.json' 2>/dev/null | sort | tail -1)
    [ -z "$latest" ] && return 1
    basename "$latest" | sed -E 's/baseline-state-(.*)\.json/\1/'
}

# Офлайн-вызов гейта: EBPF_GUARD_API указывает на заведомо недоступный
# localhost-порт — curl отваливается мгновенно отказом соединения (не
# таймаутом/зависанием), и живой агент не достаётся ни при каких
# обстоятельствах, даже если на этой машине случайно лежит настоящий токен
# (постановка требует «без сети и без агента» — полагаться на пустоту
# EBPF_GUARD_TOKEN одного недостаточно, run-gate.sh сам подхватывает токен из
# /var/lib/ebpf-guard/token, если он существует).
OFFLINE_GATE_OUTPUT=""
run_offline_gate() {
    local results_dir="$1" ts="$2"
    save_diff_state
    # Явный "$BASH" "$GATE" вместо "$GATE" напрямую: run-gate.sh использует
    # declare -A (bash4+), а его собственный шебанг (#!/bin/bash) на системе,
    # где /bin/bash — устаревший 3.2 (macOS по умолчанию), подхватил бы не
    # тот интерпретатор, которым запущен сам replay-gate.sh. На линуксовом
    # стенде /bin/bash уже bash4+, так что для него это не имело бы значения
    # — но реплей обязан быть переносимым, а не полагаться на то, где его
    # запускают.
    OFFLINE_GATE_OUTPUT=$(EBPF_GUARD_API="http://127.0.0.1:1" EBPF_GUARD_TOKEN="" "${BASH:-bash}" "$GATE" "$results_dir" "$ts" 2>&1)
    restore_diff_state
}

extract_section() {
    # extract_section OUTPUT START_RE END_RE — печатает строки между первым
    # совпадением START_RE (включительно) и следующим совпадением END_RE
    # (исключая её саму).
    awk -v s="$2" -v e="$3" '
        $0 ~ s { f=1 }
        f && $0 ~ e && $0 !~ s { exit }
        f { print }
    ' <<< "$1"
}

echo "==========================================="
echo "REPLAY-GATE: 5.9.7c (№85) — 5.9.6b/5.9.6c/5.9.7a на архивах"
echo "==========================================="
echo ""

# --- Реплей 1: collect-2.9.5 (до 5.9.6a/b) --------------------------------
echo "--- реплей 1/4: collect-2.9.5, секция 19 обязана SKIP по отсутствующей серии ---"
ts5=$(find_ts "$C295_DIR/attacks" 2>/dev/null || true)
if [ -z "$ts5" ]; then
    bad "collect-2.9.5: baseline-state-*.json не найден в $C295_DIR/attacks — архив недоступен"
else
    run_offline_gate "$C295_DIR/attacks" "$ts5"
    sec19_295=$(extract_section "$OFFLINE_GATE_OUTPUT" '^=== 19[.]' '^=== 20[.]')
    if grep -q 'серия events_emitted_kernel_total отсутствует' <<< "$sec19_295"; then
        ok "collect-2.9.5 (ts=$ts5): секция 19 = SKIP по отсутствующей серии — левой части баланса в этом архиве действительно нет (сборка старее 5.9.6b)"
    else
        bad "collect-2.9.5 (ts=$ts5): секция 19 не дала ожидаемого SKIP — вывод разошёлся с зафиксированным на сессии 5.9.7c (см. plan.md)"
    fi
fi
echo ""

# --- Реплей 2: collect-2.9.6, баланс + счётность с синтетическим фоном ---
echo "--- реплей 2/4: collect-2.9.6, секция 19 PASS×3, секция 20 с фоном 547/с (5.9.7a) ---"
ts6=$(find_ts "$C296_DIR/attacks" 2>/dev/null || true)
if [ -z "$ts6" ]; then
    bad "collect-2.9.6: baseline-state-*.json не найден в $C296_DIR/attacks — архив недоступен"
else
    run_offline_gate "$C296_DIR/attacks" "$ts6"
    sec19_296=$(extract_section "$OFFLINE_GATE_OUTPUT" '^=== 19[.]' '^=== 20[.]')
    balance_pass_count=$(grep -c '\[PASS\].*баланс сходится' <<< "$sec19_296" || true)
    if [ "$balance_pass_count" -eq 3 ]; then
        ok "collect-2.9.6 (ts=$ts6): секция 19 сходится PASS по всем трём коллекторам (syscall/network/fileaccess)"
    else
        bad "collect-2.9.6 (ts=$ts6): секция 19 дала $balance_pass_count PASS из 3 ожидаемых — баланс, который в 5.9.6 сходился, теперь не сходится"
    fi

    # Архив collect-2.9.6 предшествует 5.9.7a — своего null-прогона в нём
    # нет. Фон 547/с — величина, которую разбор №2.9.6 дал вручную
    # (plan.md, «остаток 17087 при допуске 4495» делится на её же
    # background_estimate/rate) и которую постановка 5.9.7c называет прямо
    # («по новой, фон 547/с — проходит»); подкладываем его синтетическим
    # null-маркером во ВРЕМЕННУЮ копию архива, а не в сам архив — реплей не
    # имеет права дописывать в git-каталог с сохранёнными данными прогона.
    tmp296=$(mktemp -d)
    cp -r "$C296_DIR/attacks/." "$tmp296/" 2>/dev/null
    cat > "$tmp296/counting-control-null-$ts6.txt" <<EOF
mode=null
n=0
events_delta=16957
drops_delta=0
ringbuf_full_delta=0
sum=16957
diff=16957
quiesced_iterations=1
generator_seconds=0
window_seconds=31
EOF
    run_offline_gate "$tmp296" "$ts6"
    rm -rf "$tmp296"
    sec20_296=$(extract_section "$OFFLINE_GATE_OUTPUT" '^=== 20[.]' '^=== 21[.]')
    if grep -q '\[PASS\].*idle: N=10000 сходится' <<< "$sec20_296" \
        && ! grep -q '\[FAIL\].*drop:' <<< "$sec20_296"; then
        ok "collect-2.9.6 (ts=$ts6) + синтетический null (547/с): idle PASS, drop не FAIL (SKIP по ringbuf_full=0 на этом стенде — ожидаемо, см. plan.md) — старая формула валила оба режима, новая нет"
    else
        bad "collect-2.9.6 (ts=$ts6) + синтетический null (547/с): секция 20 разошлась с зафиксированным исходом (idle PASS / drop не FAIL) — см. вывод выше"
    fi
fi
echo ""

# --- Реплей 3: синтетическая потеря 1000 событий -------------------------
echo "--- реплей 3/4: collect-2.9.6 с искусственно потерянной 1000 событий на syscall — баланс обязан упасть ---"
if [ -z "${ts6:-}" ]; then
    bad "синтетическая потеря: collect-2.9.6 недоступен, шаг пропущен"
else
    tmp_loss=$(mktemp -d)
    cp -r "$C296_DIR/attacks/." "$tmp_loss/" 2>/dev/null
    loss_final="$tmp_loss/final-metrics-$ts6.txt"
    if [ ! -f "$loss_final" ]; then
        bad "синтетическая потеря: final-metrics-$ts6.txt не найден в копии архива"
    else
        # +1000 к emitted_kernel{collector="syscall"} в final БЕЗ роста
        # events_total/ringbuf_to_router/router_to_queue/malformed —
        # ровно та потеря, которую тождество 5.9.6b обязано ловить: ядро
        # зарезервировало слот в кольце, а событие потерялось где-то ПОСЛЕ
        # резерва, не попав ни в одно учтённое слагаемое правой части.
        awk '/ebpf_guard_events_emitted_kernel_total\{collector="syscall"\}/{$NF=$NF+1000} {print}' \
            "$loss_final" > "$loss_final.tmp" && mv "$loss_final.tmp" "$loss_final"
        run_offline_gate "$tmp_loss" "$ts6"
        sec19_loss=$(extract_section "$OFFLINE_GATE_OUTPUT" '^=== 19[.]' '^=== 20[.]')
        if grep -q '\[FAIL\].*syscall: невязка' <<< "$sec19_loss"; then
            ok "collect-2.9.6 (ts=$ts6) с искусственной потерей 1000 на syscall: секция 19 упала FAIL именно на syscall — тождество умеет падать, а не только сходиться"
        else
            bad "collect-2.9.6 (ts=$ts6) с искусственной потерей 1000 на syscall: секция 19 НЕ упала — тождество, которое не умеет обнаруживать заведомую потерю, бесполезно как проверка (см. вывод выше)"
        fi
    fi
    rm -rf "$tmp_loss"
fi
echo ""

# --- Реплей 4: collect-2.9.7, крит. 9 обязан дать 88.6/мин, а не SKIP -----
echo "--- реплей 4/4: collect-2.9.7, крит. 9 (темп по окну атаки) = 88.6/мин, не SKIP (5.9.8e, №90) ---"
ts7=$(find_ts "$C297_DIR/attacks" 2>/dev/null || true)
if [ -z "$ts7" ]; then
    bad "collect-2.9.7: baseline-state-*.json не найден в $C297_DIR/attacks — архив недоступен"
elif [ ! -f "$C297_DIR/attacks/attack-manifest.json" ]; then
    bad "collect-2.9.7: attack-manifest.json не найден в архиве — реплей крит. 9 невозможен без множества атакующих comms"
else
    save_manifest
    cp "$C297_DIR/attacks/attack-manifest.json" "$MANIFEST_FILE_LIVE"
    run_offline_gate "$C297_DIR/attacks" "$ts7"
    restore_manifest
    sec6_297=$(extract_section "$OFFLINE_GATE_OUTPUT" '^=== 6[.]' '^=== 7[.]')
    if grep -q '\[PASS\].*темп алертов от атакующих:.*= 88\.6/мин' <<< "$sec6_297"; then
        ok "collect-2.9.7 (ts=$ts7): крит. 9 = PASS, 88.6/мин — окно атаки разобралось по first/last без потери точности (5.9.8e)"
    else
        bad "collect-2.9.7 (ts=$ts7): крит. 9 не дал ожидаемого PASS/88.6 — вывод разошёлся с зафиксированным на сессии 5.9.8e (см. plan.md); секция 6:"$'\n'"$sec6_297"
    fi
fi
echo ""

echo "==========================================="
if [ "$REPLAY_FAILED" -eq 0 ]; then
    echo -e "${GREEN}REPLAY-GATE: PASS${NC} — 5.9.6b/5.9.6c/5.9.7a воспроизведены на архиве с ожидаемыми исходами"
    exit 0
else
    echo -e "${RED}REPLAY-GATE: FAIL${NC} — реплей разошёлся с зафиксированным исходом, преflight №2.9.7 обязан остановиться здесь"
    exit 1
fi
