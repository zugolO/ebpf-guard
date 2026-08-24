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
# Шесть обязательных ожиданий (числа получены прогоном текущего run-gate.sh
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
#   5. collect-2.9.8 (5.9.9a, №99): механизм «база брошена» (5.9.6f) даёт ОБА
#      исхода на одних и тех же данных — молчит при повторном вызове гейта за
#      тот же замер (совпал TIMESTAMP в файле состояния) и печатает WARN,
#      когда TIMESTAMP чужой, а тело сигнатуры то же. Реплей, давший только
#      один из двух исходов, — стоп: до 5.9.9a WARN печатался всегда, и
#      «всегда молчит» было бы такой же поломкой, только тихой.
#   6. collect-2.9.9 (5.9.9.Fe, разбор №111): третья ветка спасения фонового
#      правила (idle_prewindow_list — «счётчик ненулевой, но прироста за
#      idle-час нет») отличается от второй («выросло за idle-час») на ОДНОМ
#      прогоне с двумя искусственно потерянными background-правилами —
#      anomaly_detection (реально выросло за idle-час этого архива) и
#      container_escape_init_proc (реально не выросло, но ненулевое на обоих
#      концах). Реплей, не различивший обе формулировки, — стоп, как и
#      остальные пять.
#
# Использование: replay-gate.sh [collect-2.9.5-dir] [collect-2.9.6-dir] [collect-2.9.7-dir] [collect-2.9.8-dir] [collect-2.9.9-dir]
# По умолчанию — server-logs/collect-2.9.5, server-logs/collect-2.9.6,
# server-logs/collect-2.9.7, server-logs/collect-2.9.8 и server-logs/collect-2.9.9 относительно корня
# репозитория. Любое
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
# 5.9.9a (№99, P0): пятый реплей — collect-2.9.8, механизм «база брошена»
# (5.9.6f) обязан дать ОБА исхода на одних и тех же данных: молчать при
# повторном вызове гейта за тот же замер (тот же TIMESTAMP в файле
# состояния) и печатать WARN, когда TIMESTAMP другой, а сигнатура та же.
# Постановка №2.9.9 называет это пятым жёстким стопом преflight'а.
C298_DIR="${4:-$REPO_ROOT/server-logs/collect-2.9.8}"
# 5.9.9.Fe (P3, разбор находки №111): шестой реплей — collect-2.9.9, третья
# ветка спасения фонового правила (idle_prewindow_list, run-gate.sh:1136+,
# «сработывало до окна») проверяется тестом, а не глазами. Архив 2.9.9
# несёт настоящие idle-метрики этого прогона (idle/metrics-start.txt →
# metrics-end.txt) — они и подставляются как IDLE_METRICS_START/END,
# синтетика нужна только на СТОРОНЕ final (искусственная потеря двух
# background-правил из final-metrics/final-alerts одного и того же
# реального attack-прогона этого архива).
C299_DIR="${5:-$REPO_ROOT/server-logs/collect-2.9.9}"
# 5.9.9.F.1a (находка №116): седьмой реплей — collect-2.9.9.F, единственный
# архив, где дерево измерителя дало алерт в слепом окне и где маркер
# observer-root-register-*.txt лежит рядом с подтверждением подхвата.
C299F_DIR="${6:-$REPO_ROOT/server-logs/collect-2.9.9.F}"

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
# 5.9.9a (№99): вызов гейта БЕЗ снимка/восстановления detection-baseline-diff-state.txt.
# Нужен ровно одному реплею — пятому, который проверяет сам этот файл и
# обязан видеть состояние, оставленное собственным предыдущим вызовом.
# Снимок/восстановление там делается один раз вокруг всей тройки вызовов,
# а не вокруг каждого.
run_offline_gate_keepstate() {
    local results_dir="$1" ts="$2"
    OFFLINE_GATE_OUTPUT=$(EBPF_GUARD_API="http://127.0.0.1:1" EBPF_GUARD_TOKEN="" "${BASH:-bash}" "$GATE" "$results_dir" "$ts" 2>&1)
}

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
echo "--- реплей 1/8: collect-2.9.5, секция 19 обязана SKIP по отсутствующей серии ---"
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
echo "--- реплей 2/8: collect-2.9.6, секция 19 PASS×3, секция 20 с фоном 547/с (5.9.7a) ---"
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
echo "--- реплей 3/8: collect-2.9.6 с искусственно потерянной 1000 событий на syscall — баланс обязан упасть ---"
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
echo "--- реплей 4/8: collect-2.9.7, крит. 9 (темп по окну атаки) = 88.6/мин, не SKIP (5.9.8e, №90) ---"
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

# --- Реплей 5: collect-2.9.8, «база брошена» обязана и молчать, и падать ---
#
# 5.9.9a (№99, P0). Дефект был в том, что WARN печатался ВСЕГДА при
# расхождении состава: гейт, запускаемый дважды за один замер (второй вызов
# руками после full_run()), сравнивал сигнатуру со своим же первым вызовом.
# Правка привязала сигнатуру к TIMESTAMP замера — и ровно поэтому её надо
# проверять на ОБОИХ исходах: механизм, который теперь всегда молчит, был бы
# такой же поломкой, только тихой (риск №1 постановки — «умеет ли критерий
# падать», не только сходиться).
#
# Сигнатура берётся не из кода, а из самого прогона: первый вызов пишет её,
# какой бы она ни была; второй вызов с тем же TIMESTAMP обязан промолчать;
# третий — с подменённой ПЕРВОЙ строкой файла (чужой TIMESTAMP, то же тело)
# — обязан напечатать WARN. Если первый вызов файла не оставил (состав
# сошёлся с detection-baseline.txt, расхождения нет) — это не «PASS
# отсутствием», а невозможность проверки, и она считается несовпадением:
# архив, на котором нечего проверять, для этого реплея не годится.
echo "--- реплей 5/8: collect-2.9.8, «база брошена» молчит на повторном вызове и падает на чужом TIMESTAMP (5.9.9a, №99) ---"
ts8=$(find_ts "$C298_DIR/attacks" 2>/dev/null || true)
if [ -z "$ts8" ]; then
    bad "collect-2.9.8: baseline-state-*.json не найден в $C298_DIR/attacks — архив недоступен"
else
    save_diff_state
    rm -f "$DIFF_STATE"
    run_offline_gate_keepstate "$C298_DIR/attacks" "$ts8"
    if [ ! -f "$DIFF_STATE" ]; then
        bad "collect-2.9.8 (ts=$ts8): первый вызов не оставил detection-baseline-diff-state.txt — состав детекта этого архива сошёлся с detection-baseline.txt, и оба исхода 5.9.9a на нём непроверяемы (нужен архив с расхождением состава)"
    elif [ "$(head -1 "$DIFF_STATE")" != "$ts8" ]; then
        bad "collect-2.9.8 (ts=$ts8): первая строка файла состояния = «$(head -1 "$DIFF_STATE")», ожидался TIMESTAMP замера — формат 5.9.9a не применён либо файл записан старым кодом"
    else
        # Исход 1: тот же TIMESTAMP — тот же замер, WARN печататься не обязан.
        run_offline_gate_keepstate "$C298_DIR/attacks" "$ts8"
        if grep -q 'база брошена' <<< "$OFFLINE_GATE_OUTPUT"; then
            bad "collect-2.9.8 (ts=$ts8): повторный вызов гейта за ТОТ ЖЕ замер напечатал «база брошена» — самонаведение №99 не починено"
        else
            ok "collect-2.9.8 (ts=$ts8): повторный вызов за тот же замер молчит — WARN больше не привязан к запуску гейта (5.9.9a)"
        fi
        # Исход 2: чужой TIMESTAMP, то же тело сигнатуры — WARN обязан быть.
        awk 'NR==1{print "19700101_000000"; next} {print}' "$DIFF_STATE" > "$DIFF_STATE.replay" \
            && mv "$DIFF_STATE.replay" "$DIFF_STATE"
        run_offline_gate_keepstate "$C298_DIR/attacks" "$ts8"
        if grep -q 'база брошена' <<< "$OFFLINE_GATE_OUTPUT"; then
            ok "collect-2.9.8 (ts=$ts8): с подменённым TIMESTAMP и тем же телом сигнатуры WARN печатается — механизм 5.9.6f умеет падать, а не только молчать (5.9.9a)"
        else
            bad "collect-2.9.8 (ts=$ts8): с подменённым TIMESTAMP WARN «база брошена» НЕ напечатан — механизм 5.9.6f ослеплён правкой 5.9.9a, что хуже дефекта №99 (тихо, а не шумно)"
        fi
    fi
    restore_diff_state
fi
echo ""

# --- Реплей 6/8: collect-2.9.9, третья ветка спасения фонового правила ---
echo "--- реплей 6/8: collect-2.9.9, вторая и третья ветки спасения фонового правила различаются (5.9.9.Fe, №111) ---"
ts9=$(find_ts "$C299_DIR/attacks" 2>/dev/null || true)
idle_start9="$C299_DIR/idle/metrics-start.txt"
idle_end9="$C299_DIR/idle/metrics-end.txt"
if [ -z "$ts9" ]; then
    bad "collect-2.9.9: baseline-state-*.json не найден в $C299_DIR/attacks — архив недоступен"
elif [ ! -s "$idle_start9" ] || [ ! -s "$idle_end9" ]; then
    bad "collect-2.9.9: idle/metrics-start.txt или metrics-end.txt отсутствуют/пусты в $C299_DIR — вторая/третья ветка непроверяемы без реального idle-часа"
else
    # anomaly_detection реально выросло за idle-час этого архива (93→113,
    # ветка 2 — «выросло за idle-час»); container_escape_init_proc реально
    # не выросло, но ненулевое на обоих концах (21→21, ветка 3 — «до
    # открытия окна»). Обе — background-правила (background-rules.txt),
    # присутствующие в baseline И final этого прогона архива на самом деле
    # (не потеряны взаправду) — искусственно вычёркиваются из final
    # (metrics + store), чтобы критерий 6 счёл их потерянными и отдал на
    # разбор второй попытке; правится ВРЕМЕННАЯ копия архива, не сам архив.
    tmp299=$(mktemp -d)
    cp -r "$C299_DIR/attacks/." "$tmp299/" 2>/dev/null
    sed -i.bak '/rule_id="anomaly_detection"/d;/rule_id="container_escape_init_proc"/d' \
        "$tmp299/final-metrics-$ts9.txt"
    rm -f "$tmp299/final-metrics-$ts9.txt.bak"
    if [ -s "$tmp299/final-alerts-$ts9.json" ]; then
        jq '[.[] | select(.rule_id!="anomaly_detection" and .rule_id!="container_escape_init_proc")]' \
            "$tmp299/final-alerts-$ts9.json" > "$tmp299/final-alerts-$ts9.json.tmp" \
            && mv "$tmp299/final-alerts-$ts9.json.tmp" "$tmp299/final-alerts-$ts9.json"
    fi
    IDLE_METRICS_START="$idle_start9" IDLE_METRICS_END="$idle_end9" \
        run_offline_gate "$tmp299" "$ts9"
    rm -rf "$tmp299"
    sec6_299=$(extract_section "$OFFLINE_GATE_OUTPUT" '^=== 6[.]' '^=== 5\.9\.9\.Fe[.]')
    branch2_ok=0
    branch3_ok=0
    grep -q 'фоновое anomaly_detection: не сработало под атакой, но выросло за idle-час' <<< "$sec6_299" && branch2_ok=1
    grep -q 'фоновое container_escape_init_proc: за idle-час прироста нет, но счётчик ненулевой' <<< "$sec6_299" && branch3_ok=1
    if [ "$branch2_ok" -eq 1 ] && [ "$branch3_ok" -eq 1 ]; then
        ok "collect-2.9.9 (ts=$ts9): вторая ветка («выросло за idle-час», anomaly_detection) и третья ветка («сработывало до окна», container_escape_init_proc) напечатаны разными формулировками на одном прогоне"
    else
        bad "collect-2.9.9 (ts=$ts9): вторая ветка=$branch2_ok, третья ветка=$branch3_ok (ожидались обе=1) — реплей не различил ветки спасения idle_delta_list/idle_prewindow_list (run-gate.sh:1136+)"
    fi
fi
echo ""

# --- Реплей 7/8: collect-2.9.9.F, крит. 16 умеет и PASS, и FAIL (5.9.9.F.1a) ---
#
# Находка №116. До правки вердикт критерия 16 смотрел только на
# harness_alerts > 0 и валил прогон независимо от случая — печатая при этом
# «не считается поломкой подхвата». На №2.9.9.F это дало единственный FAIL
# прогона на алерте, который на 26 мс СТАРШЕ регистрации корня, то есть у
# критерия не было достижимого PASS по построению.
#
# Реплей обязан показать оба исхода на ОДНОМ архиве, иначе правка
# неотличима от «критерий больше никогда не падает»:
#   исход 1 — архив как есть: случай 1, PASS, случай назван числом;
#   исход 2 — тот же архив с timestamp'ом харнесс-алерта, сдвинутым ЗА
#             confirm_epoch: случай 3, FAIL, причина «observer_root не
#             подхвачен».
# Правится ВРЕМЕННАЯ копия архива, не сам архив.
echo "--- реплей 7/8: collect-2.9.9.F, крит. 16 умеет выносить и PASS (случай 1), и FAIL (случай 3) (5.9.9.F.1a, №116) ---"
ts9f=$(find_ts "$C299F_DIR/attacks" 2>/dev/null || true)
marker9f=""
[ -n "$ts9f" ] && marker9f="$C299F_DIR/attacks/observer-root-register-$ts9f.txt"
idle_alerts9f="$C299F_DIR/idle/alerts-end.json"
idle_state9f="$C299F_DIR/idle/state-end.json"
if [ -z "$ts9f" ]; then
    bad "collect-2.9.9.F: baseline-state-*.json не найден в $C299F_DIR/attacks — архив недоступен"
elif [ ! -s "$marker9f" ]; then
    bad "collect-2.9.9.F: маркер $marker9f отсутствует — без register/confirm epoch классификация 5.9.9.Fb непроверяема"
elif [ ! -s "$idle_alerts9f" ] || [ ! -s "$idle_state9f" ]; then
    bad "collect-2.9.9.F: idle/alerts-end.json или idle/state-end.json отсутствуют — слепое окно не измеряется без конца idle-часа"
else
    confirm9f=$(awk -F= '$1=="confirm_epoch"{print $2}' "$marker9f")
    harness_ts9f=$(jq -r -n --slurpfile a "$C299F_DIR/attacks/baseline-alerts-$ts9f.json" \
        --slurpfile b "$idle_alerts9f" '
        ($b[0] | map(.id)) as $seen
        | ($a[0] | map(select(.id as $i | ($seen | index($i)) | not)))
        | map(select((.comm // "") == "bash")) | .[0].timestamp // empty' 2>/dev/null)
    if [ -z "$harness_ts9f" ] || [ -z "$confirm9f" ]; then
        bad "collect-2.9.9.F (ts=$ts9f): в слепом окне нет алерта дерева измерителя либо в маркере нет confirm_epoch — оба исхода 5.9.9.F.1a на этом архиве непроверяемы"
    else
        # Исход 1: архив как есть — случай 1, PASS.
        IDLE_ALERTS_END="$idle_alerts9f" IDLE_STATE_END="$idle_state9f" \
            IDLE_ALERTS_START="$C299F_DIR/idle/alerts-start.json" \
            IDLE_METRICS_START="$C299F_DIR/idle/metrics-start.txt" \
            IDLE_METRICS_END="$C299F_DIR/idle/metrics-end.txt" \
            run_offline_gate "$C299F_DIR/attacks" "$ts9f"
        sec16_a=$(extract_section "$OFFLINE_GATE_OUTPUT" '^=== 16[.]' '^=== 5\.9\.9\.Fd[.]')
        case1_ok=0
        grep -q 'предшествуют регистрации корня=1' <<< "$sec16_a" && case1_ok=1
        pass16=0
        grep -qE '\[PASS\].*структурно неизбежные' <<< "$sec16_a" && pass16=1
        if [ "$case1_ok" -eq 1 ] && [ "$pass16" -eq 1 ]; then
            ok "collect-2.9.9.F (ts=$ts9f): архив как есть — случай 1 (алерт старше регистрации корня) и PASS с названным случаем; критерий 16 достижим (5.9.9.F.1a)"
        else
            bad "collect-2.9.9.F (ts=$ts9f): случай1=$case1_ok, PASS=$pass16 (ожидались оба=1) — крит. 16 либо не классифицировал алерт (проверить iso_to_epoch), либо всё ещё валит структурно неизбежный случай (находка №116)"
        fi

        # Исход 2: тот же архив, timestamp харнесс-алерта сдвинут за
        # confirm_epoch — случай 3, FAIL. Сдвиг делается по epoch'у маркера,
        # а не константой, чтобы реплей не рассыпался при пересъёмке архива.
        tmp299f=$(mktemp -d)
        cp -r "$C299F_DIR/attacks/." "$tmp299f/" 2>/dev/null
        after9f=$(awk -v c="$confirm9f" 'BEGIN{printf "%d", c+5}')
        after_iso9f=$(date -u -d "@$after9f" +%Y-%m-%dT%H:%M:%S.000000000Z 2>/dev/null \
            || date -u -r "$after9f" +%Y-%m-%dT%H:%M:%S.000000000Z 2>/dev/null)
        if [ -z "$after_iso9f" ]; then
            bad "collect-2.9.9.F (ts=$ts9f): не удалось построить timestamp после confirm_epoch ни GNU, ни BSD date — исход 2 не проверен"
        else
            jq --arg old "$harness_ts9f" --arg new "$after_iso9f" \
                'map(if (.comm // "") == "bash" and .timestamp == $old then .timestamp = $new else . end)' \
                "$C299F_DIR/attacks/baseline-alerts-$ts9f.json" > "$tmp299f/baseline-alerts-$ts9f.json"
            IDLE_ALERTS_END="$idle_alerts9f" IDLE_STATE_END="$idle_state9f" \
                IDLE_ALERTS_START="$C299F_DIR/idle/alerts-start.json" \
                IDLE_METRICS_START="$C299F_DIR/idle/metrics-start.txt" \
                IDLE_METRICS_END="$C299F_DIR/idle/metrics-end.txt" \
                run_offline_gate "$tmp299f" "$ts9f"
            sec16_b=$(extract_section "$OFFLINE_GATE_OUTPUT" '^=== 16[.]' '^=== 5\.9\.9\.Fd[.]')
            case3_ok=0
            grep -q 'после подтверждения (не подхвачен)=1' <<< "$sec16_b" && case3_ok=1
            fail16=0
            grep -qE '\[FAIL\].*observer_root не подхвачен' <<< "$sec16_b" && fail16=1
            if [ "$case3_ok" -eq 1 ] && [ "$fail16" -eq 1 ]; then
                ok "collect-2.9.9.F (ts=$ts9f): с алертом, сдвинутым за confirm_epoch — случай 3 и FAIL «observer_root не подхвачен»; критерий 16 умеет падать, а не только пропускать (5.9.9.F.1a)"
            else
                bad "collect-2.9.9.F (ts=$ts9f): случай3=$case3_ok, FAIL=$fail16 (ожидались оба=1) — правка 5.9.9.F.1a ослепила критерий 16, что хуже находки №116 (тихо, а не шумно)"
            fi
        fi
        rm -rf "$tmp299f"
    fi
fi
echo ""

# --- Реплей 8/8: collect-2.9.9.F, ноль web_sql_injection_files объясняется
#     реестром, а не печатается потерей (5.9.9.F.1c, №114) ---
#
# 5.9.9.F.1c убирает из web_sql_injection_files голые "--", "#" и ";" —
# единственные паттерны, которые правило когда-либо матчило на этом стенде
# (10 критикалов за прогон №2.9.9.F, истинных 0). Ожидаемая величина после
# правки — 0 за прогон, и это ОПАСНАЯ форма приёмки: «правило замолчало»
# неотличимо от ослепления по одному счётчику — находка №57 в чистом виде.
# У 5.9.9.F.1b защита есть (позитивный контроль credscrape держит правило
# ненулевым), у 5.9.9.F.1c её нет по построению: реестр silent-rules.txt
# прямо говорит, что у стенда НЕТ сценария, создающего файл с SQLi-паттерном
# в имени, а позитивный контроль на это заводит волна 6.
#
# Поэтому проверка 5.9.9.F.1c — не число, а ВЕТКА РЕЕСТРА: гейт обязан
# напечатать, что ноль объяснён, и назвать чем. Постановка волны требует это
# проверить, а не допустить. Реплей и проверяет — на двух исходах:
#   исход 1 — правило вычеркнуто из final и из ОБОИХ срезов idle-часа
#             (иначе его спасла бы ветка background-rules по idle-приросту,
#             и ветка реестра осталась бы неисполненной): крит. 6 обязан
#             отнести его в «потеряно намеренно» и НЕ упасть;
#   исход 2 — тем же способом вычеркнуто owasp_path_traversal, которого нет
#             ни в одном из трёх реестров: крит. 6 обязан УПАСТЬ и назвать
#             его. Без второго исхода первый доказывал бы только то, что
#             критерий 6 вообще никогда не падает.
echo "--- реплей 8/8: collect-2.9.9.F, ноль web_sql_injection_files объясняется реестром, а не печатается потерей (5.9.9.F.1c, №114) ---"
ts9f2=$(find_ts "$C299F_DIR/attacks" 2>/dev/null || true)
if [ -z "$ts9f2" ]; then
    bad "collect-2.9.9.F: baseline-state-*.json не найден в $C299F_DIR/attacks — архив недоступен"
elif [ ! -s "$C299F_DIR/idle/metrics-start.txt" ] || [ ! -s "$C299F_DIR/idle/metrics-end.txt" ]; then
    bad "collect-2.9.9.F: idle/metrics-start.txt или metrics-end.txt отсутствуют — без них ветка background-rules спасла бы правило, и ветка реестра осталась бы непроверенной"
else
    # Вычёркивает правило из временной копии архива И из временных копий
    # срезов idle-часа, затем гоняет гейт. Сам архив не правится.
    replay8_run() {
        local rule="$1"
        local tmpdir idle_s idle_e
        tmpdir=$(mktemp -d)
        cp -r "$C299F_DIR/attacks/." "$tmpdir/" 2>/dev/null
        idle_s="$tmpdir/replay8-idle-start.txt"
        idle_e="$tmpdir/replay8-idle-end.txt"
        grep -v "rule_id=\"$rule\"" "$C299F_DIR/idle/metrics-start.txt" > "$idle_s"
        grep -v "rule_id=\"$rule\"" "$C299F_DIR/idle/metrics-end.txt" > "$idle_e"
        grep -v "rule_id=\"$rule\"" "$C299F_DIR/attacks/final-metrics-$ts9f2.txt" > "$tmpdir/final-metrics-$ts9f2.txt"
        if [ -s "$C299F_DIR/attacks/final-alerts-$ts9f2.json" ]; then
            jq --arg r "$rule" '[.[] | select(.rule_id != $r)]' \
                "$C299F_DIR/attacks/final-alerts-$ts9f2.json" > "$tmpdir/final-alerts-$ts9f2.json"
        fi
        IDLE_METRICS_START="$idle_s" IDLE_METRICS_END="$idle_e" \
            IDLE_ALERTS_END="$C299F_DIR/idle/alerts-end.json" \
            IDLE_ALERTS_START="$C299F_DIR/idle/alerts-start.json" \
            IDLE_STATE_END="$C299F_DIR/idle/state-end.json" \
            run_offline_gate "$tmpdir" "$ts9f2"
        rm -rf "$tmpdir"
    }

    # Исход 1: правило из реестров — ноль обязан быть объяснён, крит. 6 не падает.
    replay8_run web_sql_injection_files
    sec6_a=$(extract_section "$OFFLINE_GATE_OUTPUT" '^=== 6[.]' '^=== 5\.9\.9\.Fe[.]')
    explained8=0
    grep -qE '^\s+~ web_sql_injection_files$' <<< "$sec6_a" && explained8=1
    crit6_pass=0
    grep -qE '\[PASS\].*состав детекта без потерь вне списка намеренных' <<< "$sec6_a" && crit6_pass=1
    lost_named=0
    grep -qE '^\s+- web_sql_injection_files$' <<< "$sec6_a" && lost_named=1
    if [ "$explained8" -eq 1 ] && [ "$crit6_pass" -eq 1 ] && [ "$lost_named" -eq 0 ]; then
        ok "collect-2.9.9.F (ts=$ts9f2): web_sql_injection_files с нулём за прогон отнесён реестром («~» в объяснённых) и крит. 6 не упал — ноль 5.9.9.F.1c объясняется печатью, а не допущением (№114)"
    else
        bad "collect-2.9.9.F (ts=$ts9f2): объяснён=$explained8, крит.6 PASS=$crit6_pass, назван потерей=$lost_named (ожидались 1/1/0) — ноль web_sql_injection_files НЕ разбирается реестром, и приёмка 5.9.9.F.1c осталась бы допущением"
    fi

    # Исход 2: правило вне всех трёх реестров — крит. 6 обязан упасть.
    replay8_run owasp_path_traversal
    sec6_b=$(extract_section "$OFFLINE_GATE_OUTPUT" '^=== 6[.]' '^=== 5\.9\.9\.Fe[.]')
    crit6_fail=0
    grep -qE '\[FAIL\].*потеряно .* типов вне intentional-loss' <<< "$sec6_b" && crit6_fail=1
    unreg_named=0
    grep -qE '^\s+- owasp_path_traversal$' <<< "$sec6_b" && unreg_named=1
    if [ "$crit6_fail" -eq 1 ] && [ "$unreg_named" -eq 1 ]; then
        ok "collect-2.9.9.F (ts=$ts9f2): owasp_path_traversal (ни в одном реестре) с нулём за прогон валит крит. 6 и назван поимённо — ветка реестра различает объяснённый ноль и регресс детекта (5.9.9.F.1c)"
    else
        bad "collect-2.9.9.F (ts=$ts9f2): крит.6 FAIL=$crit6_fail, назван=$unreg_named (ожидались оба=1) — крит. 6 пропускает потерю правила вне реестров, то есть исход 1 выше не доказывает ничего"
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
