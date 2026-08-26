#!/bin/bash
# Проверяет четырнадцать критериев ЗАМЕРА №1/№2/№3 (plan.md, разделы "ЗАМЕР №1",
# "Волна 1.75", гейт волны 2 и пункт 2.Gd)
# по baseline/final снимкам одного прогона run-all-attacks.sh
# и печатает PASS/SKIP/FAIL по каждому плюс общий вердикт. Возвращает
# ненулевой код при любом FAIL — до этого скрипта критерии замера проверялись
# руками (plan.md волна 1.5h, вопрос 12).
#
# Волна 1.75c переписала три критерия и добавила два новых:
#   2 (DNS)        — активный dig-зонд вместо "растёт на сотни" (атаки на
#                    localhost:3000 не вызывают резолвинга; SKIP, не FAIL);
#   6 (детект жив) — темп алертов/мин (>= 74, уровень прогона №4) вместо
#                    абсолютного >= 850, привязанного к длине окна;
#   7 (recall)     — новый критерий: доля категорий манифеста, чьи comm
#                    появились в новых алертах (порог 0.5);
#   8 (alerts_dropped) — новый, информационно: подавление алертов движком
#                    (rate-limit/dedup), без PASS/FAIL. Порог после волны 3.
# Критерий 4 (comm в инцидентах) уже читает /api/v1/incidents, а не алерты
# incident_confirmed_attack — это было починено в волне 1.5h после замера №1.
#
# Волна 3 добавила гейт волны 2 (его критерии до этого считались только ручным
# разбором снапшота инцидентов — см. замечание 2 к волне 2):
#   9  (доля на демонах)   — < 20%; в прогоне №4 было 100% (114/114 на sshd),
#                            в замере №1 — 37.4%;
#   10 (process_chain)     — >= 80% инцидентов с непустой цепочкой (P0-1).
# Оба читают /api/v1/incidents, то есть то же множество, что и критерий 4 —
# в замере №1 гейт и снапшот считали по разным множествам (326 против 107).
#
# Пункт 2.Gd (перед замером №2) добавил четыре критерия: они были записаны в
# таблице замера, но считать их было некому — та же ситуация, из-за которой
# заведена волна 1.75 (величина есть, критерий записан, никто не проверяет):
#   11 (anomalies_total)      — /metrics против /debug/state (в замере №1: 46 против 0);
#   12 (кардинальность)       — серий profiler_anomaly_score < 1000 и ноль с comm=""
#                               (в замере №1: 8616, из них 3145 пустых), P1-11;
#   13 (path_denylist)        — приёмка 4.3: дропы читаются вместе с файловым
#                               детектом, иначе широкий префикс выглядит как успех;
#   14 (CPU-watchdog)         — приёмка 4.4: ноль шеддинга на ДЕФОЛТНЫХ порогах
#                               40/70/20 (со стендовым оверрайдом критерий пуст).
# Все четыре дают SKIP при отсутствии данных, а не FAIL: непроверенное не
# засчитывается ни в одну сторону (замечание 1 к волне 1.75).
#
# Волна 5.3 переписала три критерия — все три печатали FAIL при исправно
# работающем агенте (находки №4 и №5 замера №2). Это второй случай того же
# класса, что волна 1.75c: линейка чинится ДО прогона, иначе следующий замер
# снова провалит систему за то, что она сделала правильно.
#   3  (деградация)  — reason="path_denylist" исключён из суммы дропов.
#                      Намеренная фильтрация не есть потеря видимости, а приёмка
#                      4.3 требует, чтобы этих дропов было НЕ ноль: старый
#                      критерий ломался на каждом прогоне с рабочим фильтром.
#   6  (детект жив)  — сравнение СОСТАВА типов с detection-baseline.txt и diff
#                      «потеряно/добавлено» вместо порога ">= 43 типа". Число не
#                      отличает просевший детект от FP, переставшего считаться
#                      детектом (замер №2: 41 тип и FAIL без единой реальной
#                      потери).
#   14 (CPU-watchdog) — число пар reduce↔recover по счётчику
#                      ebpf_guard_cpu_pressure_transitions_total (заведён в 5.3)
#                      плюс cpu_degraded_fraction, вместо мгновенного
#                      cpu_pressure_level в момент среза. Ноль переходов означал
#                      бы, что регулятор не нужен; критерий про флап.
#
# Использование: run-gate.sh [RESULTS_DIR] [TIMESTAMP]
# По умолчанию берёт последний TIMESTAMP, для которого в RESULTS_DIR есть
# baseline-state-*.json и final-state-*.json.

set -u

# Секция 19 (баланс событий, 5.9.6b) использует `declare -A` — это bash 4+.
# На bash 3.2 (штатный /bin/bash в macOS) она падает рантайм-ошибкой посреди
# вывода, и гейт печатает КРАСНЫЙ вердикт по причине, не имеющей отношения к
# прогону: ровно тот класс «красный гейт, о котором известно, что это не
# считается», ради которого заведена волна 5.9.7. Проверка стоит первой и
# останавливает скрипт с отдельным кодом 4, чтобы такой запуск нельзя было
# спутать ни с FAIL (1), ни со стопом преflight'а (3). На стенде (Linux)
# /bin/bash уже 4+, эта ветка там недостижима.
if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
    echo "RUN-GATE: неподходящий интерпретатор — bash ${BASH_VERSION:-?}, требуется 4+ (секция 19 использует declare -A). Запускать как: bash5 run-gate.sh ..." >&2
    exit 4
fi

RESULTS_DIR="${1:-./attack-results}"
TIMESTAMP="${2:-}"

# Active DNS probe (criterion 2 after 1.75c) needs to reach /metrics directly.
# Inherit from env when run-all-attacks.sh exports them; otherwise use the same
# defaults the master script does so run-gate.sh stays runnable standalone on
# the test stand.
EBPF_GUARD_API="${EBPF_GUARD_API:-http://${VPS_IP:-localhost}:19090}"
EBPF_GUARD_TOKEN="${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 5.9.6i (№68 хвост + №77): PASS отсутствием ("событие не наступило") и PASS
# доказательством раньше печатались одинаково — единственным различием было
# читать журнал глазами. PASS_COUNT/SKIP_COUNT считаются здесь, а не
# постфактум grep'ом по выводу, потому что вывод раскрашен ANSI-кодами и
# идёт вперемешку с диагностическими echo — печатаются итоговой строкой
# рядом с PASS/FAIL, чтобы число SKIP было видно без пересчёта вручную.
# 5.9.9e (№102): вторая, отдельная от преflight (5.9.7h) сверка
# criteria-index.txt — не «код для пункта написан?» (это уже спрашивает
# 5.9.7h статическим grep по исходнику ДО чтения снимков), а «строка пункта
# реально напечаталась на ЭТОМ прогоне?». CRITERIA_SELF_IDS/PATTERNS —
# только записи с file="-" (печатаются самим run-gate.sh); заполняются
# ниже, во время того же прохода по criteria-index.txt, что и преflight.
# record_covered вызывается из pass()/fail()/warn()/skip() автоматически
# (они уже получают готовый текст строки первым аргументом), плюс явно —
# из горстки мест, где пункт печатается голым echo, а не через одну из
# этих функций (см. вызовы record_covered ниже по файлу).
declare -A CRITERIA_COVERED=()
CRITERIA_SELF_IDS=()
CRITERIA_SELF_PATTERNS=()
record_covered() {
    local text="$1" i id
    for i in "${!CRITERIA_SELF_PATTERNS[@]}"; do
        id="${CRITERIA_SELF_IDS[$i]}"
        [ -n "${CRITERIA_COVERED[$id]:-}" ] && continue
        [[ "$text" == *"${CRITERIA_SELF_PATTERNS[$i]}"* ]] && CRITERIA_COVERED[$id]=1
    done
}

PASS_COUNT=0
SKIP_COUNT=0
pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS_COUNT=$((PASS_COUNT + 1)); record_covered "$1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; GATE_FAILED=1; record_covered "$1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; record_covered "$1"; }
skip() { echo -e "${YELLOW}[SKIP]${NC} $1"; SKIP_COUNT=$((SKIP_COUNT + 1)); record_covered "$1"; }

# 5.9.9.F.1a (находка №116, вторая половина): перевод ISO-8601 в epoch с
# долями секунды БЕЗ опоры на GNU date. Классификация харнесс-алертов
# (критерий 16) различает случаи по разнице в десятки миллисекунд — на
# №2.9.9.F это 26 мс, — то есть доли секунды обязательны, а `date -d ...
# +%s.%N` есть только у GNU coreutils. На стенде это Linux и работало бы,
# но проверять правку критерия 16 полагается офлайн-реплеем на архиве, а
# replay-gate.sh обязан быть переносимым (тот же довод, что у явного
# "$BASH" "$GATE" в нём). С BSD date классификация молча уходила бы в
# «не классифицировано» — то есть реплей на маке показывал бы FAIL там,
# где стенд даёт PASS, и правку 5.9.9.F.1a нечем было бы проверить.
# Целая часть считается date'ом (GNU или BSD), дробная приписывается как
# есть — она не зависит от календаря.
iso_to_epoch() {
    local ts="$1" whole frac e
    [ -z "$ts" ] && return 1
    whole=${ts%%.*}
    whole=${whole%Z}
    frac=""
    case "$ts" in
        *.*) frac=${ts#*.}; frac=${frac%Z} ;;
    esac
    e=$(date -u -d "${whole}Z" +%s 2>/dev/null) || e=""
    if [ -z "$e" ]; then
        e=$(date -u -j -f "%Y-%m-%dT%H:%M:%S" "$whole" +%s 2>/dev/null) || e=""
    fi
    [ -z "$e" ] && return 1
    if [ -n "$frac" ]; then
        printf '%s.%s\n' "$e" "$frac"
    else
        printf '%s\n' "$e"
    fi
}


# sum_metric_delta PATTERN FILE_BASE FILE_FINAL — sums every metric line in
# each file matching the ERE PATTERN and prints (final-sum − base-sum) as an
# integer. Generalizes the base/final-diff idiom criterion 3 introduced for
# a single key, for 5.9.6a/5.9.6b's per-collector sums (plan.md).
sum_metric_delta() {
    local pattern="$1" file_base="$2" file_final="$3"
    # ENVIRON, not -v: patterns here carry \{ to match a literal Prometheus
    # label-brace, and -v assignments run the same backslash-escape
    # processing as an awk string constant — \{ isn't a recognized escape,
    # so every call warned "escape sequence `\{' treated as plain `{'" on
    # stderr (criterion 19 alone calls this 3x per collector per run).
    # ENVIRON entries are plain environment strings, never escape-processed.
    P="$pattern" awk -F'} ' '
        FNR==NR { if ($0 ~ ENVIRON["P"]) base+=$2+0; next }
        { if ($0 ~ ENVIRON["P"]) fin+=$2+0 }
        END { printf "%.0f", fin-base }
    ' "$file_base" "$file_final"
}

GATE_FAILED=0

if ! command -v jq &> /dev/null; then
    echo "jq не найден — run-gate.sh не может проверить критерии" >&2
    exit 2
fi

if [ -z "$TIMESTAMP" ]; then
    latest_state=$(find "$RESULTS_DIR" -maxdepth 1 -name 'baseline-state-*.json' 2>/dev/null | sort | tail -1)
    if [ -z "$latest_state" ]; then
        echo "Не найден baseline-state-*.json в $RESULTS_DIR — укажите TIMESTAMP явно" >&2
        exit 2
    fi
    TIMESTAMP=$(basename "$latest_state" | sed -E 's/baseline-state-(.*)\.json/\1/')
fi

echo "==========================================="
echo "RUN-GATE: TIMESTAMP=$TIMESTAMP RESULTS_DIR=$RESULTS_DIR"
# 5.9.9.Fc (находка №110): окно журнала первой строкой, а не выводом из
# расхождения PASS/SKIP между двумя вызовами гейта (прямой вызов пайплайна
# задаёт AGENT_START_FILE, внутренний вызов из full_run()/run-all-attacks.sh —
# нет). Секция 17 ниже читает ту же переменную.
if [ -s "${AGENT_START_FILE:-}" ]; then
    echo "окно журнала: $(head -1 "$AGENT_START_FILE")"
else
    echo "окно журнала: не задано"
fi
# 5.9.9.F.3e (№136): record_covered ЗДЕСЬ был бы no-op по построению —
# CRITERIA_SELF_IDS/PATTERNS заполняются только ниже, во время загрузки
# criteria-index.txt (строка 343+), и на пустых массивах цикл record_covered
# не проходит ни одной итерации. Вызов перенесён после загрузки индекса (см.
# ниже, сразу после преflight-сверки 5.9.7h) — печать текста осталась здесь,
# первой строкой, только регистрация покрытия сдвинута.
echo "==========================================="
echo ""

baseline_state="$RESULTS_DIR/baseline-state-$TIMESTAMP.json"
final_state="$RESULTS_DIR/final-state-$TIMESTAMP.json"
baseline_health="$RESULTS_DIR/baseline-health-$TIMESTAMP.json"
final_health="$RESULTS_DIR/final-health-$TIMESTAMP.json"
baseline_metrics="$RESULTS_DIR/baseline-metrics-$TIMESTAMP.txt"
final_metrics="$RESULTS_DIR/final-metrics-$TIMESTAMP.txt"
baseline_alerts="$RESULTS_DIR/baseline-alerts-$TIMESTAMP.json"
final_alerts="$RESULTS_DIR/final-alerts-$TIMESTAMP.json"
# 5.9.5b (находка №62): маркер наведённого дропа, написанный run_induced_drop
# (run-all-attacks.sh) — исполнился ли всплеск и был ли во время него замечен
# status=degraded. Опционален: без него критерий 3 просто печатает "не
# исполнялся" в ветке отсутствия дропов, вместо FAIL/SKIP по построению.
induced_drop_marker="$RESULTS_DIR/induced-drop-$TIMESTAMP.txt"
# Маркеры шагов, которые исполняются ВНЕ окна замера (run_ringbuf_overflow,
# контроли DNS, наведённое CPU-давление), пишутся отдельным вызовом
# run-all-attacks.sh со СВОИМ TIMESTAMP, поэтому находятся по маске, а не по
# $TIMESTAMP этого прогона. Выбор — по ИМЕНИ (в имени лежит
# YYYYmmdd_HHMMSS, лексикографический порядок совпадает с хронологическим),
# а не `ls -t` по mtime: на дереве, выгруженном одним `git checkout`
# (офлайн-реплей), все маркеры получают одинаковый mtime, и `ls -t` брал
# первый по алфавиту — то есть САМЫЙ СТАРЫЙ марку, из-за чего критерий 22
# уходил в устаревшую ветку вычета фона вместо formula=closed и валил
# исправный архив. На живом стенде порядок тот же, что давал `ls -t`.
latest_marker() {
    local dir="$1" mask="$2"
    ls -1 "$dir"/$mask 2>/dev/null | LC_ALL=C sort | tail -1
}

# 5.9.9.F.2a (№123): поднята сюда из секции 22 — крит. 18 теперь тоже читает
# этот маркер (run_ringbuf_overflow, SIGSTOP-метод), а не только наведённый
# дроп 5.9.5b, который никогда не был откалиброван на переполнение именно
# ring buffer (долг 5.9.6d). run_ringbuf_overflow переполняет кольцо
# управляемо на каждом архивном прогоне — вторая половина крит. 18 получает
# достижимый PASS вместо постоянного SKIP.
ringbuf_overflow_marker=$(latest_marker "$RESULTS_DIR" 'ringbuf-overflow-*.txt')
# 5.9.9.F.2b (№125): маркер наведённого CPU-давления с выдержкой
# (run_cpu_pressure_control, run-all-attacks.sh) — даёт критерию 14
# достижимую пару reduce↔recover вместо постоянного SKIP. Ищется ПО МАСКЕ,
# а не по $TIMESTAMP этого прогона: шаг идёт ВНЕ окна замера, отдельным
# вызовом run-all-attacks.sh, и пишет маркер со СВОИМ TIMESTAMP — тот же
# приём и та же причина, что у ringbuf-overflow-*.txt выше и у
# dns-{negative,positive}-control-*.txt в секции 5.9.8a. По $TIMESTAMP
# основного прогона этот маркер не нашёлся бы никогда, и критерий 14
# остался бы в SKIP на живом стенде, как будто шаг не запускался.
cpu_pressure_control_marker=$(latest_marker "$RESULTS_DIR" 'cpu-pressure-control-*.txt')
# 5.9.9.Fb (находка №109): регистрация/подтверждение observer_root, написанные
# run-all-attacks.sh (observer_root_register). Даёт критерию 16 времена,
# которых раньше не было ни в одном артефакте: без них секция не может
# отличить «алерт до регистрации корня» и «алерт в окне лага подхвата» от
# «observer_root не подхвачен вовсе» — все три печатались одним текстом.
observer_root_marker="$RESULTS_DIR/observer-root-register-$TIMESTAMP.txt"
# 5.9.8g (находки №95/№96): дерево измерителя run-all-attacks.sh/idle-run.sh —
# инструменты, которые сам харнесс порождает в прологе, периодических срезах и
# постобработке, не список "подозрительных" comm. Выведен ИЗ ДАННЫХ (разбор
# слепого окна №2.9.6), не из чтения тела функций. Хоистится на уровень
# скрипта (было локально внутри критерия 16): 5.9.9.Fd использует тот же
# список для разбора окна атаки, а не только критерий 16 — окно idle-конец →
# attack-baseline.
harness_comms='bash sh curl jq grep awk sed cat cut tr head tail wc sort seq sleep date rm ps dirname basename mktemp stat systemctl tar journalctl du'
# The manifest is written by the four attack sub-scripts next to the scripts
# themselves, so anchor to this script's directory rather than deriving a path
# from RESULTS_DIR or the working directory (plan.md волна 1.5g).
GATE_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
manifest_file="$GATE_SCRIPT_DIR/attack-manifest.json"
# Зафиксированный состав типов детекта для критерия 6 (волна 5.3).
baseline_types_file="$GATE_SCRIPT_DIR/detection-baseline.txt"
# Разметка "фоновых" правил для критерия 6 (волна 5.8a, находка №22).
background_rules_file="$GATE_SCRIPT_DIR/background-rules.txt"
# Явный список "намеренно вне базы" для критерия 6 — правила, которым нечем
# сработать на этом стенде вообще, ни на простое, ни под атакой (волна 5.9g,
# находка №33). Отдельно от background_rules_file: там вторая попытка по
# idle-приросту, здесь её нет смысла давать — idle-прирост тоже будет нулевым.
intentional_loss_file="$GATE_SCRIPT_DIR/intentional-loss.txt"
# 5.9.5d (находка №63): реестр правил, немых за весь аптайм агента с
# установленной причиной (волна 5.9.4h) — до этой правки критерий 6 его не
# читал вовсе, так что правило, уже объяснённое здесь категорией (а)/(б),
# всё равно засчитывалось критерием 6 как непонятная потеря, хотя секция
# 5.9.4h ниже уже печатала для него причину. Тот же файл, читается тем же
# способом (comm -12), что и intentional_loss_file.
silent_rules_file="$GATE_SCRIPT_DIR/silent-rules.txt"
# 5.9.7f (находка №83): реестр объяснённых DNS-FP на idle — тот же формат,
# что silent-rules.txt (`<rule_id> <comm> <категория>`). Прирост четырёх
# long-label правил за idle-час обязан быть 0 либо каждый экземпляр иметь
# строку здесь; пустой реестр и ненулевой прирост — FAIL этой секции.
dns_idle_fp_file="$GATE_SCRIPT_DIR/dns-idle-fp.txt"
# 5.9.6f (находка №75): база реестра сама по себе не устаревает молча —
# нужно ловить, когда расхождение «прогон vs база» держится два замера
# подряд (значит, никто её не обновил, а не что она разово другая на этом
# прогоне). Состояние — сигнатура прошлого прогона, а не сам гейт: файл
# перезаписывается каждым запуском и в git не попадает (та же схема, что у
# attack-manifest.json — см. .gitignore), поэтому сравнение работает только
# при последовательных прогонах на одном стенде/чекауте.
diff_state_file="$GATE_SCRIPT_DIR/detection-baseline-diff-state.txt"
# Снимки /metrics idle-часа (idle-run.sh), опционально — только они дают
# критерию 6 вторую сторону измерения для фоновых правил (5.8a).
IDLE_METRICS_START="${IDLE_METRICS_START:-}"
IDLE_METRICS_END="${IDLE_METRICS_END:-}"
# 5.9f (находка №32): состояние idle-run.sh на момент его завершения
# (state-end.json — тот же /debug/state, что и baseline/final здесь), нужно
# только для критерия 16 (слепое окно между idle-часом и attack-baseline).
# Опционально — без него критерий 16 печатает SKIP, остальные 15 не страдают.
IDLE_STATE_END="${IDLE_STATE_END:-}"
# 5.9.4g (находка №58): снимок /api/v1/alerts на конец idle-часа
# (alerts-end.json — idle-run.sh уже пишет его сам). Нужен, чтобы критерий 16
# считал объём слепого окна по множеству `id`, а не по кумулятивному счётчику
# ebpf_guard_alerts_total — тот обнуляется рестартом агента в конце
# idle-run.sh (P0-3) и на №2.9.3 давал отрицательную/вырожденную дельту.
# Опционально — без него критерий 16 печатает SKIP по объёму (длительность
# окна печатается и без него).
IDLE_ALERTS_END="${IDLE_ALERTS_END:-}"
# 5.9.9.F.1d (находка №115): срез алертов на НАЧАЛО idle-часа. Пайплайн
# экспортировал его и раньше, гейт не читал — без него разбор дельты
# idle-часа по comm провести не на чем.
IDLE_ALERTS_START="${IDLE_ALERTS_START:-}"
# 5.9.7f (находка №83): снимок /api/v1/alerts на НАЧАЛО idle-часа
# (alerts-start.json — idle-run.sh уже пишет его сам, см. idle-run.sh).
# Нужен только для разбивки прироста DNS long-label правил по comm — без
# него секция печатает SKIP по разбивке, но прирост по метрике всё равно
# считается (IDLE_METRICS_START/END).
IDLE_ALERTS_START="${IDLE_ALERTS_START:-}"

# 5.9.7h (находка №83, P2): преflight — сверка criteria-index.txt, ДО того,
# как гейт начнёт читать снимки прогона. Реестр называет id пункта
# постановки, файл и паттерн; паттерн обязан реально встретиться в файле —
# иначе пункт постановки есть, а машинной печати для него нет, и это в
# точности то, что случилось с п.8 постановки №2.9.6 и было замечено не
# гейтом, а ручным разбором задним числом. Один из трёх жёстких стопов
# преflight'а волны 5.9.7 (два других — replay-gate.sh на архивах и
# отдельное окно run_ringbuf_overflow — вне run-gate.sh).
CRITERIA_INDEX_FILE="$GATE_SCRIPT_DIR/criteria-index.txt"
uncovered_criteria_count=0
uncovered_criteria_ids=""
if [ -f "$CRITERIA_INDEX_FILE" ]; then
    while IFS=$'\t' read -r ci_id ci_file ci_pattern; do
        [ -z "$ci_id" ] && continue
        case "$ci_id" in "#"*) continue ;; esac
        [ -z "$ci_pattern" ] && continue
        if [ "$ci_file" = "-" ]; then
            ci_target="${BASH_SOURCE[0]}"
            # 5.9.9e: те же строки, но для рантайм-сверки «ветка реально
            # исполнилась», не только «код для неё есть» (см. record_covered).
            CRITERIA_SELF_IDS+=("$ci_id")
            CRITERIA_SELF_PATTERNS+=("$ci_pattern")
        else
            ci_target="$GATE_SCRIPT_DIR/$ci_file"
        fi
        if [ ! -f "$ci_target" ] || ! grep -qF -- "$ci_pattern" "$ci_target"; then
            uncovered_criteria_count=$((uncovered_criteria_count + 1))
            uncovered_criteria_ids="$uncovered_criteria_ids $ci_id"
        fi
    done < "$CRITERIA_INDEX_FILE"
    if [ "$uncovered_criteria_count" -gt 0 ]; then
        echo "ПРЕФЛАЙТ FAIL (5.9.7h, №83): непокрытых пунктов постановки: $uncovered_criteria_count ($uncovered_criteria_ids) — секции в гейте нет, цепочка остановлена до чтения снимков прогона" >&2
        exit 3
    fi
    echo "преflight (5.9.7h): criteria-index.txt сверен, непокрытых пунктов постановки: 0"
    # 5.9.9.F.3e (№136): регистрация покрытия «окно журнала:», отложенная
    # с самой первой строки вывода (см. комментарий там) — CRITERIA_SELF_*
    # заполнены строкой выше, вызов больше не no-op.
    record_covered "окно журнала:"
else
    # Реестр отсутствует — это не "0 непокрытых", это "сверка не
    # выполнялась", и финальная строка гейта обязана отличать одно от
    # другого (см. итог ниже): -1 читается там как "не проверено", не PASS.
    uncovered_criteria_count=-1
    echo "преflight (5.9.7h): $CRITERIA_INDEX_FILE не найден — сверка пунктов постановки не выполнена" >&2
fi
echo ""

for f in "$baseline_state" "$final_state" "$baseline_metrics" "$final_metrics" "$baseline_alerts" "$final_alerts"; do
    if [ ! -f "$f" ]; then
        echo "Отсутствует ожидаемый файл прогона: $f" >&2
        exit 2
    fi
done

# 1. Потери network / dns — ноль (сумма по reason=ringbuf_to_router и
# reason=router_to_queue, plan.md 1.5c).
echo "=== 1. Потери network / dns ==="
for etype in network dns; do
    dropped=$(grep "ebpf_guard_events_dropped_total{" "$final_metrics" | grep "collector=\"$etype\"" \
        | awk -F'} ' '{sum += $2} END {print sum+0}')
    if [ "${dropped%.*}" -eq 0 ] 2>/dev/null; then
        pass "$etype: потерь 0"
    else
        fail "$etype: потеряно $dropped событий (ожидалось 0)"
    fi
done
echo ""

# 2. DNS-события: активная проверка, что коллектор видит резолвинг, ПЛЮС
# проверка периодической слепоты за весь прогон (5.7d, находка №16).
#
# В замере №1 атаки шли на localhost:3000 — резолвинг не нужен, поэтому
# предыдущая формулировка ("растёт на сотни") давала FAIL при +2, хотя
# сам коллектор рабочий (вопрос 3 закрыт диагностикой на стенде: dig даёт
# прирост). Гейт сам шлёт dig example.com @8.8.8.8 (путь sendto) и требует,
# чтобы events_total{dns} вырос хотя бы на 1. Без dig, без сети или без
# доступа к API — SKIP с явной записью, а не FAIL: критерий непроверяем по
# построению, не провален (план 1.75c).
#
# 5.7d добавила вторую часть: "выросли на N после дига" — точечная проверка,
# не ловит пятиминутные окна слепоты между дигами (находка №16 — коллектор
# слеп 5 минут и оживает сам, "растёт на 5" проходит и при провале, и без
# него). ebpf_guard_dns_collector_stale_transitions_total — монотонный
# счётчик входов в состояние "нет событий дольше dnsStaleThreshold",
# читается из final_metrics и покрывает весь прогон целиком, а не момент
# снятия снимка.
echo "=== 2. DNS-события: активная проверка коллектора + периодическая слепота ==="
if ! command -v dig &> /dev/null; then
    skip "dig не найден — DNS-проверка пропущена (установить dnsutils для активной проверки)"
elif [ -z "$EBPF_GUARD_TOKEN" ]; then
    skip "EBPF_GUARD_TOKEN пуст — DNS-проверка пропущена (нет доступа к /metrics)"
elif ! curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/health" 2>/dev/null | grep -q "200"; then
    skip "ebpf-guard API недоступен на $EBPF_GUARD_API — DNS-проверка пропущена"
else
    dns_metric_before=$(curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/metrics" \
        | grep 'ebpf_guard_events_total{' | grep 'type="dns"' | awk -F'} ' '{sum+=$2} END{print sum+0}')
    # Несколько резолвов разными путями: @8.8.8.8 (sendto), системный (connect+
    # write через nss), localhost (Docker 127.0.0.11). Если хоть один путь
    # виден коллектору — прирост будет.
    for target in "@8.8.8.8" "" "@127.0.0.11"; do
        dig +short +time=2 +tries=1 example.com $target >/dev/null 2>&1 || true
    done
    sleep 1  # дать коллектору такт на обработку
    dns_metric_after=$(curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/metrics" \
        | grep 'ebpf_guard_events_total{' | grep 'type="dns"' | awk -F'} ' '{sum+=$2} END{print sum+0}')
    dns_delta=$(awk -v a="$dns_metric_after" -v b="$dns_metric_before" 'BEGIN{print a-b}')
    if awk -v d="$dns_delta" 'BEGIN{exit !(d>=1)}'; then
        pass "dns events_total выросли на $dns_delta после активного резолвинга"
    else
        fail "dns events_total не вырос после dig (delta=$dns_delta) — коллектор слеп на резолвинг (см. вопрос 3: systemd-resolved/nss-пути)"
    fi
fi

# 5.8c (продолжение находки №16): stale_transitions на этом стенде не отличает
# «коллектор слеп» от «хост тихий» — idle-час замера №2.4 дал 36 dns-событий
# (~0.6/мин), то есть пятиминутные паузы между резолвами НОРМАЛЬНЫ здесь. FAIL
# по этому счётчику на такой базе гарантированно ложный, поэтому он снят в
# наблюдение без порога; активная проверка выше (dig + прирост events_total)
# остаётся единственным PASS/FAIL для этого критерия. Порог по слепоте
# вернуть, когда появится стенд с постоянным DNS-фоном (волна 6.3).
if [ ! -f "$final_metrics" ]; then
    skip "нет final_metrics — наблюдение периодической тишины DNS пропущено"
else
    dns_stale_transitions=$(grep '^ebpf_guard_dns_collector_stale_transitions_total' "$final_metrics" \
        | awk '{print $2+0}')
    if [ -z "$dns_stale_transitions" ]; then
        skip "ebpf_guard_dns_collector_stale_transitions_total не найден в final_metrics — сборка агента старее 5.7d?"
    elif [ "${dns_stale_transitions%.*}" -eq 0 ] 2>/dev/null; then
        echo "    (наблюдение) dns_collector_stale_transitions_total = 0 — окон тишины дольше порога не было"
    else
        dns_events_final=$(grep '^ebpf_guard_events_total{' "$final_metrics" 2>/dev/null \
            | grep 'type="dns"' | awk -F'} ' '{sum+=$2} END{print sum+0}')
        echo "    (наблюдение, без PASS/FAIL — см. 5.8c) dns_collector_stale_transitions_total = $dns_stale_transitions за прогон; всего dns-событий: ${dns_events_final:-n/a}. На тихом стенде это ожидаемо; разбирать по журналу (WARN silent_for/last_seen) только если dns-событий за прогон много, а транзиций тоже много."
    fi
fi
echo ""

# 3. Деградация в /health видна при любых НЕПРЕДНАМЕРЕННЫХ потерях.
# Волна 5.3 (находка №4 замера №2): reason="path_denylist" исключён из суммы.
# Это не потеря видимости, а сработавший по конфигу фильтр — приёмка 4.3 по
# построению требует, чтобы дропы по нему были НЕ нулевые, поэтому старая
# формулировка ломала критерий 3 на каждом прогоне, где фильтр вообще работал
# (замер №2: 25 дропов при status=healthy → FAIL при исправном агенте).
# Величина всё равно печатается и проверяется отдельно — критерием 13.
#
# Волна 5.9b (находка №30): 5.3 читала final_metrics как есть — кумулятивный
# счётчик с момента старта процесса агента, а не с начала ЭТОГО прогона. Любые
# дропы, накопленные до baseline-снимка (idle-час до прогона, предыдущий
# attack-прогон без рестарта агента), уже делали any_dropped_total > 0 ДО
# первой атаки, и критерий 3 требовал status=degraded с самого начала —
# структурно непроходим на любом стенде без гарантированного рестарта агента
# перед каждым прогоном. Считаем как ΔΣ = final − baseline ПО КАЖДОМУ
# лейблсету (кроме reason="path_denylist"), суммируя только положительные
# дельты — это то же измерение, которым проверяется предсказание волны 5.9
# на данных №2.5 (374 = 374 → PASS).
#
# 5.9.4d (находка №55): "потери есть → требуем degraded В ФИНАЛЬНОМ СНИМКЕ"
# ловит только флаг, залипший до конца прогона — если агент перешёл в
# degraded и вернулся в healthy ДО снятия final_health (регулятор отработал,
# как и должен), критерий печатал FAIL за штатное поведение: потери были,
# видимость восстановлена, а формулировка требовала видеть деградацию именно
# в срезе. Источник истины — переход, а не мгновенный снимок: cmd/ebpf-guard/
# main.go пишет slog "visibility reduced: a priority queue is dropping events"
# при входе в degraded и "visibility restored: ..." при выходе (обе строки
# существуют с P0-25/5.9.2a, до этой правки их не читал никто). Гейт считает
# такие записи в журнале agent-сервиса за окно baseline→final; это дешевле,
# чем заводить отдельный экспортируемый счётчик переходов (второй вариант из
# постановки 5.9.4d), и ничего не требует от продукта. Финальный флаг
# по-прежнему проверяется — но только на противоположную ошибку, "залипание
# ВКЛ": дропов не было вовсе, а /health всё равно показывает
# visibility_reduced=true.
echo "=== 3. Деградация в /health при потерях (переход в degraded — 5.9.4d) ==="
if [ -f "$final_health" ]; then
    any_dropped_total=$(awk -F'} ' '
        FNR==NR { if ($0 !~ /reason="path_denylist"/) base[$1]=$2+0; next }
        { if ($0 !~ /reason="path_denylist"/) { fin[$1]=$2+0; keys[$1]=1 } }
        END {
            total=0
            for (k in keys) {
                b = (k in base) ? base[k] : 0
                d = fin[k] - b
                if (d > 0) total += d
            }
            printf "%d", total
        }
    ' <(grep 'ebpf_guard_events_dropped_total{' "$baseline_metrics") \
      <(grep 'ebpf_guard_events_dropped_total{' "$final_metrics"))
    intentional_drops=$(grep 'ebpf_guard_events_dropped_total{' "$final_metrics" \
        | grep 'reason="path_denylist"' | awk -F'} ' '{sum+=$2} END{print sum+0}')
    echo "  непреднамеренных дропов за прогон (Δ final-baseline): $any_dropped_total; намеренных за весь аптайм агента (path_denylist, кумулятив): ${intentional_drops%.*} — в критерий не входят"
    visibility_reduced=$(jq -r '.visibility_reduced // false' "$final_health" 2>/dev/null)
    status=$(jq -r '.status // "unknown"' "$final_health" 2>/dev/null)

    # Окно прогона — те же .timestamp снимков /debug/state, что критерий 6
    # использует для темпа алертов ниже; читаются здесь заново (а не через
    # переменную из критерия 6), потому что критерий 3 по порядку идёт раньше.
    degraded_journal_checked=0
    degraded_transitions=0
    if command -v jq &> /dev/null && command -v journalctl &> /dev/null; then
        c3_baseline_ts=$(jq -r '.timestamp // empty' "$baseline_state" 2>/dev/null)
        c3_final_ts=$(jq -r '.timestamp // empty' "$final_state" 2>/dev/null)
        if [ -n "$c3_baseline_ts" ] && [ -n "$c3_final_ts" ]; then
            c3_since=$(date -d "$c3_baseline_ts" +"%Y-%m-%d %H:%M:%S" 2>/dev/null)
            # +15с запаса на конце окна. Наведённый дроп (5.9.5b) стоит
            # последним шагом перед финальным снимком, а WARN о переходе пишет
            # секундный тикер — то есть строка всегда ложится на границу окна.
            # На №2.9.5 она легла в ту же секунду, что и снимок, и на 260 мс
            # РАНЬШЕ него (журнал 09:28:41.024, снимок 09:28:41.284), но
            # `--until` у journalctl режет по целой секунде и эту секунду
            # исключает: критерий напечатал "переходов 0" и провалил прогон,
            # имея доказательство перехода в собственном журнале. Запас берётся
            # только на конце и только вперёд — событий после финального снимка
            # ничего, кроме этого же наведённого дропа, породить не может.
            c3_until=$(date -d "$c3_final_ts + 15 seconds" +"%Y-%m-%d %H:%M:%S" 2>/dev/null)
            if [ -n "$c3_since" ] && [ -n "$c3_until" ]; then
                degraded_journal=$(journalctl -u "${EBPF_GUARD_SERVICE_UNIT:-ebpf-guard-test.service}" \
                    --since "$c3_since" --until "$c3_until" 2>/dev/null)
                if [ $? -eq 0 ]; then
                    degraded_journal_checked=1
                    degraded_transitions=$(echo "$degraded_journal" \
                        | grep -c "visibility reduced: a priority queue is dropping events" || true)
                fi
            fi
        fi
    fi

    if awk -v d="$any_dropped_total" 'BEGIN{exit !(d>0)}'; then
        if [ "$degraded_journal_checked" -eq 1 ]; then
            echo "  переходов в degraded за окно прогона (журнал $c3_since .. $c3_until): $degraded_transitions"
            # Маркер наведённого дропа — второй, независимый источник того же
            # факта: run_induced_drop опрашивает /health во время всплеска и
            # пишет degraded_seen=1 только при реально увиденном status=
            # degraded. Постановка 5.9.5b требует НАБЛЮДАВШЕГОСЯ перехода, а
            # опрос /health — это и есть наблюдение; журнальная строка лишь
            # его лог. Читается, когда журнал перехода не показал: иначе
            # прогон валится из-за границы окна при исправном механизме.
            c3_induced_executed=0
            c3_induced_degraded=0
            if [ -f "$induced_drop_marker" ]; then
                c3_induced_executed=$(awk -F= '$1=="executed"{print $2+0}' "$induced_drop_marker" 2>/dev/null)
                c3_induced_degraded=$(awk -F= '$1=="degraded_seen"{print $2+0}' "$induced_drop_marker" 2>/dev/null)
            fi
            if [ "$degraded_transitions" -gt 0 ]; then
                pass "потери есть ($any_dropped_total) и в журнале зафиксирован переход в degraded ($degraded_transitions раз, 5.9.4d)"
            elif [ "${c3_induced_executed:-0}" -eq 1 ] && [ "${c3_induced_degraded:-0}" -eq 1 ]; then
                pass "потери есть ($any_dropped_total); журнал перехода за окно не показал, но наведённый дроп (5.9.5b) наблюдал status=degraded опросом /health — механизм проверен управляемым входом"
            else
                fail "потери есть ($any_dropped_total), но перехода в degraded не видели ни в журнале за окно прогона, ни опросом /health во время наведённого дропа (5.9.4d/5.9.5b); наведённый дроп: исполнен=${c3_induced_executed:-0}, degraded=${c3_induced_degraded:-0}; финальный флаг для справки: visibility_reduced=$visibility_reduced status=$status"
            fi
        else
            # Журнал недоступен (не root / нет journalctl / нет .timestamp) —
            # резервная проверка по финальному флагу, как до 5.9.4d. Слабее:
            # не отличает "деградация ещё идёт" от "уже восстановилась и
            # снимок этого не увидел", но лучше, чем непроверяемый критерий.
            warn "журнал agent-сервиса недоступен для проверки перехода (5.9.4d) — резервная проверка по финальному флагу"
            if [ "$visibility_reduced" = "true" ] && [ "$status" = "degraded" ]; then
                pass "потери есть ($any_dropped_total) и /health показывает degraded (резервная проверка)"
            else
                fail "потери есть ($any_dropped_total), но /health: visibility_reduced=$visibility_reduced status=$status (резервная проверка, журнал недоступен)"
            fi
        fi
    else
        # Дропов не было вовсе — единственное, что здесь может быть неверно,
        # это залипший флаг ("залипание ВКЛ"): visibility_reduced=true без
        # единой причины. Обратное залипание (флаг молчит при дропах) выше
        # уже покрыто веткой any_dropped_total>0.
        if [ "$visibility_reduced" = "true" ]; then
            fail "потерь нет, но /health.visibility_reduced=true — флаг залип (5.9.4d)"
        else
            # 5.9.5b (находка №62): нулевые дропы на №2.9.3/№2.9.4 чередовались
            # со случаем, а не с работающим фильтром — "PASS: проверка
            # неприменима" читалось как "критерий пройден", хотя механизм не
            # проверялся ни разу. Печатаем SKIP и явно — был ли исполнен
            # наведённый дроп (run_induced_drop), чтобы "не проверено" было
            # строкой отчёта, а не молчанием под маской PASS.
            induced_executed=0
            induced_degraded=0
            induced_rounds="n/a"
            induced_pressure_before="n/a"
            induced_pressure_after="n/a"
            induced_bounded_files="n/a"
            induced_settle_reason="n/a"
            induced_drop_total="n/a"
            if [ -f "$induced_drop_marker" ]; then
                induced_executed=$(awk -F= '$1=="executed"{print $2+0}' "$induced_drop_marker" 2>/dev/null)
                induced_degraded=$(awk -F= '$1=="degraded_seen"{print $2+0}' "$induced_drop_marker" 2>/dev/null)
                induced_rounds=$(awk -F= '$1=="rounds"{print $2}' "$induced_drop_marker" 2>/dev/null)
                induced_pressure_before=$(awk -F= '$1=="cpu_pressure_level_before"{print $2}' "$induced_drop_marker" 2>/dev/null)
                induced_pressure_after=$(awk -F= '$1=="cpu_pressure_level_after"{print $2}' "$induced_drop_marker" 2>/dev/null)
                induced_bounded_files=$(awk -F= '$1=="bounded_files"{print $2}' "$induced_drop_marker" 2>/dev/null)
                induced_settle_reason=$(awk -F= '$1=="settle_reason"{print $2}' "$induced_drop_marker" 2>/dev/null)
                induced_drop_total=$(awk -F= '$1=="induced_drop_total"{print $2}' "$induced_drop_marker" 2>/dev/null)
            fi
            echo "  наведённый дроп (5.9.5b): исполнен=${induced_executed:-0}, degraded зафиксирован во время всплеска=${induced_degraded:-0}, раундов=${induced_rounds:-n/a}"
            # 5.9.6d (находка №73, P1): всплеск теперь ограничен списком файлов
            # (bounded_files, не весь /usr), а снимок этой секции (final-health)
            # снимается после затухания прироста дропов (settle_reason), а не
            # сразу за концом всплеска — величина потери, которую этот вход
            # стоил критерию 3, печатается числом, а не только выводится из
            # журнала постфактум, как на №2.9.5.
            echo "  наведённый дроп (5.9.6d): ограничен ${induced_bounded_files:-n/a} файлами, снимок отложен до «${induced_settle_reason:-n/a}», потеряно всего (fileaccess, все хопы) = ${induced_drop_total:-n/a}"
            # cpu_pressure_level (0=норма, 1=file_sampling_reduced,
            # 2=all_noisy_sampling_reduced) отвечает на вопрос, почему всплеск
            # мог не дать дропа: пока регулятор держит пониженную выборку
            # файловых событий (min_dwell 180с после срабатывания), уронить
            # bulk-очередь нечем по построению — и это работающий регулятор, а
            # не непроверенный фильтр. Замерено на стенде 2026-08-21: после
            # часа нагрузки level=1, и всплеск перестал давать прирост
            # events_dropped_total вовсе.
            echo "  cpu_pressure_level до/после всплеска: ${induced_pressure_before:-n/a}/${induced_pressure_after:-n/a} (1 или 2 = выборка снижена регулятором, дроп навести нельзя)"
            skip "механизм не проверен — потерь за прогон нет (5.9.5b); /health status=$status"
        fi
    fi
else
    fail "final-health-$TIMESTAMP.json отсутствует"
fi
echo ""

# 4. comm в инцидентах непустой во всех.
echo "=== 4. comm в инцидентах ==="
final_incidents="$RESULTS_DIR/final-incidents-$TIMESTAMP.json"
if [ ! -f "$final_incidents" ]; then
    fail "final-incidents-$TIMESTAMP.json не собран — критерий P1-27 не проверен"
elif ! jq -e 'type == "array"' "$final_incidents" >/dev/null 2>&1; then
    # /api/v1/incidents answers 503 with a plain-text body when incident
    # tracking is not configured. Without this branch jq would fail, the
    # `|| echo` fallbacks would yield 0, and the criterion would report PASS
    # for a run that tracked no incidents at all.
    fail "final-incidents-$TIMESTAMP.json не является JSON-массивом (вероятно 503 — incident tracking выключен): $(head -c 120 "$final_incidents")"
else
    total_incidents=$(jq 'length' "$final_incidents")
    empty_comm=$(jq '[.[] | select(.comm == "" or .comm == null)] | length' "$final_incidents")
    if [ "$total_incidents" -eq 0 ]; then
        # Zero incidents cannot demonstrate that comm is populated. Under a
        # 15-minute attack run this is itself a finding (wave 2 expects at
        # least one incident on a real attacker), so it is not a silent pass.
        fail "инцидентов нет вовсе — критерий 'comm непустой' непроверяем на этом прогоне"
    elif [ "$empty_comm" -eq 0 ]; then
        pass "все $total_incidents инцидентов имеют непустой comm"
    else
        fail "$empty_comm из $total_incidents инцидентов с пустым comm"
    fi
fi
# 5.9h (находка №33): критерий 4 покрывал только инциденты (IncidentTracker
# сворачивает цепочку алертов и сам подставляет leaf comm — pkg/types/incident.go),
# а не сами алерты в сторе. 15 алертов с пустым comm на замере №2.5 не поймал ни
# один критерий — ни этот (смотрит инциденты), ни 12-й (смотрит серии профайлера,
# другой набор меток). Тот же порог 0, что и у инцидентов выше.
if [ -f "$final_alerts" ] && jq -e 'type == "array"' "$final_alerts" >/dev/null 2>&1; then
    total_alerts_comm=$(jq 'length' "$final_alerts")
    empty_comm_alerts=$(jq '[.[] | select(.comm == "" or .comm == null)] | length' "$final_alerts")
    if [ "$total_alerts_comm" -eq 0 ]; then
        skip "алертов нет вовсе — 'comm непустой в алертах' непроверяем на этом прогоне"
    elif [ "$empty_comm_alerts" -eq 0 ]; then
        pass "все $total_alerts_comm алертов в сторе имеют непустой comm"
    else
        fail "$empty_comm_alerts из $total_alerts_comm алертов в сторе с пустым comm"
    fi
else
    skip "final-alerts-$TIMESTAMP.json отсутствует или не JSON-массив — 'comm непустой в алертах' не проверен"
fi
echo ""

# 5. jq . FINAL-REPORT.json проходит.
echo "=== 5. FINAL-REPORT.json валиден ==="
json_report="$RESULTS_DIR/FINAL-REPORT-$TIMESTAMP.json"
if [ -f "$json_report" ] && jq empty "$json_report" 2>/dev/null; then
    pass "FINAL-REPORT-$TIMESTAMP.json — валидный JSON"
else
    fail "FINAL-REPORT-$TIMESTAMP.json отсутствует или невалиден"
fi
echo ""

# 5.9.6h (находка №76): rule_id'ы, чей прирост попадает целиком в слепое
# окно idle-конец → attack-baseline (критерий 16 ниже измеряет только его
# ОБЪЁМ, не состав). Тот же расчёт "новое в baseline_alerts, чего не было в
# IDLE_ALERTS_END" критерий 16 уже делает по .id для темпа окна; здесь —
# то же множество, но по .rule_id, чтобы критерий 6 мог заменить "фаза не
# определена" на третью фазу ("gap") везде, где прирост объясняется именно
# этим окном, а не отсутствием измерения. Опционально — без IDLE_ALERTS_END
# gap_rule_ids остаётся пустым и обе секции ведут себя как раньше (5.9.6h
# не может СУЗИТЬ множество "фаза не определена" без данных, но не проваливает
# остальное).
gap_rule_ids=""
# Инициализация здесь, а не только внутри критерия 6, — под `set -u` крит.
# 16 читает эту переменную, а критерий 6 присваивает её лишь в ветке
# added_count>0; без дефолта здесь запуск с added_count=0 падал бы на
# необъявленной переменной, а не печатал бы честный SKIP/PASS.
added_undetermined_count=0
# added_types_analyzed=1 означает "критерий 6 действительно разбирал прирост
# типов по фазам", а не "прироста не было". Без этого различия критерий 16
# ниже печатал PASS «у каждого добавленного типа определена фаза» и при
# added_count=0, где добавленных типов нет вовсе — то есть PASS
# ненаступлением события, ровно тот дефект, который 5.9.6i (№77) выносит из
# гейта. А added_count=0 — это ОЖИДАЕМЫЙ исход №2.9.6 после обновления базы
# в 5.9.6f, то есть ветка сработала бы именно на том прогоне, ради которого
# написана.
added_types_analyzed=0
# 5.9.7g (находка №84): added_types_analyzed различает "прироста не было" от
# "критерий 6 вообще не смог его посчитать", но крит. 16 ниже нужно ТРЕТЬЕ
# состояние — "added_count известен и меньше трёх" — которое не совпадает ни
# с одним из первых двух (added_count=0 тоже < 3, но при отсутствующей базе
# added_count не существует вовсе). baseline_types_present закрывает этот
# зазор: 1 означает "detection-baseline.txt читался, added_count достоверен".
baseline_types_present=0
added_count=0
if [ -n "$IDLE_ALERTS_END" ] && [ -s "$IDLE_ALERTS_END" ] && [ -s "$baseline_alerts" ] \
    && jq -e 'type == "array"' "$IDLE_ALERTS_END" >/dev/null 2>&1 \
    && jq -e 'type == "array"' "$baseline_alerts" >/dev/null 2>&1; then
    gap_rule_ids=$(jq -r -n --slurpfile a "$baseline_alerts" --slurpfile b "$IDLE_ALERTS_END" '
        ($b[0] | map(.id)) as $seen
        | ($a[0] | map(select(.id as $i | ($seen | index($i)) | not)) | map(.rule_id) | map(select(. != null)))
        | unique | .[]' 2>/dev/null | sort -u)
fi

# 6. Детект жив: >= 43 типов + темп алертов от атакующих >= 74/мин.
# Абсолютный порог 850 (бывшая формулировка) привязан к длине окна: замер №1
# дал 490 за 8.2 мин и FAIL, хотя темп 111/мин против 74 в прогоне №4 — рост,
# а не просадка. Темп нормирует на окно и сравним между прогонами разной
# длины (план 1.75c). docker-proxy (402 алерта замера №1) теперь в манифесте
# с transit:true — без него множество атакующих comms занижало темп вдвое.
echo "=== 6. Детект жив (типы атак, темп алертов от атакующих) ==="

attacker_alerts=0
attacker_alerts_known=1
if [ -f "$manifest_file" ]; then
    attacker_comms=$(jq -c '[.[].comm] | unique' "$manifest_file" 2>/dev/null || echo '[]')
    attacker_alerts=$(jq -s --argjson comms "$attacker_comms" '
        (.[0] // []) as $baseline | (.[1] // []) as $final |
        ($baseline | map(.id) | unique) as $bids |
        ($final | map(select(.id as $id | ($bids | index($id)) | not))) as $new |
        $new | map(select(.comm as $c | $comms | index($c))) | length
    ' -r "$baseline_alerts" "$final_alerts" 2>/dev/null || echo 0)
else
    warn "attack-manifest.json не найден — алерты от атакающих процессов не посчитаны"
    # Без манифеста множество атакующих comms неизвестно, поэтому темп
    # непроверяем, а не равен нулю. Печатать здесь FAIL "0/мин" — ровно тот
    # класс дефекта, ради которого заведена волна 1.75 (отчёт печатает провал
    # там, где критерий не измерен). Отмечаем флагом → SKIP ниже.
    attacker_alerts_known=0
fi

# Время окна = delta timestamp из /debug/state (поле .timestamp у DebugState).
# Файлы baseline-state и final-state снимаются в начале и в конце прогона.
# Это ПОЛНОЕ окно пайплайна (baseline→final) — 5.9.7d держит его только как
# справочную величину рядом, темп в вердикт делится не на неё (см. ниже).
runtime_min=0
if command -v jq &> /dev/null; then
    b_ts=$(jq -r '.timestamp // empty' "$baseline_state" 2>/dev/null)
    f_ts=$(jq -r '.timestamp // empty' "$final_state" 2>/dev/null)
    if [ -n "$b_ts" ] && [ -n "$f_ts" ]; then
        # date -d понимает ISO 8601 с миллисекундами/таймзоной; awk делает
        # деление на 60 для минут (с дробной частью).
        b_epoch=$(iso_to_epoch "$b_ts" || echo 0)
        f_epoch=$(iso_to_epoch "$f_ts" || echo 0)
        runtime_min=$(awk -v b="$b_epoch" -v f="$f_epoch" 'BEGIN{ if(b>0 && f>b) print (f-b)/60; else print 0 }')
    fi
fi
if ! awk -v r="$runtime_min" 'BEGIN{exit !(r>0)}'; then
    # Fallback: mtime файлов состояния — менее точно, но работает, если
    # DebugState.timestamp отсутствует (старая сборка агента).
    b_mt=$(stat -c %Y "$baseline_state" 2>/dev/null || stat -f %m "$baseline_state" 2>/dev/null || echo 0)
    f_mt=$(stat -c %Y "$final_state" 2>/dev/null || stat -f %m "$final_state" 2>/dev/null || echo 0)
    runtime_min=$(awk -v b="$b_mt" -v f="$f_mt" 'BEGIN{ if(b>0 && f>b) print (f-b)/60; else print 0 }')
fi

# 5.9.7d (№80, P1): темп делится на ОКНО АТАКИ, а не на длину всего
# пайплайна. runtime_min выше (baseline→final) включает режимы
# run_counting_control, kill-сценарий, наведённый дроп и снятие метрик — ни
# один из них не отправляет трафик атаки, и удлинение любого из них раньше
# просаживало темп детекта без единой реальной потери (находка №80: 64.0/мин
# по полному окну против 74/мин, хотя срабатывания не терялись).
# attack-window-$TIMESTAMP.txt пишется run-all-attacks.sh: каждый шаг,
# реально отправляющий трафик атаки, помечает first/last сам (mark_attack_window),
# так что гейт не вычисляет границы по именам функций — новый шаг,
# добавленный позже, попадёт в окно автоматически, если сам вызовет метку.
attack_window_marker="$RESULTS_DIR/attack-window-$TIMESTAMP.txt"
attack_window_min=0
attack_window_known=0
# 5.9.8e (№90, P1): SKIP по этому пункту раньше называл одну причину
# («сборка харнесса старее 5.9.7d») для трёх разных ситуаций: маркера нет
# файлом, маркер есть, но пуст, и маркер есть и непуст, но first/last не
# разобрались (или разобрались в невалидное окно) — последнее ровно то, что
# происходило из-за дефекта OFMT ниже, и никак не было связано со старой
# сборкой харнесса. Причина теперь различается явно.
attack_window_reason="marker_missing"
if [ -f "$attack_window_marker" ]; then
    if [ ! -s "$attack_window_marker" ]; then
        attack_window_reason="marker_empty"
    else
        attack_window_reason="marker_unparsed"
        # "first"/"last" — дробный unix-эпох (date +%s.%N), т.е. НЕ целое
        # число. `print $2+0` без printf форматируется по OFMT awk (по
        # умолчанию "%.6g") ровно потому, что значение не целое —
        # 1787406778.924855 и 1787407280.204581 (реальные значения с
        # №2.9.7) оба усекаются до "1.78741e+09" и совпадают, окно
        # обнуляется. Целые счётчики этого дефекта не несут (awk печатает
        # целое значение без OFMT независимо от величины), поэтому правка
        # точечная — только эти два поля форматируются через printf с
        # микросекундной точностью.
        aw_first=$(awk -F= '$1=="first"{printf "%.6f", $2+0}' "$attack_window_marker" 2>/dev/null)
        aw_last=$(awk -F= '$1=="last"{printf "%.6f", $2+0}' "$attack_window_marker" 2>/dev/null)
        attack_window_min=$(awk -v f="${aw_first:-0}" -v l="${aw_last:-0}" 'BEGIN{ if(f>0 && l>f) print (l-f)/60; else print 0 }')
        if awk -v m="$attack_window_min" 'BEGIN{exit !(m>0)}'; then
            attack_window_known=1
            attack_window_reason=""
        fi
    fi
fi
if [ "$attack_window_known" -eq 1 ]; then
    attacker_rate=$(awk -v a="$attacker_alerts" -v m="$attack_window_min" 'BEGIN{printf "%.1f", a/m}')
else
    attacker_rate="n/a"
fi

# Состав, а не число (волна 5.3, находка №2 замера №2). Порог «>= 43» был снят
# с прогона №4 и стал недостижим после законного сужения правил: 41 тип в замере
# №2 дал FAIL, хотя ни один настоящий детект не пропал. Одно число не отличает
# «детект просел» от «FP перестал считаться детектом» — гейт печатает diff.
#
# Волна 5.6a (находка №10, замер №2.2): состав строится по счётчикам
# ebpf_guard_alerts_total{rule_id=...} из final-снимка /metrics, а не по
# дельте списков алертов по id. Дельта по id видит только то, что сработало
# внутри окна атаки (7.79 мин в замере №2.2); правило с частотой
# 2-20 срабатываний в час может отстреляться целиком ДО baseline или ПОСЛЕ
# final и пропасть из diff, оставаясь живым — так потерялись пять типов на
# замере №2.2 при полном совпадении счётчиков baseline/final (15/15 и т.д.).
#
# Волна 5.7b (находка №14, замер №2.3): 5.6a сменила источник, но условие
# осталось final[r] > b (дельта baseline→final) — на №2.3 owasp_log_tampering
# (5→5) и sigma_log_deletion (10→10) сработали за пределами окна атаки, но
# печатались как «потеряны», хотя оба живы. Условие теперь final[r] > 0:
# тип, сработавший хоть раз за всё время жизни агента (включая простой ДО
# окна атаки), — живой. base[] для этого больше не нужен, baseline-снимок
# по-прежнему читается — FILENAME == basefile просто пропускает его строки,
# чтобы final[] не задваивался значениями из baseline при общем rule_id.
#
# Разделение снимков — по FILENAME, а не по NR == FNR: пустой (нулевой длины)
# baseline-снимок делает NR == FNR истинным для строк ВТОРОГО файла, и тогда
# весь final уходит в base[], seen[] остаётся пустым, а состав выводится как
# «потеряны все 41 тип» — гейт напечатал бы полный регресс детекта вместо
# проблемы сбора. Существование файлов проверено выше (-f), непустота — нет:
# оборвавшийся curl оставляет 0-байтный файл, который -f проходит.
# tr -d '\r' на входе: FS не включает \r, поэтому на CRLF-снимке rule_id из
# последней метки получил бы хвостовой \r и разошёлся бы с базой, очищенной
# через tr ниже (тот же дефект, что ловили при пересчёте 5.3).
#
# Ревизия 5.7 (неточность №7): после 5.7b baseline-снимок в РАСЧЁТЕ не
# участвует — он только пропускается (FILENAME == basefile), чтобы его строки
# не попали в final[]. Обрывать весь гейт (exit 2) из-за файла, который больше
# не читается, значит терять 14 остальных критериев на ровном месте. Жёсткое
# требование осталось только у final-снимка; отсутствующий/пустой baseline
# теперь просто не передаётся awk (basefile="" не совпадёт ни с одним
# FILENAME) с явной записью в вывод.
if [ ! -s "$final_metrics" ]; then
    echo "Снимок /metrics пуст: $final_metrics — состав детекта (критерий 6) посчитать нельзя" >&2
    exit 2
fi

# Два помощника, общие для критерия 6 и для 5.8a-вычитания ниже. Раньше та же
# awk-программа была написана дважды (в detected_type_list и в idle_delta_list)
# и различалась только именем метрики; из-за этого 5.8a умел смотреть только на
# ebpf_guard_alerts_total и только на прирост — обе неточности разобраны в
# правках ниже по этому же критерию.
#
# metric_grown_rules <метрика> <снимок-старт|""> <снимок-конец>
#   печатает rule_id, у которых счётчик вырос между снимками. Пустой первый
#   аргумент означает «старта нет» — тогда «выросло» = «> 0 в конце».
# metric_nonzero_rules <метрика> <снимок>
#   печатает rule_id, у которых счётчик в снимке > 0 (сработало хоть раз за
#   жизнь этого процесса агента, независимо от границ окна).
#
# Разделение снимков по FILENAME, а не по NR == FNR — по той же причине, что
# расписана выше: пустой стартовый снимок ломает NR == FNR.
metric_grown_rules() {
    local metric="$1" startf="$2" endf="$3"
    local files=("$endf")
    if [ -n "$startf" ] && [ -s "$startf" ]; then
        files=("$startf" "$endf")
    else
        startf=""
    fi
    awk -F'[{}", ]+' -v metric="$metric" -v startfile="$startf" '
        function rule_id(   i, rid) {
            rid = ""
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^rule_id=?$/) { rid = $(i+1); break }
            }
            return rid
        }
        { gsub(/\r/, "") }
        index($0, metric "{") != 1 { next }
        {
            rid = rule_id(); if (rid == "") next
            if (startfile != "" && FILENAME == startfile) { start[rid] += $NF; next }
            end[rid] += $NF; seen[rid] = 1
        }
        END {
            for (r in seen) {
                if (end[r] - (start[r]+0) > 0) print r
            }
        }
    ' "${files[@]}" | sort
}

metric_nonzero_rules() {
    metric_grown_rules "$1" "" "$2"
}
if [ -s "$baseline_metrics" ]; then
    metrics_inputs=("$baseline_metrics" "$final_metrics")
    basefile_arg="$baseline_metrics"
else
    echo "  (baseline-снимок пуст или отсутствует — на состав детекта не влияет, считается по final)"
    metrics_inputs=("$final_metrics")
    basefile_arg=""
fi

# 5.9.9d (находка №100, P1): позитивный контроль DNS (5.9.8a,
# --dns-fd-reuse-controls) — отдельный шаг харнесса, ВНЕ окна замера,
# запускаемый ДО get_baseline_metrics. Событие, поднятое им, уже отражено
# И в baseline_metrics, И в final_metrics (родилось раньше обоих снимков),
# поэтому metric_grown_rules (final-baseline) для него всегда 0 — рост не
# виден ни в одном из трёх окон (attack/idle/gap) ниже. При этом само
# срабатывание живёт в сторе (final_alerts — полный дамп с момента старта
# агента, не диф по снимкам) и раньше единственно объяснялось как «конвейер
# не слился» (only_in_store), хотя это не рассинхронизация метрики и стора,
# а нормальное поведение метрики для события, случившегося до открытия
# любого измеряемого окна. Здесь — не диф "attack/idle/gap", а прямое
# сравнение времени: маркер контроля старше снимка baseline_metrics.
dns_ctl_marker=$(latest_marker "$RESULTS_DIR" 'dns-positive-control-*.txt')
dns_ctl_before_baseline=0
if [ -n "$dns_ctl_marker" ] && [ -s "$baseline_metrics" ]; then
    # stat -f %m — BSD/macOS. Остальные четыре чтения mtime в этом файле
    # (строки 802/803, окно idle) фолбэк уже имели, а эти два — нет: на
    # macOS обе величины выходили пустыми, dns_ctl_before_baseline молча
    # оставался нулём, и четвёртая фаза (5.9.9d/№100) была недостижима.
    # Реплей 13/14 проверяет именно её, и без фолбэка он давал бы разные
    # исходы на стенде и на машине разработчика.
    dns_ctl_mtime=$(stat -c %Y "$dns_ctl_marker" 2>/dev/null || stat -f %m "$dns_ctl_marker" 2>/dev/null || echo "")
    baseline_mtime=$(stat -c %Y "$baseline_metrics" 2>/dev/null || stat -f %m "$baseline_metrics" 2>/dev/null || echo "")
    if [ -n "$dns_ctl_mtime" ] && [ -n "$baseline_mtime" ] && [ "$dns_ctl_mtime" -lt "$baseline_mtime" ]; then
        dns_ctl_before_baseline=1
    fi
fi
# Правило, уже сработавшее ДО снятия baseline_metrics (ABSOLUTE, не дельта),
# растёт на 0 между baseline и final по конструкции delta = final - baseline —
# оно живо, но невидимо ни одному из трёх окон (attack/idle/gap) ниже. Тот же
# приём, что 5.9.1d ввела для idle_prewindow_list (metric_nonzero_rules над
# ОДНИМ снимком, не дельта), применённый к снимку baseline_metrics вместо
# IDLE_METRICS_END.
preexisting_at_baseline_list=""
if [ -n "$basefile_arg" ]; then
    preexisting_at_baseline_list=$( { metric_nonzero_rules ebpf_guard_alerts_total "$baseline_metrics"
                                       metric_nonzero_rules ebpf_guard_alerts_filtered_total "$baseline_metrics"; } | sort -u)
fi

detected_type_list=$(awk -F'[{}", ]+' -v basefile="$basefile_arg" '
    function rule_id(   i, rid) {
        rid = ""
        for (i = 1; i <= NF; i++) {
            if ($i ~ /^rule_id=?$/) { rid = $(i+1); break }
        }
        return rid
    }
    { gsub(/\r/, "") }
    !/^ebpf_guard_alerts_total\{/ { next }
    FILENAME == basefile { next }
    {
        rid = rule_id(); if (rid == "") next
        final[rid] += $NF
        seen[rid] = 1
    }
    END {
        for (r in seen) {
            if (final[r] > 0) print r
        }
    }
' "${metrics_inputs[@]}" | sort)

# 5.9.4c (находка №54): состав детекта до этой правки читался ТОЛЬКО из
# /metrics. Криттерий 5.9.4c ставит порядок снимков так, что /metrics не
# может отстать от стора (get_final_metrics в run-all-attacks.sh снимает её
# последней) — но на случай, если гейт когда-нибудь запустят на артефактах,
# собранных до этой правки, или конвейер всё же не слился за 30с (см.
# final-drain-offset ниже по критерию 15), состав считается по ОБЪЕДИНЕНИЮ
# метрики и стора: тип, присутствующий хотя бы в одном источнике, живой.
# Расхождение — типы, видимые в сторе, но отсутствующие в метрике — печатается
# отдельной диагностической строкой ("конвейер не слился"), а не как потеря
# детекта: правило, которое стор уже видел, а метрика ещё нет, — не регресс.
metric_type_list="$detected_type_list"
store_type_list=""
if [ -f "$final_alerts" ] && jq -e 'type == "array"' "$final_alerts" >/dev/null 2>&1; then
    store_type_list=$(jq -r '[.[].rule_id] | map(select(. != null and . != "")) | unique | .[]' "$final_alerts" 2>/dev/null | sort)
fi
only_in_store=$(comm -23 <(echo "$store_type_list") <(echo "$metric_type_list") | grep -v '^$' || true)
only_in_store_count=$(echo "$only_in_store" | grep -c . || true)
detected_type_list=$(printf '%s\n%s\n' "$metric_type_list" "$store_type_list" | grep -v '^$' | sort -u)
detected_types=$(echo "$detected_type_list" | grep -c . || true)
if [ "$only_in_store_count" -gt 0 ]; then
    echo "  типов только в сторе: $only_in_store_count — конвейер не слился (5.9.4c):"
    echo "$only_in_store" | sed 's/^/    ? /'
else
    echo "  типов только в сторе: 0 — метрика и стор согласованы (5.9.4c)"
fi

if [ ! -f "$baseline_types_file" ]; then
    skip "detection-baseline.txt не найден рядом с гейтом — состав детекта сравнить не с чем (число типов: $detected_types)"
else
    baseline_types_present=1
    # tr -d '\r' с обеих сторон: иначе diff вырождается в "всё потеряно и всё
    # добавлено" при малейшем расхождении переводов строк между базой и выводом
    # jq (поймано при пересчёте 5.3 на Windows-сборке jq).
    expected_types=$(grep -vE '^\s*(#|$)' "$baseline_types_file" | tr -d '\r' | sort)
    lost_types_raw=$(comm -23 <(echo "$expected_types") <(echo "$detected_type_list"))
    added_types=$(comm -13 <(echo "$expected_types") <(echo "$detected_type_list"))
    added_count=$(echo "$added_types" | grep -c . || true)
    echo "  типов в прогоне: $detected_types, в базе: $(echo "$expected_types" | grep -c .)"
    if [ "$added_count" -gt 0 ]; then
        # 5.9.5g (находка №67): "добавлено (+N)" раньше не говорило, откуда
        # взялся прирост — под атакой или на простое. Прирост, целиком
        # состоящий из idle-срабатываний, для этого критерия по-прежнему
        # "детект жив" (порог не меняется), но читателю нужно видеть разницу:
        # idle-only прирост — кандидат в ложноположительные, а не победа.
        # Фаза считается по тем же двум помощникам (metric_grown_rules), что
        # уже используются для 5.8a-вычитания ниже — attack: рост между
        # baseline_metrics/final_metrics (окно атак), idle: рост между
        # IDLE_METRICS_START/END (idle-час, опционально).
        added_attack_list=$( { metric_grown_rules ebpf_guard_alerts_total "$basefile_arg" "$final_metrics"
                                metric_grown_rules ebpf_guard_alerts_filtered_total "$basefile_arg" "$final_metrics"; } | sort -u)
        added_idle_list=""
        if [ -n "$IDLE_METRICS_START" ] && [ -n "$IDLE_METRICS_END" ] \
            && [ -s "$IDLE_METRICS_START" ] && [ -s "$IDLE_METRICS_END" ]; then
            added_idle_list=$( { metric_grown_rules ebpf_guard_alerts_total "$IDLE_METRICS_START" "$IDLE_METRICS_END"
                                  metric_grown_rules ebpf_guard_alerts_filtered_total "$IDLE_METRICS_START" "$IDLE_METRICS_END"; } | sort -u)
        fi
        added_attack_count=0
        added_idle_count=0
        added_gap_count=0
        added_undetermined_count=0
        added_undetermined_ids=""
        added_induced_count=0
        added_induced_ids=""
        added_types_analyzed=1
        echo "  добавлено (+$added_count):"
        while IFS= read -r rid; do
            [ -z "$rid" ] && continue
            in_attack=0; in_idle=0; in_gap=0
            echo "$added_attack_list" | grep -qx "$rid" && in_attack=1
            echo "$added_idle_list" | grep -qx "$rid" && in_idle=1
            echo "$gap_rule_ids" | grep -qx "$rid" && in_gap=1
            # 5.9.6h (находка №76): третья фаза ("gap" — слепое окно
            # idle-конец → attack-baseline) закрывает "фаза не определена"
            # для приростов, объяснимых именно этим окном, а не отсутствием
            # измерения. Правило может расти в gap И attack/idle одновременно
            # (окна не пересекаются по времени, но одно и то же правило
            # вправе сработать в обоих) — печатается составной меткой, как
            # уже делает attack+idle.
            phase_parts=""
            [ "$in_attack" -eq 1 ] && phase_parts="${phase_parts}attack+"
            [ "$in_idle" -eq 1 ] && phase_parts="${phase_parts}idle+"
            [ "$in_gap" -eq 1 ] && phase_parts="${phase_parts}gap+"
            # 5.9.9d (находка №100): четвёртая фаза, проверяемая ДО падения в
            # "не определена". preexisting_at_baseline_list — тип, чей
            # ebpf_guard_alerts_total/_filtered_total уже ненулевой В САМОМ
            # baseline_metrics (не дельта final-baseline, а абсолютное
            # значение снимка) — то есть сработал ДО того, как baseline был
            # снят, а не в промежутке между baseline и final. dns_ctl_before_baseline
            # подтверждает, что такое окно вообще было на этом прогоне (маркер
            # позитивного контроля DNS старше снимка baseline_metrics) — без
            # этого условия любое правило, случайно сработавшее до старта
            # окна по не связанной с контролем причине, маскировалось бы под
            # "наведено контролем" вместо честного "не определено".
            in_induced=0
            if [ "$dns_ctl_before_baseline" -eq 1 ] && echo "$preexisting_at_baseline_list" | grep -qx "$rid"; then
                in_induced=1
            fi
            # 5.9.9.F.3d (находка №134): окна attack/idle/gap проверяются
            # ДО «наведено преflight'ом» — тип, сработавший до baseline-
            # снимка, но ТАКЖЕ выросший в измеряемом окне, отныне получает
            # окно, а не преflight-ярлык (composite "idle+induced" и т. п.
            # предпочтительна плоскому "${phase_parts}"). Метка «наведено
            # шагом преflight'а» остаётся только тем типам, для которых НИ
            # ОДНО измеряемое окно не применимо — это единственный случай,
            # где ни один из трёх предыдущих флагов не установлен.
            if [ -n "$phase_parts" ] && [ "$in_induced" -eq 1 ]; then
                phase="${phase_parts%+}+induced (также наведён шагом преflight'а до baseline, 5.9.8a/5.9.9d/№100 — не входит в added_induced_count, окно уже объясняет прирост)"
            elif [ -n "$phase_parts" ]; then
                phase="${phase_parts%+}"
            elif [ "$in_induced" -eq 1 ]; then
                # Формулировка намеренно шире, чем «контроль DNS»: признак
                # (а) — «ненулевое ЗНАЧЕНИЕ в baseline-снимке» — ловит любое
                # правило, сработавшее до открытия окна, а до окна на этом
                # прогоне идут ВСЕ шаги преflight'а (контроли DNS 5.9.8a,
                # run_ringbuf_overflow 5.9.7b, контроль счётности 5.9.7a).
                # Маркер контроля DNS здесь — доказательство, что преflight
                # вообще был, а не имя источника конкретного срабатывания;
                # называть источником DNS-контроль значило бы приписывать ему
                # чужие типы (та же неточность, что поправка к №67).
                phase="наведено шагом преflight'а до открытия baseline (5.9.8a/5.9.9d, №100) — ни одно из измеряемых окон не применимо; источник — один из шагов вне окна, не обязательно контроль DNS"
            elif [ -z "$IDLE_METRICS_START" ] || [ -z "$IDLE_METRICS_END" ]; then
                phase="фаза не определена — IDLE_METRICS_START/END не заданы"
            elif [ -z "$IDLE_ALERTS_END" ]; then
                phase="фаза не определена — IDLE_ALERTS_END не задан, gap-окно не проверено"
            else
                phase="фаза не определена — сработало вне всех трёх окон измерения (до baseline, между idle-снимками, и вне gap)"
            fi
            [ "$in_attack" -eq 1 ] && added_attack_count=$((added_attack_count + 1))
            [ "$in_idle" -eq 1 ] && added_idle_count=$((added_idle_count + 1))
            [ "$in_gap" -eq 1 ] && added_gap_count=$((added_gap_count + 1))
            # 5.9.9.F.3d: added_induced_count/ids mirror the label above —
            # only the types with NO window match at all (in_attack=in_idle=
            # in_gap=0) are "pure" preflight-induced and need a
            # detection-baseline.txt line of their own. A type that is both
            # induced AND grew in a window is already accounted for by that
            # window's counter above and printed with the composite label;
            # counting it here too would double it into added_induced_ids
            # without a window ever failing to explain it.
            if [ "$in_induced" -eq 1 ] && [ "$in_attack" -eq 0 ] && [ "$in_idle" -eq 0 ] && [ "$in_gap" -eq 0 ]; then
                added_induced_count=$((added_induced_count + 1))
                added_induced_ids="$added_induced_ids$rid"$'\n'
            elif [ "$in_induced" -eq 0 ] && [ "$in_attack" -eq 0 ] && [ "$in_idle" -eq 0 ] && [ "$in_gap" -eq 0 ]; then
                added_undetermined_count=$((added_undetermined_count + 1))
                added_undetermined_ids="$added_undetermined_ids$rid"$'\n'
            fi
            echo "    + $rid ($phase)"
        done <<< "$added_types"
        echo "  добавлено по фазам: attack=$added_attack_count, idle=$added_idle_count, gap=$added_gap_count, наведено преflight-шагом=$added_induced_count, не определено=$added_undetermined_count (сумма может превышать $added_count — правило, выросшее в нескольких окнах, считается в каждом)"
        if [ "$added_undetermined_count" -gt 0 ] && [ -z "$IDLE_ALERTS_END" ]; then
            echo "  (5.9.6h: gap-окно не проверялось на этом прогоне — IDLE_ALERTS_END не задан; \"не определено\" выше не означает, что фаза действительно отсутствует)"
        fi
        # 5.9.9d (находка №100): типы, наведённые позитивным контролем, — не
        # доказательство детекта продукта (сам факт срабатывания ожидаем и
        # желателен — это подтверждает, что контроль жив), но и не
        # "потерянная фаза" критерия 6. Печатаются отдельным списком, чтобы
        # detection-baseline.txt пополнялся по факту наблюдения (см.
        # run_dns_cross_thread_positive_control, plan.md 5.9.9d), а не через
        # общий список "не заносить, фаза не определена" ниже.
        if [ "$added_induced_count" -gt 0 ]; then
            echo "  наведено шагом преflight'а (вне измеряемых окон), не входит в \"не определено\" ($added_induced_count шт., заносить в detection-baseline.txt отдельной строкой с пояснением после наблюдения):"
            echo "$added_induced_ids" | grep -v '^$' | sed 's/^/    * /'
        fi
        # 5.9.7e (находка №81): фаза "не определена" — не доказательство
        # детекта (могло быть ssh-логином оператора, ручной командой, чем
        # угодно вне сценария run-all-attacks.sh). Печатается отдельным
        # списком с явным запретом, а не оставляется читателю выводить
        # правило из общей таблицы фаз выше — 5.9.6f подняла в базу именно
        # так три ssh-артефакта и один ручной dpkg-query, не заметив, что
        # это единственный случай без определённой фазы.
        if [ "$added_undetermined_count" -gt 0 ]; then
            echo "  не заносить в detection-baseline.txt (фаза не определена, $added_undetermined_count шт.):"
            echo "$added_undetermined_ids" | grep -v '^$' | sed 's/^/    ! /'
        fi
    fi

    # 5.9.1e-следствие, найдено пересчётом на снятых данных №2.9 (условие №1
    # гейта волны 5.9.1). detected_type_list строится по ebpf_guard_alerts_total,
    # а туда попадает только то, что прошло store.min_severity (на стенде —
    # warning). Правило, ПОНИЖЕННОЕ до info — ровно то, что 5.9.1e сделала с
    # sigma_passwd_shadow_read, разводя дубль на /etc/passwd по осям, —
    # продолжает срабатывать в полном объёме, но уходит в
    # ebpf_guard_alerts_filtered_total и пропадает из alerts_total. Критерий 6
    # засчитал бы это как потерю детекта: пересчёт на данных №2.9 с вырезанными
    # строками alerts_total{rule_id="sigma_passwd_shadow_read"} даёт «потеряно
    # (-4)» вместо (-3), причём четвёртый — правило, которое срабатывает 53 раза
    # за прогон. Это ложный FAIL того же класса, что чинили 5.3 и 5.8a:
    # понижение severity — не потеря детекта, а перенос в другой счётчик.
    #
    # Снимаем такие правила из потерь ОТДЕЛЬНОЙ строкой, а не молча: понижение
    # должно быть видно в выводе гейта, иначе следующая правка severity опять
    # пройдёт незамеченной. Порог тут не нужен — факт роста filtered_total за то
    # же окно атаки и есть доказательство, что правило живо.
    info_detected=$(metric_grown_rules ebpf_guard_alerts_filtered_total "$basefile_arg" "$final_metrics")
    if [ -n "$lost_types_raw" ] && [ -n "$info_detected" ]; then
        info_recovered=$(comm -12 <(echo "$lost_types_raw") <(echo "$info_detected"))
        if [ -n "$info_recovered" ]; then
            while IFS= read -r rid; do
                [ -z "$rid" ] && continue
                echo "  $rid: сработало под атакой ниже store.min_severity (прирост ebpf_guard_alerts_filtered_total) — детект жив, не потеря"
            done <<< "$info_recovered"
            lost_types_raw=$(comm -23 <(echo "$lost_types_raw") <(echo "$info_recovered"))
        fi
    fi

    # Волна 5.8a (находка №22): final[r] > 0 в attack-results смешивает две
    # популяции правил — те, что срабатывают под атакой, и фоновые, которым
    # там неоткуда сработать (owasp_log_tampering/sigma_log_deletion — на
    # rsyslogd, а не на действия атакующего). Правило из background-rules.txt,
    # потерянное по attack-results, получает вторую попытку — по приросту
    # между IDLE_METRICS_START и IDLE_METRICS_END (снимки idle-run.sh,
    # передаются через переменные окружения). OR, а не замена: правило,
    # переставшее срабатывать И там, и там, остаётся потерянным.
    lost_types="$lost_types_raw"
    recovered_types=""
    if [ -n "$lost_types_raw" ] && [ -f "$background_rules_file" ]; then
        # 5.9.9.Fe: строки несут второй столбец (<замер>:<алертов за
        # idle-час>) — читаем только первое поле, иначе comm -12 ниже
        # сравнивал бы целые строки и переставал матчить (awk '{print $1}',
        # а не сам текст строки).
        background_set=$(grep -vE '^\s*(#|$)' "$background_rules_file" | tr -d '\r' | awk '{print $1}' | sort)
        lost_background=$(comm -12 <(echo "$lost_types_raw") <(echo "$background_set"))
        if [ -n "$lost_background" ]; then
            if [ -n "$IDLE_METRICS_START" ] && [ -n "$IDLE_METRICS_END" ] \
                && [ -s "$IDLE_METRICS_START" ] && [ -s "$IDLE_METRICS_END" ]; then
                # Прирост за idle-час. Считается по ОБЕИМ метрикам, а не только
                # по alerts_total: фоновое правило info-уровня (их на стенде
                # уже несколько — sigma_log_deletion_daemon, и с 5.9.1e
                # sigma_passwd_shadow_read) целиком живёт в filtered_total, и
                # старый однометричный вариант объявлял бы его потерянным и
                # здесь, во второй попытке, а не только в первой.
                idle_delta_list=$( { metric_grown_rules ebpf_guard_alerts_total "$IDLE_METRICS_START" "$IDLE_METRICS_END"
                                     metric_grown_rules ebpf_guard_alerts_filtered_total "$IDLE_METRICS_START" "$IDLE_METRICS_END"; } | sort -u)
                # Третья попытка: правило, сработавшее ПОСЛЕ старта агента, но
                # ДО открытия idle-окна. Пересчёт 5.9.1d на данных №2.9 показал,
                # что находка №37 назвала web_sql_injection_files «фоном, который
                # 5.8a обязан вычесть», прочитав абсолют (2 на обоих концах
                # idle-часа) как прирост; прироста там ноль, и предсказание
                # «критерий 6 напечатает 0 потерь» на данных №2.9 не сбылось —
                # печатается 3, из них web_sql_injection_files ложное. Правило
                # сработало дважды между рестартом агента (шаг 1 пайплайна
                # обнуляет счётчики вместе с процессом) и стартом окна — то есть
                # оно живо на этой сборке, просто не попало в час наблюдения.
                # Считать это «регрессом детекта» нельзя; печатаем отдельной,
                # заметно иначе сформулированной строкой, чтобы разница между
                # «сработало в окне» и «сработало до окна» не стёрлась.
                idle_prewindow_list=$( { metric_nonzero_rules ebpf_guard_alerts_total "$IDLE_METRICS_END"
                                         metric_nonzero_rules ebpf_guard_alerts_filtered_total "$IDLE_METRICS_END"; } | sort -u)
                # Разбираем lost_background по одному, чтобы напечатать судьбу
                # каждого правила, а не только итоговое число.
                while IFS= read -r rid; do
                    [ -z "$rid" ] && continue
                    if echo "$idle_delta_list" | grep -qx "$rid"; then
                        recovered_types="$recovered_types$rid"$'\n'
                        echo "  фоновое $rid: не сработало под атакой, но выросло за idle-час — не считается потерей (5.8a)"
                    elif echo "$idle_prewindow_list" | grep -qx "$rid"; then
                        recovered_types="$recovered_types$rid"$'\n'
                        echo "  фоновое $rid: за idle-час прироста нет, но счётчик ненулевой — правило срабатывало после старта агента, до открытия окна; живо, не считается потерей (5.8a, уточнение 5.9.1d)"
                    else
                        echo "  фоновое $rid: не сработало ни под атакой, ни за idle-час, счётчик нулевой с самого старта агента — потеря подтверждена"
                    fi
                done <<< "$lost_background"
            else
                skip "IDLE_METRICS_START/END не заданы — фоновые правила из потерь (${lost_background//$'\n'/, }) проверены только по attack-results, как до 5.8a"
            fi
        fi
        if [ -n "$recovered_types" ]; then
            recovered_sorted=$(echo "$recovered_types" | grep -v '^$' | sort -u)
            lost_types=$(comm -23 <(echo "$lost_types_raw") <(echo "$recovered_sorted"))
        fi
    fi
    # 5.9g (находка №33): правила из intentional_loss_file не имеют сценария
    # трафика на этом стенде вообще — их потеря печатается как наблюдение и не
    # участвует в lost_count, в отличие от background_rules_file выше (там
    # потеря снимается только при подтверждённом idle-приросте).
    intentional_lost=""
    if [ -n "$lost_types" ] && [ -f "$intentional_loss_file" ]; then
        intentional_set=$(grep -vE '^\s*(#|$)' "$intentional_loss_file" | tr -d '\r' | sort)
        intentional_lost=$(comm -12 <(echo "$lost_types") <(echo "$intentional_set"))
        if [ -n "$intentional_lost" ]; then
            lost_types=$(comm -23 <(echo "$lost_types") <(echo "$intentional_lost"))
        fi
    fi
    intentional_lost_count=$(echo "$intentional_lost" | grep -c . || true)
    if [ "$intentional_lost_count" -gt 0 ]; then
        echo "  потеряно намеренно (-$intentional_lost_count, наблюдение без порога, см. intentional-loss.txt):"
        echo "$intentional_lost" | sed 's/^/    ~ /'
    fi
    # 5.9.5d (находка №63): третий реестр. Правило, немое за весь аптайм
    # агента с УЖЕ установленной причиной (silent-rules.txt, категория (а)
    # «немо по конструкции» или (б) «немо из-за среды», волна 5.9.4h),
    # засчитывалось этим критерием как непонятная потеря — тот же класс
    # рассогласования, что 5.9.4c чинила для метрики/стора: два реестра
    # об одном и том же множестве правил не совпадали, потому что этот
    # критерий читал только два файла из трёх. Вычитание таким же образом,
    # как intentional_loss_file строкой выше (comm -12).
    silent_lost=""
    if [ -n "$lost_types" ] && [ -f "$silent_rules_file" ]; then
        silent_lost_a=$(awk '!/^[[:space:]]*(#|$)/ && $2 == "a" {print $1}' "$silent_rules_file" | sort -u)
        silent_lost_b=$(awk '!/^[[:space:]]*(#|$)/ && $2 == "b" {print $1}' "$silent_rules_file" | sort -u)
        silent_set=$(printf '%s\n%s\n' "$silent_lost_a" "$silent_lost_b" | grep -v '^$' | sort -u)
        silent_lost=$(comm -12 <(echo "$lost_types") <(echo "$silent_set"))
        if [ -n "$silent_lost" ]; then
            lost_types=$(comm -23 <(echo "$lost_types") <(echo "$silent_lost"))
        fi
    fi
    silent_lost_count=$(echo "$silent_lost" | grep -c . || true)
    if [ "$silent_lost_count" -gt 0 ]; then
        echo "  потеряно, но уже объяснено немотой за весь аптайм (-$silent_lost_count, см. silent-rules.txt, секция 5.9.4h ниже):"
        echo "$silent_lost" | sed 's/^/    ~ /'
    fi
    background_recovered_count=$(echo "${recovered_sorted:-}" | grep -c . || true)
    echo "  объяснено: intentional-loss $intentional_lost_count, silent-rules $silent_lost_count, background-rules $background_recovered_count (\"потеряно 0\" не означает, что список объяснений пуст — см. счётчики выше)"
    lost_count=$(echo "$lost_types" | grep -c . || true)
    if [ "$lost_count" -gt 0 ]; then
        echo "  потеряно (-$lost_count):"
        echo "$lost_types" | sed 's/^/    - /'
    fi
    # Провал — только потеря вне intentional_loss_file. Добавления печатаются и
    # требуют обновления базы, но не проваливают прогон: новое правило, которое
    # сработало, — не регресс.
    if [ "$lost_count" -eq 0 ]; then
        pass "состав детекта без потерь вне списка намеренных (добавлено: $added_count — обновить detection-baseline.txt вместе с записью в plan.md) (5.9.7e: потеряно вне реестров)"
    else
        fail "состав детекта: потеряно $lost_count типов вне intentional-loss.txt (см. список выше). Если потеря намеренная — обновить detection-baseline.txt/intentional-loss.txt и записать причину в plan.md, иначе это регресс детекта (5.9.7e: потеряно вне реестров)"
    fi

    # 5.9.6f (находка №75): «добавлено»/«потеряно» этого прогона — сигнатура
    # расхождения с базой. Один прогон с расхождением — это находка (ожидаемо,
    # гейт её и печатает выше). Тот же самый набор типов на ДВУХ прогонах
    # подряд означает, что находку никто не разобрал и базу не обновили —
    # реестр устарел молча. Сравниваем с сигнатурой, оставленной прошлым
    # запуском, не с самим фактом расхождения: разные расхождения на двух
    # прогонах подряд — это два разных наблюдения, не одна брошенная база.
    # Сигнатура строится ТОЛЬКО из содержимого списков. Прежняя редакция
    # печатала литералы "added:"/"lost:" безусловно, поэтому на чистом
    # прогоне (расхождения нет) сигнатура всё равно выходила непустой, ветка
    # rm -f была недостижима, а ДВА чистых прогона подряд давали одинаковую
    # сигнатуру и печатали "база брошена" — ровно наоборот смыслу критерия.
    diff_signature=""
    if [ -n "$(echo "$added_types" | grep -v '^$' || true)" ] || [ -n "$(echo "$lost_types" | grep -v '^$' || true)" ]; then
        diff_signature=$(printf 'added:\n%s\nlost:\n%s\n' "$added_types" "$lost_types")
    fi
    # 5.9.9a (находка №99): detection-baseline-diff-state.txt несёт TIMESTAMP
    # замера первой строкой, тело сигнатуры — ниже. Без этого гейт,
    # запускаемый дважды за один и тот же замер (второй ручной вызов после
    # full_run() run-all-attacks.sh — обычный режим разбора без цепочки),
    # сравнивает сигнатуру со своим же первым вызовом и печатает "база
    # брошена" на одном расхождении — самонаведение измерителя, не находка.
    # Если сохранённый TIMESTAMP равен текущему — это тот же замер, а не
    # следующий: WARN не печатается, файл не перезаписывается и веткой
    # rm -f не трогается. Разные TIMESTAMP — сравнение тел, как раньше.
    saved_state_ts=""
    saved_signature=""
    if [ -f "$diff_state_file" ]; then
        saved_state_ts=$(head -1 "$diff_state_file")
        saved_signature=$(tail -n +2 "$diff_state_file")
    fi
    if [ -f "$diff_state_file" ] && [ "$saved_state_ts" = "$TIMESTAMP" ]; then
        : # тот же замер, что уже оставил файл — состояние не трогаем
    elif [ -n "$diff_signature" ]; then
        if [ -f "$diff_state_file" ] && [ "$saved_signature" = "$diff_signature" ]; then
            warn "состав детекта расходится с detection-baseline.txt уже второй замер подряд тем же набором типов (добавлено $added_count, потеряно $lost_count вне intentional-loss.txt) — база брошена, обновить detection-baseline.txt и записать в plan.md"
        fi
        printf '%s\n%s\n' "$TIMESTAMP" "$diff_signature" > "$diff_state_file"
    elif [ -f "$diff_state_file" ]; then
        rm -f "$diff_state_file"
    fi
fi
if [ "$attacker_alerts_known" -eq 0 ]; then
    skip "темп алертов непроверяем — нет attack-manifest.json, множество атакующих comms неизвестно"
elif [ "$attack_window_known" -eq 0 ]; then
    case "$attack_window_reason" in
        marker_missing)
            skip "темп алертов непроверяем по окну атаки — attack-window-$TIMESTAMP.txt отсутствует (сборка харнесса старее 5.9.7d); полное окно baseline→final: ${runtime_min} мин, справочно, в вердикт не входит" ;;
        marker_empty)
            skip "темп алертов непроверяем по окну атаки — attack-window-$TIMESTAMP.txt пуст (mark_attack_window не вызывался ни разу за прогон); полное окно baseline→final: ${runtime_min} мин, справочно, в вердикт не входит" ;;
        *)
            skip "темп алертов непроверяем по окну атаки — attack-window-$TIMESTAMP.txt не разобрался (first=${aw_first:-?} last=${aw_last:-?}, окно = ${attack_window_min} мин); полное окно baseline→final: ${runtime_min} мин, справочно, в вердикт не входит" ;;
    esac
elif awk -v r="$attacker_rate" 'BEGIN{exit !(r+0>=74)}'; then
    pass "темп алертов от атакующих: $attacker_alerts за ${attack_window_min} мин (окно атаки, 5.9.7d) = $attacker_rate/мин (>= 74, уровень прогона №4); полное окно baseline→final: ${runtime_min} мин"
else
    fail "темп алертов от атакующих: $attacker_alerts за ${attack_window_min} мин (окно атаки, 5.9.7d) = $attacker_rate/мин (ожидалось >= 74); полное окно baseline→final: ${runtime_min} мин"
fi

# 5.9.4f (№57/№61): база темпа (83.0/мин) признана загрязнённой — снята до
# того, как 10 FP-типов волны 5.9.3b были убраны из детекта (найдены только
# разбором №2.9.3, см. intentional-loss.txt), то есть считала шум частью
# темпа. Порог гейта (>= 74, строка выше) остаётся прежним до двух чистых
# прогонов подряд — постановка 5.9.4f запрещает менять его на данных одного
# прогона. Эта строка — сырой материал для новой базы, не решение: печатает
# фактический темп текущего прогона и топ-10 rule_id по числу алертов от
# атакующих, чтобы просадку темпа можно было объяснить составом, а не гадать.
if [ "$attacker_alerts_known" -eq 1 ] && [ -f "$manifest_file" ] && command -v jq &> /dev/null; then
    echo "  темп этого прогона как кандидат новой базы: $attacker_rate/мин (нужен второй чистый прогон, прежде чем заменить 83.0)"
    top10=$(jq -s -r --argjson comms "$attacker_comms" '
        (.[0] // []) as $baseline | (.[1] // []) as $final |
        ($baseline | map(.id) | unique) as $bids |
        ($final | map(select(.id as $id | ($bids | index($id)) | not))) as $new |
        $new | map(select(.comm as $c | $comms | index($c))) |
        group_by(.rule_id) | map({rule_id: .[0].rule_id, n: length}) |
        sort_by(-.n) | .[0:10] | .[] | "    \(.n)  \(.rule_id)"
    ' "$baseline_alerts" "$final_alerts" 2>/dev/null)
    if [ -n "$top10" ]; then
        echo "  алертов от атакующих по правилам, топ-10:"
        echo "$top10"
        # 5.9.7d (№80, P1): доля числителя, приходящаяся на топ-10 правил —
        # без порога, наблюдение. Шесть правил по 84 из 743 (68% числителя,
        # разбор №2.9.6) выглядели подозрительно круглым числом на правило —
        # признак упора в потолок MaxAlertsPerWindow (per-rule rate limit),
        # а не в глубину сценария: если завтра лимит изменится, темп прыгнет
        # без всякой связи с детектом. Печатается ЧИСЛОМ рядом с темпом,
        # прежде чем по темпу снова будут судить (сам гейт не отличает
        # "упёрлось в лимит" от "сценарий и правда бьёт часто" — это разбор
        # человека по колонке "правило n").
        top10_sum=$(echo "$top10" | awk '{s+=$1} END{print s+0}')
        if [ "${attacker_alerts:-0}" -gt 0 ]; then
            top10_fraction=$(awk -v s="$top10_sum" -v a="$attacker_alerts" 'BEGIN{printf "%.1f%%", 100*s/a}')
            echo "  доля числителя на топ-10 правил: $top10_sum из $attacker_alerts = $top10_fraction (наблюдение без порога, 5.9.7d)"
        fi
    fi
fi

# 5.9e (находка №31): темп детекта сам по себе не отличает "агент не детектит"
# от "агент половину прогона просидел под CPU-шеддингом", а замер №2.5 провёл
# именно так — 49% времени при cpu_pressure_percent=14.13. cpu_degraded_fraction
# печатается рядом с темпом и заводит отдельный FAIL при > 0.2: прогон,
# наполовину прошедший под урезанным сэмплингом, не измеряет детект, даже если
# темп выше порога 74/мин (шеддинг режет file/syscall/network, но не
# lsm/canary/exec — часть детекта продолжает срабатывать и на шеддинге).
cpu_degraded_fraction=$(awk '/^ebpf_guard_cpu_degraded_fraction( |\{)/ {print $NF; exit}' "$final_metrics")
if [ -z "${cpu_degraded_fraction:-}" ]; then
    skip "cpu_degraded_fraction отсутствует в срезе — доля времени под шеддингом не проверена (сборка до волны 5.3/4.4)"
elif awk -v f="$cpu_degraded_fraction" 'BEGIN{exit !(f+0 > 0.2)}'; then
    fail "cpu_degraded_fraction=$cpu_degraded_fraction > 0.2 — прогон прошёл под шеддингом слишком долго, темп детекта выше не является чистым измерением (5.9e)"
else
    pass "cpu_degraded_fraction=$cpu_degraded_fraction (<= 0.2) — прогон не искажён CPU-шеддингом"
fi
echo ""

# 5.9.9.Fe (P3, разбор находки №111): гигиена background-rules.txt.
# Отдельно от разбора lost_background внутри критерия 6 выше (тот проверяет
# idle-прирост только для строк, РЕАЛЬНО потерянных в attack-results этого
# прогона) — здесь проверяются ВСЕ 17 строк реестра безусловно, иначе
# устаревание строки, которая пока срабатывает под атакой и потому не
# попадает в lost_background вовсе, остаётся невидимым бессрочно. Пункт
# производит только величину и список ("наблюдение без порога" в
# постановке) — реестр не пересобирается и строки из него не удаляются
# (вторая ветка OR критерия 6 для таких строк остаётся мертва: устаревание
# делает гейт строже, а не мягче).
echo "=== 5.9.9.Fe. Гигиена background-rules.txt: idle-час ЭТОГО прогона (№111) ==="
if [ ! -f "$background_rules_file" ]; then
    skip "background-rules.txt не найден — гигиена не проверена (5.9.9.Fe)"
else
    bg_total=$(grep -vE '^\s*(#|$)' "$background_rules_file" | tr -d '\r' | grep -c . || true)
    bg_no_value=$(grep -vE '^\s*(#|$)' "$background_rules_file" | tr -d '\r' | awk 'NF<2{print $1}')
    bg_no_value_count=$(echo "$bg_no_value" | grep -c . || true)
    if [ "$bg_no_value_count" -gt 0 ]; then
        fail "строк background-rules.txt без замера и величины: $bg_no_value_count из $bg_total ($(echo "$bg_no_value" | tr '\n' ' ')) — каждая строка обязана нести <замер>:<алертов за idle-час> (5.9.9.Fe)"
    else
        pass "строк background-rules.txt без замера и величины: 0 из $bg_total — каждая несёт <замер>:<алертов за idle-час> (5.9.9.Fe)"
    fi
    if [ -n "$IDLE_METRICS_START" ] && [ -n "$IDLE_METRICS_END" ] \
        && [ -s "$IDLE_METRICS_START" ] && [ -s "$IDLE_METRICS_END" ]; then
        bg_all_ids=$(grep -vE '^\s*(#|$)' "$background_rules_file" | tr -d '\r' | awk '{print $1}' | sort -u)
        bg_grown_ids=$( { metric_grown_rules ebpf_guard_alerts_total "$IDLE_METRICS_START" "$IDLE_METRICS_END"
                           metric_grown_rules ebpf_guard_alerts_filtered_total "$IDLE_METRICS_START" "$IDLE_METRICS_END"; } | sort -u)
        bg_unconfirmed=$(comm -23 <(echo "$bg_all_ids") <(echo "$bg_grown_ids"))
        bg_unconfirmed_count=$(echo "$bg_unconfirmed" | grep -c . || true)
        echo "  строк background-rules.txt, не подтверждённых idle-часом ЭТОГО прогона: $bg_unconfirmed_count"
        [ "$bg_unconfirmed_count" -gt 0 ] && echo "$bg_unconfirmed" | sed 's/^/    ~ /'
        record_covered "строк background-rules.txt, не подтверждённых idle-часом"
    else
        skip "IDLE_METRICS_START/END не заданы — гигиена background-rules.txt по idle-часу ЭТОГО прогона не проверена (5.9.9.Fe)"
    fi
fi
echo ""

# 5.9.5c (находки №64/№65, P1): DNS decode-error разбивка по reason плюс
# ответ на вопрос №64 — тишина стенда или регресс разбора — для четырёх
# правил, молчавших на №2.9.4 (dns_tunneling_long_domain,
# exfil_dns_txt_long_label, netintr_dns_long_label,
# webshell_dns_exfil_long_subdomain, см. TestDNSLongLabelControlRules_
# MatchOnQNameLengthAlone, internal/correlator/rules_coverage_test.go).
# run_dns_long_label_attack (run-all-attacks.sh) даёт им позитивный контроль:
# один long-label запрос через dig, заведомо выше порога всех четырёх правил,
# неотличимый от фонового comm=grafana только благодаря уникальной метке с
# TIMESTAMP этого прогона.
#
# dns_decode_errors_total печатается по reason БЕЗ порога (постановка 5.9.5c,
# п.2): три гипотезы находки №65 (ответы с sport 53, TCP-DNS/mDNS, обрезка по
# DNS_MAX_PAYLOAD) ещё не разделены, и дропать записи до установления причины
# повторило бы ошибку 5.9.1f — это наблюдение, не гейт.
# dns_target_rules объявлена ДО ветвления на final_metrics — под `set -u`
# 5.9.7f ниже читает её независимо от того, взяла ли эта секция ветку skip
# (та же причина, что added_undetermined_count=0 инициализирована до
# критерия 6 выше).
dns_target_rules="dns_tunneling_long_domain exfil_dns_txt_long_label netintr_dns_long_label webshell_dns_exfil_long_subdomain"
echo "=== 5.9.5c. DNS-видимость: decode errors по reason + позитивный контроль на длинный лейбл ==="
if [ ! -s "$final_metrics" ]; then
    skip "$final_metrics пуст — DNS decode errors/позитивный контроль не проверены"
else
    echo "  dns_decode_errors_total по reason (кумулятив за весь аптайм агента, наблюдение без порога):"
    decode_err_lines=$(grep '^ebpf_guard_dns_decode_errors_total{' "$final_metrics" 2>/dev/null)
    if [ -z "$decode_err_lines" ]; then
        echo "    метрика отсутствует — сборка агента старее 5.9.5c (dns_decode_errors_total ещё без label reason);"
        echo "    начиная с 5.9.5c коллектор публикует все шесть reason'ов нулями с первого скрейпа,"
        echo "    поэтому \"ноль ошибок разбора\" выглядит как шесть строк с 0, а не как отсутствие метрики"
    else
        echo "$decode_err_lines" | awk -F'[{}", ]+' '
            function reason_of(   i, r) {
                r = ""
                for (i = 1; i <= NF; i++) { if ($i ~ /^reason=?$/) { r = $(i+1); break } }
                return r
            }
            { r = reason_of(); if (r != "") sum[r] += $NF }
            END { for (r in sum) printf "    %-18s %d\n", r, sum[r] }
        ' | sort
    fi

    dns_events_final=$(grep '^ebpf_guard_events_total{' "$final_metrics" 2>/dev/null \
        | grep 'type="dns"' | awk -F'} ' '{sum+=$2} END{print sum+0}')

    # Обе метрики, как в критерии 6: правило, чей алерт съеден пост-фильтром
    # (rate limit / Rego), по alerts_total не растёт — и без
    # alerts_filtered_total читалось бы здесь как «молчит», то есть как
    # «регресс разбора», хотя разбор отработал и правило сматчило.
    grown_dns_rules=$( { metric_grown_rules ebpf_guard_alerts_total "$basefile_arg" "$final_metrics"
                          metric_grown_rules ebpf_guard_alerts_filtered_total "$basefile_arg" "$final_metrics"; } | sort -u)
    dns_silent_registry="$GATE_SCRIPT_DIR/silent-rules.txt"

    fired_count=0
    unexplained_dns=""
    for rid in $dns_target_rules; do
        if echo "$grown_dns_rules" | grep -qx "$rid"; then
            fired_count=$((fired_count + 1))
            chain_empty=0
            chain_total=0
            # Цепочка читается из ИНЦИДЕНТОВ, а не из /api/v1/alerts: алерт в
            # выдаче API несёт только id/timestamp/rule_id/severity/pid/comm/
            # message/enrichment/first_seen/last_seen — поля process_chain у
            # него нет вовсе (проверено на стенде 2026-08-21). jq по
            # .process_chain на alerts-снимке молча даёт пусто у ВСЕХ алертов,
            # то есть критерий 13 печатал бы "пуст у N/N" при исправной
            # линейке — ровно тот класс лжи, из-за которого заведена волна.
            # Тот же источник, что у п.13 отчёта run-2.9.5-report.sh.
            if [ -f "$final_incidents" ] && command -v jq &> /dev/null; then
                chain_total=$(jq --arg r "$rid" '[.[] | select(((.rule_ids // [.rule_id]) | map(select(. != null))) | index($r))] | length' "$final_incidents" 2>/dev/null || echo 0)
                chain_empty=$(jq --arg r "$rid" '[.[] | select(((.rule_ids // [.rule_id]) | map(select(. != null))) | index($r)) | select(((.process_chain // []) | length) == 0)] | length' "$final_incidents" 2>/dev/null || echo 0)
            fi
            echo "  $rid: сработало (позитивный контроль подтверждён); process_chain пуст у ${chain_empty:-0}/${chain_total:-0} инцидентов с этим правилом (крит. 13 постановки, живой вход впервые — 5.9.4i)"
        elif [ -f "$dns_silent_registry" ] && awk -v id="$rid" '!/^[[:space:]]*(#|$)/ && $1 == id {found=1} END{exit !found}' "$dns_silent_registry"; then
            reason_cat=$(awk -v id="$rid" '!/^[[:space:]]*(#|$)/ && $1 == id {print $2; exit}' "$dns_silent_registry")
            echo "  $rid: молчит, но причина установлена (категория $reason_cat, silent-rules.txt)"
        else
            unexplained_dns="$unexplained_dns $rid"
            echo "  $rid: молчит, причина НЕ установлена"
        fi
    done

    if [ "$fired_count" -eq 4 ]; then
        pass "все 4 DNS long-label правила сработали под позитивным контролем — молчание №2.9.4 было тишиной стенда, не регрессом разбора (находка №64 закрыта)"
    elif [ -n "$unexplained_dns" ]; then
        if [ "${dns_events_final%.*}" -eq 0 ] 2>/dev/null; then
            fail "events_total{type=\"dns\"}=0 за весь прогон — регресс DNS-коллектора (dns.bpf.c/dns.go), а не вопрос №64; чинить/откатывать коллектор до всего остального"
        else
            fail "$fired_count/4 DNS long-label правил сработало, без объяснения:$unexplained_dns (events_total{type=dns}=${dns_events_final:-n/a}, а не 0) — регресс разбора, не тишина стенда (находка №64)"
        fi
    elif [ "$fired_count" -eq 0 ]; then
        # Вырожденный PASS — ровно тот класс, из-за которого заведена находка
        # №62: позитивный контроль был исполнен, но НИ ОДНО правило не
        # поднялось, а все четыре объяснены реестром. Реестр объясняет
        # молчание за аптайм, он не отвечает на вопрос №64 («тишина стенда
        # или регресс разбора») — при исполненном контроле на этот вопрос
        # отвечает только срабатывание.
        fail "0/4 DNS long-label правил сработало при исполненном позитивном контроле — silent-rules.txt объясняет молчание за аптайм, но не заменяет ответ на вопрос №64; проверить, дошёл ли запрос dig (лог атак) и растёт ли events_total{type=dns}=${dns_events_final:-n/a}"
    else
        pass "$fired_count/4 сработало под контролем, остальные — с установленной причиной в silent-rules.txt"
    fi
fi
echo ""

# 5.9.8a (№94, P0, запрет №6): dns_socket_map ключ pid_tgid→tgid плюс
# validateDNSHeader() не принимаются без ОБОИХ контролей на одном прогоне.
# Оба — отдельный шаг харнесса (run-all-attacks.sh --dns-fd-reuse-controls),
# ВНЕ окна замера (запрет №3), маркеры находятся по маске, а не по TIMESTAMP
# этого прогона — тот же приём, что критерий 22 использует для
# run_ringbuf_overflow (5.9.7b), потому что оба шага пишутся отдельным
# вызовом скрипта со своим собственным TIMESTAMP.
echo "=== 5.9.8a. DNS: негативный + позитивный контроль переиспользования fd (№94) ==="
record_covered "=== 5.9.8a. DNS: негативный + позитивный контроль"
dns_neg_marker=$(latest_marker "$RESULTS_DIR" 'dns-negative-control-*.txt')
dns_pos_marker=$(latest_marker "$RESULTS_DIR" 'dns-positive-control-*.txt')

if [ -z "$dns_neg_marker" ] && [ -z "$dns_pos_marker" ]; then
    skip "run-all-attacks.sh --dns-fd-reuse-controls не запускался — маркеры dns-{negative,positive}-control-*.txt отсутствуют; сборка/пайплайн старее 5.9.8a"
else
    dns_neg_ok=0
    if [ -z "$dns_neg_marker" ]; then
        skip "негативный контроль DNS не запускался — маркер dns-negative-control-*.txt отсутствует"
    elif grep -q '^skipped=1' "$dns_neg_marker" 2>/dev/null; then
        skip "негативный контроль DNS пропущен харнессом (python3 недоступен в момент прогона)"
    else
        dns_neg_delta=$(awk -F= '$1=="events_dns_delta"{print $2+0}' "$dns_neg_marker" 2>/dev/null)
        dns_neg_reused=$(awk -F= '$1=="reused_fd"{print $2+0}' "$dns_neg_marker" 2>/dev/null)
        # cross_thread_close — вторая половина сценария №94 и единственное,
        # что отличает этот контроль от тавтологии: close() ОБЯЗАН прийти с
        # чужого потока, иначе старый (потоковый) ключ удалил бы запись сам
        # и «0 DNS-событий» ничего не доказывало бы (ревизия волны 5.9.8).
        # Отсутствует поле — маркер писала сборка харнесса старее этой правки.
        dns_neg_xthread=$(awk -F= '$1=="cross_thread_close"{print $2+0}' "$dns_neg_marker" 2>/dev/null)
        echo "  негативный: reused_fd=${dns_neg_reused:-0} cross_thread_close=${dns_neg_xthread:-нет поля} Δevents_total{type=dns}=${dns_neg_delta:-n/a}"
        if ! grep -q '^cross_thread_close=' "$dns_neg_marker" 2>/dev/null; then
            skip "негативный контроль: маркер без cross_thread_close — сборка харнесса, где close() шёл с того же потока, что connect(); такой сценарий проходит и на старом ключе, доказательством №94 не является"
        elif [ "${dns_neg_xthread:-0}" -ne 1 ]; then
            skip "негативный контроль: close() с чужого потока не удался — сценарий №94 не воспроизведён, критерий без входа на этот раз"
        elif [ "${dns_neg_reused:-0}" -ne 1 ]; then
            skip "негативный контроль: fd не переиспользован этим прогоном (reused_fd=0) — сценарий не воспроизвёлся, критерий без входа на этот раз"
        elif [ "${dns_neg_delta:-0}" -eq 0 ] 2>/dev/null; then
            dns_neg_ok=1
            pass "негативный контроль: fd переиспользован, TLS-ClientHello-подобные байты по нему НЕ дали DNS-событий (dns_socket_map больше не принимает переиспользованный fd, 5.9.8a)"
        else
            fail "негативный контроль: fd переиспользован, Δevents_total{type=dns}=${dns_neg_delta} > 0 — dns_socket_map всё ещё принимает переиспользованный fd за DNS (№94 не закрыта)"
        fi
    fi

    dns_pos_ok=0
    if [ -z "$dns_pos_marker" ]; then
        skip "позитивный контроль DNS не запускался — маркер dns-positive-control-*.txt отсутствует"
    elif grep -q '^skipped=1' "$dns_pos_marker" 2>/dev/null; then
        skip "позитивный контроль DNS пропущен харнессом (python3 недоступен в момент прогона)"
    else
        dns_pos_n=$(awk -F= '$1=="n"{print $2+0}' "$dns_pos_marker" 2>/dev/null)
        dns_pos_delta=$(awk -F= '$1=="events_dns_delta"{print $2+0}' "$dns_pos_marker" 2>/dev/null)
        echo "  позитивный: N=${dns_pos_n:-0} Δevents_total{type=dns}=${dns_pos_delta:-n/a}"
        if [ -z "${dns_pos_n:-}" ] || [ "${dns_pos_n:-0}" -eq 0 ]; then
            skip "позитивный контроль: N не записан или равен 0 — python-генератор не отработал"
        elif [ "${dns_pos_delta:-0}" -ge "${dns_pos_n:-0}" ] 2>/dev/null; then
            dns_pos_ok=1
            pass "позитивный контроль: межпоточный резолв (N=${dns_pos_n}) дал Δevents_total{type=dns}=${dns_pos_delta} >= N — connect() на одном потоке, write()/read() на другом остаётся видимым (5.9.8a)"
        else
            fail "позитивный контроль: Δevents_total{type=dns}=${dns_pos_delta:-0} < N=${dns_pos_n:-0} — межпоточный резолв недосчитан, правка ключа сузила видимость вместо починки (риск №2 постановки №2.9.8)"
        fi
    fi

    if [ "$dns_neg_ok" -eq 1 ] && [ "$dns_pos_ok" -eq 1 ]; then
        pass "оба контроля 5.9.8a исполнены на этом прогоне и сошлись — запрет №6 выполнен"
    fi
fi
echo ""

# 5.9.7e / риск №3 постановки №2.9.7: позитивный контроль сужения по ssh.
# Волна 5.9.7e сузила rootkit_ssh_authorized_keys_modified (`op: eq write`) и
# sigma_sensitive_dir_listing (исключение comm=sshd на /root/.ssh/), чтобы
# штатный ssh-логин перестал считаться детектом. У этого приёма есть ровно
# один способ провалиться незаметно — правило умирает целиком (находка №57,
# восемь типов на 5.9.3b), и по артефактам прогона это неотличимо от
# «нечему было срабатывать». Поэтому критерий двусторонний, и обе стороны
# считаются на ОДНОМ прогоне: шаг run_ssh_keys_positive_control пишет в
# authorized_keys посторонним comm (обязан дать алерт), а sshd за тот же
# прогон обязан не дать ни одного алерта этих двух правил.
echo "=== 5.9.7e. Позитивный контроль сужения по ssh (риск №3) ==="
if [ ! -s "$final_alerts" ] || ! jq -e 'type == "array"' "$final_alerts" >/dev/null 2>&1; then
    skip "final-alerts-$TIMESTAMP.json отсутствует или не JSON-массив — позитивный контроль 5.9.7e не проверен (5.9.7e: позитивный контроль)"
else
    ssh_ctl_hits=$(jq '[.[] | select(.rule_id == "rootkit_ssh_authorized_keys_modified")
        | select(.comm != "sshd")] | length' "$final_alerts" 2>/dev/null || echo 0)
    ssh_ctl_sshd=$(jq '[.[] | select(.rule_id == "rootkit_ssh_authorized_keys_modified"
        or .rule_id == "sigma_sensitive_dir_listing") | select(.comm == "sshd")] | length' "$final_alerts" 2>/dev/null || echo 0)
    ssh_ctl_comms=$(jq -r '[.[] | select(.rule_id == "rootkit_ssh_authorized_keys_modified")
        | .comm] | unique | join(",")' "$final_alerts" 2>/dev/null || echo "")
    echo "  алертов rootkit_ssh_authorized_keys_modified: comm != sshd — $ssh_ctl_hits, comm = sshd — по обоим правилам $ssh_ctl_sshd (comm'ы правила: ${ssh_ctl_comms:-нет})"
    if [ "$ssh_ctl_hits" -ge 1 ] && [ "$ssh_ctl_sshd" -eq 0 ]; then
        pass "запись в authorized_keys посторонним comm поднимает правило ($ssh_ctl_hits), sshd не поднимает ни одного — сужение не ослепило (5.9.7e: позитивный контроль)"
    elif [ "$ssh_ctl_hits" -eq 0 ]; then
        fail "rootkit_ssh_authorized_keys_modified не сработало ни разу на записи посторонним comm — сужение 5.9.7e неотличимо от ослепления правила (риск №3, тот же класс, что находка №57) (5.9.7e: позитивный контроль)"
    else
        fail "$ssh_ctl_sshd алерт(ов) этих двух правил с comm=sshd — штатный ssh-логин по-прежнему считается детектом, сужение 5.9.7e не работает (5.9.7e: позитивный контроль)"
    fi
fi
echo ""

# 5.9.7f (находка №83): постановка п.8 требовала "DNS long-label на idle — 0,
# либо запись с числами в 6.3", но 5.9.6e была оформлена только как правка
# правил+разбор — критерия в гейте не было, и три критикала в idle-час
# (comm=grafana, 19:46:32) ушли молча. Отдельно от позитивного контроля
# выше (тот проверяет "правило живо под атакой", этот — "правило молчит на
# простое"): прирост тех же четырёх правил СТРОГО за idle-час (не за весь
# прогон), по каждому экземпляру (rule_id + comm) либо 0, либо объяснено в
# dns-idle-fp.txt.
echo "=== 5.9.7f. DNS-FP на idle: прирост long-label правил за idle-час = 0 либо объяснено ==="
record_covered "=== 5.9.7f. DNS-FP"
if [ -z "$IDLE_METRICS_START" ] || [ -z "$IDLE_METRICS_END" ] \
    || [ ! -s "$IDLE_METRICS_START" ] || [ ! -s "$IDLE_METRICS_END" ]; then
    skip "IDLE_METRICS_START/END не заданы — прирост DNS long-label правил за idle-час не измерен"
else
    idle_dns_grown=$( { metric_grown_rules ebpf_guard_alerts_total "$IDLE_METRICS_START" "$IDLE_METRICS_END"
                         metric_grown_rules ebpf_guard_alerts_filtered_total "$IDLE_METRICS_START" "$IDLE_METRICS_END"; } | sort -u)
    idle_dns_hit=""
    for rid in $dns_target_rules; do
        echo "$idle_dns_grown" | grep -qx "$rid" && idle_dns_hit="$idle_dns_hit$rid"$'\n'
    done
    idle_dns_hit=$(echo "$idle_dns_hit" | grep -v '^$' || true)
    idle_dns_hit_count=$(echo "$idle_dns_hit" | grep -c . || true)

    if [ "$idle_dns_hit_count" -eq 0 ]; then
        pass "прирост long-label правил за idle-час = 0 (5.9.7f, п.8 постановки закрыт)"
    else
        echo "  выросло за idle-час: $idle_dns_hit_count тип(ов) из четырёх"
        unexplained_count=0
        have_comm_breakdown=0
        if [ -n "$IDLE_ALERTS_START" ] && [ -s "$IDLE_ALERTS_START" ] \
            && [ -n "$IDLE_ALERTS_END" ] && [ -s "$IDLE_ALERTS_END" ] \
            && command -v jq &> /dev/null \
            && jq -e 'type == "array"' "$IDLE_ALERTS_START" >/dev/null 2>&1 \
            && jq -e 'type == "array"' "$IDLE_ALERTS_END" >/dev/null 2>&1; then
            have_comm_breakdown=1
        fi
        while IFS= read -r rid; do
            [ -z "$rid" ] && continue
            if [ "$have_comm_breakdown" -eq 1 ]; then
                # comm'ы, у которых это правило сработало К КОНЦУ idle-часа,
                # минус comm'ы, у которых оно уже было сработавшим В НАЧАЛЕ —
                # тот же приём, что gap_rule_ids делает по .id выше, здесь по
                # (rule_id, comm), чтобы не засчитать один и тот же штатный
                # comm за новый экземпляр на каждом прогоне подряд.
                end_comms=$(jq -r --arg r "$rid" '[.[] | select(.rule_id == $r) | .comm] | unique | .[]' "$IDLE_ALERTS_END" 2>/dev/null)
                start_comms=$(jq -r --arg r "$rid" '[.[] | select(.rule_id == $r) | .comm] | unique | .[]' "$IDLE_ALERTS_START" 2>/dev/null)
                new_comms=$(comm -23 <(echo "$end_comms" | sort -u) <(echo "$start_comms" | sort -u))
                [ -z "$new_comms" ] && [ -n "$end_comms" ] && new_comms="$end_comms"
                if [ -z "$new_comms" ]; then
                    echo "  $rid: метрика выросла, но ни один comm не новый в /api/v1/alerts idle-конца — вероятно, тот же экземпляр, что уже был в начале idle-часа"
                    continue
                fi
                while IFS= read -r c; do
                    [ -z "$c" ] && continue
                    reason=""
                    if [ -f "$dns_idle_fp_file" ]; then
                        reason=$(awk -v id="$rid" -v cm="$c" '!/^[[:space:]]*(#|$)/ && $1 == id && $2 == cm {print $3; exit}' "$dns_idle_fp_file")
                    fi
                    if [ -n "$reason" ]; then
                        echo "  $rid ($c): объяснено (категория $reason, dns-idle-fp.txt)"
                    else
                        unexplained_count=$((unexplained_count + 1))
                        echo "  $rid ($c): прирост НЕ объяснён — нет строки \"$rid $c <категория>\" в dns-idle-fp.txt"
                    fi
                done <<< "$new_comms"
            else
                # Без снимков alerts на обоих концах idle-часа — реестр
                # проверяется по rule_id без comm (реестр допускает это же
                # обозначение, если comm неизвестен, но по постановке 5.9.7f
                # разбивка по comm обязательна) — считаем необъяснённым,
                # чтобы отсутствие данных не читалось как PASS ненаступлением.
                unexplained_count=$((unexplained_count + 1))
                echo "  $rid: вырос за idle-час, разбивка по comm не измерена (IDLE_ALERTS_START/END не заданы, не JSON-массив, или jq недоступен)"
            fi
        done <<< "$idle_dns_hit"

        if [ "$unexplained_count" -eq 0 ]; then
            pass "прирост long-label правил за idle-час объяснён построчно в dns-idle-fp.txt (5.9.7f)"
        else
            fail "$unexplained_count необъяснённых экземпляров прироста DNS long-label правил за idle-час (5.9.7f) — занести в dns-idle-fp.txt построчно (rule_id comm категория) либо поднять порог длины лейбла, третьего варианта («перенести в 6.3») нет"
        fi
    fi
fi
echo ""

# 5.9.7f, п.16 постановки: у DNS-алертов обязано быть имя запроса. Без него
# риск №4 неразрешим по артефактам — разбор «порог верен, стенд шумный» или
# «порог неверен» делается из записи алерта, а журнал коллектора к моменту
# разбора уже ротирован (именно так был потерян разбор grafana/:46:32 на
# №2.9.6). Проверяются ровно те правила, чей вход — DNS-событие
# ($dns_target_rules); правила по exec (lolbin_dns_exfil_via_dig и соседи)
# сюда не входят: их событие не DNS-пакет, и qname у них взяться неоткуда —
# требовать его там значило бы валить критерий за то, чего он не называет.
echo "=== 5.9.7f. dns.qname в DNS-алертах (п.16 постановки) ==="
if [ ! -s "$final_alerts" ] || ! jq -e 'type == "array"' "$final_alerts" >/dev/null 2>&1; then
    skip "final-alerts-$TIMESTAMP.json отсутствует или не JSON-массив — наличие details.dns.qname не проверено (5.9.7f: dns.qname)"
else
    dns_rules_json=$(printf '%s\n' $dns_target_rules | jq -R . | jq -s .)
    qname_total=$(jq --argjson r "$dns_rules_json" '[.[] | select(.rule_id as $x | $r | index($x))] | length' "$final_alerts")
    qname_empty=$(jq --argjson r "$dns_rules_json" '[.[] | select(.rule_id as $x | $r | index($x))
        | select((.details["dns.qname"] // "") == "")] | length' "$final_alerts")
    echo "  DNS-алертов (правила по DNS-событию): $qname_total, из них без dns.qname: $qname_empty"
    jq -r --argjson r "$dns_rules_json" '[.[] | select(.rule_id as $x | $r | index($x))
        | {rule_id, comm, qname: (.details["dns.qname"] // ""), len: (.details["dns.max_label_len"] // "-")}]
        | unique | .[] | "    \(.rule_id) (\(.comm)): \(.qname) [макс. лейбл \(.len)]"' "$final_alerts" 2>/dev/null | head -20
    if [ "$qname_total" -eq 0 ]; then
        skip "DNS-алертов на этом прогоне нет — п.16 непроверяем (dig-контроль 5.9.5c обязан был их дать, см. секцию 2) (5.9.7f: dns.qname)"
    elif [ "$qname_empty" -eq 0 ]; then
        pass "у всех $qname_total DNS-алертов details.dns.qname непусто (5.9.7f: dns.qname)"
    else
        fail "$qname_empty из $qname_total DNS-алертов без details.dns.qname — разбор порога длины лейбла по артефактам невозможен (риск №4) (5.9.7f: dns.qname)"
    fi
fi
echo ""

# 7. Recall по attack-manifest: все ли категории атак задетектированы.
# Это критерий, которого в гейте не было вовсе (план 1.75c), поэтому FAIL
# recall в замере №1 (напечатанный 1.75a как 0 при фактических 4/4) прошёл
# незамеченным между двумя дефектами критериев. Transit-категории
# (docker-proxy и подобные) из recall исключены — это транзитные процессы
# атаки, не отдельные категории.
#
# Волна 5.7c (находка №15, замер №2.3): считалось по unique(comm), а несколько
# категорий манифеста могут делить один comm (на №2.3 — bruteforce/ssrf/
# ldap_csrf все под curl). unique схлопывал 4 категории в 2 «атакующих comm»,
# и гейт печатал 2/2 = 1.000 PASS даже если bruteforce и ssrf не задетектились
# вовсе — критерий физически не мог напечатать 4/4. Теперь recall считается
# по category: comm остаётся способом сопоставить категорию с алертами
# (comm → «был ли хоть один новый алерт от этого comm» — как и раньше), но
# знаменатель и числитель — уникальные категории, а не уникальные comm.
#
# Ревизия 5.7, две правки поверх 5.7c:
#
#   (неточность №3) свёртка категорий была unique_by(.category) — а это
#   group_by | map(.[0]), то есть «взять ПЕРВЫЙ comm группы», а не «хоть
#   один». Категория, заявленная в манифесте под двумя comm и задетектированная
#   только по второму, печаталась как непойманная. На манифесте №2.3 не
#   стреляло (один comm на категорию), но это ровно тот класс дефекта, против
#   которого заведена сама 5.7c. Теперь group_by(.category) + any.
#
#   (неточность №2) порог PASS был >= 0.5 и остался от знаменателя 2. С
#   знаменателем 4 он пропускает 2/4 — то есть сценарий из самой находки №15
#   («bruteforce и ssrf не детектятся, ldap_csrf остался») снова печатал бы
#   PASS. Порог поднят до 1.0: манифест мы пишем сами, каждая его категория
#   обязана быть поймана, и потеря любой — это потеря детекта, а не допуск.
#   Это ужесточение критерия, а не подгонка под результат (п. 4): таблица
#   приёмки волны 5.7 и так требует 4/4. Непойманные категории печатаются
#   поимённо, чтобы FAIL было с чем разбирать.
echo "=== 7. Recall по attack-manifest ==="
if [ ! -f "$manifest_file" ]; then
    skip "attack-manifest.json не найден — recall непроверяем"
elif ! command -v jq &> /dev/null; then
    skip "jq недоступен — recall непроверяем"
else
    manifest_real=$(jq '[.[] | select(.transit != true)]' "$manifest_file" 2>/dev/null)
    manifest_total=$(echo "$manifest_real" | jq '[.[].category] | unique | length')
    if [ "$manifest_total" -eq 0 ] 2>/dev/null; then
        skip "манифест пуст (нет не-transit категорий) — recall непроверяем"
    else
        attacker_categories_for_recall=$(echo "$manifest_real" | jq -c '[.[] | {category, comm}] | unique')
        recall_result=$(jq -s --argjson categories "$attacker_categories_for_recall" '
            (.[0] // []) as $baseline | (.[1] // []) as $final |
            ($baseline | map(.id) | unique) as $bids |
            ($final | map(select(.id as $id | ($bids | index($id)) | not))) as $new |
            ($new | map(.comm) | unique) as $new_comms |
            ($categories
                | map(. as $c | {category: $c.category, detected: ($new_comms | index($c.comm) != null)})
                | group_by(.category)
                | map({category: .[0].category, detected: (map(.detected) | any)})) as $per_category |
            {
                detected: ($per_category | map(select(.detected)) | length),
                total: ($per_category | length),
                missed: ($per_category | map(select(.detected | not) | .category))
            }
        ' -r "$baseline_alerts" "$final_alerts" 2>/dev/null)
        recall_detected=$(echo "$recall_result" | jq -r '.detected // 0')
        recall_total=$(echo "$recall_result" | jq -r '.total // 0')
        recall_missed=$(echo "$recall_result" | jq -r '(.missed // []) | join(", ")')
        if [ "$recall_total" -gt 0 ] 2>/dev/null; then
            recall_value=$(awk -v d="$recall_detected" -v t="$recall_total" 'BEGIN{printf "%.3f", d/t}')
        else
            recall_value="0"
        fi
        if awk -v r="$recall_value" 'BEGIN{exit !(r+0>=1.0)}'; then
            pass "recall по манифесту: $recall_detected/$recall_total = $recall_value (все категории манифеста пойманы)"
        else
            fail "recall по манифесту: $recall_detected/$recall_total = $recall_value (ожидалось 1.000; не пойманы: ${recall_missed:-—})"
        fi
    fi
fi
echo ""

# 8. alerts_dropped — информационно, без PASS/FAIL (план 1.75c).
# В замере №1 это 229181 при 4459 опубликованных — подавление по rate-limit/dedup,
# не потеря видимости. Порог фиксируется по факту после волны 3 (когда шум
# правил упадёт и число обязано снизиться). Сейчас важно, чтобы величина
# печаталась и была видна под наблюдением — иначе фон rate-limit маскирует
# потерю сигнала, как в замечании 4.6.
echo "=== 8. alerts_dropped (информационно, без PASS/FAIL) ==="
if command -v jq &> /dev/null; then
    alerts_dropped=$(jq -r '.engine_stats.alerts_dropped // 0' "$final_state" 2>/dev/null || echo 0)
    alerts_published=$(jq -r '.engine_stats.total_alerts // 0' "$final_state" 2>/dev/null || echo 0)
    dropped_per_published=$(awk -v d="$alerts_dropped" -v p="$alerts_published" \
        'BEGIN{ if(p+0>0) printf "%.1f", d/p; else print "n/a" }')
    echo "  alerts_published: $alerts_published"
    echo "  alerts_dropped:   $alerts_dropped (rate-limit/dedup/feedback)"
    echo "  ratio dropped/published: $dropped_per_published"
    echo "  (порог фиксируется после волны 3; пока — только наблюдение)"
else
    skip "jq недоступен — alerts_dropped не посчитан"
fi
echo ""

# 9. Доля инцидентов на системных демонах < 20% (гейт волны 2, критерий 1).
# В прогоне №4 было 114/114 = 100% на sshd, в замере №1 — 37.4%. До волны 3
# этот критерий считался только ручным разбором снапшота инцидентов — ровно
# тот способ потерять критерий, против которого пункт 4 «Порядка работы».
# Считается по тому же /api/v1/incidents, что и критерий 4 (одно множество,
# в отличие от расхождения 326/107, найденного в замере №1).
echo "=== 9. Доля инцидентов на системных демонах (гейт волны 2: < 20%) ==="
if [ ! -f "$final_incidents" ]; then
    skip "final-incidents-$TIMESTAMP.json не собран — доля на демонах не посчитана"
elif ! jq -e 'type == "array"' "$final_incidents" >/dev/null 2>&1; then
    skip "final-incidents-$TIMESTAMP.json не JSON-массив — доля на демонах не посчитана"
else
    inc_total=$(jq 'length' "$final_incidents")
    if [ "$inc_total" -eq 0 ]; then
        skip "инцидентов нет — доля на демонах неопределена (не ноль: делить не на что)"
    else
        # root_comm — корень дерева процессов инцидента, тот же признак, по
        # которому считает ebpf_guard_incidents_trusted_root_total. Список
        # демонов совпадает с defaultTrustedComms/correlator.trusted_comms.
        daemon_inc=$(jq '[.[] | select((.root_comm // .comm) as $c
            | $c == "sshd" or $c == "cron" or $c == "landscape-sysin"
            or $c == "systemd-logind" or $c == "grafana")] | length' "$final_incidents")
        daemon_share=$(awk -v d="$daemon_inc" -v t="$inc_total" \
            'BEGIN{ printf "%.1f", 100*d/t }')
        if awk -v s="$daemon_share" 'BEGIN{exit !(s+0 < 20)}'; then
            pass "инцидентов на демонах: $daemon_inc/$inc_total = ${daemon_share}% (< 20%)"
        else
            fail "инцидентов на демонах: $daemon_inc/$inc_total = ${daemon_share}% (гейт волны 2: < 20%)"
        fi
    fi
fi
echo ""

# 10. process_chain (гейт волны 2, критерий 2; переформулировано волной 5.6b,
# находка №11 замера №2.2).
# P0-1: в прогоне №4 было 114/114 «chain unknown». Метрика
# ebpf_guard_incidents_empty_chain_total заведена в 2.1, но гейт её не читал —
# здесь она сверяется со снапшотом, чтобы расхождение метрики и снапшота
# (как в замере №1 по comm) было видно сразу, а не через прогон.
#
# Находка №11: порог 80% на знаменателе «все инциденты» недостижим на выборке
# из 13 — шаг 7.7 п.п., «ровно 80%» не существует. Знаменатель включал
# однoалертные anomaly_detection-инциденты на короткоживущих процессах, где
# дерева нет ПО УСТРОЙСТВУ (мгновенный алерт на уже завершившемся процессе), а
# не по дефекту — и на замере №2.2 их доля выросла с 33% до 77%, утопив
# критерий не в детекте, а в составе выборки.
#
# Правка из двух частей, обе делают критерий строже, а не мягче:
#   1. Знаменатель — только многоалертные инциденты (alert_count > 1): цепочка
#      имеет смысл только для них.
#   2. Новое условие: доля с цепочкой среди verdict="attack" = 100% — это
#      сторона, которая ловит настоящий регресс P0-1 (нет цепочки у
#      подтверждённой атаки), и раньше не проверялась вовсе.
# Однoалертные инциденты не пропадают из отчёта — печатаются отдельной
# строкой (план 5.1a, п. 8: рост этого числа должен быть виден).
echo "=== 10. process_chain: многоалертные >= 80%, attack-инциденты = 100% (волна 5.6b) ==="
if [ ! -f "$final_incidents" ]; then
    skip "final-incidents-$TIMESTAMP.json не собран — process_chain не проверен"
elif ! jq -e 'type == "array"' "$final_incidents" >/dev/null 2>&1; then
    skip "final-incidents-$TIMESTAMP.json не JSON-массив — process_chain не проверен"
else
    inc_total=$(jq 'length' "$final_incidents")
    if [ "$inc_total" -eq 0 ]; then
        skip "инцидентов нет — доля с process_chain неопределена"
    else
        multi_total=$(jq '[.[] | select((.alert_count // 1) > 1)] | length' "$final_incidents")
        # «без цепочки» — именно инциденты с пустым process_chain (любой
        # alert_count), а не все однoалертные: однoалертный инцидент с цепочкой
        # существует (долгоживущий процесс), и записывать его в бесцепочечные
        # значило бы печатать в отчёте не то число, которое подписано.
        no_chain=$(jq '[.[] | select((.process_chain // []) | length == 0)] | length' "$final_incidents")
        single_instant=$(jq '[.[] | select((.alert_count // 1) <= 1
            and ((.process_chain // []) | length == 0))] | length' "$final_incidents")
        echo "  без цепочки: $no_chain, из них однoалертных мгновенных: $single_instant"

        # Сторона attack считается ДО и НЕЗАВИСИМО от многоалертной: это
        # отдельное условие критерия (п. 2 правки 5.6b), и именно оно ловит
        # регресс P0-1. Внутри ветки multi_total > 0 она была бы пропущена
        # вместе со всем критерием на выборке без многоалертных инцидентов —
        # attack без цепочки прошёл бы как skip, а не FAIL.
        attack_total=$(jq '[.[] | select(.verdict == "attack")] | length' "$final_incidents")
        if [ "$attack_total" -eq 0 ]; then
            echo "  attack-инцидентов нет — доля с process_chain среди них не проверена"
            attack_ok=1
            attack_checked=0
            attack_note=" attack: инцидентов нет, сторона не проверена"
        else
            attack_with_chain=$(jq '[.[] | select(.verdict == "attack"
                and ((.process_chain // []) | length > 0))] | length' "$final_incidents")
            attack_share=$(awk -v c="$attack_with_chain" -v t="$attack_total" 'BEGIN{ printf "%.1f", 100*c/t }')
            attack_ok=0
            attack_checked=1
            if awk -v s="$attack_share" 'BEGIN{exit !(s+0 >= 100)}'; then attack_ok=1; fi
            attack_note=" attack: $attack_with_chain/$attack_total = ${attack_share}% (= 100%)"
        fi

        if [ "$multi_total" -eq 0 ]; then
            # Многоалертная сторона неопределена, но attack-сторона могла быть
            # посчитана — её провал остаётся FAIL, а не превращается в skip.
            if [ "$attack_checked" -eq 1 ] && [ "$attack_ok" -eq 0 ]; then
                fail "многоалертных инцидентов нет (доля среди них неопределена);$attack_note"
            else
                skip "многоалертных инцидентов нет — доля с process_chain среди них неопределена;$attack_note"
            fi
        else
            with_chain=$(jq '[.[] | select((.alert_count // 1) > 1
                and ((.process_chain // []) | length > 0))] | length' "$final_incidents")
            chain_share=$(awk -v c="$with_chain" -v t="$multi_total" 'BEGIN{ printf "%.1f", 100*c/t }')
            multi_ok=0
            if awk -v s="$chain_share" 'BEGIN{exit !(s+0 >= 80)}'; then multi_ok=1; fi

            if [ "$multi_ok" -eq 1 ] && [ "$attack_ok" -eq 1 ]; then
                pass "многоалертные: $with_chain/$multi_total = ${chain_share}% (>= 80%);$attack_note"
            else
                fail "многоалертные: $with_chain/$multi_total = ${chain_share}% (>= 80% требуется);$attack_note"
            fi
        fi

        # 5.9.4g (находка №60): «доля с непустым process_chain» дошла до
        # 100% (0 из 18 без цепочки на №2.9.3) и перестала различать связные
        # и несвязные инциденты — большинство цепочек оказались минимальными
        # («процесс + его родитель», 15 из 18), а у двух все звенья с одним
        # comm. PASS/FAIL остаётся на (а) выше как регрессионный сторож
        # (значение уже не тавтология: не «пусто/непусто», а «>=80% с
        # содержательной цепочкой»); наблюдение (б) печатает состав без
        # порога — второй прогон нужен, прежде чем ставить границу.
        chain_present=$(jq '[.[] | select((.process_chain // []) | length > 0)] | length' "$final_incidents")
        if [ "$chain_present" -eq 0 ]; then
            echo "  крит.10 (б): ни одного инцидента с process_chain — состав не измерен"
        else
            hops3=$(jq '[.[] | select((.process_chain // []) | length >= 3)] | length' "$final_incidents")
            comm2=$(jq '[.[] | select(((.process_chain // []) | unique | length) >= 2)] | length' "$final_incidents")
            hops3_share=$(awk -v c="$hops3" -v t="$chain_present" 'BEGIN{ printf "%.1f", 100*c/t }')
            comm2_share=$(awk -v c="$comm2" -v t="$chain_present" 'BEGIN{ printf "%.1f", 100*c/t }')
            echo "  крит.10 (б, наблюдение без порога): >=3 хопов: $hops3/$chain_present = ${hops3_share}%; >=2 разных comm: $comm2/$chain_present = ${comm2_share}%"
        fi
    fi
fi
echo ""

# 5.7e (находка №17): ни одного инцидента с пустым/отсутствующим verdict.
# Раньше all-info инцидент (все алерты severity=info, 5.5a — они не участвуют
# в скоринге) оставался с verdict="" и severity="" — в JSON это неотличимо от
# «скоринг не отработал». Агент теперь пишет verdict="none" явно (пакет
# types.VerdictNone); критерий проверяет, что пустых строк в снапшоте
# инцидентов не осталось.
echo "=== 5.7e. verdict: ни одного пустого/отсутствующего в снапшоте инцидентов ==="
if [ ! -f "$final_incidents" ]; then
    skip "final-incidents-$TIMESTAMP.json не собран — verdict не проверен"
elif ! jq -e 'type == "array"' "$final_incidents" >/dev/null 2>&1; then
    skip "final-incidents-$TIMESTAMP.json не JSON-массив — verdict не проверен"
else
    empty_verdict=$(jq '[.[] | select((.verdict // "") == "")] | length' "$final_incidents")
    if [ "$empty_verdict" -eq 0 ]; then
        pass "verdict заполнен во всех инцидентах ($(jq 'length' "$final_incidents") шт.)"
    else
        fail "$empty_verdict инцидент(ов) с пустым/отсутствующим verdict — сборка агента старее 5.7e?"
    fi
fi
echo ""

# 11. anomalies_total совпадает в /metrics и /debug/state (замер №2, пункт 2.Gd).
# В замере №1 было 46 против 0: AlertCount не инкрементировался нигде, кроме
# восстановления состояния (1.75b). Расхождение этих двух источников — рецидив
# того же класса, что DNS healthy:true и profiler_state_restored 1: индикатор
# показывает число, а механизм под ним не подключён. Проверяется здесь, а не
# юнит-тестом, потому что после 2.4 (persistence по пулу детекторов) сломать
# равенство может ещё и рестарт — бродкаст снапшота против суммирования.
echo "=== 11. anomalies_total: /metrics против /debug/state ==="
metrics_anom=$(awk '/^ebpf_guard_anomalies_total( |\{)/ {sum += $NF} END {print sum+0}' "$final_metrics")
state_anom=$(jq -r '.profiler_stats.anomalies_total // empty' "$final_state" 2>/dev/null || echo "")
if [ -z "$state_anom" ]; then
    skip "profiler_stats.anomalies_total отсутствует в final-state — сравнить не с чем"
elif [ "${metrics_anom%.*}" -eq 0 ] && [ "$state_anom" -eq 0 ] 2>/dev/null; then
    # Ноль в обоих источниках формально «совпадает», но не доказывает, что
    # механизм подключён — это ровно та маскировка «нет данных» под «ноль»,
    # против которой замечание 1 к волне 1.75.
    skip "anomalies_total = 0 в обоих источниках — аномалий не было, равенство не проверено"
elif [ "${metrics_anom%.*}" -eq "$state_anom" ] 2>/dev/null; then
    pass "anomalies_total совпадает: /metrics=$metrics_anom, /debug/state=$state_anom"
else
    fail "anomalies_total расходится: /metrics=$metrics_anom, /debug/state=$state_anom (в замере №1: 46 против 0)"
fi
echo ""

# 12. Кардинальность profiler_anomaly_score (P1-11, волна 3).
# Замер №1: 8616 серий, из них 3145 с comm="" (36.5%). Правка волны 3 — лимит
# 500, TTL 5 мин, пустой comm не публикуется вовсе. Оба условия проверяются
# вместе: одно число серий не поймало бы возврат пустых меток, а одни пустые
# метки не поймали бы утечку кардинальности короткоживущими PID атаки.
echo "=== 12. Серии profiler_anomaly_score (< 1000, ноль с comm=\"\") ==="
score_series=$(grep -c '^ebpf_guard_profiler_anomaly_score{' "$final_metrics" || true)
score_empty=$(grep '^ebpf_guard_profiler_anomaly_score{' "$final_metrics" | grep -c 'comm=""' || true)
echo "  серий: $score_series (в замере №1: 8616), из них с comm=\"\": $score_empty (было 3145)"
if [ "$score_series" -eq 0 ]; then
    skip "серий profiler_anomaly_score нет — профайлер не публиковал скоры, лимит не проверен"
else
    series_ok=0
    [ "$score_series" -lt 1000 ] && series_ok=1
    if [ "$series_ok" -eq 1 ] && [ "$score_empty" -eq 0 ]; then
        pass "серий $score_series (< 1000), пустых comm нет"
    elif [ "$series_ok" -eq 1 ]; then
        fail "серий $score_series (< 1000 ✓), но $score_empty с comm=\"\" (ожидался 0 — guard должен отбрасывать до построения ключа)"
    elif [ "$score_empty" -eq 0 ]; then
        fail "пустых comm нет ✓, но серий $score_series (ожидалось < 1000 при лимите 500)"
    else
        fail "серий $score_series (ожидалось < 1000) и $score_empty с comm=\"\" (ожидался 0)"
    fi
fi
echo ""

# 13. P1-18b: счётчик дропов path_denylist (приёмка волны 4.3).
# Смысл критерия — не «дропов много», а «фильтр наблюдаем». Ошибка в префиксе
# не даёт ошибки: она даёт тихого, более здорового на вид агента, переставшего
# кормить fim_*/canary_*/cred_*. Поэтому дропы читаются ВМЕСТЕ с файловым
# детектом: растущие дропы при упавших файловых алертах = префикс слишком широк.
# Строгий ноль при пустом списке — вторая половина критерия (см. plan.md).
echo "=== 13. P1-18b: events_dropped_total{reason=\"path_denylist\"} ==="
denylist_drops=$(grep 'ebpf_guard_events_dropped_total{' "$final_metrics" \
    | grep 'reason="path_denylist"' | awk -F'} ' '{sum += $2} END {print sum+0}')
file_alerts=$(jq '[.[] | select((.rule_id // "") | test("^(fim_|canary_|cred_)"))] | length' \
    "$final_alerts" 2>/dev/null || echo 0)
echo "  дропов path_denylist: ${denylist_drops%.*}"
echo "  алертов fim_*/canary_*/cred_* в final-alerts: $file_alerts"
if [ "${denylist_drops%.*}" -eq 0 ] 2>/dev/null; then
    # Ноль допустим только если список пуст. Гейт не читает конфиг агента, так
    # что различить «список пуст» и «фильтр не работает» он не может — это SKIP
    # с явной записью, а не PASS: непроверенное не засчитывается (пункт 4).
    skip "дропов 0 — либо path_denylist пуст, либо фильтр не сработал; сверить с конфигом стенда"
elif [ "$file_alerts" -eq 0 ]; then
    fail "дропов ${denylist_drops%.*} при НУЛЕ файловых алертов (fim_/canary_/cred_) — признак слишком широкого префикса"
else
    pass "дропов ${denylist_drops%.*}, файловый детект жив ($file_alerts алертов fim_/canary_/cred_)"
fi
echo ""

# 14. P1-18a: CPU-watchdog не флапает (приёмка волны 4.4, переформулировано
# волной 5.3 по находке №5 замера №2).
#
# Старая формулировка требовала level==0 в обоих срезах. Замер №2 показал, что
# она мерит не то: агент отработал ровно как задуман — один reduce под нагрузкой
# атаки и один recover, cpu_degraded_fraction 0.091 — но срез пришёлся на
# шеддинг (level=1), и гейт напечатал FAIL за штатную работу регулятора. Ноль
# переходов означал бы, что регулятор не нужен; критерий про то, чтобы он не
# ФЛАПАЛ (813 циклов за ночь в ISSUES-attack-run-2026-08-03 — вот это находка).
#
# Поэтому меряем: (а) число пар reduce↔recover за прогон по счётчику
# ebpf_guard_cpu_pressure_transitions_total (заведён в 5.3 — gauge не может
# ответить «сколько раз»); (б) cpu_degraded_fraction как долю потерянной
# видимости. Порог: ноль ПОВТОРНЫХ переходов, то есть не более одной пары.
# Основание порога: замер №2 — 2 перехода за 96 мин, degraded_fraction 0.091.
# Критерий имеет смысл только на дефолтных порогах 40/70/20 (пункт 2.Gb).
echo "=== 14. P1-18a: CPU-watchdog без флапа (пары reduce↔recover, пороги 40/70/20) ==="
lvl_base=$(awk '/^ebpf_guard_cpu_pressure_level( |\{)/ {print $NF; exit}' "$baseline_metrics")
lvl_final=$(awk '/^ebpf_guard_cpu_pressure_level( |\{)/ {print $NF; exit}' "$final_metrics")
cpu_pct=$(awk '/^ebpf_guard_cpu_pressure_percent( |\{)/ {print $NF; exit}' "$final_metrics")
deg_frac=$(awk '/^ebpf_guard_cpu_degraded_fraction( |\{)/ {print $NF; exit}' "$final_metrics")
# Дельта между срезами, а не абсолют: счётчик монотонный и переживает прогоны.
tr_reduce_base=$(awk '/^ebpf_guard_cpu_pressure_transitions_total\{/ && /direction="reduce"/ {sum+=$NF} END{print sum+0}' "$baseline_metrics")
tr_reduce_final=$(awk '/^ebpf_guard_cpu_pressure_transitions_total\{/ && /direction="reduce"/ {sum+=$NF} END{print sum+0}' "$final_metrics")
tr_recover_base=$(awk '/^ebpf_guard_cpu_pressure_transitions_total\{/ && /direction="recover"/ {sum+=$NF} END{print sum+0}' "$baseline_metrics")
tr_recover_final=$(awk '/^ebpf_guard_cpu_pressure_transitions_total\{/ && /direction="recover"/ {sum+=$NF} END{print sum+0}' "$final_metrics")
has_transition_metric=$(grep -c '^ebpf_guard_cpu_pressure_transitions_total{' "$final_metrics" || true)

if [ -z "${lvl_base:-}" ] || [ -z "${lvl_final:-}" ]; then
    skip "ebpf_guard_cpu_pressure_level отсутствует в срезах — шеддинг не проверен"
elif [ "$has_transition_metric" -eq 0 ]; then
    # Старая сборка агента без счётчика (до волны 5.3). Считать её PASS по
    # level нельзя — это ровно та подмена критерия, которую 5.3 и чинит.
    skip "ebpf_guard_cpu_pressure_transitions_total отсутствует (сборка до волны 5.3) — число пар не измерено; level: baseline=$lvl_base final=$lvl_final"
else
    d_reduce=$(awk -v a="$tr_reduce_final" -v b="$tr_reduce_base" 'BEGIN{print a-b}')
    d_recover=$(awk -v a="$tr_recover_final" -v b="$tr_recover_base" 'BEGIN{print a-b}')
    echo "  переходов за прогон: reduce=$d_reduce recover=$d_recover"
    echo "  cpu_pressure_level: baseline=$lvl_base final=$lvl_final, cpu_pressure_percent=${cpu_pct:-n/a}"
    echo "  cpu_degraded_fraction: ${deg_frac:-n/a} (доля времени с урезанным сэмплингом)"
    # Пара = один reduce и следующий за ним recover. Незакрытая пара (агент всё
    # ещё шеддит в момент среза) — норма, ровно случай замера №2, поэтому
    # считаем по reduce: 0 или 1 reduce = не флапает.
    #
    # 5.9.6i (находка №77, тот же класс, что кластер ua-timer/тест коллизий):
    # reduce=0 раньше печатался как PASS "повторных нет" — но при reduce=0
    # механизм НЕ СРАБОТАЛ НИ РАЗУ за прогон, то есть утверждение "не
    # флапает" ничем не доказано, а не отличается по тексту от "сработал
    # один раз и не повторился". PASS отсутствием события — ровно то, что
    # 5.9.5b уже вытеснила из критерия 3 постановкой наведённого дропа;
    # здесь наведённого CPU-давления в прогоне нет (вне объёма этой волны),
    # поэтому reduce=0 — SKIP с названной причиной, а не PASS.
    if [ "$d_reduce" -eq 0 ]; then
        # 5.9.9.F.2b (№125): раньше reduce=0 всегда означал SKIP — критерий
        # зависел от того, поднимется ли давление САМО во время окна атак.
        # Теперь читаем маркер run_cpu_pressure_control (вне окна замера,
        # запрет №3): если он есть, естественных переходов в окне и не
        # требуется — пара reduce↔recover уже доказана управляемой нагрузкой.
        if [ -f "$cpu_pressure_control_marker" ] && ! grep -q '^skipped=1' "$cpu_pressure_control_marker" 2>/dev/null; then
            cpc_reduce=$(awk -F= '$1=="reduce"{print $2+0}' "$cpu_pressure_control_marker" 2>/dev/null)
            cpc_recover=$(awk -F= '$1=="recover"{print $2+0}' "$cpu_pressure_control_marker" 2>/dev/null)
            cpc_reduce_wait=$(awk -F= '$1=="reduce_wait_seconds"{print $2+0}' "$cpu_pressure_control_marker" 2>/dev/null)
            cpc_recover_wait=$(awk -F= '$1=="recover_wait_seconds"{print $2+0}' "$cpu_pressure_control_marker" 2>/dev/null)
            cpc_min_dwell=$(awk -F= '$1=="min_dwell_seconds"{print $2+0}' "$cpu_pressure_control_marker" 2>/dev/null)
            cpc_max_recover_wait=$(awk -F= '$1=="max_recover_wait_seconds"{print $2+0}' "$cpu_pressure_control_marker" 2>/dev/null)
            cpc_file_shed=$(awk -F= '$1=="file_shed_threshold_pct"{print $2}' "$cpu_pressure_control_marker" 2>/dev/null)
            cpc_all_shed=$(awk -F= '$1=="all_shed_threshold_pct"{print $2}' "$cpu_pressure_control_marker" 2>/dev/null)
            cpc_recovery=$(awk -F= '$1=="recovery_threshold_pct"{print $2}' "$cpu_pressure_control_marker" 2>/dev/null)
            cpc_num_cpu=$(awk -F= '$1=="num_cpu"{print $2}' "$cpu_pressure_control_marker" 2>/dev/null)
            cpc_fail_reason=$(awk -F= '$1=="fail_reason"{ $1=""; print substr($0,2)}' "$cpu_pressure_control_marker" 2>/dev/null)
            echo "  наведённое CPU-давление вне окна (5.9.9.F.2b, №125): reduce=${cpc_reduce:-0} recover=${cpc_recover:-0}, ожидание reduce=${cpc_reduce_wait:-n/a}с recover=${cpc_recover_wait:-n/a}с (min_dwell=${cpc_min_dwell:-n/a}с, потолок=${cpc_max_recover_wait:-n/a}с)"
            echo "  пороги, прочитанные у агента: file_shed=${cpc_file_shed:-n/a} all_shed=${cpc_all_shed:-n/a} recovery=${cpc_recovery:-n/a} (num_cpu=${cpc_num_cpu:-n/a})"
            if [ "${cpc_reduce:-0}" -eq 1 ] && [ "${cpc_recover:-0}" -eq 1 ]; then
                pass "наведённое CPU-давление: reduce=1 recover=1, флапа нет (5.9.9.F.2b, №125); естественных переходов в окне замера 0, degraded_fraction=${deg_frac:-n/a}"
            elif [ "${cpc_reduce:-0}" -eq 1 ]; then
                fail "наведённое CPU-давление: reduce=1, но recovered не пришёл за 2×min_dwell=${cpc_max_recover_wait:-n/a}с — пара reduce↔recover не подтверждена (5.9.9.F.2b, №125)"
            else
                fail "наведённое CPU-давление: reduce=0 — ${cpc_fail_reason:-нагрузка не подняла cpu_pressure_level до file_shed} (5.9.9.F.2b, №125)"
            fi
        else
            skip "переходов reduce=0 — watchdog ни разу не сработал за прогон, и наведённое CPU-давление (5.9.9.F.2b, run_cpu_pressure_control) не запускалось или пропущено харнессом; порог \"не флапает\" не проверен; degraded_fraction=${deg_frac:-n/a}"
        fi
    elif awk -v r="$d_reduce" 'BEGIN{exit !(r+0 <= 1)}'; then
        pass "переходов reduce=$d_reduce recover=$d_recover — сработал, повторных нет (порог: <= 1 пара); degraded_fraction=${deg_frac:-n/a}"
    else
        fail "watchdog флапает: reduce=$d_reduce recover=$d_recover за прогон (ожидалось <= 1 пары; 813 циклов за ночь — ISSUES-attack-run-2026-08-03)"
    fi
fi
echo ""

# 15. Тождество счётчиков алертов (5.9c, находка №29). engine_stats.total_alerts
# считает всё, что сгенерировал движок ДО store.min_severity; ebpf_guard_alerts_total
# {rule_id} — то, что реально прошло фильтр и ушло в /metrics; /api/v1/alerts — стор,
# третье, независимое измерение. Находка №29 (5.8b, замер №2.5): расхождение
# стор/метрика было 2-30x на части правил, причина для них не найдена — стор и
# метрика НЕ гарантированно синхронны (canary-tamper/hidden-process пишутся в стор
# в обход счётчика, см. cmd/ebpf-guard/main.go). Тождество
# Δengine − Δalerts_filtered_total = Δexported = Δstore с допуском ≤1%: сходится —
# объяснение (min_severity + известные обходные пути) исчерпывающее; не сходится —
# есть четвёртый счётчик, о котором мы не знаем, и FAIL печатает все дельты, чтобы
# было с чем разбирать.
echo "=== 15. Тождество счётчиков алертов: Δengine−Δfiltered−Δsuppressed = Δexported = Δstore (5.9c) ==="
if command -v jq &> /dev/null; then
    engine_base=$(jq -r '.engine_stats.total_alerts // 0' "$baseline_state" 2>/dev/null || echo 0)
    engine_final=$(jq -r '.engine_stats.total_alerts // 0' "$final_state" 2>/dev/null || echo 0)
    d_engine=$(( engine_final - engine_base ))

    filtered_base=$(grep '^ebpf_guard_alerts_filtered_total{' "$baseline_metrics" 2>/dev/null \
        | awk -F'} ' '{s+=$2} END{printf "%d", s+0}')
    filtered_final=$(grep '^ebpf_guard_alerts_filtered_total{' "$final_metrics" 2>/dev/null \
        | awk -F'} ' '{s+=$2} END{printf "%d", s+0}')
    d_filtered=$(( ${filtered_final:-0} - ${filtered_base:-0} ))

    exported_base=$(grep '^ebpf_guard_alerts_total{' "$baseline_metrics" 2>/dev/null \
        | awk -F'} ' '{s+=$2} END{printf "%d", s+0}')
    exported_final=$(grep '^ebpf_guard_alerts_total{' "$final_metrics" 2>/dev/null \
        | awk -F'} ' '{s+=$2} END{printf "%d", s+0}')
    d_exported=$(( ${exported_final:-0} - ${exported_base:-0} ))

    store_base=$(jq 'length' "$baseline_alerts" 2>/dev/null || echo 0)
    store_final=$(jq 'length' "$final_alerts" 2>/dev/null || echo 0)
    d_store=$(( store_final - store_base ))

    # 5.9c-доработка (разбор на данных №2.5): между alertsGenerated и экспортом
    # есть легальный сток — analyst-подавление (feedbackManager.FilterAlerts),
    # с этой волны считаемое в ebpf_guard_alerts_suppressed_total{reason}.
    # Без вычитания тождество текло бы на каждом подавленном алерте. На
    # снимках агента до этой правки метрики нет — дельта тогда 0, и на данных
    # №2.5 idle тождество даёт задокументированный FAIL (340 против 344: +11
    # несчитанных incident_confirmed_attack, −7 не считавшихся подавлений).
    suppressed_base=$(grep '^ebpf_guard_alerts_suppressed_total{' "$baseline_metrics" 2>/dev/null \
        | awk -F'} ' '{s+=$2} END{printf "%d", s+0}')
    suppressed_final=$(grep '^ebpf_guard_alerts_suppressed_total{' "$final_metrics" 2>/dev/null \
        | awk -F'} ' '{s+=$2} END{printf "%d", s+0}')
    d_suppressed=$(( ${suppressed_final:-0} - ${suppressed_base:-0} ))

    d_lhs=$(( d_engine - d_filtered - d_suppressed ))
    echo "  Δengine(total_alerts)=$d_engine, Δfiltered(alerts_filtered_total)=$d_filtered, Δsuppressed(alerts_suppressed_total)=$d_suppressed, Δengine−Δfiltered−Δsuppressed=$d_lhs"
    echo "  Δexported(ebpf_guard_alerts_total)=$d_exported"
    echo "  Δstore(/api/v1/alerts)=$d_store"

    # 5.9.1c (находка №36): дельта тождества выше сходится только если ОБА
    # конца окна (baseline и final) сами по себе уже слиты — если baseline
    # снят слишком рано после рестарта (P0-3), у него остаётся собственный
    # engine−filtered−suppressed−exported ≠ 0, и это смещение переходит на
    # Δlhs целиком, хотя тождество внутри самого прогона верно. Печатаем
    # offset каждого конца отдельной строкой всегда — раньше это было видно
    # только если разбирать абсолютные величины вручную (см. plan.md, 5.9.1c).
    base_offset=$(( engine_base - ${filtered_base:-0} - ${suppressed_base:-0} - ${exported_base:-0} ))
    final_offset=$(( engine_final - ${filtered_final:-0} - ${suppressed_final:-0} - ${exported_final:-0} ))
    echo "  offset базового среза (engine−filtered−suppressed−exported)=$base_offset"
    echo "  offset финального среза (engine−filtered−suppressed−exported)=$final_offset"
    if [ "$base_offset" -ne 0 ] || [ "$final_offset" -ne 0 ]; then
        echo "  ВНИМАНИЕ: ненулевой offset на одном из концов окна — конвейер не слился к моменту снимка (см. 5.9.1c); baseline снимается с ожиданием слива в run-all-attacks.sh, но не гарантирован при таймауте 30с"
    fi

    # 5.9.4c (находка №54): final_offset выше — то же число, что и
    # final-drain-offset-$TIMESTAMP.txt, но посчитанное здесь заново из
    # готовых снимков, а не то, что get_final_metrics измерил В МОМЕНТ
    # снятия (с ретраями до 30с). Явный критерий по обоим числам: файл
    # подтверждает, что ожидание слива вообще было — final_offset подтверждает,
    # что оно сработало и на итоговых снимках, которые видит весь остальной
    # гейт. Расхождение между ними означало бы, что конвейер дотёк уже ПОСЛЕ
    # записи файла, но до снятия финальных снимков, — маловероятно (снимки
    # берутся сразу после цикла ожидания), но стоит печатать отдельно, а не
    # молча доверять файлу.
    final_drain_offset_file="$RESULTS_DIR/final-drain-offset-$TIMESTAMP.txt"
    if [ -f "$final_drain_offset_file" ]; then
        final_drain_offset=$(grep -o 'drain_offset_before_final=.*' "$final_drain_offset_file" | cut -d= -f2)
        echo "  final_drain_offset (5.9.4c, измерен в get_final_metrics с ретраями до 30с)=${final_drain_offset:-n/a}"
        if [ "$final_drain_offset" = "0" ] && [ "$final_offset" -eq 0 ]; then
            pass "final_drain_offset=0 и offset финального среза=0 — конвейер слился перед снятием финального среза (5.9.4c)"
        else
            fail "final_drain_offset=${final_drain_offset:-n/a}, offset финального среза=$final_offset — конвейер не слился перед финальным срезом (5.9.4c); тождество ниже наследует это смещение"
        fi
    else
        skip "final-drain-offset-$TIMESTAMP.txt не найден — final_drain_offset не измерен (артефакты собраны до 5.9.4c)"
    fi

    identity_ok=$(awk -v lhs="$d_lhs" -v exported="$d_exported" -v store="$d_store" '
        BEGIN {
            base = (lhs > 0) ? lhs : ((exported > 0) ? exported : ((store > 0) ? store : 0))
            if (base == 0) {
                print (lhs == exported && exported == store) ? 1 : 0
                exit
            }
            tol = base * 0.01
            if (tol < 1) tol = 1
            diff_exp = lhs - exported; if (diff_exp < 0) diff_exp = -diff_exp
            diff_store = lhs - store; if (diff_store < 0) diff_store = -diff_store
            print (diff_exp <= tol && diff_store <= tol) ? 1 : 0
        }
    ')
    if [ "$identity_ok" -eq 1 ]; then
        pass "тождество сходится (допуск <= 1%): Δengine−Δfiltered−Δsuppressed=$d_lhs = Δexported=$d_exported = Δstore=$d_store"
    else
        fail "тождество расходится сверх допуска 1%: Δengine=$d_engine, Δfiltered=$d_filtered, Δsuppressed=$d_suppressed, Δengine−Δfiltered−Δsuppressed=$d_lhs, Δexported=$d_exported, Δstore=$d_store — есть четвёртый счётчик (находка №29)"
    fi
else
    skip "jq недоступен — тождество счётчиков алертов не проверено"
fi
echo ""

# 16. Слепое окно idle-конец → attack-baseline (5.9f, находка №32; переписано
# 5.9.4g, находка №58): окно между концом idle-часа (idle-run.sh) и снятием
# baseline этого прогона — время подготовки стенда и входа оператора — не
# покрыто ни idle-измерением, ни окном атаки, и в прогоне №2.5 именно в нём
# произошли все дропы, а темп алертов в нём был выше обоих измеряемых окон.
# Постановка 5.9f: baseline этого прогона снимается ПОСЛЕ подготовки стенда и
# входа оператора (см. run-all-attacks.sh: get_baseline_metrics вызывается
# только после check_services) — здесь эта политика не проверяется, только
# измеряется её следствие: объём окна. Информационно, без PASS/FAIL — порог
# для нового окна ставить рано.
#
# №58: на №2.9.3 снимок конца idle и baseline атак совпали по времени (окно
# 0.0 мин), но объём «38 новых алертов» всё равно напечатался — числитель и
# знаменатель были оба вырождены, и величина выглядела как измерение там, где
# измерения не было. 5.9.4g: окно короче 10с честно печатает «не измерялось»
# вместо деления на почти-ноль.
#
# №58, вторая часть: объём окна раньше брался дельтой кумулятивного счётчика
# ebpf_guard_alerts_total (idle-конец vs attack-baseline) — тот же счётчик,
# который idle-run.sh обнуляет своим рестартом в конце (P0-3), и делал дельту
# отрицательной/бессмысленной. Теперь считается по множеству `id` снимков
# /api/v1/alerts: IDLE_ALERTS_END (idle-run.sh пишет его сам как
# alerts-end.json) против baseline-alerts этого прогона. Разность множеств
# «id есть в baseline, id нет в idle-конце» уже исключает всё, что попало в
# idle-час — считать это отдельным вычитанием не нужно.
# 5.9.6h (находка №76): раньше секция была наблюдением без PASS/FAIL — окно
# растянулось с 8.9 до 12с (5.9.5i) и заполнилось 53 алертами (22% прогона
# №2.9.5) без единой связи с гейтом. Постановка даёт два легитимных исхода:
# окно схлопывается до объёма, где содержимое пренебрежимо (<= 5 алертов),
# либо каждый тип из критерия 6 получает фазу из трёх (attack/idle/gap) без
# "не определено". Проверяется здесь оба варианта, PASS по первому истинному.
echo "=== 16. Слепое окно idle-конец → attack-baseline (5.9.6h: <=5 алертов либо все фазы определены; 5.9.7g: при added_count<3 — по составу окна) ==="
if [ -z "$IDLE_STATE_END" ] || [ ! -s "$IDLE_STATE_END" ]; then
    skip "IDLE_STATE_END не задан — окно idle-конец → attack-baseline не измерено"
elif ! command -v jq &> /dev/null; then
    skip "jq недоступен — окно idle-конец → attack-baseline не измерено"
else
    idle_end_ts=$(jq -r '.timestamp // empty' "$IDLE_STATE_END" 2>/dev/null)
    baseline_ts=$(jq -r '.timestamp // empty' "$baseline_state" 2>/dev/null)
    if [ -z "$idle_end_ts" ] || [ -z "$baseline_ts" ]; then
        skip "нет .timestamp в IDLE_STATE_END или baseline-state — окно не измерено"
    else
        # 5.9.9.F.1a: через iso_to_epoch, иначе вся секция 16 «не измерялась»
        # на любой системе без GNU date — то есть офлайн-реплей правки
        # 5.9.9.F.1a не доходил бы до классификации вовсе.
        idle_end_epoch=$(iso_to_epoch "$idle_end_ts" || echo 0)
        baseline_epoch=$(iso_to_epoch "$baseline_ts" || echo 0)
        blind_sec=$(awk -v a="$idle_end_epoch" -v b="$baseline_epoch" 'BEGIN{ if(a>0 && b>a) printf "%.1f", (b-a); else print "n/a" }')

        if [ "$blind_sec" = "n/a" ]; then
            echo "  не измерялось: timestamp'ы IDLE_STATE_END/baseline-state не разобраны или baseline не позже idle-конца"
        elif awk -v s="$blind_sec" 'BEGIN{exit !(s+0 < 10)}'; then
            echo "  не измерялось: окно ${blind_sec}с < 10с — снимки idle-конца и attack-baseline совпали по времени (№58)"
        else
            blind_min=$(awk -v s="$blind_sec" 'BEGIN{printf "%.1f", s/60}')
            if [ -z "$IDLE_ALERTS_END" ] || [ ! -s "$IDLE_ALERTS_END" ]; then
                echo "  окно: ${blind_min} мин; объём не измерен — IDLE_ALERTS_END не задан"
            elif ! jq -e 'type == "array"' "$IDLE_ALERTS_END" >/dev/null 2>&1; then
                echo "  окно: ${blind_min} мин; объём не измерен — IDLE_ALERTS_END не JSON-массив"
            else
                blind_new_alerts=$(jq -n --slurpfile a "$baseline_alerts" --slurpfile b "$IDLE_ALERTS_END" '
                    ($b[0] | map(.id)) as $seen
                    | ($a[0] | map(select(.id as $i | ($seen | index($i)) | not))) | length')
                blind_rate="n/a"
                if awk -v m="$blind_min" 'BEGIN{exit !(m+0>0)}'; then
                    blind_rate=$(awk -v a="$blind_new_alerts" -v m="$blind_min" 'BEGIN{printf "%.1f", a/m}')
                fi
                echo "  окно: ${blind_min} мин, новых алертов (по id, вне idle-часа): $blind_new_alerts (темп: ${blind_rate}/мин)"
                echo "  (для сравнения: измеряемые окна атаки/idle дают $attacker_rate/мин и (idle-час) отдельно)"
                # 5.9.9.Fb (находка №109): лаг подхвата печатается числом
                # всегда, а не только при FAIL — это величина, которой раньше
                # не было ни в одном артефакте прогона, хотя она и определяет
                # ширину структурно неизмеримого окна (регистрация корня →
                # подтверждение агентом через /debug/state).
                root_register_epoch=""
                root_confirm_epoch=""
                root_confirmed=""
                root_lag_sec="n/a"
                if [ -s "$observer_root_marker" ]; then
                    root_register_epoch=$(awk -F= '$1=="register_epoch"{print $2}' "$observer_root_marker")
                    root_confirmed=$(awk -F= '$1=="confirmed"{print $2}' "$observer_root_marker")
                    root_confirm_epoch=$(awk -F= '$1=="confirm_epoch"{print $2}' "$observer_root_marker")
                    lag_from_marker=$(awk -F= '$1=="lag_sec"{print $2}' "$observer_root_marker")
                    [ -n "$lag_from_marker" ] && root_lag_sec="$lag_from_marker"
                fi
                if [ "$root_lag_sec" = "n/a" ]; then
                    echo "  лаг подхвата observer_root (регистрация → подтверждение через /debug/state): не измерен (маркер observer-root-register-$TIMESTAMP.txt отсутствует или подтверждения не было)"
                else
                    echo "  лаг подхвата observer_root (регистрация → подтверждение через /debug/state): ${root_lag_sec}с"
                fi
                # 5.9.9e (№102, находка №2.9.8): разбор по составу раньше был
                # условен на blind_new_alerts > 5 — окно с 1-5 новыми алертами
                # получало ранний PASS по объёму и НИКОГДА не проверялось на
                # присутствие дерева измерителя. Пункт постановки существовал
                # (5.9.7g/5.9.8g), а ветка для малых окон не исполнялась —
                # именно тот разрыв, который эта волна закрывает. Теперь
                # разбор считается всегда, когда есть чем его считать
                # (detection-baseline.txt доступен), а ранний PASS по объёму
                # остаётся вердиктом — но harness_alerts > 0 проваливает
                # критерий безусловно, даже если blind_new_alerts <= 5.
                harness_alerts=0
                background_alerts=0
                background_breakdown=""
                composition_checked=0
                if [ "$baseline_types_present" -ne 0 ]; then
                    composition_checked=1
                    # harness_comms — хоистирован на уровень скрипта (см.
                    # определение выше, 5.9.9.Fd): дерево измерителя
                    # run-all-attacks.sh/idle-run.sh, выведено ИЗ ДАННЫХ, не из
                    # чтения тела функций. Намеренно НЕ содержит comm'ов
                    # атакующих шагов (chmod, tee, insmod, bpftool, clang, dig,
                    # python3, sqlmap): пометить их «деревом измерителя»
                    # значило бы дать настоящему регрессу спрятаться под этим
                    # списком.
                    blind_comm_breakdown=$(jq -n --slurpfile a "$baseline_alerts" --slurpfile b "$IDLE_ALERTS_END" '
                        ($b[0] | map(.id)) as $seen
                        | ($a[0] | map(select(.id as $i | ($seen | index($i)) | not)))
                        | group_by(.comm // "")
                        | map({comm: (.[0].comm // "(пусто)"), count: length})
                        | sort_by(-.count)')
                    echo "  разбор по составу (5.9.7g/5.9.8g):"
                    record_covered "разбор по составу (5.9.7g/5.9.8g)"
                    while IFS= read -r row; do
                        [ -z "$row" ] && continue
                        row_comm=$(echo "$row" | jq -r '.comm')
                        row_count=$(echo "$row" | jq -r '.count')
                        row_is_harness=0
                        for hc in $harness_comms; do
                            [ "$row_comm" = "$hc" ] && row_is_harness=1 && break
                        done
                        if [ "$row_is_harness" -eq 1 ]; then
                            harness_alerts=$((harness_alerts + row_count))
                            echo "    ! $row_comm: $row_count (дерево измерителя)"
                        else
                            background_alerts=$((background_alerts + row_count))
                            background_breakdown="$background_breakdown $row_comm:$row_count"
                            echo "    . $row_comm: $row_count"
                        fi
                    done < <(echo "$blind_comm_breakdown" | jq -c '.[]')
                    # Строка "фон" — отдельно от вердикта по построению
                    # (5.9.8g: "алерты фона печатаются отдельной строкой").
                    # docker-proxy и подобные comm'ы вне дерева измерителя не
                    # проваливают критерий 16 сами по себе — это наблюдение,
                    # не промах.
                    echo "  дерево измерителя: $harness_alerts алерт(ов); фон вне дерева измерителя (5.9.8g): $background_alerts алерт(ов)${background_breakdown:+ (${background_breakdown# })}"
                    record_covered "фон вне дерева измерителя (5.9.8g)"

                    # 5.9.9.Fb (находка №109): каждый алерт дерева измерителя
                    # относится к одному из трёх случаев, различимых только по
                    # временам — регистрация корня, подтверждение подхвата,
                    # собственный timestamp алерта:
                    #   1. алерт СТАРШЕ регистрации root_pid — предшествует ей;
                    #   2. алерт МЕЖДУ регистрацией и подтверждением — окно лага;
                    #   3. алерт ПОСЛЕ подтверждения — вот это и есть
                    #      «observer_root не подхвачен» в буквальном смысле.
                    # Без маркера (наблюдательное дерево регистрируется, но
                    # эта волна не переиграна на стенде, либо старый
                    # run-all-attacks.sh) все харнесс-алерты остаются
                    # неклассифицированными — вердикт ниже не должен молчать
                    # об этом.
                    harness_case1=0
                    harness_case2=0
                    harness_case3=0
                    harness_unclassified=0
                    # 5.9.9.F.2f (находка №126): постановка 5.9.9.F.1a просила
                    # формат «1 алерт предшествует регистрации корня, −26 мс» —
                    # печатались только число алертов по случаю и лаг подхвата
                    # (отдельная величина), самого смещения не было, и
                    # восстановить его из отчёта было нельзя. Смещение
                    # (alert_epoch − root_register_epoch, мс, отрицательное —
                    # алерт раньше регистрации) собирается для каждого алерта
                    # случая 1 и печатается рядом со счётчиком.
                    harness_case1_offsets=""
                    if [ "$harness_alerts" -gt 0 ]; then
                        harness_comms_jq=$(printf '%s\n' $harness_comms | jq -R . | jq -s .)
                        # 5.9.9.Fh (находка №113): -r обязателен. Без него jq
                        # печатает JSON-строку В КАВЫЧКАХ, date -d "\"…\"" не
                        # разбирает её никогда, alert_epoch пуст — и КАЖДЫЙ
                        # харнесс-алерт попадал в harness_unclassified, то есть
                        # вся классификация 5.9.9.Fb была мертва с рождения, а
                        # вердикт называл причиной «маркер недоступен» при
                        # исправном маркере.
                        harness_ts_list=$(jq -rn --slurpfile a "$baseline_alerts" --slurpfile b "$IDLE_ALERTS_END" --argjson hc "$harness_comms_jq" '
                            ($b[0] | map(.id)) as $seen
                            | ($a[0] | map(select(.id as $i | ($seen | index($i)) | not)))
                            | map(select((.comm // "") as $c | $hc | index($c)))
                            | map(.timestamp // empty)
                            | .[]' 2>/dev/null)
                        while IFS= read -r alert_ts; do
                            [ -z "$alert_ts" ] && continue
                            if [ -z "$root_register_epoch" ]; then
                                harness_unclassified=$((harness_unclassified + 1))
                                continue
                            fi
                            alert_epoch=$(iso_to_epoch "$alert_ts")
                            if [ -z "$alert_epoch" ]; then
                                harness_unclassified=$((harness_unclassified + 1))
                                continue
                            fi
                            if awk -v a="$alert_epoch" -v r="$root_register_epoch" 'BEGIN{exit !(a<r)}'; then
                                harness_case1=$((harness_case1 + 1))
                                offset_ms=$(awk -v a="$alert_epoch" -v r="$root_register_epoch" 'BEGIN{printf "%.0f", (a-r)*1000}')
                                harness_case1_offsets="$harness_case1_offsets ${offset_ms}мс"
                            elif [ "$root_confirmed" = "1" ] && [ -n "$root_confirm_epoch" ] \
                                 && awk -v a="$alert_epoch" -v c="$root_confirm_epoch" 'BEGIN{exit !(a<=c)}'; then
                                harness_case2=$((harness_case2 + 1))
                            else
                                harness_case3=$((harness_case3 + 1))
                            fi
                        done <<< "$harness_ts_list"
                        echo "  дерево измерителя по случаю (5.9.9.Fb): предшествуют регистрации корня=$harness_case1${harness_case1_offsets:+ (смещения:${harness_case1_offsets})}, окно лага подхвата=$harness_case2, после подтверждения (не подхвачен)=$harness_case3, не классифицировано=$harness_unclassified"
                    fi
                fi
                # 5.9.9.Fb (находка №109): причина FAIL называется тем из трёх
                # случаев выше, который реально наблюдался — «observer_root не
                # подхвачен» теперь означает только случай 3 (алерт ПОСЛЕ
                # подтверждения); случаи 1 и 2 структурно неизбежны (алерт до
                # регистрации корня, алерт в окне лага) и называются так же.
                #
                # 5.9.9.F.1a (находка №116): вердикт теперь СЛЕДУЕТ этому
                # разбору, а не игнорирует его. До правки ветка смотрела
                # только на harness_alerts > 0 и валила прогон независимо от
                # случая — то есть печатала «не считается поломкой подхвата»
                # и тут же FAIL. Дефект не косметический: харнесс-bash
                # алертится РАНЬШЕ, чем пролог успевает записать свой pid
                # (замер №2.9.9.F: алерт ...439.880, регистрация ...439.906,
                # разница 26 мс, и pid алерта даже не тот, что регистрируется
                # корнем) — значит у критерия не было достижимого PASS по
                # построению, и он навсегда оставался ручным переводом
                # вердикта. Валят только те случаи, которые действительно
                # означают промах подхвата:
                #   случай 3        — алерт от дерева измерителя ПОСЛЕ
                #                     подтверждения подхвата;
                #   не классифицировано — маркер отсутствует или не читается,
                #                     то есть разбор провести не на чем.
                # Второе обязательно: без него пропажа маркера снова стала бы
                # тихим PASS, а это находка №109 наоборот.
                # Значения по умолчанию: блок классификации выше исполняется
                # только при composition_checked=1 и harness_alerts>0.
                harness_case1=${harness_case1:-0}; harness_case2=${harness_case2:-0}
                harness_case3=${harness_case3:-0}; harness_unclassified=${harness_unclassified:-0}
                harness_blocking=$((harness_case3 + harness_unclassified))
                harness_benign=$((harness_case1 + harness_case2))
                harness_reason() {
                    if [ "$harness_case3" -gt 0 ]; then
                        echo "observer_root не подхвачен агентом на этом прогоне: $harness_case3 алерт(ов) после подтверждения подхвата (5.9.7g/5.9.8g/5.9.9.Fb)"
                    else
                        echo "$harness_unclassified алерт(ов) от дерева измерителя не классифицированы по времени (маркер observer-root-register-$TIMESTAMP.txt недоступен или не разобран, 5.9.9.Fb/5.9.9.F.1a)"
                    fi
                }
                # Величина не исчезает вместе с FAIL: случай называется и в
                # тексте PASS, числом (5.9.9.F.1a).
                harness_benign_reason() {
                    if [ "$harness_case1" -gt 0 ] && [ "$harness_case2" -gt 0 ]; then
                        echo "$harness_case1 предшествуют регистрации корня + $harness_case2 в окне лага подхвата (${root_lag_sec}с)"
                    elif [ "$harness_case2" -gt 0 ]; then
                        echo "$harness_case2 алерт(ов) в окне лага подхвата (${root_lag_sec}с между регистрацией и подтверждением)"
                    else
                        echo "$harness_case1 алерт(ов) предшествуют регистрации корня"
                    fi
                }
                if awk -v n="$blind_new_alerts" 'BEGIN{exit !(n<=5)}'; then
                    if [ "$composition_checked" -eq 1 ] && [ "$harness_blocking" -gt 0 ]; then
                        fail "объём слепого окна $blind_new_alerts <= 5, но $harness_blocking алерт(ов) — от дерева измерителя (см. \"!\" выше) — $(harness_reason)"
                    elif [ "$composition_checked" -eq 1 ] && [ "$harness_benign" -gt 0 ]; then
                        pass "объём слепого окна $blind_new_alerts <= 5; $harness_benign алерт(ов) дерева измерителя — структурно неизбежные: $(harness_benign_reason) (5.9.9.Fb/5.9.9.F.1a)"
                    else
                        pass "объём слепого окна $blind_new_alerts <= 5 — содержимое окна пренебрежимо (5.9.6h)"
                    fi
                elif [ "$composition_checked" -eq 0 ]; then
                    # detection-baseline.txt отсутствует вовсе — added_count
                    # недостоверен (не 0, а "не считался"), ни разбор по
                    # фазам, ни разбор по составу (5.9.7g/5.9.8g) провести не на чем.
                    skip "объём слепого окна $blind_new_alerts > 5, а detection-baseline.txt отсутствует — added_count не определён, ни фазы, ни разбор по составу (5.9.7g/5.9.8g) не проверены"
                else
                    # 5.9.9.F.1a: на широком окне структурно неизбежные алерты
                    # НЕ дают pass сами по себе — исполнение обязано провалиться
                    # дальше, в разбор по фазам. Иначе харнесс-алерт стал бы
                    # способом обойти 5.9.6h/5.9.7g на окне любой ширины.
                    harness_note=""
                    [ "$harness_benign" -gt 0 ] && harness_note=" ($harness_benign алерт(ов) дерева измерителя структурно неизбежны: $(harness_benign_reason))"
                    if [ "$harness_blocking" -gt 0 ]; then
                        fail "объём слепого окна $blind_new_alerts > 5, и $harness_blocking алерт(ов) — от дерева измерителя (см. \"!\" выше) — $(harness_reason)"
                    elif [ "$added_count" -lt 3 ]; then
                        pass "объём слепого окна $blind_new_alerts > 5, added_count=$added_count < 3, 0 алертов дерева измерителя, означающих промах подхвата${harness_note} — окно не слепое по составу (5.9.7g)"
                    elif [ "$added_undetermined_count" -eq 0 ]; then
                        pass "объём слепого окна $blind_new_alerts > 5, 0 алертов дерева измерителя, означающих промах подхвата${harness_note}, и у каждого из добавленных в критерии 6 типов определена фаза (attack/idle/gap) — окно не слепое (5.9.6h/5.9.8g)"
                    else
                        fail "объём слепого окна $blind_new_alerts > 5, 0 алертов дерева измерителя, означающих промах подхвата${harness_note}, но $added_undetermined_count добавленных типов в критерии 6 остались с неопределённой фазой — состав не объяснён (5.9.6h)"
                    fi
                fi
            fi
        fi
    fi
fi
echo ""

# 5.9.9.Fd (№108, P1): состав окна атаки (baseline→final, новые по id) по
# критикалам, разобранным по comm на три класса — величина, которой на
# №2.9.9 не было вовсе: 138 новых критикалов за окно, и ни один критерий
# гейта не спрашивал, кто их породил. Второй по величине производитель был
# grep (23) — все они cred_proc_maps_mass_read на /proc/self/maps, дефект
# правила (5.9.9.Fa), а не что-то отдельное, требующее разбора здесь.
#
# Секция 16 выше — про слепое окно между концом idle-часа и attack-baseline;
# эта секция — про само окно атаки (baseline→final). Их пересечение пусто по
# построению (5.9.9.Fd намеренно не трогает секцию 16), поэтому harness_comms
# (хоистирован на уровень скрипта) используется тем же списком, но на другом
# срезе алертов.
#
# Вердикта на первом прогоне нет — только величина (см. plan.md 5.9.9.Fd):
# порог назначается по итогам №2.9.9.F, той же логикой, что уже применена к
# alerts_dropped/published (5.9.6i: порог на неизмеренную величину даёт
# PASS/FAIL по случайности, а не по существу). Единственный уже вынесенный
# вердикт внутри разбора — cred_proc_maps_mass_read на /proc/self/maps = 0
# (5.9.9.Fa), потому что там правильный ответ известен заранее (44 из 44
# разобраны поимённо на №2.9.9).
echo "=== 5.9.9.Fd. Состав окна атаки по критикалам: манифест / дерево измерителя / прочее (№108) ==="
if [ ! -s "$baseline_alerts" ] || [ ! -s "$final_alerts" ]; then
    skip "baseline/final-alerts недоступны — состав окна атаки не разобран (5.9.9.Fd)"
elif ! command -v jq &> /dev/null; then
    skip "jq недоступен — состав окна атаки не разобран (5.9.9.Fd)"
else
    attackwin_criticals=$(jq -s '
        (.[0] // []) as $baseline | (.[1] // []) as $final |
        ($baseline | map(.id) | unique) as $bids |
        ($final | map(select(.id as $id | ($bids | index($id)) | not))) as $new |
        $new | map(select(.severity == "critical"))
    ' -r "$baseline_alerts" "$final_alerts" 2>/dev/null)
    attackwin_total=$(echo "${attackwin_criticals:-[]}" | jq 'length' 2>/dev/null || echo 0)
    if ! [ "$attackwin_total" -ge 0 ] 2>/dev/null; then
        attackwin_total=0
    fi
    if [ "$attackwin_total" -eq 0 ]; then
        echo "  критикалов окна атаки: 0"
        record_covered "критикалов окна атаки"
        pass "критикалов окна атаки: 0 — разбор по составу не нужен (5.9.9.Fd)"
    else
        attackwin_manifest_comms='[]'
        [ -f "$manifest_file" ] && attackwin_manifest_comms=$(jq -c '[.[].comm] | unique' "$manifest_file" 2>/dev/null || echo '[]')
        attackwin_harness_comms_jq=$(printf '%s\n' $harness_comms | jq -R . | jq -s .)
        attackwin_breakdown=$(echo "$attackwin_criticals" | jq -c \
            --argjson manifest "$attackwin_manifest_comms" --argjson harness "$attackwin_harness_comms_jq" '
            map(
                (.comm // "") as $c |
                if ($manifest | index($c)) then {class: "manifest", comm: $c}
                elif ($harness | index($c)) then {class: "harness", comm: $c}
                else {class: "other", comm: (.comm // "(пусто)")}
                end
            )')
        attackwin_manifest_n=$(echo "$attackwin_breakdown" | jq '[.[] | select(.class=="manifest")] | length')
        attackwin_harness_n=$(echo "$attackwin_breakdown" | jq '[.[] | select(.class=="harness")] | length')
        attackwin_other_n=$(echo "$attackwin_breakdown" | jq '[.[] | select(.class=="other")] | length')
        attackwin_other_list=$(echo "$attackwin_breakdown" | jq -r '
            [.[] | select(.class=="other") | .comm] | group_by(.)
            | map({comm: .[0], count: length}) | sort_by(-.count) | .[] | "\(.comm):\(.count)"' \
            2>/dev/null | tr '\n' ' ')

        echo "  критикалов окна атаки (baseline→final, новые по id): $attackwin_total"
        echo "  от манифестных comm: $attackwin_manifest_n"
        echo "  от дерева измерителя (harness_comms, тот же список, что у критерия 16): $attackwin_harness_n"
        echo "  прочее: $attackwin_other_n${attackwin_other_list:+ (${attackwin_other_list% })}"
        record_covered "критикалов окна атаки"

        # 5.9.9.F.2e (№121): состав только по comm не отличал бы правило,
        # которое волна 5.9.9.F.1 уже погасила (web_sql_injection_files), от
        # правила, которое осталось шуметь (sigma_memory_proc_dump), — обе
        # величины 19/10 нашла не эта секция, а ручной разбор
        # ISSUES-5.9.9.F-threshold-audit.txt по ebpf_guard_alerts_total.
        # Состав по правилам печатается тем же срезом (attackwin_criticals),
        # чтобы следующая волна получила ответ "какое правило" бесплатно.
        attackwin_by_rule=$(echo "$attackwin_criticals" | jq -r '
            [.[] | (.rule_id // "(пусто)")] | group_by(.)
            | map({rule: .[0], count: length}) | sort_by(-.count)
            | .[] | "    \(.count)\t\(.rule)"' 2>/dev/null)
        echo "  критикалов окна атаки по правилам:"
        echo "$attackwin_by_rule"

        attackwin_sum=$((attackwin_manifest_n + attackwin_harness_n + attackwin_other_n))
        if [ "$attackwin_sum" -ne "$attackwin_total" ]; then
            fail "5.9.9.Fd: сумма классов ($attackwin_sum) != общего числа критикалов окна ($attackwin_total) — разбор по составу не сходится"
        else
            pass "критикалов окна атаки разобраны по составу: манифест=$attackwin_manifest_n, дерево измерителя=$attackwin_harness_n, прочее=$attackwin_other_n, сумма=$attackwin_total — величина, порог назначается по итогам №2.9.9.F (5.9.9.Fd)"
        fi
    fi

    # 5.9.9.F.2e (№121): найденные 19/10 шумели ВНЕ окна атаки (в idle и на
    # других отрезках аптайма), поэтому состав, ограниченный baseline→final,
    # по построению их не видит — секция 5.9.9.Fd мерила не то окно, в
    # котором была величина. Состав за ВЕСЬ аптайм печатается отдельной
    # строкой из final_alerts (полный дамп стора с момента старта агента, не
    # окно прогона — тот же источник, что критерий 5.9.9c использует для
    # store_final) — без разбора baseline/new, специально шире окна атаки.
    if [ -s "$final_alerts" ] && command -v jq &> /dev/null \
        && jq -e 'type == "array"' "$final_alerts" >/dev/null 2>&1; then
        uptime_crit_total=$(jq '[.[] | select(.severity == "critical")] | length' "$final_alerts" 2>/dev/null || echo 0)
        echo "  критикалов за весь аптайм (final_alerts, полный дамп стора, справочно вне окна атаки): $uptime_crit_total"
        if [ "$uptime_crit_total" -gt 0 ]; then
            echo "  состав за весь аптайм по правилам:"
            jq -r '[.[] | select(.severity == "critical") | (.rule_id // "(пусто)")]
                | group_by(.) | map({rule: .[0], count: length}) | sort_by(-.count)
                | .[] | "    \(.count)\t\(.rule)"' "$final_alerts" 2>/dev/null
            echo "  состав за весь аптайм по comm:"
            jq -r '[.[] | select(.severity == "critical") | (.comm // "(пусто)")]
                | group_by(.) | map({comm: .[0], count: length}) | sort_by(-.count)
                | .[] | "    \(.comm): \(.count)"' "$final_alerts" 2>/dev/null
        fi
        record_covered "критикалов за весь аптайм"
    else
        echo "  состав за весь аптайм не считался: final_alerts недоступен или не массив"
    fi
fi
echo ""

# 5.9.9.F.1d (№115, P1): дельта ebpf_guard_incidents_total{verdict="attack"}
# за idle-час — главная величина часа простоя, которую до этой волны не читал
# НИ ОДИН критерий гейта. idle/SUMMARY.txt печатал её сам, с собственной
# пометкой «должно быть 0 — P1-6/P1-13», и на этом всё: на №2.9.9.F там стояло
# 7, гейт напечатал PASS=42 и о числе не знал. Родня находки №108 (там не
# проверялся состав окна атаки), но про другое окно.
#
# Порога в этой волне НЕТ намеренно — тем же запретом 5.9.6, что применён к
# 5.9.9.Fd и к alerts_dropped/published: критерий с неизвестным правильным
# ответом выносит вердикт по случайности. 7 из SUMMARY.txt — не измерение
# критерием, а число, напечатанное сбоку; эта секция измеряет его впервые.
# Порог назначается по итогам №2.9.9.F.1.
#
# Вместе с числом печатается состав — по comm и по правилам-участникам.
# Иначе следующая волна получит ту же величину без ответа на вопрос «кто»,
# ровно как критерий 6 получал 138 критикалов до 5.9.9.Fd. Состав считается
# по алертам idle-часа (IDLE_ALERTS_START→END): снимка инцидентов за idle-час
# стенд не делает, а правило incident_confirmed_attack срабатывает ровно на
# промоушене инцидента — на №2.9.9.F его 7 алертов совпали с дельтой
# счётчика 4→11 ... 7, то есть прокси точная, но она ПРОКСИ, и расхождение
# печатается, а не скрывается.
echo "=== 5.9.9.F.1d. Инциденты verdict=\"attack\" за idle-час: величина + состав (№115) ==="
if [ -z "$IDLE_METRICS_START" ] || [ -z "$IDLE_METRICS_END" ] \
    || [ ! -s "$IDLE_METRICS_START" ] || [ ! -s "$IDLE_METRICS_END" ]; then
    skip "IDLE_METRICS_START/END не заданы — дельта verdict=\"attack\" за idle-час не измерена (5.9.9.F.1d)"
else
    idle_verdict_metric() {
        awk -v v="$2" '$0 ~ "^ebpf_guard_incidents_total\\{verdict=\"" v "\"\\}" {print $2}' "$1" 2>/dev/null | tail -1
    }
    idle_attack_start=$(idle_verdict_metric "$IDLE_METRICS_START" attack)
    idle_attack_end=$(idle_verdict_metric "$IDLE_METRICS_END" attack)
    idle_susp_start=$(idle_verdict_metric "$IDLE_METRICS_START" suspicious)
    idle_susp_end=$(idle_verdict_metric "$IDLE_METRICS_END" suspicious)
    if [ -z "$idle_attack_start" ] || [ -z "$idle_attack_end" ]; then
        skip "ebpf_guard_incidents_total{verdict=\"attack\"} отсутствует в срезах idle-часа — величина не измерена (5.9.9.F.1d)"
    else
        idle_attack_delta=$(awk -v a="$idle_attack_start" -v b="$idle_attack_end" 'BEGIN{printf "%d", b-a}')
        idle_susp_delta=$(awk -v a="${idle_susp_start:-0}" -v b="${idle_susp_end:-0}" 'BEGIN{printf "%d", b-a}')
        echo "  verdict=\"attack\" за idle-час: ${idle_attack_start} -> ${idle_attack_end}, дельта = $idle_attack_delta"
        echo "  verdict=\"suspicious\" за idle-час (справочно): ${idle_susp_start:-n/a} -> ${idle_susp_end:-n/a}, дельта = $idle_susp_delta"
        record_covered "verdict=\"attack\" за idle-час"

        # 5.9.9.F.2d (№118): дельта не сопоставима между замерами (11:07
        # утром против 4 ночью на одной и той же волне) — её меняет не
        # регресс, а час суток. Порог по числу по-прежнему не назначается.
        # Вместо порога печатается окно idle-часа в UTC (по mtime срезов
        # IDLE_METRICS_START/END — единственная метка времени, которая есть
        # у среза без дополнительных переменных окружения) — величина,
        # которая делает дельты разных замеров читаемыми рядом, а не
        # сопоставимыми напрямую.
        idle_win_start_epoch=$(stat -c %Y "$IDLE_METRICS_START" 2>/dev/null || stat -f %m "$IDLE_METRICS_START" 2>/dev/null)
        idle_win_end_epoch=$(stat -c %Y "$IDLE_METRICS_END" 2>/dev/null || stat -f %m "$IDLE_METRICS_END" 2>/dev/null)
        idle_win_start_utc=$(date -u -d "@${idle_win_start_epoch:-0}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
            || date -u -r "${idle_win_start_epoch:-0}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)
        idle_win_end_utc=$(date -u -d "@${idle_win_end_epoch:-0}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
            || date -u -r "${idle_win_end_epoch:-0}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)
        echo "  окно idle-часа (UTC, по mtime срезов IDLE_METRICS_START/END): ${idle_win_start_utc:-?} -> ${idle_win_end_utc:-?}"

        # Состав. Печатается ВСЕГДА, когда есть на чём считать, — в том числе
        # при дельте 0: «состав пуст» и «состав не считался» это разные строки.
        idle_actors_ok=""
        if [ -n "$IDLE_ALERTS_START" ] && [ -s "$IDLE_ALERTS_START" ] \
            && [ -n "$IDLE_ALERTS_END" ] && [ -s "$IDLE_ALERTS_END" ] \
            && command -v jq &> /dev/null; then
            idle_new_alerts=$(jq -c -n --slurpfile a "$IDLE_ALERTS_START" --slurpfile b "$IDLE_ALERTS_END" '
                ($a[0] // [] | map(.id)) as $seen
                | (($b[0] // []) | map(select(.id as $i | ($seen | index($i)) | not)))' 2>/dev/null)
            idle_new_n=$(echo "${idle_new_alerts:-[]}" | jq 'length' 2>/dev/null || echo 0)
            idle_new_crit=$(echo "${idle_new_alerts:-[]}" | jq '[.[] | select(.severity=="critical")] | length' 2>/dev/null || echo 0)
            idle_promo_n=$(echo "${idle_new_alerts:-[]}" | jq '[.[] | select(.rule_id=="incident_confirmed_attack")] | length' 2>/dev/null || echo 0)
            echo "  алертов за idle-час: $idle_new_n, из них critical: $idle_new_crit"
            echo "  алертов incident_confirmed_attack (прокси промоушена): $idle_promo_n"
            if [ "$idle_promo_n" -ne "$idle_attack_delta" ]; then
                echo "  ! прокси расходится со счётчиком ($idle_promo_n против $idle_attack_delta) — состав ниже неполон, разбирать по журналу"
            fi
            echo "  состав промоушенов по comm:"
            echo "${idle_new_alerts:-[]}" | jq -r '
                [.[] | select(.rule_id=="incident_confirmed_attack") | (.comm // "(пусто)")]
                | group_by(.) | map({comm: .[0], count: length}) | sort_by(-.count)
                | .[] | "    \(.comm): \(.count)"' 2>/dev/null || true
            echo "  критикалы idle-часа по правилам (кто наполняет час простоя):"
            echo "${idle_new_alerts:-[]}" | jq -r '
                [.[] | select(.severity=="critical") | {r: (.rule_id // "(пусто)"), c: (.comm // "(пусто)")}]
                | group_by(.r) | map({rule: .[0].r, count: length, comms: (map(.c) | unique | join(","))})
                | sort_by(-.count) | .[] | "    \(.count)\t\(.rule)\t[\(.comms)]"' 2>/dev/null || true
            record_covered "состав промоушенов по comm"

            # 5.9.9.F.2d (№118): состав ВСЕХ новых алертов idle-часа по comm
            # (не только промоушенов) сверяется с реестром idle-actors.txt —
            # величина, которая от часа запуска не зависит: критерий падает
            # не на числе алертов, а на новом акторе, которого нет в
            # реестре. Реестр заведён из двух уже снятых idle-часов
            # (collect-2.9.9.F — утро, collect-2.9.9.F.1 — ночь), то есть
            # покрывает оба окна суток, а не подгоняется под последнее.
            echo "  состав ВСЕХ новых алертов idle-часа по comm (сверка с idle-actors.txt):"
            echo "${idle_new_alerts:-[]}" | jq -r '
                [.[] | (.comm // "(пусто)")]
                | group_by(.) | map({comm: .[0], count: length}) | sort_by(-.count)
                | .[] | "    \(.comm): \(.count)"' 2>/dev/null || true
            idle_actors_registry="$GATE_SCRIPT_DIR/idle-actors.txt"
            if [ ! -f "$idle_actors_registry" ]; then
                echo "  ! idle-actors.txt отсутствует рядом с гейтом — состав не сверен с реестром"
            else
                idle_seen_comms=$(echo "${idle_new_alerts:-[]}" | jq -r '[.[] | (.comm // "(пусто)")] | unique | .[]' 2>/dev/null | sort -u)
                idle_known_comms=$(awk -F'\t' '!/^[[:space:]]*(#|$)/ && NF>=1 {print $1}' "$idle_actors_registry" | sort -u)
                idle_unknown_comms=$(comm -23 <(echo "$idle_seen_comms") <(echo "$idle_known_comms") | grep -v '^$' || true)
                if [ -z "$idle_unknown_comms" ]; then
                    idle_actors_ok=1
                else
                    idle_actors_ok=0
                    echo "  новые акторы idle-часа вне idle-actors.txt: $(echo "$idle_unknown_comms" | tr '\n' ' ')"
                fi
                record_covered "состав idle-часа против idle-actors.txt"
            fi
        else
            echo "  состав не считался: IDLE_ALERTS_START/END не заданы или jq недоступен (величина выше от этого не зависит)"
        fi

        if [ "$idle_actors_ok" = "1" ]; then
            pass "verdict=\"attack\" за idle-час измерена критерием: дельта $idle_attack_delta, окно ${idle_win_start_utc:-?}..${idle_win_end_utc:-?} UTC; состав idle-часа целиком покрыт idle-actors.txt, новых акторов 0 (5.9.9.F.2d, №118; величина 5.9.9.F.1d, №115, порог по-прежнему не назначен)"
        elif [ "$idle_actors_ok" = "0" ]; then
            fail "новый(е) актор(ы) idle-часа вне idle-actors.txt: $(echo "$idle_unknown_comms" | tr '\n' ' ') — дельта verdict=\"attack\" за idle-час = $idle_attack_delta, окно ${idle_win_start_utc:-?}..${idle_win_end_utc:-?} UTC (5.9.9.F.2d, №118; величина 5.9.9.F.1d, №115)"
        else
            pass "verdict=\"attack\" за idle-час измерена критерием: дельта $idle_attack_delta, окно ${idle_win_start_utc:-?}..${idle_win_end_utc:-?} UTC; состав против idle-actors.txt не проверен (реестр отсутствует, IDLE_ALERTS_START/END не заданы или jq недоступен) — не засчитывается ни в одну сторону (5.9.9.F.1d, №115)"
        fi
    fi
fi
echo ""

# 5.9.4h (находка №59): машинный гейт на правила, немые за ВЕСЬ аптайм
# агента (не за окно этого прогона — final_metrics кумулятивен с момента
# старта процесса). Раньше такого гейта не было вовсе: четыре правила
# (sigma_cpu_info_access, sigma_kernel_version_read, sigma_memory_proc_dump,
# web_sql_injection_files) молчали с самого старта агента и на №2.9.3 это
# всплыло только ручным разбором таблицы находки №57. Правило хода:
# каждое молчащее правило обязано быть поименовано в
# silent-rules.txt с категорией (а) «немо по конструкции» или (б) «немо
# из-за среды» — без строки там оно проваливает гейт как категория (в)
# «без объяснения», ровно та потеря, что дожила до №2.9.3.
#
# Область проверки — НЕ все ~600 правил репозитория (подавляющее
# большинство — aks_/cloud_/gpu_/k8s_/eks_/... — заведомо немо не по
# дефекту, а потому что на этом docker-стенде нет ни узла, ни облака, ни
# GPU: это сфера волны 6, не находки №59), а $lost_types критерия 6 —
# подмножество detection-baseline.txt, которое НЕ сработало в этом
# прогоне и уже пережило обе имеющиеся отсрочки критерия 6 (вторую
# попытку по idle-приросту через background-rules.txt и вычитание
# intentional-loss.txt). Всё, что доживает до этой точки, — по
# определению либо немо с самого начала (находка №59), либо настоящий
# регресс детекта; критерий 6 выше уже пометил это FAIL по составу — этот
# гейт требует вдобавок, чтобы каждое такое правило было ПОИМЕНОВАНО с
# категорией, а не просто числилось в потере.
echo "=== 5.9.4h. Правила из детект-базы, немые за весь аптайм (без объяснения — 0) ==="
if [ ! -s "$final_metrics" ]; then
    skip "$final_metrics пуст — немые правила не проверены"
elif [ ! -f "$baseline_types_file" ]; then
    skip "$baseline_types_file отсутствует — немые правила не проверены"
elif [ -z "${lost_types+x}" ]; then
    skip "критерий 6 не вычислил lost_types (нет baseline-снимка) — немые правила не проверены"
else
    silent_registry="$GATE_SCRIPT_DIR/silent-rules.txt"

    # 5.9.9.F.2e (№122): агент сам печатает при старте, какие syscall-правила
    # не имеют достижимого "nr" в kernel-allowlist ("rules: syscall rules
    # with no reachable nr in the kernel allowlist", cmd/ebpf-guard/main.go) —
    # эти правила никогда не срабатывали и не появляются в
    # detection-baseline.txt вовсе, поэтому $lost_types (baseline минус
    # текущий прогон) их не видит по построению, а крит. 5.9.4h печатал
    # "немых правил: 0", хотя агент назвал 11 поимённо. Читается из журнала
    # сервиса без границ окна — строка печатается один раз при старте
    # процесса и живёт в журнале весь его аптайм, тем же приёмом, что уже
    # применён к 5.9.9.F.2b (min_dwell читается из журнальной строки агента,
    # а не задаётся константой).
    kernel_unreachable_ids=""
    if command -v journalctl &> /dev/null; then
        kernel_unreachable_line=$(journalctl -u "${EBPF_GUARD_SERVICE_UNIT:-ebpf-guard-test.service}" \
            --no-pager -o cat 2>/dev/null \
            | grep 'rules: syscall rules with no reachable nr in the kernel allowlist' | tail -1)
        if [ -n "$kernel_unreachable_line" ] && command -v jq &> /dev/null; then
            kernel_unreachable_ids=$(echo "$kernel_unreachable_line" | jq -r '.rule_ids[]?' 2>/dev/null | sort -u)
        fi
    fi

    silent_ids=$(printf '%s\n%s\n' "$lost_types" "$kernel_unreachable_ids" | grep -v '^$' | sort -u)
    silent_count=$(echo "$silent_ids" | grep -c . || true)

    if [ "$silent_count" -eq 0 ]; then
        pass "немых правил за весь аптайм: 0 (после отсрочек критерия 6 потерь не осталось)"
    elif [ ! -f "$silent_registry" ]; then
        fail "$silent_count правил(о) немы за весь аптайм, а silent-rules.txt отсутствует — все они категория (в): $(echo "$silent_ids" | tr '\n' ' ')"
    else
        recorded_a=$(awk '!/^[[:space:]]*(#|$)/ && $2 == "a" {print $1}' "$silent_registry" | sort -u)
        recorded_b=$(awk '!/^[[:space:]]*(#|$)/ && $2 == "b" {print $1}' "$silent_registry" | sort -u)
        recorded_all=$(printf '%s\n%s\n' "$recorded_a" "$recorded_b" | grep -v '^$' | sort -u)
        unexplained=$(comm -23 <(echo "$silent_ids") <(echo "$recorded_all"))
        unexplained_count=$(echo "$unexplained" | grep -c . || true)

        a_count=$(comm -12 <(echo "$silent_ids") <(echo "$recorded_a") | grep -c . || true)
        b_count=$(comm -12 <(echo "$silent_ids") <(echo "$recorded_b") | grep -c . || true)
        echo "  немых всего: $silent_count — (а) по конструкции: $a_count, (б) нет сценария на стенде: $b_count"

        if [ "$unexplained_count" -eq 0 ]; then
            pass "0 правил категории (в) без объяснения ($silent_count немых, все — в silent-rules.txt) (5.9.7e: немых за аптайм без объяснения)"
        else
            fail "$unexplained_count правил(о) немы за весь аптайм без строки в silent-rules.txt (категория (в)): $(echo "$unexplained" | tr '\n' ' ') (5.9.7e: немых за аптайм без объяснения)"
        fi
    fi
fi
echo ""

# 5.9.9c (находка №101): наблюдение без порога, а не критерий — сколько
# правил детект-базы имеют исполненный позитивный контроль в
# attack-manifest.json на этом прогоне, а не полагаются на органический
# трафик атак/простоя. Смысл в различении двух разных немот: правило БЕЗ
# контроля, замолчавшее за весь аптайм, — категория (в) выше и FAIL; правило
# С контролем, замолчавшее несмотря на него, — совсем другая находка (сам
# контроль сломан), которую этот счётчик не проверяет по существу, но делает
# видимой без ручного вспоминания, у какого правила контроль вообще есть.
# Карта статическая и пополняется штучно вместе с каждым run_*_positive_control
# (ssh_keys — 5.9.7e, webshell_* — 5.9.8g/5.9.9b, container_escape — 5.9.9c),
# а не выводится автоматически из имён функций run-all-attacks.sh.
# У двух правил семьи webshell_* категории РАЗНЫЕ намеренно: одна на обоих
# (как было в первой редакции 5.9.9c) означала бы, что исполнившийся
# контроль script_write засчитывает контроль crontab, которого не было —
# счётчик, врущий ровно про то, что он заведён различать.
declare -A positive_control_rule_categories=(
    [rootkit_ssh_authorized_keys_modified]="ssh_keys_positive_control"
    [webshell_script_write_via_web_process]="webshell_positive_control"
    [webshell_crontab_modification]="webshell_crontab_positive_control"
    [container_escape_cap_sys_admin]="container_escape_positive_control"
    # 5.9.9.Fa (находка №107): numeric-PID сужение cred_proc_maps_mass_read
    # оставило правило без единого входа на стенде — 44 его алерта были
    # шумом на /proc/self/maps, а ни один шаг манифеста чужой
    # /proc/<pid>/maps не читал. Постановка 5.9.9.Fa считала контроль
    # существующим («4 из 70») — его не было; шаг
    # run_cred_proc_maps_positive_control добавлен вместе с этой строкой.
    [cred_proc_maps_mass_read]="cred_proc_maps_positive_control"
)
echo "=== 5.9.9c. Правила детект-базы с позитивным контролем в манифесте ==="
# 5.9.9e: заголовок печатается голым echo (секция — наблюдение без порога, у
# неё нет ни pass, ни fail в общем случае), поэтому рантайм-отметку надо
# ставить явно — иначе 5.9.9c попадает в список «ветка не исполнилась» на
# КАЖДОМ прогоне и валит собственный критерий 5.9.9e в SKIP.
record_covered "=== 5.9.9c. Правила детект-базы с позитивным контролем в манифесте ==="
if [ ! -f "$baseline_types_file" ]; then
    skip "$baseline_types_file отсутствует — соответствие правило/контроль не проверено"
else
    baseline_all_rules=$(grep -vE '^\s*(#|$)' "$baseline_types_file" | tr -d '\r' | sort -u)
    baseline_rule_count=$(echo "$baseline_all_rules" | grep -c . || true)
    manifest_categories_present=""
    if [ -f "$manifest_file" ] && command -v jq &> /dev/null; then
        manifest_categories_present=$(jq -r '[.[].category] | unique | .[]' "$manifest_file" 2>/dev/null)
    fi
    covered_count=0
    covered_ids=""
    for rid in $baseline_all_rules; do
        cat="${positive_control_rule_categories[$rid]:-}"
        [ -z "$cat" ] && continue
        if echo "$manifest_categories_present" | grep -qx "$cat"; then
            covered_count=$((covered_count + 1))
            covered_ids="$covered_ids$rid"$'\n'
        fi
    done
    echo "  правила детект-базы, у которых есть позитивный контроль в манифесте: $covered_count из $baseline_rule_count"
    if [ "$covered_count" -gt 0 ]; then
        echo "$covered_ids" | grep -v '^$' | sed 's/^/    * /'
    fi
fi
echo ""

# 17. Kill-сценарий парный (5.9.5a, находка №62, P0).
#
# На №2.9.4 оба счётчика (enforcement_actions_total{kill} и
# enforcement_dryrun_total{kill}) стояли на 0/0 за весь аптайм: "dry_run
# гасит kill" было измерено как отсутствие срабатывания, а не как
# срабатывание-без-убийства (риск №3 постановки 5.9.4, найдено на замере, а
# не на ревью). run_kill_scenario (run-all-attacks.sh, 5.9.5a) даёт
# ebpf_subversion_detach_nonroot — единственному kill-правилу репозитория,
# без comm-условия, см. attacks/destructive-actions.txt блок 5.9.5a и
# TestKillScenarioControlRule_ActionIsKill — реальный вход: bpf(2) от
# непривилегированного дочернего процесса харнесса.
#
# Критерий по построению ТРОЙНОЙ, один ноль без остальных двух — FAIL, а не
# PASS (это и есть парность, которую риск №3 требовал и находка №62 не
# получила):
#   (1) enforcement_dryrun_total{action="kill"} >= 1   — правило сработало;
#   (2) enforcement_actions_total{action="kill"} == 0  — dry_run погасил;
#   (3) ноль записей "KILL action executed" в журнале за ВЕСЬ аптайм агента
#       (не за окно прогона — 5.9.4a измеряла именно так).
echo "=== 17. Kill-сценарий: dry_run гасит kill, доказано живьём (5.9.5a) ==="
if [ ! -s "$final_metrics" ]; then
    skip "$final_metrics пуст — критерий 17 не проверен"
elif [ ! -s "${AGENT_START_FILE:-}" ]; then
    # 5.9.9.Fc (находка №110): без AGENT_START_FILE секция раньше подставляла
    # `--boot` и считала "KILL action executed" по всему журналу юнита за
    # ВЕСЬ аптайм хоста — то есть и по прошлым, не относящимся к этому
    # прогону замерам (107 записей из №2.9.3 в этом журнале ничего не
    # говорят о текущем kill-сценарии). Это не консервативная оценка, а
    # неверная: печатать по ней FAIL/PASS значит выносить вердикт по чужим
    # данным. Внутренний вызов из full_run() (run-all-attacks.sh) не
    # экспортирует AGENT_START_FILE — единственный способ получить хоть
    # какой-то вердикт при интерактивном прогоне без цепочки, и убирать этот
    # вызов значит чинить симптом ценой рабочего режима (см. 5.9.9a).
    skip "окно журнала не задано — вердикт не выносится (AGENT_START_FILE пуст или отсутствует, критерий 17 не может ограничить журнал текущим прогоном)"
else
    dry_kill=$(grep 'ebpf_guard_enforcement_dryrun_total{' "$final_metrics" 2>/dev/null \
        | grep 'action="kill"' | awk -F'} ' '{sum+=$2} END{print sum+0}')
    act_kill=$(grep 'ebpf_guard_enforcement_actions_total{' "$final_metrics" 2>/dev/null \
        | grep 'action="kill"' | awk -F'} ' '{sum+=$2} END{print sum+0}')

    journal_checked=0
    kill_executed=0
    if command -v journalctl &> /dev/null; then
        journal_args=(--since "$(head -1 "$AGENT_START_FILE")")
        kill_journal=$(journalctl -u "${EBPF_GUARD_SERVICE_UNIT:-ebpf-guard-test.service}" "${journal_args[@]}" 2>/dev/null)
        # journalctl выходит с кодом 0 и на несуществующем юните («-- No
        # entries --»), поэтому одного кода возврата мало: пустой журнал
        # доказывал бы п.3 («ноль KILL за аптайм») ровно тем же способом,
        # каким №2.9.4 «доказал» предохранитель нулём срабатываний. Агент за
        # аптайм пишет в журнал непрерывно, так что пустота здесь означает
        # неверное имя юнита или нехватку прав, а не чистый прогон.
        if [ $? -eq 0 ] && [ -n "$kill_journal" ]; then
            journal_checked=1
            kill_executed=$(echo "$kill_journal" | grep -c "KILL action executed" || true)
        fi
    fi

    echo "  enforcement_dryrun_total{kill}=$dry_kill, enforcement_actions_total{kill}=$act_kill, журнал проверен=$journal_checked, \"KILL action executed\"=$kill_executed"
    if [ "$journal_checked" -eq 0 ]; then
        skip "журнал agent-сервиса недоступен или пуст (проверить EBPF_GUARD_SERVICE_UNIT и права) — критерий 17 не может подтвердить п.3 (ноль KILL за аптайм)"
    elif awk -v d="$dry_kill" 'BEGIN{exit !(d>=1)}' && [ "$act_kill" -eq 0 ] && [ "$kill_executed" -eq 0 ]; then
        pass "правило сработало ($dry_kill раз), убийств 0, журнал за весь аптайм чист — предохранитель доказан живьём (5.9.5a)"
    elif awk -v d="$dry_kill" 'BEGIN{exit !(d<1)}'; then
        fail "enforcement_dryrun_total{kill}=$dry_kill < 1 — kill-сценарий не дал правилу сработать, критерий 17 не доказывает ничего (проверить run_kill_scenario)"
    elif [ "$act_kill" -ne 0 ] || [ "$kill_executed" -ne 0 ]; then
        fail "enforcement_actions_total{kill}=$act_kill, \"KILL action executed\"=$kill_executed за аптайм — dry_run не погасил kill (регресс находки №52)"
    else
        fail "критерий 17: непредвиденная комбинация dry_kill=$dry_kill act_kill=$act_kill kill_executed=$kill_executed"
    fi
fi
echo ""

# 18. 5.9.6a (находка №71, P0): потеря в ядре считается собственным
# счётчиком, а не молчаливо теряется. До этой волны
# ebpf_guard_bpf_lost_events_total обещал ядро именем, а на деле дублировал
# userspace-хоп ringbuf_to_router (см. plan.md 5.9.6a) — критерий 1 выше эту
# путаницу не ловит, потому что считает как раз ringbuf_to_router/
# router_to_queue, а не переполнение самого кольца. Секция читает НОВЫЙ
# счётчик ringbuf_full_counters (bpf/common.h), выгруженный per-коллектор как
# events_dropped_total{collector,reason="ringbuf_full"} для syscall/network/
# fileaccess — трёх коллекторов, делящих `events`-ringbuf через
# reserve_event()/reserve_event_with_sampling(). privesc-коллектор не
# инстанцируется в cmd/ebpf-guard/main.go на момент этой правки (отдельный,
# ранее не замеченный пробел — см. открытые вопросы 5.9.6a) и в критерий не
# входит.
echo "=== 18. events_dropped_total{reason=\"ringbuf_full\"}: потеря в ядре считается (5.9.6a, №71) ==="
core_collectors_have_series=0
for c in syscall network fileaccess; do
    if grep -Eq "ebpf_guard_events_dropped_total\{(collector=\"$c\",reason=\"ringbuf_full\"|reason=\"ringbuf_full\",collector=\"$c\")\}" "$final_metrics" 2>/dev/null; then
        core_collectors_have_series=$((core_collectors_have_series + 1))
    fi
    d=$(sum_metric_delta "collector=\"$c\".*reason=\"ringbuf_full\"" "$baseline_metrics" "$final_metrics")
    eval "ringbuf_full_delta_$c=\${d:-0}"
    echo "  $c: Δringbuf_full за прогон = ${d:-0}"
done
if [ "$core_collectors_have_series" -eq 0 ]; then
    skip "серия events_dropped_total{reason=\"ringbuf_full\"} отсутствует ни для одного из syscall/network/fileaccess — сборка агента старее 5.9.6a"
else
    idle_zero_checked=0
    idle_zero_ok=1
    idle_report=""
    if [ -n "$IDLE_METRICS_START" ] && [ -n "$IDLE_METRICS_END" ] \
        && [ -s "$IDLE_METRICS_START" ] && [ -s "$IDLE_METRICS_END" ]; then
        idle_zero_checked=1
        for c in syscall network fileaccess; do
            di=$(sum_metric_delta "collector=\"$c\".*reason=\"ringbuf_full\"" "$IDLE_METRICS_START" "$IDLE_METRICS_END")
            idle_report="$idle_report $c=${di:-0}"
            if ! awk -v d="${di:-0}" 'BEGIN{exit !(d==0)}'; then
                idle_zero_ok=0
            fi
        done
    fi

    # 5.9.9.F.2a (№123): источник индуцированного переполнения — сперва
    # run_ringbuf_overflow (крит. 22, SIGSTOP-метод, переполняет кольцо
    # управляемо на каждом прогоне), и только если он недоступен — наведённый
    # дроп 5.9.5b (не откалиброван на переполнение именно ring buffer, долг
    # 5.9.6d закрыт как поставленный неверно, а не исполнением: у режима не
    # было и не могло быть собственного способа переполнить кольцо).
    induced_ok=0
    induced_source=""
    if [ -n "$ringbuf_overflow_marker" ] && [ -f "$ringbuf_overflow_marker" ] && ! grep -q '^skipped=1' "$ringbuf_overflow_marker" 2>/dev/null; then
        ro_ring_full_c18=$(awk -F= '$1=="ringbuf_full_delta"{print $2+0}' "$ringbuf_overflow_marker" 2>/dev/null)
        if awk -v d="${ro_ring_full_c18:-0}" 'BEGIN{exit !(d>0)}'; then
            induced_ok=1
            induced_source="run_ringbuf_overflow (5.9.7b), Δringbuf_full=${ro_ring_full_c18}"
        fi
    fi
    if [ "$induced_ok" -ne 1 ] && [ -f "$induced_drop_marker" ]; then
        induced_executed_c18=$(awk -F= '$1=="executed"{print $2+0}' "$induced_drop_marker" 2>/dev/null)
        if [ "${induced_executed_c18:-0}" -eq 1 ]; then
            fa_delta=$(eval echo "\$ringbuf_full_delta_fileaccess")
            if awk -v d="${fa_delta:-0}" 'BEGIN{exit !(d>0)}'; then
                induced_ok=1
                induced_source="наведённый дроп 5.9.5b"
            fi
        fi
    fi

    if [ "$idle_zero_checked" -eq 1 ] && [ "$idle_zero_ok" -eq 0 ]; then
        fail "ringbuf_full ненулевой на idle-часе (ожидался 0 для всех трёх коллекторов):$idle_report"
    elif [ "$induced_ok" -eq 1 ] && { [ "$idle_zero_checked" -eq 0 ] || [ "$idle_zero_ok" -eq 1 ]; }; then
        pass "fileaccess: ringbuf_full > 0 под управляемым переполнением ($induced_source, 5.9.9.F.2a/№123)$( [ "$idle_zero_checked" -eq 1 ] && echo ", на idle-часе 0" )"
    elif [ "$idle_zero_checked" -eq 1 ] && [ "$idle_zero_ok" -eq 1 ] && [ "$induced_ok" -eq 0 ]; then
        skip "idle-час чист (0 у всех трёх), но ни run_ringbuf_overflow, ни наведённый дроп не дали fileaccess.ringbuf_full > 0 — половина критерия 5.9.6a не проверена ни одним из двух источников"
    else
        skip "ни IDLE_METRICS_START/END, ни run_ringbuf_overflow, ни наведённый дроп с fileaccess.ringbuf_full > 0 не доступны — механизм не проверен ни с одной стороны"
    fi
fi
echo ""

# 19. 5.9.6b (находка №72, P0): сквозной баланс событий по коллектору.
#
# ТОЧКА СЪЁМА ЛЕВОЙ ЧАСТИ (существенно, ревизия 2026-08-21): счётчик
# events_emitted_counters (bpf/common.h) инкрементируется на УСПЕШНОМ
# bpf_ringbuf_reserve(), то есть считает события, реально положенные в
# кольцо. Всё, что теряется РАНЬШЕ резерва, в него не попадает по
# построению:
#   - ringbuf_full     — резерв не состоялся (это и есть счётчик неудач);
#   - path_denylist    — path_is_denied() делает `return 0` ДО reserve
#                        (bpf/fileaccess.bpf.c, комментарий P1-18b прямо
#                        говорит: "так фильтрованный путь не стоит слота
#                        кольца");
#   - observer_tree    — observer_should_drop() тоже стоит ДО reserve
#                        (bpf/*.bpf.c, "immediately before the reserve").
# Поэтому тождество, сходящееся по построению, ровно одно:
#
#   emitted_kernel = events_total + ringbuf_to_router + router_to_queue
#                    + malformed
#
# Прежняя редакция этой секции складывала в правую часть ещё ringbuf_full и
# path_denylist — то есть события, которых в левой части нет ни одного.
# Невязка тогда обязана была равняться −(ringbuf_full + path_denylist)
# на ИСПРАВНОЙ системе, и критерий валил бы гейт тем сильнее, чем лучше
# работает 5.9.6d (наведённый дроп специально гонит ringbuf_full вверх).
# Пункт 4 порядка работы запрещает двигать допуск под результат — здесь и
# не двигается допуск, здесь исправлено само равенство.
#
# Потери ДО резерва печатаются отдельной строкой «ядро видело, но не
# положило в кольцо» — постановка требует, чтобы ни одно слагаемое не
# отсутствовало молча, и они не отсутствуют: они просто стоят по другую
# сторону точки съёма. excluded{observer_tree} остаётся информационным по
# прежней причине (ce.eventsExcludedTotal публикует его одним числом на всё
# приложение, а не per-коллектор — internal/correlator/engine.go).
#
# Допуск объявлен ДО прогона, а не подобран под результат (пункт 4 порядка
# работы): снимки counter-серий не атомарны друг относительно друга (каждая
# серия читается отдельным HTTP-скрейпом `/metrics` в разное мгновение), так
# что допуск берётся порядка секундного темпа детекта, зафиксированного
# №2.9.5 (79.9 событий/мин детекта; событий на входе на порядки больше) —
# 500 событий или 0.5% от emitted_kernel, что больше.
echo "=== 19. Сквозной баланс событий (5.9.6b, №72) ==="
emitted_have_series=0
for c in syscall network fileaccess; do
    if grep -q "ebpf_guard_events_emitted_kernel_total{collector=\"$c\"}" "$final_metrics" 2>/dev/null; then
        emitted_have_series=$((emitted_have_series + 1))
    fi
done
if [ "$emitted_have_series" -eq 0 ]; then
    skip "серия events_emitted_kernel_total отсутствует — сборка агента старее 5.9.6b"
else
    # 5.9.6a/5.9.6b используют один и тот же коллектор→тип-label маппинг
    # exporter.EventTypeLabel применяет к network (TCP_CONNECT+NET_CLOSE
    # оба дают type="network"); syscall/fileaccess совпадают с collector.
    declare -A c19_type
    c19_type[syscall]="syscall"
    c19_type[network]="network"
    c19_type[fileaccess]="file"
    any_balance_checked=0
    for c in syscall network fileaccess; do
        emitted=$(grep "ebpf_guard_events_emitted_kernel_total{collector=\"$c\"}" "$final_metrics" 2>/dev/null | awk -F'} ' '{print $2+0}')
        emitted_base=$(grep "ebpf_guard_events_emitted_kernel_total{collector=\"$c\"}" "$baseline_metrics" 2>/dev/null | awk -F'} ' '{print $2+0}')
        emitted_delta=$(awk -v a="${emitted:-0}" -v b="${emitted_base:-0}" 'BEGIN{printf "%.0f", a-b}')

        # Шаблон якорится именем семейства: голое type="syscall" совпало бы
        # с любой другой серией, у которой есть лейбл type с тем же
        # значением (а такие в проекте есть — internal/drift/detector.go),
        # и невязка молча вобрала бы чужой счётчик.
        events_total_delta=$(sum_metric_delta "^ebpf_guard_events_total\\{.*type=\"${c19_type[$c]}\"" "$baseline_metrics" "$final_metrics")
        ringbuf_full_d=$(sum_metric_delta "collector=\"$c\".*reason=\"ringbuf_full\"" "$baseline_metrics" "$final_metrics")
        r2r_d=$(sum_metric_delta "collector=\"$c\".*reason=\"ringbuf_to_router\"" "$baseline_metrics" "$final_metrics")
        r2q_d=$(sum_metric_delta "collector=\"$c\".*reason=\"router_to_queue\"" "$baseline_metrics" "$final_metrics")
        denylist_d=0
        if [ "$c" = "fileaccess" ]; then
            denylist_d=$(sum_metric_delta "collector=\"$c\".*reason=\"path_denylist\"" "$baseline_metrics" "$final_metrics")
        fi
        malformed_d=$(awk -F'} ' -v c="$c" '
            FNR==NR { if ($0 ~ "ebpf_guard_events_malformed_total\\{" && $0 ~ ("collector=\"" c "\"")) base+=$2+0; next }
            { if ($0 ~ "ebpf_guard_events_malformed_total\\{" && $0 ~ ("collector=\"" c "\"")) fin+=$2+0 }
            END { printf "%.0f", fin-base }
        ' "$baseline_metrics" "$final_metrics")

        # Правая часть — только то, что случилось ПОСЛЕ успешного резерва.
        # ringbuf_full/path_denylist сюда не входят: см. врезку «точка съёма»
        # над секцией.
        rhs=$(awk -v a="${events_total_delta:-0}" -v d="${r2r_d:-0}" \
                  -v e="${r2q_d:-0}" -v g="${malformed_d:-0}" \
                  'BEGIN{printf "%.0f", a+d+e+g}')
        residual=$(awk -v l="${emitted_delta:-0}" -v r="$rhs" 'BEGIN{printf "%.0f", l-r}')
        tolerance=$(awk -v e="${emitted_delta:-0}" 'BEGIN{t=e*0.005; if(t<500) t=500; printf "%.0f", t}')
        abs_residual=$(awk -v r="$residual" 'BEGIN{print (r<0)?-r:r}')
        pre_reserve=$(awk -v b="${ringbuf_full_d:-0}" -v f="${denylist_d:-0}" 'BEGIN{printf "%.0f", b+f}')

        echo "  $c: emitted_kernel=$emitted_delta = events_total=$events_total_delta + ringbuf_to_router=$r2r_d + router_to_queue=$r2q_d + malformed=$malformed_d | невязка=$residual (допуск ±$tolerance)"
        echo "  $c: потеряно ДО резерва (в тождество не входит, левой части не касается): ringbuf_full=$ringbuf_full_d path_denylist=$denylist_d | всего=$pre_reserve"
        if awk -v p="$pre_reserve" -v e="${emitted_delta:-0}" 'BEGIN{exit !(e>0 && p>0)}'; then
            echo "  $c: доля потерь до резерва = $(awk -v p="$pre_reserve" -v e="${emitted_delta:-0}" 'BEGIN{printf "%.3f%%", 100*p/(p+e)}') (наблюдение без порога — 5.9.6b печатает долю, но не судит её)"
        fi
        if [ "$emitted_have_series" -gt 0 ] && grep -q "ebpf_guard_events_emitted_kernel_total{collector=\"$c\"}" "$final_metrics" 2>/dev/null; then
            any_balance_checked=1
            if awk -v a="$abs_residual" -v t="$tolerance" 'BEGIN{exit !(a<=t)}'; then
                pass "$c: баланс сходится в пределах допуска (невязка $residual, допуск ±$tolerance)"
            else
                fail "$c: невязка $residual превышает допуск ±$tolerance — потеря считается не полностью (проверить, не появился ли новый путь потери мимо перечисленных слагаемых)"
            fi
        else
            skip "$c: events_emitted_kernel_total отсутствует для этого коллектора"
        fi
    done
    excluded_observer_tree=$(sum_metric_delta "reason=\"observer_tree\"" "$baseline_metrics" "$final_metrics")
    # 5.9.8d (№97): observer_should_drop() стоит ДО bpf_ringbuf_reserve() на
    # каждом из шести хуков трёх коллекторов — bpf/syscall.bpf.c:60/119,
    # bpf/network.bpf.c:103/208, bpf/fileaccess.bpf.c:227/350/417 (везде
    # `if (observer_should_drop()) return 0;` предшествует
    # `reserve_event[_with_sampling]()`). excluded{observer_tree} поэтому не
    # входит в emitted_kernel по построению — это код, а не утверждение по
    # памяти; если рефакторинг когда-нибудь переставит эти строки, находка
    # всплывёт здесь же как невязка, растущая вместе с ростом excluded.
    echo "  excluded{observer_tree} за прогон (не коллектор-специфично, в невязку выше не входит — observer_should_drop() до reserve_event() во всех шести хуках, 5.9.8d): ${excluded_observer_tree:-0}"
    if [ "$any_balance_checked" -eq 0 ]; then
        skip "ни для одного коллектора баланс не проверен"
    fi
fi

# 5.9.8d (№97, P1): events_drain_offset — тот же приём, что final_drain_offset
# (5.9.4c, критерий 15), только для событийного тождества секции 19 вместо
# алертного. get_final_metrics (run-all-attacks.sh) снимает финальный срез
# ПОСЛЕ того, как суммарный |остаток| этого тождества по трём коллекторам
# перестал убывать между срезами (не "стал нулём" — секция 19 держит допуск
# 500/0.5%, а не 0), с ретраями до 30с, и пишет величину в
# final-drain-offset-$TIMESTAMP.txt рядом с drain_offset_before_final.
# Печатается числом независимо от того, к чему сошёлся, — постановка не
# требует, чтобы он был мал, только чтобы он не отсутствовал молча.
events_drain_offset_file="$RESULTS_DIR/final-drain-offset-$TIMESTAMP.txt"
if [ -f "$events_drain_offset_file" ] && grep -q '^events_drain_offset=' "$events_drain_offset_file" 2>/dev/null; then
    events_drain_offset=$(grep -o 'events_drain_offset=.*' "$events_drain_offset_file" | cut -d= -f2)
    echo "  events_drain_offset (5.9.8d, |остаток| тождества секции 19 перед final, устоялся или истёк таймаут 30с) = ${events_drain_offset:-n/a}"
    pass "events_drain_offset напечатан числом (5.9.8d, №97): ${events_drain_offset:-n/a}"
else
    skip "events_drain_offset отсутствует в final-drain-offset-$TIMESTAMP.txt — сборка харнесса старее 5.9.8d"
fi
echo ""

# 20. 5.9.6c/5.9.7a (P0): контроль счётности — известный вход N, независимый
# от 5.9.6b's баланса (который доказывает лишь внутреннюю непротиворечивость
# счётчиков ДРУГ С ДРУГОМ, а не то, что ядро вообще увидело вызов).
# run_counting_control (run-all-attacks.sh) пишет ТРИ маркера:
#   null — негативный контроль, N=0, никакого генератора; Δevents+Δdrops
#          этого режима И ЕСТЬ измеренный фон окна (5.9.7a, №78);
#   idle — N openat() на канарейку в тишине;
#   drop — тот же генератор увеличенный до размера, рассчитанного
#          переполнить кольцо самостоятельно (без tar — см. plan.md 5.9.6c,
#          почему совмещать с наведённым дропом 5.9.6d нельзя без искажения N).
#
# 5.9.7a удаляет прежнюю оценку фона (окно ДО генератора, измеренное
# отдельным curl-циклом) целиком, а не корректирует её: снятая до 300 тыс.
# openat(), она не несла хвост, который эти вызовы оставляют в очередях
# коллектор→router→bulk queue, и потому систематически занижала фон
# следующих за ней idle/drop-окон. Вместо неё используется ЖИВОЙ null-прогон,
# исполненный ПЕРВЫМ (до idle и до drop — иначе его собственное окно понесёт
# хвост от их канареек).
echo "=== 20. Контроль счётности: null/idle, остаток после вычета фона (5.9.7a; режим drop удалён 5.9.9.F.2a, №123 — его половину тождества несёт критерий 22) ==="
record_covered "=== 20. Контроль счётности"
c20_null_marker="$RESULTS_DIR/counting-control-null-$TIMESTAMP.txt"
c20_null_rate=0
c20_null_jitter=5
c20_null_available=0
if [ -f "$c20_null_marker" ] && ! grep -q '^skipped=1' "$c20_null_marker" 2>/dev/null; then
    c20_null_sum=$(awk -F= '$1=="sum"{print $2+0}' "$c20_null_marker" 2>/dev/null)
    c20_null_window=$(awk -F= '$1=="window_seconds"{print $2+0}' "$c20_null_marker" 2>/dev/null)
    # Темп фона = null-режима сумма / его собственное окно. Окно null короче
    # idle/drop (нет генератора, устаканивание почти мгновенное) — это не
    # искажение: рассчитанный темп затем умножается на ДЛИНУ ОКНА КАЖДОГО
    # позитивного режима отдельно, так что разница в длительности окон
    # компенсируется, а не переносится как есть.
    c20_null_rate=$(awk -v s="${c20_null_sum:-0}" -v w="${c20_null_window:-0}" 'BEGIN{if(w<=0) w=1; printf "%.4f", s/w}')
    # Джиттер null-режима: та же неатомарность снимков, что и у idle/drop,
    # применённая к его собственной сумме — насколько точно измерен сам
    # фон, а не насколько точно фон предсказывает будущее окно.
    c20_null_jitter=$(awk -v s="${c20_null_sum:-0}" 'BEGIN{j=s*0.005; if(j<5) j=5; printf "%.0f", j}')
    c20_null_available=1
    echo "  null: N=0 окно=${c20_null_window:-0}с Δevents+Δdrops=${c20_null_sum:-0} => фон ${c20_null_rate}/с (джиттер ±${c20_null_jitter})"
    pass "null: негативный контроль исполнен первым, фон измерен числом вместо оценки до генератора (5.9.7a, №78)"

    # 5.9.8b (№91): канареечная серия сама себя проверяет в mode=null — она
    # обязана быть строго 0, потому что генератор в этом режиме не
    # запускается вовсе. Ненулевая канареечная сумма при N=0 значит, что
    # префикс /tmp/ebpf-guard-counting-canary- ловит что-то за пределами
    # самого контроля счётности (см. IsCountingCanaryPath, prometheus.go).
    if grep -q '^canary_sum=' "$c20_null_marker" 2>/dev/null; then
        c20_null_canary_sum=$(awk -F= '$1=="canary_sum"{print $2+0}' "$c20_null_marker" 2>/dev/null)
        echo "  null: канареечная серия Δevents+Δdropped=${c20_null_canary_sum:-0} (обязана быть 0)"
        if [ "${c20_null_canary_sum:-0}" -eq 0 ]; then
            pass "null: канареечная серия = 0 (5.9.8b, №91) — префикс не ловит лишнее"
        else
            fail "null: канареечная серия = ${c20_null_canary_sum} при N=0 — префикс /tmp/ebpf-guard-counting-canary- ловит события за пределами контроля счётности (5.9.8b)"
        fi
    else
        skip "null: маркер без canary_sum — сборка агента/харнесса старее 5.9.8b, канареечная серия не проверена"
    fi
elif [ -f "$c20_null_marker" ]; then
    skip "null: python3 недоступен на харнессе в момент прогона — фон не измерен"
else
    skip "null не запускался — маркер counting-control-null-$TIMESTAMP.txt отсутствует; сборка харнесса старее 5.9.7a, idle/drop ниже считаются без поправки на фон"
fi
echo ""

# 5.9.8c (№92, P0): единая арифметика остатка контроля счётности — читает
# canary_sum из маркера, если он есть (5.9.8b), иначе вычитает измеренный
# фон null-режима (5.9.7a). Общая для секции 20 (idle) и секции 22
# (run_ringbuf_overflow): тот же код counting_control_residual, а не
# независимо переписанная копия — параметр formula переключает только
# арифметику допуска. Секция 22 раньше несла собственный фиксированный
# допуск ±1500, который не масштабировался ни с N, ни с длиной окна
# (находка №92); теперь несёт formula="closed" (5.9.9.F.2a) — замкнутое
# тождество canary_events+canary_dropped+ringbuf_full=N с тем же
# фиксированным ±1500, но без асимметрии. Секция 20 (idle/null) не
# переполняет кольцо по построению и продолжает пользоваться прежней
# процентной формулой (formula по умолчанию, "legacy").
# Канареечная серия считается ТОЛЬКО в userspace (RecordCountingCanary,
# cmd/ebpf-guard/main.go + internal/collector/{fileaccess,priority}.go) — по
# трём хопам, до которых событие дошло живым: events, ringbuf_to_router,
# router_to_queue. Событие, потерянное В КОЛЬЦЕ, до userspace не доходит
# вовсе, и приписать его канарейке нечем: ringbuf_full — перцпу-счётчик ядра
# (5.9.6a) без метки пути, он считает потери ВСЕХ файловых событий окна
# сразу. Поэтому тождество канарейки не «canary_sum == N», а
#
#     0 <= N - canary_sum <= Δringbuf_full          (± допуск)
#
# то есть: канарейка не может насчитать БОЛЬШЕ, чем было вызовов (левая
# граница ловит двойной счёт и загрязнение префикса), и её недостача не
# может превысить то, что кольцо в этом окне заведомо потеряло (правая
# граница). Правая граница — ВЕРХНЯЯ ОЦЕНКА, а не вычитание фона: фон
# входит в Δringbuf_full и делает её только шире, но недостачу СВЕРХ
# доказанной потери кольца она не прячет — а это и есть то, что критерий
# 20/22 обязан ловить. В окнах без переполнения (Δringbuf_full = 0 —
# idle, null) обе границы схлопываются в прежнее строгое
# |canary_sum - N| <= допуск, без единого слагаемого фона, ровно как
# требует 5.9.8b.
#
# Без этого канареечный путь был бы заведомо красным везде, где кольцо
# переполняется намеренно: на №2.9.7 шаг run_ringbuf_overflow потерял в
# кольце 288 195 событий из N=300 000, то есть «остаток» -288 195 при
# допуске 1500 — критерий 22 не мог бы пройти ни при каком исправном
# продукте (5.9.8c, ревизия волны 5.9.8).
#
# Выход через глобали (bash-функции не возвращают структур):
#   CR_TOLERANCE, CR_RESIDUAL, CR_ABS_RESIDUAL, CR_USED_CANARY (1/0),
#   CR_RING_BOUND, CR_OK (1/0), CR_LINE
#
# 5.9.9.F.2a (№123/№124): четвёртый параметр formula="closed" переключает
# канареечную ветку на замкнутое тождество
# canary_events + canary_dropped + ringbuf_full = N с фиксированным
# симметричным допуском ±1500 — им пользуется только критерий 22.
# Прежнее асимметричное окно -(Δringbuf_full+допуск)…+допуск растягивалось
# на всю величину потери в кольце и проходило любой результат (№124);
# закрытое тождество включает потерю в кольце в сумму, а не в допуск.
# Критерий 20 (idle/null) продолжает пользоваться прежней процентной
# формулой без параметра — там Δringbuf_full=0 по построению, и тождество
# ей не нужно.
counting_control_residual() {
    local marker="$1" n="$2" window="$3" formula="${4:-legacy}"
    local ring_full
    ring_full=$(awk -F= '$1=="ringbuf_full_delta"{print $2+0}' "$marker" 2>/dev/null)
    CR_RING_BOUND="${ring_full:-0}"
    if grep -q '^canary_sum=' "$marker" 2>/dev/null; then
        local canary_events canary_dropped canary_sum canary_diff
        canary_events=$(awk -F= '$1=="canary_events_delta"{print $2+0}' "$marker" 2>/dev/null)
        canary_dropped=$(awk -F= '$1=="canary_dropped_delta"{print $2+0}' "$marker" 2>/dev/null)
        canary_sum=$(awk -F= '$1=="canary_sum"{print $2+0}' "$marker" 2>/dev/null)
        canary_diff=$(awk -F= '$1=="canary_diff"{print $2+0}' "$marker" 2>/dev/null)
        CR_USED_CANARY=1
        if [ "$formula" = "closed" ]; then
            CR_TOLERANCE=1500
            local closed_sum
            closed_sum=$(( canary_sum + CR_RING_BOUND ))
            CR_RESIDUAL=$(( closed_sum - n ))
            CR_ABS_RESIDUAL=$(awk -v d="$CR_RESIDUAL" 'BEGIN{print (d<0)?-d:d}')
            CR_OK=$(awk -v a="$CR_ABS_RESIDUAL" -v t="$CR_TOLERANCE" 'BEGIN{print (a<=t)?1:0}')
            CR_LINE="тождество Δevents=${canary_events:-0}+Δdropped=${canary_dropped:-0}+Δringbuf_full=${CR_RING_BOUND}=${closed_sum}, N=${n:-0}, остаток=${CR_RESIDUAL} (допуск ±${CR_TOLERANCE}, симметричный, без поправки на потерю в кольце — 5.9.9.F.2a, №123/№124)"
        else
            CR_TOLERANCE=$(awk -v n="${n:-0}" 'BEGIN{t=n*0.005; if(t<5) t=5; printf "%.0f", t}')
            CR_RESIDUAL="${canary_diff:-0}"
            CR_ABS_RESIDUAL=$(awk -v d="${canary_diff:-0}" 'BEGIN{print (d<0)?-d:d}')
            # d = canary_sum - N. Верх: d <= +допуск (насчитано лишнее).
            # Низ: d >= -(Δringbuf_full + допуск) (недостача сверх потери кольца).
            CR_OK=$(awk -v d="${canary_diff:-0}" -v t="$CR_TOLERANCE" -v r="${CR_RING_BOUND:-0}" \
                'BEGIN{ if(r<0) r=0; print (d<=t && d>=-(r+t)) ? 1 : 0 }')
            if [ "${CR_RING_BOUND:-0}" -gt 0 ] 2>/dev/null; then
                CR_LINE="канарейка Δevents=${canary_events:-0} Δdropped=${canary_dropped:-0} сумма=${canary_sum:-0} остаток=${CR_RESIDUAL} (окно с переполнением: допустимо от -(Δringbuf_full=${CR_RING_BOUND} + ${CR_TOLERANCE}) до +${CR_TOLERANCE}; потеря в кольце канарейке не видна по построению — 5.9.8b/5.9.8c, №91/№92)"
            else
                CR_LINE="канарейка Δevents=${canary_events:-0} Δdropped=${canary_dropped:-0} сумма=${canary_sum:-0} остаток=${CR_RESIDUAL} (допуск ±${CR_TOLERANCE} = max(5,0.5%N), без вычета фона, Δringbuf_full=0 — 5.9.8b/5.9.8c, №91/№92)"
            fi
        fi
    else
        local diff bg
        diff=$(awk -F= '$1=="diff"{print $2+0}' "$marker" 2>/dev/null)
        bg=$(awk -v r="$c20_null_rate" -v w="${window:-0}" 'BEGIN{printf "%.0f", r*w}')
        CR_RESIDUAL=$(( ${diff:-0} - bg ))
        CR_TOLERANCE=$(awk -v n="${n:-0}" -v j="$c20_null_jitter" 'BEGIN{t=n*0.005; if(t<5) t=5; printf "%.0f", t+j}')
        CR_ABS_RESIDUAL=$(awk -v d="$CR_RESIDUAL" 'BEGIN{print (d<0)?-d:d}')
        CR_USED_CANARY=0
        # Запасной путь считает общую серию, которая ringbuf_full УЖЕ
        # включает в drops_delta — там граница по кольцу не нужна.
        CR_OK=$(awk -v a="$CR_ABS_RESIDUAL" -v t="$CR_TOLERANCE" 'BEGIN{print (a<=t)?1:0}')
        CR_LINE="фон=${bg} остаток=${CR_RESIDUAL} (допуск ±${CR_TOLERANCE} = 0.5%N/мин.5 + джиттер фона ${c20_null_jitter}) — маркер старее 5.9.8b/5.9.8c, канареечная серия недоступна"
    fi
}

counting_checked_modes=0
counting_ok_modes=0
# 5.9.9.F.2a (№123): режим drop удалён вместе с COUNTING_CONTROL_DROP_N —
# генератор never имел собственного способа переполнить кольцо (N ни при
# чём, потеря уходила в router_to_queue при ringbuf_full=0), а его половина
# тождества 5.9.6c ("сходится ПОД дропом") теперь целиком несётся критерием
# 22 (run_ringbuf_overflow, SIGSTOP-метод, переполняет кольцо управляемо на
# каждом прогоне). Долг 5.9.6d закрыт записью «поставлен неверно», не
# исполнением.
for c20_mode in idle; do
    c20_marker="$RESULTS_DIR/counting-control-${c20_mode}-$TIMESTAMP.txt"
    if [ ! -f "$c20_marker" ]; then
        skip "контроль счётности ($c20_mode) не запускался — маркер counting-control-${c20_mode}-$TIMESTAMP.txt отсутствует"
        continue
    fi
    if grep -q '^skipped=1' "$c20_marker" 2>/dev/null; then
        skip "контроль счётности ($c20_mode): python3 недоступен на харнессе в момент прогона"
        continue
    fi
    c20_n=$(awk -F= '$1=="n"{print $2+0}' "$c20_marker" 2>/dev/null)
    c20_sum=$(awk -F= '$1=="sum"{print $2+0}' "$c20_marker" 2>/dev/null)
    c20_diff=$(awk -F= '$1=="diff"{print $2+0}' "$c20_marker" 2>/dev/null)
    c20_events=$(awk -F= '$1=="events_delta"{print $2+0}' "$c20_marker" 2>/dev/null)
    c20_drops=$(awk -F= '$1=="drops_delta"{print $2+0}' "$c20_marker" 2>/dev/null)
    c20_ringbuf_full=$(awk -F= '$1=="ringbuf_full_delta"{print $2+0}' "$c20_marker" 2>/dev/null)
    c20_window=$(awk -F= '$1=="window_seconds"{print $2+0}' "$c20_marker" 2>/dev/null)
    counting_checked_modes=$((counting_checked_modes + 1))

    # 5.9.8b/5.9.8c (№91/№92): приём меняется с "оценить фон точнее" на
    # "убрать фон из измеряемой величины" — counting_control_residual читает
    # канареечную серию, если маркер её несёт (сборка агента+харнесса не
    # старее 5.9.8b), иначе считает запасным путём с вычетом фона (5.9.7a).
    # Общая серия (c20_sum/c20_diff) печатается ниже справочно в обоих
    # случаях.
    counting_control_residual "$c20_marker" "$c20_n" "$c20_window"
    if [ "$CR_USED_CANARY" -eq 1 ]; then
        echo "  $c20_mode: N=${c20_n:-0} $CR_LINE"
        echo "  $c20_mode: справочно, общая серия (контаминирована фоном): Δevents(file)=${c20_events:-0} Δdrops(fileaccess)=${c20_drops:-0} Δringbuf_full=${c20_ringbuf_full:-0} сумма=${c20_sum:-0}"
    else
        echo "  $c20_mode: N=${c20_n:-0} Δevents(file)=${c20_events:-0} Δdrops(fileaccess)=${c20_drops:-0} Δringbuf_full=${c20_ringbuf_full:-0} сумма=${c20_sum:-0} $CR_LINE"
    fi
    if [ "${CR_OK:-0}" -ne 1 ]; then
        fail "$c20_mode: N=${c20_n:-0} не сходится (остаток ${CR_RESIDUAL}, допуск ±$CR_TOLERANCE$( [ "${CR_RING_BOUND:-0}" -gt 0 ] && echo " с поправкой на Δringbuf_full=${CR_RING_BOUND}" )$( [ "$CR_USED_CANARY" -eq 1 ] && echo ", по канареечной серии" || echo ", после вычета фона" )) — либо непосчитанная потеря, либо вызов не увиден ядром (5.9.8b/5.9.8c, №91)"
    else
        counting_ok_modes=$((counting_ok_modes + 1))
        pass "$c20_mode: N=${c20_n:-0} сходится (остаток ${CR_RESIDUAL}, допуск ±$CR_TOLERANCE) (5.9.8b/5.9.8c, №91)"
    fi
done
if [ "$counting_checked_modes" -eq 0 ]; then
    skip "ни один режим контроля счётности (idle) не запускался — сборка харнесса старее 5.9.6c"
fi
if [ "$c20_null_available" -eq 0 ]; then
    skip "негативный контроль (mode=null) не запускался или пропущен — критерий 5.9.7a исполнен не полностью (только positive-control половина)"
fi
# 21. 5.9.6g (№65 долг): каждая ненулевая строка dns_decode_errors_total
# имеет установленную причину — либо исправлена, либо записана как известная
# с числом и обоснованием в dns-decode-reasons.txt (тот же реестровый
# приём, что silent-rules.txt даёт критерию 6 в 5.9.4h/5.9.5d). Плюс:
# флап dns_collector_stale_transitions_total разбирается отдельной строкой
# — 44 пары за 8 часов на №2.9.5 не были ни доказаны безопасными, ни
# отнесены к потере видимости, гейт печатал бы то же самое в обоих случаях.
dns_decode_reasons_file="$GATE_SCRIPT_DIR/dns-decode-reasons.txt"
echo "=== 21. DNS decode errors: причины разделены по реестру + флап stale/recovered (5.9.6g, №65) ==="
if [ ! -s "$final_metrics" ]; then
    skip "$final_metrics пуст — decode errors/флап не проверены"
else
    decode_unexplained=""
    decode_checked=0
    decode_err_lines_21=$(grep '^ebpf_guard_dns_decode_errors_total{' "$final_metrics" 2>/dev/null)
    if [ -z "$decode_err_lines_21" ]; then
        skip "ebpf_guard_dns_decode_errors_total отсутствует в срезе — сборка агента старее 5.9.5c"
    else
        while IFS= read -r reason; do
            [ -z "$reason" ] && continue
            cnt=$(echo "$decode_err_lines_21" | grep "reason=\"$reason\"" | awk -F'} ' '{sum+=$2} END{print sum+0}')
            [ "${cnt%.*}" -eq 0 ] 2>/dev/null && continue
            decode_checked=$((decode_checked + 1))
            if [ -f "$dns_decode_reasons_file" ] && awk -v r="$reason" '!/^[[:space:]]*#/ && $1 == r {found=1} END{exit !found}' "$dns_decode_reasons_file"; then
                cat_21=$(awk -v r="$reason" '!/^[[:space:]]*#/ && $1 == r {print $2; exit}' "$dns_decode_reasons_file")
                echo "  $reason=$cnt: причина установлена (категория $cat_21, dns-decode-reasons.txt)"
            else
                decode_unexplained="$decode_unexplained $reason($cnt)"
                echo "  $reason=$cnt: причина НЕ установлена"
            fi
        done <<< "$(echo "$decode_err_lines_21" | awk -F'[{}", ]+' '{ for (i=1;i<=NF;i++) if ($i ~ /^reason=?$/) print $(i+1) }' | sort -u)"

        if [ "$decode_checked" -eq 0 ]; then
            pass "все reason'ы dns_decode_errors_total нулевые за прогон — decode-ошибок нет"
        elif [ -n "$decode_unexplained" ]; then
            fail "decode errors без установленной причины:$decode_unexplained — добавить в $dns_decode_reasons_file (категория fixed/known/pending, 5.9.6g)"
        else
            pass "все $decode_checked ненулевых reason'ов decode errors объяснены реестром (5.9.6g)"
        fi
    fi

    # Флап stale/recovered: считается по счётчику (не по логам — тот
    # опционален и трудоёмок парсить построчно), классификация — по тому,
    # растут ли decode errors/events_total одновременно с флапом (признак
    # реальной потери видимости) или флап идёт на фоне продолжающегося
    # events_total (признак, что порог dnsStaleThreshold=5м просто короче
    # пауз между резолвами на тихом стенде).
    stale_base=$(awk '/^ebpf_guard_dns_collector_stale_transitions_total( |\{)/ {print $NF+0; exit}' "$baseline_metrics" 2>/dev/null)
    stale_final=$(awk '/^ebpf_guard_dns_collector_stale_transitions_total( |\{)/ {print $NF+0; exit}' "$final_metrics" 2>/dev/null)
    if [ -z "$stale_base" ] || [ -z "$stale_final" ]; then
        skip "ebpf_guard_dns_collector_stale_transitions_total отсутствует в срезах — флап stale/recovered не проверен (сборка старее 5.7d)"
    else
        stale_delta=$((stale_final - stale_base))
        dns_events_at_base=$(grep '^ebpf_guard_events_total{' "$baseline_metrics" 2>/dev/null | grep 'type="dns"' | awk -F'} ' '{sum+=$2} END{print sum+0}')
        dns_events_at_final=$(grep '^ebpf_guard_events_total{' "$final_metrics" 2>/dev/null | grep 'type="dns"' | awk -F'} ' '{sum+=$2} END{print sum+0}')
        dns_events_grew=$(awk -v a="$dns_events_at_base" -v b="$dns_events_at_final" 'BEGIN{print (b>a)?1:0}')
        echo "  stale_transitions за прогон: $stale_delta, events_total{type=dns} baseline=$dns_events_at_base final=$dns_events_at_final"
        if [ "$stale_delta" -eq 0 ]; then
            skip "stale_transitions=0 за прогон — флап не наблюдался в этом окне, классификация не проверена (наблюдалось на №2.9.5, аптайм длиннее одного прогона)"
        elif [ "$dns_events_grew" -eq 1 ]; then
            pass "stale_transitions=$stale_delta за прогон, events_total{dns} продолжает расти между срезами — похоже на порог dnsStaleThreshold короче пауз резолва на тихом стенде, не на потерю видимости (5.9.6g)"
        else
            fail "stale_transitions=$stale_delta за прогон, events_total{dns} НЕ вырос между срезами — похоже на потерю видимости, а не на порог (5.9.6g)"
        fi
    fi
fi
echo ""

# 22. 5.9.7b/5.9.8c (№79/№92, P0): переполнение кольца под управляемой
# нагрузкой, а не надеждой на нагрузку стенда. run_ringbuf_overflow
# (run-all-attacks.sh --ringbuf-overflow) — отдельный, короткий шаг, ВНЕ окна
# замера (запрет №3 постановки 5.9.7): SIGSTOP всему процессу агента,
# генератор известного N openat() на канарейку копится в кольце ядра пока
# читатель заморожен, SIGCONT, затем остаток считается ТЕМ ЖЕ КОДОМ, что и
# критерий 20 (counting_control_residual), но формулой "closed"
# (5.9.9.F.2a, №123/№124): замкнутое тождество
# canary_events + canary_dropped + ringbuf_full = N с фиксированным
# симметричным допуском ±1500 — потеря в кольце входит в тождество, а не
# расширяет допуск. Прежнее асимметричное окно
# -(Δringbuf_full+1500)…+1500 растягивалось на всю величину потери и
# проходило любой результат (находка №124); заменено, а не расширено.
# Реплей на десяти архивных прогонах (collect-2.9.7…collect-2.9.9.F.1)
# кладёт остаток в +183…+335 — заведомо внутри допуска. Плюс НОВОЕ (5.9.7b):
# Δbpf_lost_events_total{collector} совпадает с Δevents_dropped_total{
# collector,reason="ringbuf_full"} того же коллектора — первое живое
# подтверждение 5.9.6a, которого №2.9.6 не дало. Маркер пишется ЭТИМ шагом
# заранее, отдельно от baseline/final основного окна.
echo "=== 22. run_ringbuf_overflow: переполнение под контролем + bpf_lost_events_total живьём (5.9.7b/5.9.8c, №79/№92) ==="
# 5.9.9e: строка передаётся ЦЕЛИКОМ, а не обрезанным началом заголовка —
# в criteria-index.txt на эту секцию заведены ДВА паттерна разной длины
# ("=== 22. run_ringbuf_overflow" для 5.9.7b и "=== 22. run_ringbuf_overflow:
# переполнение под контролем" для 5.9.8c), а record_covered ищет паттерн
# ПОДСТРОКОЙ в переданном тексте: короткий аргумент покрыл бы только первый
# из них, и 5.9.8c числился бы неисполнившимся на каждом прогоне.
record_covered "=== 22. run_ringbuf_overflow: переполнение под контролем + bpf_lost_events_total живьём (5.9.7b/5.9.8c, №79/№92) ==="
# ringbuf_overflow_marker: найден один раз выше (5.9.9.F.2a) — секция 18
# читает тот же маркер.
if [ -z "$ringbuf_overflow_marker" ] || [ ! -f "$ringbuf_overflow_marker" ]; then
    skip "run_ringbuf_overflow не запускался — маркер ringbuf-overflow-*.txt отсутствует; сборка/пайплайн старее 5.9.7b"
elif grep -q '^skipped=1' "$ringbuf_overflow_marker" 2>/dev/null; then
    c22_reason=$(awk -F= '$1=="skip_reason"{ $1=""; print substr($0,2)}' "$ringbuf_overflow_marker" 2>/dev/null)
    skip "run_ringbuf_overflow пропущен харнессом: ${c22_reason:-причина не записана}"
else
    c22_n=$(awk -F= '$1=="n"{print $2+0}' "$ringbuf_overflow_marker" 2>/dev/null)
    c22_events=$(awk -F= '$1=="events_delta"{print $2+0}' "$ringbuf_overflow_marker" 2>/dev/null)
    c22_drops=$(awk -F= '$1=="drops_delta"{print $2+0}' "$ringbuf_overflow_marker" 2>/dev/null)
    c22_ringbuf_full=$(awk -F= '$1=="ringbuf_full_delta"{print $2+0}' "$ringbuf_overflow_marker" 2>/dev/null)
    c22_bpf_lost=$(awk -F= '$1=="bpf_lost_delta"{print $2+0}' "$ringbuf_overflow_marker" 2>/dev/null)
    c22_sum=$(awk -F= '$1=="sum"{print $2+0}' "$ringbuf_overflow_marker" 2>/dev/null)
    c22_diff=$(awk -F= '$1=="diff"{print $2+0}' "$ringbuf_overflow_marker" 2>/dev/null)
    c22_window=$(awk -F= '$1=="window_seconds"{print $2+0}' "$ringbuf_overflow_marker" 2>/dev/null)
    c22_method_a=$(awk -F= '$1=="method_a_blocked_reason"{ $1=""; print substr($0,2)}' "$ringbuf_overflow_marker" 2>/dev/null)
    c22_idle_ringbuf_full=$(awk -F= '$1=="idle_hour_ringbuf_full"{print $2+0}' "$ringbuf_overflow_marker" 2>/dev/null)

    counting_control_residual "$ringbuf_overflow_marker" "$c22_n" "$c22_window" closed
    echo "  метод: SIGSTOP читателя (сужение bpf.ring_buf_size заблокировано кодом: ${c22_method_a:-см. открытые вопросы 5.9.7b})"
    echo "  N=${c22_n:-0} $CR_LINE"
    if [ "$CR_USED_CANARY" -eq 1 ]; then
        echo "  справочно, общая серия (контаминирована фоном): Δevents(file)=${c22_events:-0} Δdrops(fileaccess)=${c22_drops:-0} сумма=${c22_sum:-0} сумма-N=${c22_diff:-0}"
    fi
    echo "  Δringbuf_full(fileaccess)=${c22_ringbuf_full:-0} Δbpf_lost_events_total(fileaccess)=${c22_bpf_lost:-0}"
    [ -n "$c22_idle_ringbuf_full" ] && echo "  ringbuf_full за idle-час (справочно, критерий 18 судит это же значение отдельно): ${c22_idle_ringbuf_full}"

    if [ "${CR_OK:-0}" -ne 1 ]; then
        fail "run_ringbuf_overflow: N=${c22_n:-0} не сходится под SIGSTOP (остаток ${CR_RESIDUAL}, замкнутое тождество, допуск ±$CR_TOLERANCE симметричный — 5.9.9.F.2a, №123/№124) — тождество 5.9.6c не подтверждено под реальным переполнением"
    elif ! awk -v r="${c22_ringbuf_full:-0}" 'BEGIN{exit !(r>0)}'; then
        fail "run_ringbuf_overflow: N сошёлся, но ringbuf_full=${c22_ringbuf_full:-0} — SIGSTOP не переполнил кольцо на этом стенде (кольцо больше, чем предполагалось, или окно заморозки было коротким); переполнение остаётся недоказанным управляемой нагрузкой"
    elif ! awk -v a="${c22_ringbuf_full:-0}" -v b="${c22_bpf_lost:-0}" 'BEGIN{exit !(a==b)}'; then
        fail "run_ringbuf_overflow: ringbuf_full=${c22_ringbuf_full:-0} != bpf_lost_events_total=${c22_bpf_lost:-0} — счётчик 5.9.6a не совпадает с переполнением кольца под нагрузкой, которую он должен объяснять"
    else
        pass "run_ringbuf_overflow: N=${c22_n:-0} сходится (остаток ${CR_RESIDUAL}, допуск ±$CR_TOLERANCE), ringbuf_full=${c22_ringbuf_full:-0} > 0, bpf_lost_events_total совпадает — переполнение доказано управляемой нагрузкой, не надеждой (5.9.7b/5.9.8c, №79/№92)"
    fi
fi
echo ""

# 5.9.8f (№93, P1): settle_reason — каждый settle-луп контроля счётности
# (run_counting_control/run_ringbuf_overflow, counting_settle_loop в
# run-all-attacks.sh) теперь пишет причину остановки
# (flattened/ceiling/timeout), не только quiesced_iterations. "ceiling" —
# луп докрутил все срезы, не сойдясь к фону: старое условие выхода
# (сумма events+drops не выросла между двумя срезами) на стенде с
# непрерывным фоном недостижимо, и quiesced_iterations=30 было
# неотличимо от «настоящего» устаканивания за 30 срезов — это и есть
# находка №93. Критерий: причина печатается для всех трёх маркеров
# (null/idle/run_ringbuf_overflow — режим drop удалён волной 5.9.9.F.2a,
# №123), и ни один не "ceiling".
echo "=== 5.9.8f. settle_reason: контроль счётности сообщает причину остановки (№93) ==="
record_covered "=== 5.9.8f. settle_reason"
settle_reason_ceiling_count=0
settle_reason_checked=0
for settle_label in null idle; do
    settle_marker="$RESULTS_DIR/counting-control-${settle_label}-$TIMESTAMP.txt"
    if [ ! -f "$settle_marker" ] || grep -q '^skipped=1' "$settle_marker" 2>/dev/null; then
        echo "  $settle_label: маркер отсутствует или пропущен — причина не проверена"
        continue
    fi
    if ! grep -q '^settle_reason=' "$settle_marker" 2>/dev/null; then
        echo "  $settle_label: маркер без settle_reason — сборка харнесса старее 5.9.8f"
        continue
    fi
    settle_reason_checked=$((settle_reason_checked + 1))
    settle_val=$(awk -F= '$1=="settle_reason"{print $2}' "$settle_marker" 2>/dev/null)
    echo "  $settle_label: settle_reason=${settle_val:-?}"
    [ "$settle_val" = "ceiling" ] && settle_reason_ceiling_count=$((settle_reason_ceiling_count + 1))
done
if [ -n "$ringbuf_overflow_marker" ] && [ -f "$ringbuf_overflow_marker" ] && ! grep -q '^skipped=1' "$ringbuf_overflow_marker" 2>/dev/null; then
    if grep -q '^settle_reason=' "$ringbuf_overflow_marker" 2>/dev/null; then
        settle_reason_checked=$((settle_reason_checked + 1))
        settle_val=$(awk -F= '$1=="settle_reason"{print $2}' "$ringbuf_overflow_marker" 2>/dev/null)
        echo "  run_ringbuf_overflow: settle_reason=${settle_val:-?}"
        [ "$settle_val" = "ceiling" ] && settle_reason_ceiling_count=$((settle_reason_ceiling_count + 1))
    else
        echo "  run_ringbuf_overflow: маркер без settle_reason — сборка харнесса старее 5.9.8f"
    fi
else
    echo "  run_ringbuf_overflow: маркер отсутствует или пропущен — причина не проверена"
fi
if [ "$settle_reason_checked" -eq 0 ]; then
    skip "settle_reason нигде не найден — сборка харнесса старее 5.9.8f, ни один из четырёх маркеров не проверен"
elif [ "$settle_reason_ceiling_count" -gt 0 ]; then
    fail "$settle_reason_ceiling_count из $settle_reason_checked маркеров settle-лупа докрутили до потолка (settle_reason=ceiling) — снимок «после» мог уйти раньше конца асинхронного хвоста (5.9.8f, №93)"
else
    pass "ни один из $settle_reason_checked проверенных маркеров settle-лупа не докрутил до потолка (5.9.8f, №93)"
fi
echo ""

# 5.9.7h (находка №83): непокрытые пункты постановки — часть итогового
# вердикта, не примечание сбоку от него. На практике преflight выше уже
# останавливает цепочку (exit 3) раньше, чем скрипт доходит досюда, если
# uncovered_criteria_count > 0 — эта проверка добивает единственный
# оставшийся случай, когда реестр отсутствовал вовсе (-1, "не проверено"), и
# не даёт такому прогону просто промолчать по этому пункту в финальной строке.
#
# 5.9.9e: этот блок стоит ПЕРЕД сводкой «ветка не исполнилась» ниже
# намеренно. Строка 5.9.7h — единственная машинная печать своего пункта, и
# считает её рантайм-сверка через record_covered из pass()/fail(); стой она
# после сводки, 5.9.7h попадал бы в список неисполнившихся на каждом
# прогоне (то же самонаведение, что чинится у 5.9.9e ниже).
if [ "$uncovered_criteria_count" -lt 0 ]; then
    fail "непокрытых пунктов постановки: не проверено (criteria-index.txt отсутствовал) (5.9.7h)"
elif [ "$uncovered_criteria_count" -gt 0 ]; then
    fail "непокрытых пунктов постановки: $uncovered_criteria_count (5.9.7h)"
else
    pass "непокрытых пунктов постановки: 0 (5.9.7h)"
fi
echo ""

# 5.9.9e (№102): «пункты постановки, чья ветка не исполнилась на этом
# прогоне» — вопрос, ОТДЕЛЬНЫЙ от преflight'а 5.9.7h выше. Преflight
# отвечает «код для пункта написан?» статическим grep по исходнику ДО
# чтения снимков этого прогона; здесь спрашивается «строка пункта реально
# напечаталась СЕЙЧАС?». №2.9.8 показал, что ответы расходятся: код для
# разбора по составу (5.9.7g/5.9.8g) существовал и проходил преflight, но
# ветка не исполнялась на окнах с blind_new_alerts<=5 (закрыто выше в этой
# же правке) — преflight такой разрыв в принципе не видит, потому что он не
# смотрит на то, что реально напечаталось.
#
# id с file="-" в criteria-index.txt считается исполнившимся, если хотя бы
# один pass()/fail()/warn()/skip() или explicit record_covered() с этим id
# уже отметил его через CRITERIA_COVERED (см. определения выше). id с
# файлом, отличным от "-", считается исполнившимся, если его паттерн сейчас
# найден в этом файле — тот же grep -F, что и в преflight'е, но выполненный
# ПОСЛЕ прогона, по свежему артефакту (rules/*.yaml, dns-idle-fp.txt,
# detection-baseline.txt, вывод replay-gate.sh), а не по состоянию до него.
#
# Собственная строка 5.9.9e отмечается ДО подсчёта, а не через pass()/skip()
# ниже: её record_covered сработал бы уже ПОСЛЕ того, как список посчитан, и
# пункт 5.9.9e числился бы неисполнившимся на каждом прогоне — то есть
# механизм самонаведённо валил бы сам себя в SKIP, ровно тот класс дефекта
# (№99), который эта же волна чинит у сигнатуры состава детекта. Отметка
# здесь честна: строка ниже печатается безусловно, у неё нет ветвления.
record_covered "пунктов постановки с неисполнившейся веткой"
unexecuted_criteria_ids=""
unexecuted_criteria_count=0
if [ -f "$CRITERIA_INDEX_FILE" ]; then
    declare -A _final_id_covered=()
    _final_ordered_ids=()
    while IFS=$'\t' read -r ci_id ci_file ci_pattern; do
        [ -z "$ci_id" ] && continue
        case "$ci_id" in "#"*) continue ;; esac
        [ -z "$ci_pattern" ] && continue
        if [[ ! " ${_final_ordered_ids[*]-} " == *" $ci_id "* ]]; then
            _final_ordered_ids+=("$ci_id")
        fi
        if [ "$ci_file" = "-" ]; then
            [ -n "${CRITERIA_COVERED[$ci_id]:-}" ] && _final_id_covered[$ci_id]=1
        else
            ci_target="$GATE_SCRIPT_DIR/$ci_file"
            [ -f "$ci_target" ] && grep -qF -- "$ci_pattern" "$ci_target" && _final_id_covered[$ci_id]=1
        fi
    done < "$CRITERIA_INDEX_FILE"
    for _fid in "${_final_ordered_ids[@]}"; do
        if [ -z "${_final_id_covered[$_fid]:-}" ]; then
            unexecuted_criteria_count=$((unexecuted_criteria_count + 1))
            unexecuted_criteria_ids="$unexecuted_criteria_ids $_fid"
        fi
    done
fi
echo "пункты постановки, чья ветка не исполнилась на этом прогоне:${unexecuted_criteria_ids:- (пусто)}"
if [ ! -f "$CRITERIA_INDEX_FILE" ]; then
    skip "пункты постановки с неисполнившейся веткой: не проверено (criteria-index.txt отсутствовал) (5.9.9e, №102)"
elif [ "$unexecuted_criteria_count" -gt 0 ]; then
    skip "пунктов постановки с неисполнившейся веткой: $unexecuted_criteria_count — это SKIP, а не PASS (5.9.9e, №102)"
else
    pass "пунктов постановки с неисполнившейся веткой: 0 (5.9.9e, №102)"
fi
echo ""

echo "==========================================="
echo "RUN-GATE: PASS=$PASS_COUNT SKIP=$SKIP_COUNT (5.9.6i), непокрытых пунктов постановки: $uncovered_criteria_count (5.9.7h)"
if [ "$GATE_FAILED" -eq 0 ]; then
    echo -e "${GREEN}RUN-GATE: PASS${NC}"
    exit 0
else
    echo -e "${RED}RUN-GATE: FAIL${NC}"
    exit 1
fi
