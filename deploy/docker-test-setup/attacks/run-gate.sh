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

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; GATE_FAILED=1; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
skip() { echo -e "${YELLOW}[SKIP]${NC} $1"; }

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
# The manifest is written by the four attack sub-scripts next to the scripts
# themselves, so anchor to this script's directory rather than deriving a path
# from RESULTS_DIR or the working directory (plan.md волна 1.5g).
GATE_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
manifest_file="$GATE_SCRIPT_DIR/attack-manifest.json"
# Зафиксированный состав типов детекта для критерия 6 (волна 5.3).
baseline_types_file="$GATE_SCRIPT_DIR/detection-baseline.txt"
# Разметка "фоновых" правил для критерия 6 (волна 5.8a, находка №22).
background_rules_file="$GATE_SCRIPT_DIR/background-rules.txt"
# Снимки /metrics idle-часа (idle-run.sh), опционально — только они дают
# критерию 6 вторую сторону измерения для фоновых правил (5.8a).
IDLE_METRICS_START="${IDLE_METRICS_START:-}"
IDLE_METRICS_END="${IDLE_METRICS_END:-}"

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
echo "=== 3. Деградация в /health при потерях ==="
if [ -f "$final_health" ]; then
    any_dropped_total=$(grep 'ebpf_guard_events_dropped_total{' "$final_metrics" \
        | grep -v 'reason="path_denylist"' | awk -F'} ' '{sum+=$2} END{print sum+0}')
    intentional_drops=$(grep 'ebpf_guard_events_dropped_total{' "$final_metrics" \
        | grep 'reason="path_denylist"' | awk -F'} ' '{sum+=$2} END{print sum+0}')
    echo "  непреднамеренных дропов: $any_dropped_total; намеренных (path_denylist): ${intentional_drops%.*} — в критерий не входят"
    visibility_reduced=$(jq -r '.visibility_reduced // false' "$final_health" 2>/dev/null)
    status=$(jq -r '.status // "unknown"' "$final_health" 2>/dev/null)
    if awk -v d="$any_dropped_total" 'BEGIN{exit !(d>0)}'; then
        if [ "$visibility_reduced" = "true" ] && [ "$status" = "degraded" ]; then
            pass "потери есть ($any_dropped_total) и /health показывает degraded"
        else
            fail "потери есть ($any_dropped_total), но /health: visibility_reduced=$visibility_reduced status=$status"
        fi
    else
        pass "потерь нет, /health status=$status (проверка неприменима)"
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
runtime_min=0
if command -v jq &> /dev/null; then
    b_ts=$(jq -r '.timestamp // empty' "$baseline_state" 2>/dev/null)
    f_ts=$(jq -r '.timestamp // empty' "$final_state" 2>/dev/null)
    if [ -n "$b_ts" ] && [ -n "$f_ts" ]; then
        # date -d понимает ISO 8601 с миллисекундами/таймзоной; awk делает
        # деление на 60 для минут (с дробной частью).
        b_epoch=$(date -d "$b_ts" +%s.%N 2>/dev/null || echo 0)
        f_epoch=$(date -d "$f_ts" +%s.%N 2>/dev/null || echo 0)
        runtime_min=$(awk -v b="$b_epoch" -v f="$f_epoch" 'BEGIN{ if(b>0 && f>b) print (f-b)/60; else print 0 }')
    fi
fi
if awk -v r="$runtime_min" 'BEGIN{exit !(r>0)}'; then
    attacker_rate=$(awk -v a="$attacker_alerts" -v m="$runtime_min" 'BEGIN{printf "%.1f", a/m}')
else
    # Fallback: mtime файлов состояния — менее точно, но работает, если
    # DebugState.timestamp отсутствует (старая сборка агента).
    b_mt=$(stat -c %Y "$baseline_state" 2>/dev/null || stat -f %m "$baseline_state" 2>/dev/null || echo 0)
    f_mt=$(stat -c %Y "$final_state" 2>/dev/null || stat -f %m "$final_state" 2>/dev/null || echo 0)
    runtime_min=$(awk -v b="$b_mt" -v f="$f_mt" 'BEGIN{ if(b>0 && f>b) print (f-b)/60; else print 0 }')
    attacker_rate=$(awk -v a="$attacker_alerts" -v m="$runtime_min" 'BEGIN{ if(m>0) printf "%.1f", a/m; else print "n/a" }')
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
if [ -s "$baseline_metrics" ]; then
    metrics_inputs=("$baseline_metrics" "$final_metrics")
    basefile_arg="$baseline_metrics"
else
    echo "  (baseline-снимок пуст или отсутствует — на состав детекта не влияет, считается по final)"
    metrics_inputs=("$final_metrics")
    basefile_arg=""
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
detected_types=$(echo "$detected_type_list" | grep -c . || true)

if [ ! -f "$baseline_types_file" ]; then
    skip "detection-baseline.txt не найден рядом с гейтом — состав детекта сравнить не с чем (число типов: $detected_types)"
else
    # tr -d '\r' с обеих сторон: иначе diff вырождается в "всё потеряно и всё
    # добавлено" при малейшем расхождении переводов строк между базой и выводом
    # jq (поймано при пересчёте 5.3 на Windows-сборке jq).
    expected_types=$(grep -vE '^\s*(#|$)' "$baseline_types_file" | tr -d '\r' | sort)
    lost_types_raw=$(comm -23 <(echo "$expected_types") <(echo "$detected_type_list"))
    added_types=$(comm -13 <(echo "$expected_types") <(echo "$detected_type_list"))
    added_count=$(echo "$added_types" | grep -c . || true)
    echo "  типов в прогоне: $detected_types, в базе: $(echo "$expected_types" | grep -c .)"
    if [ "$added_count" -gt 0 ]; then
        echo "  добавлено (+$added_count):"
        echo "$added_types" | sed 's/^/    + /'
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
        background_set=$(grep -vE '^\s*(#|$)' "$background_rules_file" | tr -d '\r' | sort)
        lost_background=$(comm -12 <(echo "$lost_types_raw") <(echo "$background_set"))
        if [ -n "$lost_background" ]; then
            if [ -n "$IDLE_METRICS_START" ] && [ -n "$IDLE_METRICS_END" ] \
                && [ -s "$IDLE_METRICS_START" ] && [ -s "$IDLE_METRICS_END" ]; then
                idle_delta_list=$(awk -F'[{}", ]+' '
                    function rule_id(   i, rid) {
                        rid = ""
                        for (i = 1; i <= NF; i++) {
                            if ($i ~ /^rule_id=?$/) { rid = $(i+1); break }
                        }
                        return rid
                    }
                    { gsub(/\r/, "") }
                    !/^ebpf_guard_alerts_total\{/ { next }
                    {
                        rid = rule_id(); if (rid == "") next
                        # Суммируем по сериям (у одного rule_id несколько
                        # лейблсетов) РАЗДЕЛЬНО по снимкам: общий аккумулятор
                        # здесь давал start+end во втором файле, и разность
                        # вырождалась в "end > 0" — правило с нулевым приростом
                        # ошибочно считалось выросшим.
                        if (FNR == NR) { start[rid] += $NF } else { end[rid] += $NF }
                    }
                    END {
                        for (r in end) {
                            if (end[r] - (start[r]+0) > 0) print r
                        }
                    }
                ' "$IDLE_METRICS_START" "$IDLE_METRICS_END" | sort)
                # Разбираем lost_background по одному, чтобы напечатать судьбу
                # каждого правила, а не только итоговое число.
                while IFS= read -r rid; do
                    [ -z "$rid" ] && continue
                    if echo "$idle_delta_list" | grep -qx "$rid"; then
                        recovered_types="$recovered_types$rid"$'\n'
                        echo "  фоновое $rid: не сработало под атакой, но выросло за idle-час — не считается потерей (5.8a)"
                    else
                        echo "  фоновое $rid: не сработало ни под атакой, ни за idle-час — потеря подтверждена"
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
    lost_count=$(echo "$lost_types" | grep -c . || true)
    if [ "$lost_count" -gt 0 ]; then
        echo "  потеряно (-$lost_count):"
        echo "$lost_types" | sed 's/^/    - /'
    fi
    # Провал — только потеря. Добавления печатаются и требуют обновления базы,
    # но не проваливают прогон: новое правило, которое сработало, — не регресс.
    if [ "$lost_count" -eq 0 ]; then
        pass "состав детекта без потерь (добавлено: $added_count — обновить detection-baseline.txt вместе с записью в plan.md)"
    else
        fail "состав детекта: потеряно $lost_count типов (см. список выше). Если потеря намеренная — обновить detection-baseline.txt и записать причину в plan.md, иначе это регресс детекта"
    fi
fi
if [ "$attacker_alerts_known" -eq 0 ]; then
    skip "темп алертов непроверяем — нет attack-manifest.json, множество атакующих comms неизвестно"
elif [ "$runtime_min" = "0" ]; then
    skip "темп алертов непроверяем — не удалось определить длительность прогона (нет .timestamp в /debug/state и stat недоступен)"
elif awk -v r="$attacker_rate" 'BEGIN{exit !(r+0>=74)}'; then
    pass "темп алертов от атакующих: $attacker_alerts за ${runtime_min} мин = $attacker_rate/мин (>= 74, уровень прогона №4)"
else
    fail "темп алертов от атакующих: $attacker_alerts за ${runtime_min} мин = $attacker_rate/мин (ожидалось >= 74)"
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
    if awk -v r="$d_reduce" 'BEGIN{exit !(r+0 <= 1)}'; then
        pass "переходов reduce=$d_reduce recover=$d_recover — повторных нет (порог: <= 1 пара); degraded_fraction=${deg_frac:-n/a}"
    else
        fail "watchdog флапает: reduce=$d_reduce recover=$d_recover за прогон (ожидалось <= 1 пары; 813 циклов за ночь — ISSUES-attack-run-2026-08-03)"
    fi
fi
echo ""

echo "==========================================="
if [ "$GATE_FAILED" -eq 0 ]; then
    echo -e "${GREEN}RUN-GATE: PASS${NC}"
    exit 0
else
    echo -e "${RED}RUN-GATE: FAIL${NC}"
    exit 1
fi
