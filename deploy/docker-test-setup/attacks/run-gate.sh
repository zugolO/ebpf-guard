#!/bin/bash
# Проверяет шесть критериев ЗАМЕРА №1 (plan.md, раздел "ЗАМЕР №1") по
# baseline/final снимкам одного прогона run-all-attacks.sh и печатает
# PASS/FAIL по каждому плюс общий вердикт. Возвращает ненулевой код при
# любом FAIL — до этого скрипта критерии замера проверялись руками
# (plan.md волна 1.5h, вопрос 12).
#
# Использование: run-gate.sh [RESULTS_DIR] [TIMESTAMP]
# По умолчанию берёт последний TIMESTAMP, для которого в RESULTS_DIR есть
# baseline-state-*.json и final-state-*.json.

set -u

RESULTS_DIR="${1:-./attack-results}"
TIMESTAMP="${2:-}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; GATE_FAILED=1; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

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

# 2. events_total{type="dns"} растёт на сотни.
echo "=== 2. DNS-события растут ==="
dns_before=$(jq -r '.engine_stats.total_events // 0' "$baseline_state" 2>/dev/null)
dns_metric_before=$(grep 'ebpf_guard_events_total{' "$baseline_metrics" | grep 'type="dns"' | awk -F'} ' '{sum+=$2} END{print sum+0}')
dns_metric_after=$(grep 'ebpf_guard_events_total{' "$final_metrics" | grep 'type="dns"' | awk -F'} ' '{sum+=$2} END{print sum+0}')
dns_delta=$(awk -v a="$dns_metric_after" -v b="$dns_metric_before" 'BEGIN{print a-b}')
if awk -v d="$dns_delta" 'BEGIN{exit !(d>=100)}'; then
    pass "dns events_total выросли на $dns_delta (>= 100)"
else
    fail "dns events_total выросли только на $dns_delta (ожидалось >= сотен)"
fi
echo ""

# 3. Деградация в /health видна при любых потерях.
echo "=== 3. Деградация в /health при потерях ==="
if [ -f "$final_health" ]; then
    any_dropped_total=$(grep 'ebpf_guard_events_dropped_total{' "$final_metrics" | awk -F'} ' '{sum+=$2} END{print sum+0}')
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

# 6. Детект жив: 43 типа, >= 850 алертов от атакующих процессов.
echo "=== 6. Детект жив (типы атак, алерты от атакующих) ==="
detected_types=$(jq -s '
    (.[0] // []) as $baseline | (.[1] // []) as $final |
    ($baseline | map(.id) | unique) as $bids |
    ($final | map(select(.id as $id | ($bids | index($id)) | not))) as $new |
    $new | map(.rule_id) | unique | length
' -r "$baseline_alerts" "$final_alerts" 2>/dev/null || echo 0)

attacker_alerts=0
if [ -f "$manifest_file" ]; then
    attacker_comms=$(jq -c '[.[].comm] | unique' "$manifest_file" 2>/dev/null || echo '[]')
    attacker_alerts=$(jq -s --argjson comms "$attacker_comms" '
        (.[0] // []) as $baseline | (.[1] // []) as $final |
        ($baseline | map(.id) | unique) as $bids |
        ($final | map(select(.id as $id | ($bids | index($id)) | not))) as $new |
        $new | map(select(.comm as $c | $comms | index($c))) | length
    ' -r "$baseline_alerts" "$final_alerts" 2>/dev/null || echo 0)
else
    warn "attack-manifest.json не найден — алерты от атакующих процессов не посчитаны"
fi

if [ "$detected_types" -ge 43 ] 2>/dev/null; then
    pass "уникальных типов атак: $detected_types (>= 43)"
else
    fail "уникальных типов атак: $detected_types (ожидалось >= 43)"
fi
if [ "$attacker_alerts" -ge 850 ] 2>/dev/null; then
    pass "алертов от атакующих процессов: $attacker_alerts (>= 850)"
else
    fail "алертов от атакующих процессов: $attacker_alerts (ожидалось >= 850)"
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
