#!/bin/bash
# Master скрипт для запуска всех атак против Juice Shop
# Запускает все типы атак последовательно и собирает результаты

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VPS_IP="${VPS_IP:-localhost}"
JUICE_SH_URL="http://${VPS_IP}:3000"
EBPF_GUARD_API="http://${VPS_IP}:19090"
# admin token from config-test.yaml (auth.admin_token) — needed because auth.enabled=true;
# /debug/state and /metrics require a bearer token. Override via env if changed.
EBPF_GUARD_TOKEN="${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}"
RESULTS_DIR="./attack-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Shared with the four attack sub-scripts and run-gate.sh. Anchored to
# SCRIPT_DIR rather than the working directory so every producer and consumer
# agrees on one path regardless of where the run was launched from
# (plan.md волна 1.5g).
MANIFEST_FILE="$SCRIPT_DIR/attack-manifest.json"

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }

# Создание директории для результатов
mkdir -p "$RESULTS_DIR"

# Проверка доступности сервисов
check_services() {
    log "==========================================="
    log "ПРОВЕРКА ДОСТУПНОСТИ СЕРВИСОВ"
    log "==========================================="

    # Проверка Juice Shop
    if curl -s -o /dev/null -w "%{http_code}" "$JUICE_SH_URL" | grep -q "200\|302"; then
        log "✓ Juice Shop доступен: $JUICE_SH_URL"
    else
        error "✗ Juice Shop недоступен"
        return 1
    fi

    # Проверка ebpf-guard
    if curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/health" | grep -q "200"; then
        log "✓ ebpf-guard доступен: $EBPF_GUARD_API"
    else
        error "✗ ebpf-guard недоступен"
        return 1
    fi

    echo ""
}

# Получение начальных метрик
get_baseline_metrics() {
    log "==========================================="
    log "СБОР БАЗОВЫХ МЕТРИК"
    log "==========================================="

    # Clear the shared attack-manifest.json (plan.md волна 1.5g, вопрос 8) so
    # each sub-script's record_manifest starts this run from an empty file —
    # otherwise categories/comms from a previous run would leak into this
    # run's precision/recall calculation below.
    rm -f "$MANIFEST_FILE"

    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/metrics" > "$RESULTS_DIR/baseline-metrics-$TIMESTAMP.txt"
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/api/v1/alerts" > "$RESULTS_DIR/baseline-alerts-$TIMESTAMP.json"
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/health" > "$RESULTS_DIR/baseline-health-$TIMESTAMP.json"
    # /health не отдаёт фазу обучения (она только в /api/v1/status) — см. P1-4/P2-7 п.6.
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/api/v1/status" > "$RESULTS_DIR/baseline-status-$TIMESTAMP.json"
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/debug/state" > "$RESULTS_DIR/baseline-state-$TIMESTAMP.json"
    # Baseline counterpart of the final incidents snapshot — lets the idle FP
    # rate (570 incidents per 2h in run #4, all on sshd) be compared against the
    # attack run rather than only counted once.
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/api/v1/incidents" > "$RESULTS_DIR/baseline-incidents-$TIMESTAMP.json"
    if ! curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/debug/state" | grep -q "200"; then
        warn "server.enable_debug не включен в конфиге ebpf-guard — /debug/state недоступен, Alerts/Events/Anomalies Total в отчете будут нулевыми"
    fi

    # Подсчет начальных алертов
    if command -v jq &> /dev/null; then
        local alert_count=$(curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/api/v1/alerts" | jq '. | length' 2>/dev/null || echo 0)
        log "Начальное количество алертов: $alert_count"
    else
        log "Начальные метрики сохранены"
    fi

    echo ""
}

# Запуск SQLMap атак
run_sqlmap_attacks() {
    log "==========================================="
    log "ЗАПУСК SQLMAP АТАК"
    log "==========================================="

    if [ -f "$SCRIPT_DIR/sqlmap-attacks.sh" ]; then
        bash "$SCRIPT_DIR/sqlmap-attacks.sh" || warn "SQLMap атаки завершились с ошибками"
    else
        warn "SQLMap скрипт не найден, пропускаем..."
    fi
    echo ""
}

# Запуск brute force атак
run_bruteforce_attacks() {
    log "==========================================="
    log "ЗАПУСК BRUTE FORCE АТАК"
    log "==========================================="

    if [ -f "$SCRIPT_DIR/bruteforce-attacks.sh" ]; then
        bash "$SCRIPT_DIR/bruteforce-attacks.sh" || warn "Brute force атаки завершились с ошибками"
    else
        warn "Brute force скрипт не найден, пропускаем..."
    fi
    echo ""
}

# Запуск SSRF атак
run_ssrf_attacks() {
    log "==========================================="
    log "ЗАПУСК SSRF АТАК"
    log "==========================================="

    if [ -f "$SCRIPT_DIR/ssrf-attacks.sh" ]; then
        bash "$SCRIPT_DIR/ssrf-attacks.sh" || warn "SSRF атаки завершились с ошибками"
    else
        warn "SSRF скрипт не найден, пропускаем..."
    fi
    echo ""
}

# Запуск LDAP/CSRF атак
run_ldap_csrf_attacks() {
    log "==========================================="
    log "ЗАПУСК LDAP/CSRF АТАК"
    log "==========================================="

    if [ -f "$SCRIPT_DIR/ldap-csrf-attacks.sh" ]; then
        bash "$SCRIPT_DIR/ldap-csrf-attacks.sh" || warn "LDAP/CSRF атаки завершились с ошибками"
    else
        warn "LDAP/CSRF скрипт не найден, пропускаем..."
    fi
    echo ""
}

# Сбор финальных метрик
get_final_metrics() {
    log "==========================================="
    log "СБОР ФИНАЛЬНЫХ МЕТРИК"
    log "==========================================="

    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/metrics" > "$RESULTS_DIR/final-metrics-$TIMESTAMP.txt"
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/api/v1/alerts" > "$RESULTS_DIR/final-alerts-$TIMESTAMP.json"
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/health" > "$RESULTS_DIR/final-health-$TIMESTAMP.json"
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/api/v1/status" > "$RESULTS_DIR/final-status-$TIMESTAMP.json"
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/debug/state" > "$RESULTS_DIR/final-state-$TIMESTAMP.json"
    # Incidents carry the P1-27 comm field that run-gate.sh criterion 4 checks.
    # Without this snapshot that criterion silently degrades to a WARN, i.e. the
    # headline result of wave 1 would go unverified by the very gate written to
    # verify it (plan.md волна 1.5h).
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/api/v1/incidents" > "$RESULTS_DIR/final-incidents-$TIMESTAMP.json"

    echo ""
}

# Генерация итогового отчета
generate_final_report() {
    log "==========================================="
    log "ГЕНЕРАЦИЯ ИТОГОВОГО ОТЧЕТА"
    log "==========================================="

    local report_file="$RESULTS_DIR/FINAL-REPORT-$TIMESTAMP.txt"
    # generate_final_report's body runs inside a "{ ... } | tee" pipeline,
    # i.e. a subshell — a plain variable set there would be lost once the
    # pipeline exits. Use a flag file instead so the caller (full_run/
    # interactive_mode) can see whether any gate failed and exit non-zero.
    local gate_flag_file="$RESULTS_DIR/.gate-failed-$TIMESTAMP"
    rm -f "$gate_flag_file"

    {
        echo "╔═══════════════════════════════════════════════════════════════╗"
        echo "║          ebpf-guard SECURITY TESTING - FINAL REPORT          ║"
        echo "╚═══════════════════════════════════════════════════════════════╝"
        echo ""
        echo "Дата: $(date)"
        echo "Timestamp: $TIMESTAMP"
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        echo "ТЕСТОВОЕ ОКРУЖЕНИЕ"
        echo "═══════════════════════════════════════════════════════════════"
        echo "Juice Shop URL: $JUICE_SH_URL"
        echo "ebpf-guard API: $EBPF_GUARD_API"
        echo ""

        echo "═══════════════════════════════════════════════════════════════"
        echo "АНАЛИЗ МЕТРИК ebpf-guard"
        echo "═══════════════════════════════════════════════════════════════"

        # Сравнение метрик — берём точные счетчики из /debug/state (JSON),
        # т.к. ebpf_guard_alerts_total / ebpf_guard_events_total в /metrics
        # экспортируются по многим комбинациям лейблов (rule_id/severity/pod/...),
        # и grep по первой строке даёт только один срез, а не сумму.
        echo ""
        echo "=== КЛЮЧЕВЫЕ МЕТРИКИ ==="

        local baseline_state="$RESULTS_DIR/baseline-state-$TIMESTAMP.json"
        local final_state="$RESULTS_DIR/final-state-$TIMESTAMP.json"

        local baseline_alerts=0 final_alerts=0 baseline_events=0 final_events=0
        local baseline_anomalies=0 final_anomalies=0
        if command -v jq &> /dev/null; then
            baseline_alerts=$(jq -r '.engine_stats.total_alerts // 0' "$baseline_state" 2>/dev/null || echo 0)
            final_alerts=$(jq -r '.engine_stats.total_alerts // 0' "$final_state" 2>/dev/null || echo 0)
            baseline_events=$(jq -r '.engine_stats.total_events // 0' "$baseline_state" 2>/dev/null || echo 0)
            final_events=$(jq -r '.engine_stats.total_events // 0' "$final_state" 2>/dev/null || echo 0)
            baseline_anomalies=$(jq -r '.profiler_stats.anomalies_total // 0' "$baseline_state" 2>/dev/null || echo 0)
            final_anomalies=$(jq -r '.profiler_stats.anomalies_total // 0' "$final_state" 2>/dev/null || echo 0)
        else
            warn "jq не найден — пропускаем разбор /debug/state, проверьте *-state-$TIMESTAMP.json вручную"
        fi

        local new_alerts=$((final_alerts - baseline_alerts))
        echo "Alerts Total:"
        echo "  До тестов: $baseline_alerts"
        echo "  После тестов: $final_alerts"
        echo "  Новых: $new_alerts"
        echo ""

        local new_events=$((final_events - baseline_events))
        echo "Events Total:"
        echo "  До тестов: $baseline_events"
        echo "  После тестов: $final_events"
        echo "  Новых: $new_events"
        echo ""

        local new_anomalies=$((final_anomalies - baseline_anomalies))
        echo "Anomalies Total:"
        echo "  До тестов: $baseline_anomalies"
        echo "  После тестов: $final_anomalies"
        echo "  Новых: $new_anomalies"
        echo ""

        # Фаза обучения — только в /api/v1/status, не в /health (см. P1-4, P2-7 п.6).
        local baseline_status="$RESULTS_DIR/baseline-status-$TIMESTAMP.json"
        local final_status="$RESULTS_DIR/final-status-$TIMESTAMP.json"
        if command -v jq &> /dev/null; then
            local b_complete b_progress f_complete f_progress
            # AgentHealth is nested under "health" in /api/v1/status
            # (see internal/exporter/api.go StatusAPIResponse.Health); the
            # top-level fallback covers a future flattened response shape
            # (plan.md волна 1.5f).
            b_complete=$(jq -r '.health.learning_complete // .learning_complete // "unknown"' "$baseline_status" 2>/dev/null)
            b_progress=$(jq -r '.health.learning_progress // .learning_progress // "unknown"' "$baseline_status" 2>/dev/null)
            f_complete=$(jq -r '.health.learning_complete // .learning_complete // "unknown"' "$final_status" 2>/dev/null)
            f_progress=$(jq -r '.health.learning_progress // .learning_progress // "unknown"' "$final_status" 2>/dev/null)
            echo "Learning Phase:"
            echo "  До тестов: complete=$b_complete progress=$b_progress"
            echo "  После тестов: complete=$f_complete progress=$f_progress"
            echo ""
        fi

        echo "═══════════════════════════════════════════════════════════════"
        echo "СТАТИСТИКА ПО ТИПАМ АТАК"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""

        # Статистика по результатам
        local attack_gate_failed=""
        for result_dir in sqlmap-results bruteforce-results ssrf-results ldap-csrf-results; do
            if [ -d "$result_dir" ]; then
                local file_count=$(find "$result_dir" -type f | wc -l)
                echo "📁 $result_dir:"
                echo "   Файлов создано: $file_count"

                # Подсчет атак attempts. curl's -w "...%{http_code}" writes the
                # *resolved* numeric status, so the literal string "http_code"
                # never appears in output files — only "Status: <code>" or
                # "<label>: <code>" do. Matching just "http_code" always
                # counted 0, which is why sqlmap/ssrf/ldap-csrf showed
                # "Попыток атак: 0" here despite real traffic being sent.
                local attempts=0
                for file in "$result_dir"/*.txt; do
                    if [ -f "$file" ]; then
                        # grep -c always prints a count (even "0") and only
                        # exits non-zero on no match, so "|| echo 0" used to
                        # append a second line and break the arithmetic below.
                        local count=$(grep -cE 'Status: [0-9]{3}|: [0-9]{3}$' "$file" 2>/dev/null)
                        attempts=$((attempts + count))
                    fi
                done
                echo "   Попыток атак: $attempts"
                echo ""

                # Gate: 0 попыток трафика делает любой вывод об алертах/детекте
                # для этой категории бессмысленным (см. P2-8) — отмечаем явно,
                # вместо того чтобы молча включать её в общий "новых алертов".
                if [ "$attempts" -eq 0 ]; then
                    attack_gate_failed="$attack_gate_failed $result_dir"
                fi
            fi
        done

        echo "=== ATTACK TRAFFIC GATE ==="
        if [ -n "$attack_gate_failed" ]; then
            warn "Категории без реального трафика (0 попыток):$attack_gate_failed"
            echo "GATE: FAILED — для этих категорий 'новых алертов: 0' не является валидным результатом детекта:$attack_gate_failed"
            touch "$gate_flag_file"
        else
            log "✓ Все категории атак отправили трафик"
            echo "GATE: OK"
        fi
        echo ""

        # Каждый под-скрипт (sqlmap/bruteforce/ssrf/ldap-csrf-attacks.sh) пишет
        # собственный "GATE: FAILED"/"GATE: OK" в свой summary-*.txt, но раньше
        # итоговый отчёт этот статус не читал вовсе — секция могла напечатать
        # "GATE: FAILED" и итог всё равно бы завершился как успешный прогон
        # (см. P3-16 п.2). Собираем реальный провал из всех summary-файлов.
        echo "=== PER-SCRIPT GATES ==="
        for result_dir in sqlmap-results bruteforce-results ssrf-results ldap-csrf-results; do
            local summary
            summary=$(find "$result_dir" -maxdepth 1 -name 'summary-*.txt' 2>/dev/null | sort | tail -1)
            if [ -n "$summary" ] && [ -f "$summary" ]; then
                if grep -q '^GATE: FAILED' "$summary"; then
                    echo "  $result_dir: FAILED ($summary)"
                    touch "$gate_flag_file"
                elif grep -q 'GATE: OK' "$summary"; then
                    echo "  $result_dir: OK"
                else
                    echo "  $result_dir: UNKNOWN (no GATE line in $summary)"
                fi
            else
                echo "  $result_dir: NO SUMMARY FOUND"
            fi
        done
        echo ""

        echo "═══════════════════════════════════════════════════════════════"
        echo "ТОП НОВЫХ АЛЕРТОВ ПО ТИПАМ (дельта baseline → final по id)"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""

        local baseline_alerts_json="$RESULTS_DIR/baseline-alerts-$TIMESTAMP.json"
        local final_alerts_json="$RESULTS_DIR/final-alerts-$TIMESTAMP.json"

        # Дельта считается по множеству id алертов (final \ baseline), а не по
        # абсолютным count'ам из /api/v1/alerts — иначе "топ алертов" не сходится
        # с "новых алертов: N" выше, т.к. эндпоинт отдаёт весь текущий стор, а не
        # только события с начала прогона.
        if command -v jq &> /dev/null; then
            echo "=== ALERT CATEGORIES (new only) ==="
            jq -s '
                (.[0] // []) as $baseline |
                (.[1] // []) as $final |
                ($baseline | map(.id) | unique) as $baseline_ids |
                ($final | map(select(.id as $id | ($baseline_ids | index($id)) | not))) as $new |
                $new | group_by(.rule_id) | map({rule: .[0].rule_id, count: length}) | sort_by(.count) | reverse | .[:10] | .[] | "\(.rule): \(.count)"
            ' -r "$baseline_alerts_json" "$final_alerts_json" 2>/dev/null || echo "Не удалось разобрать алерты"
            echo ""
        fi

        echo "═══════════════════════════════════════════════════════════════"
        echo "ДЕТЕКТИРУЕМЫЕ ТИПЫ АТАК"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""

        # Уникальные rule_id среди новых (final \ baseline) алертов
        local detected=0
        if command -v jq &> /dev/null; then
            detected=$(jq -s '
                (.[0] // []) as $baseline |
                (.[1] // []) as $final |
                ($baseline | map(.id) | unique) as $baseline_ids |
                ($final | map(select(.id as $id | ($baseline_ids | index($id)) | not))) as $new |
                $new | map(.rule_id) | unique | length
            ' -r "$baseline_alerts_json" "$final_alerts_json" 2>/dev/null || echo 0)
        fi
        echo "Уникальных типов атак детектировано (новых): $detected"
        echo ""

        # Топ атак по severity (тоже только новые, для согласованности с "Новых: $new_alerts")
        if command -v jq &> /dev/null; then
            echo "=== BY SEVERITY (new only) ==="
            jq -s '
                (.[0] // []) as $baseline |
                (.[1] // []) as $final |
                ($baseline | map(.id) | unique) as $baseline_ids |
                ($final | map(select(.id as $id | ($baseline_ids | index($id)) | not))) as $new |
                $new | group_by(.severity) | map({severity: .[0].severity, count: length}) | .[] | "\(.severity): \(.count)"
            ' -r "$baseline_alerts_json" "$final_alerts_json" 2>/dev/null || echo "Не удалось разобрать severity"
            echo ""
        fi

        echo "═══════════════════════════════════════════════════════════════"
        echo "ВЕРДИКТ ПО attack-manifest.json (plan.md волна 1.5g, вопрос 8)"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""

        # Precision/recall against the known attacker comms recorded by each
        # sub-script (sqlmap-attacks.sh etc. via record_manifest). This
        # replaces having to manually cross-reference alert PIDs against
        # attack logs (as required for the run #4 writeup) — recall is the
        # fraction of manifest categories that produced at least one new
        # alert whose comm matches, precision is the fraction of new alerts
        # whose comm is an attacker comm from the manifest.
        local manifest_file="$MANIFEST_FILE"
        if [ -f "$manifest_file" ] && command -v jq &> /dev/null; then
            local attacker_comms
            attacker_comms=$(jq -c '[.[].comm] | unique' "$manifest_file" 2>/dev/null || echo '[]')
            echo "Известные comm атакующих процессов (из манифеста): $attacker_comms"
            echo ""

            jq -s --argjson comms "$attacker_comms" '
                (.[0] // []) as $baseline |
                (.[1] // []) as $final |
                ($baseline | map(.id) | unique) as $baseline_ids |
                ($final | map(select(.id as $id | ($baseline_ids | index($id)) | not))) as $new |
                ($new | length) as $new_total |
                ($new | map(select(.comm as $c | $comms | index($c))) | length) as $new_attacker |
                {
                    new_alerts_total: $new_total,
                    new_alerts_from_attacker_comm: $new_attacker,
                    precision: (if $new_total > 0 then ($new_attacker / $new_total) else null end)
                }
            ' -r "$baseline_alerts_json" "$final_alerts_json" 2>/dev/null || echo "Не удалось посчитать precision"
            echo ""

            jq -s --argjson manifest "$(jq -c '.' "$manifest_file" 2>/dev/null || echo '[]')" '
                (.[0] // []) as $baseline |
                (.[1] // []) as $final |
                ($baseline | map(.id) | unique) as $baseline_ids |
                ($final | map(select(.id as $id | ($baseline_ids | index($id)) | not))) as $new |
                ($new | map(.comm) | unique) as $new_comms |
                ($manifest | map(.category) | unique) as $categories |
                ($manifest | group_by(.category) | map({
                    category: .[0].category,
                    comm: .[0].comm,
                    detected: ((.[0].comm as $c | $new_comms | index($c)) != null)
                })) as $per_category |
                {
                    categories_total: ($categories | length),
                    categories_detected: ($per_category | map(select(.detected)) | length),
                    recall: (if ($categories | length) > 0 then (($per_category | map(select(.detected)) | length) / ($categories | length)) else null end),
                    per_category: $per_category
                }
            ' -r 2>/dev/null || echo "Не удалось посчитать recall"
            echo ""
        else
            warn "attack-manifest.json не найден — precision/recall по вердикту не посчитаны"
            echo "GATE: FAILED — attack-manifest.json отсутствует"
            touch "$gate_flag_file"
        fi

        echo "═══════════════════════════════════════════════════════════════"
        echo "FALSE POSITIVE ANALYSIS"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""

        # Предложение для FP анализа
        echo "Для анализа false positives:"
        echo "1. Проверьте $RESULTS_DIR/baseline-alerts-$TIMESTAMP.json"
        echo "2. Проверьте $RESULTS_DIR/final-alerts-$TIMESTAMP.json"
        echo "3. Используйте analyze-alerts.py для детального анализа"
        echo ""

        echo "═══════════════════════════════════════════════════════════════"
        echo "РЕКОМЕНДАЦИИ"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""

        if [ "$new_alerts" -lt 50 ]; then
            warn "⚠️  Детектировано мало новых алертов ($new_alerts)"
            echo "   → Проверьте конфигурацию правил ebpf-guard"
            echo "   → Убедитесь, что правила подходят для вашего тестового окружения"
        else
            log "✓ Детектировано $new_alerts новых алертов"
        fi

        if [ "$new_anomalies" -lt 10 ]; then
            warn "⚠️  Детектировано мало аномалий ($new_anomalies)"
            echo "   → Проверьте настройку profiler в config"
        else
            log "✓ Детектировано $new_anomalies аномалий"
        fi

        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        echo "ССЫЛКИ"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""
        echo "📊 Prometheus: http://${VPS_IP}:9090"
        echo "📈 Grafana: http://${VPS_IP}:3001 (admin/admin123)"
        echo "🔔 ebpf-guard Alerts API: $EBPF_GUARD_API/api/v1/alerts"
        echo "🏥 ebpf-guard Health: $EBPF_GUARD_API/health"
        echo ""

    } | tee "$report_file"

    log "Итоговый отчет сохранен: $report_file"

    # Также создадим JSON версию отчета
    local json_report="$RESULTS_DIR/FINAL-REPORT-$TIMESTAMP.json"
    if command -v jq &> /dev/null; then
        {
            echo "{"
            echo "  \"timestamp\": \"$TIMESTAMP\","
            echo "  \"date\": \"$(date -Iseconds)\","
            echo "  \"environment\": {"
            echo "    \"juice_shop_url\": \"$JUICE_SH_URL\","
            echo "    \"ebpf_guard_api\": \"$EBPF_GUARD_API\""
            echo "  },"
            echo "  \"metrics\": {"
            echo "    \"alerts\": {"
            echo "      \"before\": $baseline_alerts,"
            echo "      \"after\": $final_alerts,"
            echo "      \"new\": $new_alerts"
            echo "    },"
            echo "    \"events\": {"
            echo "      \"before\": $baseline_events,"
            echo "      \"after\": $final_events,"
            echo "      \"new\": $new_events"
            echo "    },"
            echo "    \"anomalies\": {"
            echo "      \"before\": $baseline_anomalies,"
            echo "      \"after\": $final_anomalies,"
            echo "      \"new\": $new_anomalies"
            echo "    }"
            echo "  }"
            echo "}"
        } > "$json_report"

        # Regression guard (P2-28): the JSON branch broke silently once before
        # (empty $baseline_alerts/$final_alerts interpolated as bare commas,
        # producing invalid JSON) while the text branch above kept printing
        # correct numbers, so the break went unnoticed until manual review.
        # Validate the file we just wrote before calling the run done.
        if jq empty "$json_report" 2>/dev/null; then
            log "JSON отчет сохранен: $json_report"
        else
            error "JSON отчет невалиден: $json_report — см. вывод jq ниже"
            jq empty "$json_report"
            touch "$gate_flag_file"
        fi
    fi
}

# Проверяет флаг, выставленный generate_final_report при провале любого
# gate (traffic gate или per-script gate), и завершает процесс ненулевым
# кодом — раньше провал печатался в отчёт, но exit code всегда был 0
# (см. P3-16 п.2), поэтому CI/операторы, смотрящие только на код возврата,
# не видели проваленный прогон.
check_final_gate() {
    local gate_flag_file="$RESULTS_DIR/.gate-failed-$TIMESTAMP"

    # run-gate.sh checks the six ЗАМЕР №1 thresholds from plan.md (потери,
    # dns growth, деградация, comm, JSON validity, детект жив) — a superset
    # of the traffic/script gates above. Its own FAIL also marks
    # gate_flag_file so check_final_gate's exit code reflects it too
    # (plan.md волна 1.5h, вопрос 12).
    if [ -f "$SCRIPT_DIR/run-gate.sh" ]; then
        bash "$SCRIPT_DIR/run-gate.sh" "$RESULTS_DIR" "$TIMESTAMP" || touch "$gate_flag_file"
        echo ""
    else
        warn "run-gate.sh не найден рядом с $0 — критерии замера №1 не проверены"
    fi

    if [ -f "$gate_flag_file" ]; then
        error "ATTACK TESTING GATE: FAILED — см. FINAL-REPORT-$TIMESTAMP.txt для деталей"
        return 1
    fi
    log "✓ ATTACK TESTING GATE: OK"
    return 0
}

# Главное меню
show_menu() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║     ebpf-guard SECURITY TESTING - MASTER MENU                 ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "1. Запустить все атаки (полный тест)"
    echo "2. Только SQLMap атаки"
    echo "3. Только Brute Force атаки"
    echo "4. Только SSRF атаки"
    echo "5. Только LDAP/CSRF атаки"
    echo "6. Проверить состояние сервисов"
    echo "7. Собрать текущие метрики"
    echo "8. Сгенерировать отчет"
    echo "9. Выход"
    echo ""
}

# Интерактивный режим
interactive_mode() {
    while true; do
        show_menu
        read -p "Выберите опцию [1-9]: " choice

        case $choice in
            1)
                check_services || continue
                get_baseline_metrics
                run_sqlmap_attacks
                run_bruteforce_attacks
                run_ssrf_attacks
                run_ldap_csrf_attacks
                get_final_metrics
                generate_final_report
                check_final_gate
                ;;
            2)
                check_services || continue
                run_sqlmap_attacks
                ;;
            3)
                check_services || continue
                run_bruteforce_attacks
                ;;
            4)
                check_services || continue
                run_ssrf_attacks
                ;;
            5)
                check_services || continue
                run_ldap_csrf_attacks
                ;;
            6)
                check_services
                ;;
            7)
                get_baseline_metrics
                log "Текущие метрики сохранены в $RESULTS_DIR"
                ;;
            8)
                generate_final_report
                check_final_gate
                ;;
            9)
                log "Выход..."
                exit 0
                ;;
            *)
                error "Неверный выбор"
                ;;
        esac
    done
}

# Режим полного запуска (без интерактива)
full_run() {
    log "==========================================="
    log "ПОЛНЫЙ ЗАПУСК ВСЕХ АТАК"
    log "==========================================="

    check_services || exit 1
    get_baseline_metrics
    run_sqlmap_attacks
    run_bruteforce_attacks
    run_ssrf_attacks
    run_ldap_csrf_attacks
    get_final_metrics
    generate_final_report

    log "==========================================="
    log "ВСЕ ТЕСТЫ ЗАВЕРШЕНЫ"
    log "==========================================="

    # check_final_gate returning 1 under "set -e" would abort before the log
    # lines above print — capture the result and exit after reporting instead
    # (see P3-16 п.2: exit code must reflect gate failure).
    check_final_gate || exit 1
}

# Главная точка входа
main() {
    cd "$SCRIPT_DIR"

    if [ "$1" = "--interactive" ] || [ "$1" = "-i" ]; then
        interactive_mode
    elif [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
        echo "Использование: $0 [опции]"
        echo ""
        echo "Опции:"
        echo "  -i, --interactive    Интерактивный режим с меню"
        echo "  -h, --help           Показать эту справку"
        echo ""
        echo "Без опций: запуск всех атак последовательно"
        exit 0
    else
        full_run
    fi
}

# Запуск
main "$@"
