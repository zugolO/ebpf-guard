#!/bin/bash
# Master скрипт для запуска всех атак против Juice Shop
# Запускает все типы атак последовательно и собирает результаты

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VPS_IP="${VPS_IP:-localhost}"
JUICE_SH_URL="http://${VPS_IP}:3000"
EBPF_GUARD_API="http://${VPS_IP}:19090"
RESULTS_DIR="./attack-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

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
    if curl -s -o /dev/null -w "%{http_code}" "$EBPF_GUARD_API/health" | grep -q "200"; then
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

    curl -s "$EBPF_GUARD_API/metrics" > "$RESULTS_DIR/baseline-metrics-$TIMESTAMP.txt"
    curl -s "$EBPF_GUARD_API/alerts" > "$RESULTS_DIR/baseline-alerts-$TIMESTAMP.json"
    curl -s "$EBPF_GUARD_API/health" > "$RESULTS_DIR/baseline-health-$TIMESTAMP.json"
    curl -s "$EBPF_GUARD_API/debug/state" > "$RESULTS_DIR/baseline-state-$TIMESTAMP.json"

    # Подсчет начальных алертов
    if command -v jq &> /dev/null; then
        local alert_count=$(curl -s "$EBPF_GUARD_API/alerts" | jq '. | length' 2>/dev/null || echo 0)
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

    curl -s "$EBPF_GUARD_API/metrics" > "$RESULTS_DIR/final-metrics-$TIMESTAMP.txt"
    curl -s "$EBPF_GUARD_API/alerts" > "$RESULTS_DIR/final-alerts-$TIMESTAMP.json"
    curl -s "$EBPF_GUARD_API/health" > "$RESULTS_DIR/final-health-$TIMESTAMP.json"
    curl -s "$EBPF_GUARD_API/debug/state" > "$RESULTS_DIR/final-state-$TIMESTAMP.json"

    echo ""
}

# Генерация итогового отчета
generate_final_report() {
    log "==========================================="
    log "ГЕНЕРАЦИЯ ИТОГОВОГО ОТЧЕТА"
    log "==========================================="

    local report_file="$RESULTS_DIR/FINAL-REPORT-$TIMESTAMP.txt"

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

        echo "═══════════════════════════════════════════════════════════════"
        echo "СТАТИСТИКА ПО ТИПАМ АТАК"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""

        # Статистика по результатам
        for result_dir in sqlmap-results bruteforce-results ssrf-results ldap-csrf-results; do
            if [ -d "$result_dir" ]; then
                local file_count=$(find "$result_dir" -type f | wc -l)
                echo "📁 $result_dir:"
                echo "   Файлов создано: $file_count"

                # Подсчет атак attempts
                local attempts=0
                for file in "$result_dir"/*.txt; do
                    if [ -f "$file" ]; then
                        local count=$(grep -c "http_code\|Status:" "$file" 2>/dev/null || echo 0)
                        attempts=$((attempts + count))
                    fi
                done
                echo "   Попыток атак: $attempts"
                echo ""
            fi
        done

        echo "═══════════════════════════════════════════════════════════════"
        echo "ТОП АЛЕРТОВ ПО ТИПАМ"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""

        # Анализ алертов по категориям
        if command -v jq &> /dev/null; then
            echo "=== ALERT CATEGORIES ==="
            curl -s "$EBPF_GUARD_API/alerts" | jq -r 'group_by(.rule_id) | map({rule: .[0].rule_id, count: length}) | sort_by(.count) | reverse | .[:10] | .[] | "\(.rule): \(.count)"' 2>/dev/null || echo "Не удалось разобрать алерты"
            echo ""
        fi

        echo "═══════════════════════════════════════════════════════════════"
        echo "ДЕТЕКТИРУЕМЫЕ ТИПЫ АТАК"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""

        # Анализ того, что было детектировано
        local detected=$(curl -s "$EBPF_GUARD_API/alerts" | grep -oE '"rule_id":"[^"]+' | cut -d'"' -f4 | sort -u | wc -l)
        echo "Уникальных типов атак детектировано: $detected"
        echo ""

        # Топ атак по severity
        if command -v jq &> /dev/null; then
            echo "=== BY SEVERITY ==="
            curl -s "$EBPF_GUARD_API/alerts" | jq -r 'group_by(.severity) | map({severity: .[0].severity, count: length}) | .[] | "\(.severity): \(.count)"' 2>/dev/null || echo "Не удалось разобрать severity"
            echo ""
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
        echo "🔔 ebpf-guard Alerts API: $EBPF_GUARD_API/alerts"
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
        log "JSON отчет сохранен: $json_report"
    fi
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
