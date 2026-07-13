#!/bin/bash
# Скрипт для развертывания Grafana дашборда и Prometheus правил

set -e

VPS_IP="${VPS_IP:?Set VPS_IP environment variable to your test VPS address}"
VPS_HOST="root@${VPS_IP}"
LOCAL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

main() {
    log "==========================================="
    log "РАВЕРТЫВАНИЕ MONITORING ДЛЯ SECURITY TESTING"
    log "==========================================="

    # Копирование дашборда
    log "Копирование Grafana дашборда..."
    scp -o StrictHostKeyChecking=no "$LOCAL_DIR/ebpf-guard-security-dashboard.json" $VPS_HOST:/tmp/

    # Импорт дашборда в Grafana
    log "Импорт дашборда в Grafana..."
    ssh -o StrictHostKeyChecking=no $VPS_HOST "
        # Используем Grafana API для импорта дашборда
        DASHBOARD_CONTENT=\$(cat /tmp/ebpf-guard-security-dashboard.json)

        # Импорт через API
        curl -s -X POST \
            -H 'Content-Type: application/json' \
            -d '{\"dashboard\": '\$DASHBOARD_CONTENT', \"overwrite\": true, \"message\": \"Security Testing Dashboard\"}' \
            http://admin:admin123@localhost:3001/api/dashboards/db

        echo 'Dashboard импортирован'
    "

    # Копирование Prometheus правил
    log "Копирование Prometheus alert rules..."
    scp -o StrictHostKeyChecking=no "$LOCAL_DIR/alert-rules.yml" $VPS_HOST:/tmp/

    # Настройка Prometheus для использования правил
    log "Настройка Prometheus..."
    ssh -o StrictHostKeyChecking=no $VPS_HOST "
        # Копирование правил в Prometheus контейнер
        docker cp /tmp/alert-rules.yml prometheus:/etc/prometheus/alert-rules.yml

        # Обновление Prometheus конфига для загрузки правил
        docker exec prometheus sh -c '
            if ! grep -q \"alert-rules.yml\" /etc/prometheus/prometheus.yml; then
                echo \"rule_files:\" >> /etc/prometheus/prometheus.yml
                echo \"  - '/etc/prometheus/alert-rules.yml'\" >> /etc/prometheus/prometheus.yml
            fi
        '

        # Перезапуск Prometheus
        docker restart prometheus

        echo 'Prometheus rules настроены'
    "

    log "==========================================="
    log "MONITORING РАЗВЕРНУТ"
    log "==========================================="
    log ""
    log "Grafana Dashboard: http://${VPS_IP}:3001"
    log "Prometheus: http://${VPS_IP}:9090"
    log ""
    log "Для просмотра дашборда:"
    log "  1. Откройте http://${VPS_IP}:3001"
    log "  2. Login: admin / admin123"
    log "  3. Найдите дашборд 'ebpf-guard Security Testing'"
}

main "$@"
