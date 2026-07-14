#!/bin/bash
# Скрипт для развертывания attack-скриптов на VPS

set -e

VPS_IP="${VPS_IP:?Set VPS_IP environment variable to your test VPS address}"
VPS_HOST="root@${VPS_IP}"
VPS_DIR="/opt/security-testing"
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
    log "РАВЕРТЫВАНИЕ ATTACK SCRIPTS НА VPS"
    log "==========================================="
    log "VPS: $VPS_HOST"
    log "Target directory: $VPS_DIR"
    log ""

    # Создание директории на VPS
    log "Создание директории $VPS_DIR..."
    ssh -o StrictHostKeyChecking=no $VPS_HOST "mkdir -p $VPS_DIR/attacks"

    # Копирование скриптов
    log "Копирование attack скриптов..."
    scp -o StrictHostKeyChecking=no "$LOCAL_DIR/attacks/"*.sh $VPS_HOST:$VPS_DIR/attacks/
    scp -o StrictHostKeyChecking=no "$LOCAL_DIR/attacks/"*.py $VPS_HOST:$VPS_DIR/attacks/

    # Установка прав на выполнение
    log "Установка прав на выполнение..."
    ssh -o StrictHostKeyChecking=no $VPS_HOST "chmod +x $VPS_DIR/attacks/*.sh"

    # Установка зависимостей
    log "Проверка зависимостей на VPS..."
    ssh -o StrictHostKeyChecking=no $VPS_HOST "
        # Проверка sqlmap
        if ! command -v sqlmap &> /dev/null; then
            echo 'sqlmap не установлен. Установка...'
            apt-get update && apt-get install -y sqlmap
        fi

        # Проверка Python3
        if ! command -v python3 &> /dev/null; then
            echo 'Python3 не установлен'
        fi
    "

    log "==========================================="
    log "РАВЕРТЫВАНИЕ ЗАВЕРШЕНО"
    log "==========================================="
    log ""
    log "Для запуска тестов:"
    log "  ssh $VPS_HOST"
    log "  cd $VPS_DIR/attacks"
    log "  ./run-all-attacks.sh --help"
    log ""
    log "Для анализа результатов:"
    log "  python3 analyze-alerts.py --help"
}

main "$@"
