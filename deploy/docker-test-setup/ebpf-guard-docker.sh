#!/bin/bash
# Скрипт для запуска ebpf-guard на VPS с Docker
# ВАЖНО: ebpf-guard должен запускаться на ХОСТЕ, не в контейнере
# потому что eBPF требует доступ к kernel facilities

set -e

echo "=== Настройка ebpf-guard на VPS для тестирования ==="

# 1. Проверка root
if [ "$EUID" -ne 0 ]; then
    echo "Пожалуйста, запустите с sudo"
    exit 1
fi

# 2. Установка зависимостей
echo "Установка зависимостей..."
apt-get update
apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    "linux-headers-$(uname -r)" \
    linux-tools-common \
    linux-tools-generic \
    build-essential \
    git \
    wget
# Exact-kernel bpftool package isn't always available on VPS/cloud kernels
# (generic vs cloud-specific build); linux-tools-generic above is enough.
apt-get install -y "linux-tools-$(uname -r)" 2>/dev/null || true

# make generate ищет команду `clang` в PATH; если дистрибутив ставит
# только версионные clang-N/llvm-strip-N, добавляем алиасы.
if ! command -v clang &>/dev/null; then
    CLANG_BIN=$(ls /usr/bin/clang-* 2>/dev/null | sort -V | tail -1)
    [ -n "$CLANG_BIN" ] && update-alternatives --install /usr/bin/clang clang "$CLANG_BIN" 100
fi
if ! command -v llvm-strip &>/dev/null; then
    STRIP_BIN=$(ls /usr/bin/llvm-strip-* 2>/dev/null | sort -V | tail -1)
    [ -n "$STRIP_BIN" ] && update-alternatives --install /usr/bin/llvm-strip llvm-strip "$STRIP_BIN" 100
fi
command -v clang &>/dev/null || { echo "Error: clang not found after install"; exit 1; }

# 3. Установка Go 1.26 (соответствует go.mod и CI)
echo "Установка Go 1.26.5..."
if ! go version 2>/dev/null | grep -qE "go1\.(2[6-9]|[3-9][0-9])"; then
    wget -q https://go.dev/dl/go1.26.5.linux-amd64.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf go1.26.5.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /root/.bashrc
    export PATH=$PATH:/usr/local/go/bin
fi

# 4. Клонирование ebpf-guard (если нет)
if [ ! -d "/opt/ebpf-guard" ]; then
    echo "Клонирование ebpf-guard..."
    git clone https://github.com/zugolO/ebpf-guard.git /opt/ebpf-guard
    cd /opt/ebpf-guard
else
    echo "Обновление ebpf-guard..."
    cd /opt/ebpf-guard
    git pull
fi

# 5. Создание директорий (до сборки — так они точно есть перед первым запуском,
#    даже если сборка/запуск делаются вручную по шагам позже)
mkdir -p /var/log/ebpf-guard
mkdir -p /var/lib/ebpf-guard
mkdir -p /opt/ebpf-guard/rules

# 6. Сборка
echo "Сборка ebpf-guard..."
make generate
make build

# 7. Конфигурация для тестирования
cat > /opt/ebpf-guard/config-test.yaml << 'EOF'
config_version: "v0.1"

server:
  bind_address: ":19090"
  metrics_path: "/metrics"
  health_path: "/health"

bpf:
  map_sizes:
    events: 32768
    processes: 8192
    connections: 16384
  sampling:
    enabled: true
    syscall_rate: 1
    network_rate: 1
    file_rate: 1

rules:
  path: "/opt/ebpf-guard/rules/"
  hot_reload: true

profiler:
  enabled: true
  learning_period: 300
  min_learning_samples: 50
  anomaly_threshold: 0.7
  max_tracked_pids: 2048

enforcement:
  enabled: true
  block_backend: log        # Начинаем с log (dry run)
  dry_run: true             # Сначала dry run для тестов
  enable_block: true
  enable_kill: true
  enable_throttle: true
  audit_log: "/var/log/ebpf-guard/audit.jsonl"

alerting:
  enabled: true
  alertmanager:
    url: ""

store:
  backend: sqlite
  sqlite:
    path: "/var/lib/ebpf-guard/test-events.db"

collectors:
  dns:
    enabled: true
  tls:
    enabled: false

notifications:
  unix_socket:
    enabled: true
    path: /run/ebpf-guard/alerts.sock

kubernetes:
  enabled: false
EOF

echo "=== Установка завершена ==="
echo ""
echo "Следующие шаги:"
echo "1. Запустите Docker Compose с Juice Shop:"
echo "   docker-compose up -d"
echo ""
echo "2. Запустите ebpf-guard:"
echo "   cd /opt/ebpf-guard"
echo "   sudo ./build/ebpf-guard --config=config-test.yaml --log-level=debug"
echo ""
echo "3. Проверьте работу:"
echo "   curl http://localhost:3000  # Juice Shop"
echo "   curl http://localhost:19090/metrics  # ebpf-guard metrics"
echo "   curl http://localhost:19090/health   # health check"
