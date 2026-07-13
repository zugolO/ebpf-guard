#!/bin/bash
# Load Testing Setup for ebpf-guard
# This script installs load testing tools and prepares the environment

set -e

echo "=== ebpf-guard Load Testing Setup ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (required for load testing tools installation)"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Cannot detect OS"
    exit 1
fi

echo "Detected OS: $OS"
echo ""

# Install dependencies based on OS
case $OS in
    ubuntu|debian)
        echo "Installing dependencies for Ubuntu/Debian..."
        apt-get update
        apt-get install -y \
            wget \
            build-essential \
            git \
            curl \
            httping \
            apache2-utils \
            python3 \
            python3-pip
        ;;
    centos|rhel|fedora)
        echo "Installing dependencies for CentOS/RHEL/Fedora..."
        yum install -y \
            wget \
            gcc \
            make \
            git \
            curl \
            httping \
            httpd-tools \
            python3 \
            python3-pip
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

echo ""
echo "=== Installing wrk ==="
WRK_VERSION="4.2.0"
if [ ! -d /opt/wrk ]; then
    cd /tmp
    wget -q https://github.com/wg/wrk/archive/refs/tags/${WRK_VERSION}.tar.gz -O wrk.tar.gz
    tar -xzf wrk.tar.gz
    cd wrk-${WRK_VERSION}
    make
    cp -r /tmp/wrk-${WRK_VERSION} /opt/wrk
    ln -sf /opt/wrk/wrk /usr/local/bin/wrk
    echo "✓ wrk installed to /usr/local/bin/wrk"
else
    echo "✓ wrk already installed"
fi

echo ""
echo "=== Installing hey ==="
if [ ! -f /usr/local/bin/hey ]; then
    cd /tmp
    wget -q https://github.com/rakyll/hey/releases/download/v0.1.4/hey_linux_amd64 -O hey
    chmod +x hey
    mv hey /usr/local/bin/hey
    echo "✓ hey installed to /usr/local/bin/hey"
else
    echo "✓ hey already installed"
fi

echo ""
echo "=== Installing vegeta (for HTTP load testing) ==="
if [ ! -f /usr/local/bin/vegeta ]; then
    cd /tmp
    wget -q https://github.com/tsenart/vegeta/releases/download/v12.8.0/vegeta-v12.8.0-linux-amd64.tar.gz -O vegeta.tar.gz
    tar -xzf vegeta.tar.gz
    mv vegeta /usr/local/bin/vegeta
    echo "✓ vegeta installed"
else
    echo "✓ vegeta already installed"
fi

echo ""
echo "=== Installing Python stress testing tools ==="
pip3 install -q \
    locust \
    pyyaml \
    requests \
    matplotlib || echo "Some Python packages may have failed"

echo ""
echo "=== Verifying installations ==="
echo "wrk: $(which wrk) $(wrk --version 2>&1 | head -1 || echo 'installed')"
echo "hey: $(which hey)"
echo "vegeta: $(which vegeta)"
echo "ab: $(which ab)"
echo "locust: $(which locust 2>/dev/null || echo 'not found')"

echo ""
echo "=== Creating load test results directory ==="
mkdir -p /opt/ebpf-load-test/results
mkdir -p /opt/ebpf-load-test/logs

echo ""
echo "✓ Load testing setup complete!"
echo ""
echo "Available tools:"
echo "  - wrk: /usr/local/bin/wrk"
echo "  - hey: /usr/local/bin/hey"
echo "  - vegeta: /usr/local/bin/vegeta"
echo "  - ab (Apache Bench): $(which ab)"
echo ""
echo "Next steps:"
echo "  1. Deploy target application (Juice Shop)"
echo "  2. Run load tests with ./run-load-tests.sh"
echo ""
