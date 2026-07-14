#!/bin/bash
# One-Click Load Testing Setup for ebpf-guard
# Run this directly on your VPS: curl -sL ... | bash

set -e

echo "=========================================="
echo "ebpf-guard Load Testing - One-Click Setup"
echo "=========================================="
echo ""

# Configuration
PROJECT_DIR="/opt/ebpf-guard-test"
RESULTS_DIR="/opt/ebpf-load-test/results"

echo "Step 1: Installing dependencies..."
apt-get update -qq
apt-get install -y -qq wget git curl apache2-utils build-essential python3-pip docker.io docker-compose 2>&1 | grep -v "Reading\|Building\|Selecting\|Preparing\|Unpacking\|Setting up" || echo "Dependencies installed"

echo "Step 2: Installing wrk..."
cd /tmp
wget -q https://github.com/wg/wrk/archive/refs/tags/4.2.0.tar.gz -O wrk.tar.gz
tar -xzf wrk.tar.gz
cd wrk-4.2.0 && make >/dev/null 2>&1
mkdir -p /opt/wrk && cp -r . /opt/wrk/
ln -sf /opt/wrk/wrk /usr/local/bin/wrk
echo "✓ wrk installed"

echo "Step 3: Installing hey..."
wget -q https://github.com/rakyll/hey/releases/download/v0.1.4/hey_linux_amd64 -O hey
chmod +x hey && mv hey /usr/local/bin/hey
echo "✓ hey installed"

echo "Step 4: Creating project directory..."
mkdir -p $PROJECT_DIR $RESULTS_DIR
cd $PROJECT_DIR

echo "Step 5: Starting Docker services..."
systemctl start docker >/dev/null 2>&1 || true
systemctl enable docker >/dev/null 2>&1 || true

# Pull and start Juice Shop
docker pull bkimminich/juice-shop:latest >/dev/null 2>&1 &
JUICE_PID=$!

# Pull monitoring stack
docker pull prom/prometheus:latest >/dev/null 2>&1 &
PROM_PID=$!

docker pull grafana/grafana:latest >/dev/null 2>&1 &
GRAFANA_PID=$!

wait $JUICE_PID $PROM_PID $GRAFANA_PID 2>/dev/null || true

echo "Step 6: Starting containers..."
docker stop juice-shop prometheus grafana ebpf-guard 2>/dev/null || true
docker rm juice-shop prometheus grafana ebpf-guard 2>/dev/null || true

docker run -d --name juice-shop --restart unless-stopped -p 3000:3000 bkimminich/juice-shop:latest
docker run -d --name prometheus --restart unless-stopped -p 9090:9090 prom/prometheus:latest
docker run -d --name grafana --restart unless-stopped -p 3001:3000 \
  -e GF_SECURITY_ADMIN_USER=admin \
  -e GF_SECURITY_ADMIN_PASSWORD=admin \
  grafana/grafana:latest

echo "Step 7: Waiting for services to start..."
sleep 15

echo ""
echo "=========================================="
echo "✓ Setup Complete!"
echo "=========================================="
echo ""
echo "Checking services..."
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "juice-shop|prometheus|grafana"

echo ""
echo "Testing endpoints..."
echo -n "Juice Shop: "
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000 && echo " ✓" || echo " ✗"
echo -n "Prometheus: "
curl -s -o /dev/null -w "%{http_code}" http://localhost:9090 && echo " ✓" || echo " ✗"
echo -n "Grafana: "
curl -s -o /dev/null -w "%{http_code}" http://localhost:3001 && echo " ✓" || echo " ✗"

echo ""
echo "=========================================="
echo "Ready to test!"
echo "=========================================="
echo ""
echo "Available commands:"
echo "  wrk -t1 -c1 -d10s http://localhost:3000          # Quick test"
echo "  wrk -t4 -c50 -d30s http://localhost:3000         # High load test"
echo "  hey -n 1000 -c 100 http://localhost:3000        # Alternative tool"
echo ""
echo "Access URLs:"
echo "  Juice Shop:  http://$(hostname -I | awk '{print $1}'):3000"
echo "  Prometheus:  http://$(hostname -I | awk '{print $1}'):9090"
echo "  Grafana:     http://$(hostname -I | awk '{print $1}'):3001 (admin/admin)"
echo ""
