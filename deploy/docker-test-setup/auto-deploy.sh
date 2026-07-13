#!/bin/bash
# Automatic Deployment and Load Testing Script
# This script sets up the VPS and runs load tests automatically

set -e

VPS_IP="${VPS_IP:?Set VPS_IP environment variable to your test VPS address}"
VPS_USER="${VPS_USER:-root}"
VPS_PASS="${VPS_PASS:?Set VPS_PASS environment variable (never hardcode credentials)}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() { echo -e "${GREEN}[$(date +'%H:%M:%S')]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

echo "=========================================="
echo "ebpf-guard Auto Deployment & Load Testing"
echo "=========================================="
echo ""

log "Step 1: Installing public key on VPS..."
log "Using sshpass for authentication..."

# Install sshpass if not available
if ! command -v sshpass &> /dev/null; then
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        sudo apt-get update -qq && sudo apt-get install -y sshpass
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        brew install hudochenkov/sshpass/sshpass
    else
        error "sshpass not found. Please install it manually"
        exit 1
    fi
fi

# SSH public key to authorize on the server. Set SSH_KEY env var to the
# contents of your local ~/.ssh/id_rsa.pub (never hardcode key material).
SSH_KEY="${SSH_KEY:?Set SSH_KEY environment variable to your public key contents, e.g. \$(cat ~/.ssh/id_rsa.pub)}"

sshpass -p "$VPS_PASS" ssh -o StrictHostKeyChecking=no "$VPS_USER@$VPS_IP" << EOF
mkdir -p ~/.ssh
chmod 700 ~/.ssh
echo '$SSH_KEY' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
echo "✓ SSH key installed"
EOF

if [ $? -eq 0 ]; then
    log "✓ SSH key installed successfully"
else
    error "Failed to install SSH key"
    exit 1
fi

log ""
log "Step 2: Testing SSH connection..."
if ssh -o StrictHostKeyChecking=no "$VPS_USER@$VPS_IP" "echo '✓ SSH connection successful'"; then
    log "✓ SSH key authentication working"
else
    error "SSH connection failed"
    exit 1
fi

log ""
log "Step 3: Installing dependencies on VPS..."
ssh "$VPS_USER@$VPS_IP" << 'EOF'
apt-get update -qq
apt-get install -y -qq wget git curl apache2-utils build-essential python3-pip 2>&1 | grep -v "Reading\|Building\|Selecting\|Preparing\|Unpacking\|Setting up" || true
echo "✓ Dependencies installed"
EOF

log ""
log "Step 4: Installing load testing tools..."
ssh "$VPS_USER@$VPS_IP" << 'EOF'
# Install wrk
cd /tmp
if [ ! -f /usr/local/bin/wrk ]; then
    wget -q https://github.com/wg/wrk/archive/refs/tags/4.2.0.tar.gz -O wrk.tar.gz
    tar -xzf wrk.tar.gz
    cd wrk-4.2.0 && make >/dev/null 2>&1
    mkdir -p /opt/wrk && cp -r . /opt/wrk/
    ln -sf /opt/wrk/wrk /usr/local/bin/wrk
    echo "✓ wrk installed"
else
    echo "✓ wrk already installed"
fi

# Install hey
if [ ! -f /usr/local/bin/hey ]; then
    wget -q https://github.com/rakyll/hey/releases/download/v0.1.4/hey_linux_amd64 -O hey
    chmod +x hey && mv hey /usr/local/bin/hey
    echo "✓ hey installed"
else
    echo "✓ hey already installed"
fi
EOF

log ""
log "Step 5: Setting up Docker..."
ssh "$VPS_USER@$VPS_IP" << 'EOF'
# Start Docker
systemctl start docker 2>/dev/null || true
systemctl enable docker 2>/dev/null || true

# Pull images
docker pull bkimminich/juice-shop:latest >/dev/null 2>&1 &
JUICE_PID=$!

docker pull prom/prometheus:latest >/dev/null 2>&1 &
PROM_PID=$!

docker pull grafana/grafana:latest >/dev/null 2>&1 &
GRAFANA_PID=$!

wait $JUICE_PID $PROM_PID $GRAFANA_PID 2>/dev/null || true

echo "✓ Docker images pulled"
EOF

log ""
log "Step 6: Starting services..."
ssh "$VPS_USER@$VPS_IP" << 'EOF'
# Stop existing containers
docker stop juice-shop prometheus grafana 2>/dev/null || true
docker rm juice-shop prometheus grafana 2>/dev/null || true

# Start Juice Shop
docker run -d --name juice-shop --restart unless-stopped -p 3000:3000 bkimminich/juice-shop:latest

# Start Prometheus
docker run -d --name prometheus --restart unless-stopped -p 9090:9090 prom/prometheus:latest

# Start Grafana
docker run -d --name grafana --restart unless-stopped -p 3001:3000 \
  -e GF_SECURITY_ADMIN_USER=admin \
  -e GF_SECURITY_ADMIN_PASSWORD=admin \
  grafana/grafana:latest

echo "Waiting for services to start..."
sleep 20

echo "=== Service Status ==="
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "juice-shop|prometheus|grafana"

echo ""
echo "=== Endpoint Tests ==="
echo -n "Juice Shop (3000): "
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000 && echo " ✓"

echo -n "Prometheus (9090): "
curl -s -o /dev/null -w "%{http_code}" http://localhost:9090 && echo " ✓"

echo -n "Grafana (3001): "
curl -s -o /dev/null -w "%{http_code}" http://localhost:3001 && echo " ✓"
EOF

log ""
log "Step 7: Running baseline load test..."
ssh "$VPS_USER@$VPS_IP" << 'EOF'
echo "=== Baseline Test (1 connection, 30s) ==="
wrk -t1 -c1 -d30s http://localhost:3000

echo ""
echo "=== Medium Load Test (10 connections, 30s) ==="
wrk -t2 -c10 -d30s http://localhost:3000

echo ""
echo "=== High Load Test (50 connections, 30s) ==="
wrk -t4 -c50 -d30s http://localhost:3000
EOF

log ""
log "=========================================="
log "✓ Deployment and testing complete!"
log "=========================================="
log ""
log "Access URLs:"
log "  Juice Shop:  http://$VPS_IP:3000"
log "  Prometheus:  http://$VPS_IP:9090"
log "  Grafana:     http://$VPS_IP:3001 (admin/admin)"
log ""
log "Next steps:"
log "  1. Check Grafana dashboard for metrics"
log "  2. Run extended tests: ssh $VPS_USER@$VPS_IP"
log "  3. Analyze results"
