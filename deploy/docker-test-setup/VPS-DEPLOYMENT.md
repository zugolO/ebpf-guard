# Quick Start: VPS Load Testing Setup

> Replace `<VPS_IP>` and `<VPS_PASSWORD>` below with your own test VPS
> credentials. Never commit real credentials to this file or the repo -
> export them as `VPS_IP` / `VPS_PASSWORD` environment variables instead
> when using the accompanying scripts.

## Your VPS Details
- **IP**: `<VPS_IP>` (set to your VPS address)
- **User**: root
- **Password**: `<VPS_PASSWORD>` (set to your VPS password, do not commit)

## Step 1: Connect to VPS

```bash
# On Windows (PowerShell)
ssh root@<VPS_IP>
# Enter password: <VPS_PASSWORD>

# Or with PuTTY
# Host: <VPS_IP>
# Port: 22
# User: root
# Password: <VPS_PASSWORD>
```

## Step 2: Prepare Server (Run on VPS)

```bash
# Update system
apt-get update && apt-get upgrade -y

# Install Docker
curl -fsSL https://get.docker.com | sh
systemctl start docker
systemctl enable docker

# Install docker-compose
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Create project directory
mkdir -p /opt/ebpf-guard-test
cd /opt/ebpf-guard-test
```

## Step 3: Install Load Testing Tools (Run on VPS)

```bash
# Install dependencies
apt-get install -y wget git curl apache2-utils build-essential python3-pip

# Install wrk
cd /tmp
wget -q https://github.com/wg/wrk/archive/refs/tags/4.2.0.tar.gz -O wrk.tar.gz
tar -xzf wrk.tar.gz
cd wrk-4.2.0
make
mkdir -p /opt/wrk
cp -r . /opt/wrk/
ln -sf /opt/wrk/wrk /usr/local/bin/wrk

# Install hey
cd /tmp
wget -q https://github.com/rakyll/hey/releases/download/v0.1.4/hey_linux_amd64 -O hey
chmod +x hey
mv hey /usr/local/bin/hey

# Verify installations
wrk --version
hey version
```

## Step 4: Upload Files (Run on Local Machine)

```bash
# From your ebpf-guard project directory
cd d:/vs/ebpf-guard/deploy/docker-test-setup

# Upload scripts (use scp or WinSCP)
scp -r * root@<VPS_IP>:/opt/ebpf-guard-test/
```

## Step 5: Start Services (Run on VPS)

```bash
cd /opt/ebpf-guard-test

# If you have docker-compose.yml from the upload
docker-compose up -d

# Or manually pull images
docker pull bkimminich/juice-shop:latest
docker pull prom/prometheus:latest
docker pull grafana/grafana:latest

# Start Juice Shop (target application)
docker run -d --name juice-shop -p 3000:3000 bkimminich/juice-shop:latest

# Start Prometheus
docker run -d --name prometheus -p 9090:9090 \
  -v $(pwd)/prometheus.yml:/etc/prometheus/prometheus.yml \
  prom/prometheus:latest

# Start Grafana
docker run -d --name grafana -p 3001:3000 \
  -e GF_SECURITY_ADMIN_USER=admin \
  -e GF_SECURITY_ADMIN_PASSWORD=admin \
  grafana/grafana:latest
```

## Step 6: Verify Setup (Run on VPS)

```bash
# Check containers are running
docker ps

# Test Juice Shop
curl -I http://localhost:3000

# Test Prometheus
curl -I http://localhost:9090

# Test Grafana
curl -I http://localhost:3000
```

## Step 7: Run Load Tests (Run on VPS)

```bash
cd /opt/ebpf-guard-test

# Quick test (2 minutes)
export TARGET_URL="http://localhost:3000"
export QUICK_MODE=1
bash run-load-tests.sh

# Full test suite (10+ minutes)
unset QUICK_MODE
bash run-load-tests.sh

# With custom settings
DURATION=60 CONCURRENCY=50 bash run-load-tests.sh
```

## Step 8: View Results

```bash
# Results are saved in
ls -lh /opt/ebpf-load-test/results/

# View latest test
cat /opt/ebpf-load-test/results/*/summary.md
```

## Access URLs (From Your Browser)

- **Juice Shop**: http://<VPS_IP>:3000
- **Grafana**: http://<VPS_IP>:3001 (admin/admin)
- **Prometheus**: http://<VPS_IP>:9090

## Troubleshooting

### Docker not running
```bash
systemctl status docker
systemctl start docker
```

### Port conflicts
```bash
# Check what's using the port
netstat -tulpn | grep -E "3000|3001|9090"

# Stop conflicting service
systemctl stop nginx  # if nginx is using port 3000
```

### Connection refused
```bash
# Check firewall
ufw status
ufw allow 3000/tcp
ufw allow 3001/tcp
ufw allow 9090/tcp
```

### Out of memory
```bash
# Check available memory
free -h

# Add swap if needed
fallocate -l 2G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
```

## Next Steps

After deployment and initial tests:

1. Run baseline tests
2. Analyze detection rates
3. Review Grafana dashboards
4. Generate performance report
5. Identify bottlenecks

## Quick Test Commands

```bash
# Test Juice Shop is responding
wrk -t1 -c1 -d10s http://localhost:3000

# Test with 50 concurrent users
wrk -t4 -c50 -d30s http://localhost:3000

# Test specific endpoint
wrk -t2 -c10 -d30s http://localhost:3000/rest/user/login
```
