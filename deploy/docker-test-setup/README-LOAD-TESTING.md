# ebpf-guard Load Testing Guide

Complete load testing infrastructure for testing ebpf-guard performance under various traffic patterns.

## Quick Start

### 1. Deploy to VPS

```bash
# From your local machine
cd deploy/docker-test-setup
./deploy-load-test.sh
```

This will:
- Install load testing tools (wrk, hey, vegeta)
- Deploy Docker monitoring stack (Prometheus, Grafana, Juice Shop)
- Configure ebpf-guard with test settings

### 2. Run Load Tests

```bash
# SSH into your VPS
ssh root@<VPS_IP>

# Navigate to test directory
cd /opt/ebpf-guard-test/load-test

# Run full test suite (takes ~10 minutes)
./run-load-tests.sh

# Run quick test (2 minutes)
QUICK_MODE=1 ./run-load-tests.sh
```

## Test Scenarios

The load test suite includes:

| Test | Description | Duration | Concurrency |
|------|-------------|----------|-------------|
| Test 1 | Baseline (low load) | 30s | 1 conn |
| Test 2 | Medium load | 30s | 10 conn |
| Test 3 | High load | 30s | 50 conn |
| Test 4 | Peak load | 30s | 100 conn |
| Test 5 | Sustained load | 5min | 20 conn |
| Test 6 | Mixed patterns | 1000 req | 10 conn |
| Test 7 | Attack simulation | 30s | 5 conn |

## Available Tools

### wrk
HTTP benchmarking tool with Lua scripting support.

```bash
wrk -t4 -c100 -d30s http://localhost:3000
```

### hey
HTTP load generator from Google.

```bash
hey -n 1000 -c 100 http://localhost:3000
```

### vegeta
HTTP load testing tool with attack visualization.

```bash
echo "GET http://localhost:3000" | vegeta attack -duration=30s | vegeta report
```

### Apache Bench (ab)
Simple HTTP benchmarking.

```bash
ab -n 1000 -c 100 http://localhost:3000/
```

## Custom Tests

### Test Specific Endpoint

```bash
TARGET_URL="http://localhost:3000/api/Products" ./run-load-tests.sh
```

### Custom Duration and Concurrency

```bash
DURATION=120 CONCURRENCY=200 ./run-load-tests.sh
```

### Test with Authentication

```bash
# Create endpoints.txt with your endpoints
cat > endpoints.txt << EOF
http://localhost:3000/api/user/authenticated
http://localhost:3000/api/basket/products
EOF

# Run with authentication token
hey -n 1000 -c 10 \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -m GET \
  http://localhost:3000/api/
```

## Analyzing Results

### Generate Report

```bash
# After tests complete
python3 analyze-load-test.py /opt/ebpf-load-test/results/20231215_143000 \
  -o my-report.md
```

### View Real-time Metrics

```bash
# ebpf-guard metrics
curl http://localhost:19090/metrics | grep ebpf_guard

# Key metrics to watch:
# - ebpf_guard_alerts_total
# - ebpf_guard_events_total
# - ebpf_guard_correlator_processing_duration_seconds
# - process_resident_memory_bytes
```

### Grafana Dashboards

Access Grafana at `http://YOUR_VPS:3001` (admin/admin123)

Import the pre-configured dashboard:
```bash
# Dashboard file is already provisioned
docker exec grafana ls /etc/grafana/provisioning/dashboards/
```

## Performance Indicators

### What to Monitor

1. **Throughput degradation**: RPS should scale linearly with concurrency
2. **Latency spikes**: P99 latency should remain < 2x baseline
3. **Alert rate**: Should correlate with attack patterns
4. **Memory usage**: Should stabilize, not grow continuously
5. **CPU usage**: Should not exceed 80% under normal load

### Common Issues

| Issue | Symptom | Fix |
|-------|---------|-----|
| Map full | Errors in logs | Increase `bpf.map_size_events` |
| High latency | P99 > 1000ms | Reduce `profiler.learning_period` |
| Memory leak | Continuous growth | Check event buffer sharding |
| Missing alerts | No detections | Check rule loading |

## Advanced Testing

### Custom Attack Simulation

Create a Lua script for wrk:

```lua
-- xss-attack.lua
request = function()
    local path = "/search"
    local body = "q=<script>alert('xss')</script>"
    return wrk.format("POST", path, nil, body)
end
```

Run it:
```bash
wrk -t2 -c10 -d30s -s xss-attack.lua http://localhost:3000
```

### Locust Swarm Mode

For distributed load testing:

```bash
# On master
locust -f loadtest.py --master --host=http://localhost:3000

# On workers
locust -f loadtest.py --worker --master-host=MASTER_IP
```

## Troubleshooting

### Connection Refused

```bash
# Check if services are running
docker ps | grep -E "ebpf-guard|juice-shop|prometheus"

# Check logs
docker logs ebpf-guard
docker logs juice-shop
```

### No Metrics Available

```bash
# Verify ebpf-guard metrics endpoint
curl -v http://localhost:19090/metrics

# Check if metrics are enabled in config
grep -A 5 "server:" config-test.yaml
```

### Permission Denied (eBPF)

```bash
# ebpf-guard must run with privileges
docker inspect ebpf-guard | grep -E "Privileged|CapAdd"
```

## Access URLs

After deployment:
- **Grafana**: http://<VPS_IP>:3001 (admin/admin123)
- **Prometheus**: http://<VPS_IP>:9090
- **Juice Shop**: http://<VPS_IP>:3000
- **ebpf-guard metrics**: http://<VPS_IP>:19090/metrics

## Next Steps

1. ✅ Deploy load testing infrastructure
2. 🔄 Run baseline tests
3. ⏳ Run sustained load tests
4. ⏳ Analyze detection rates by attack type
5. ⏳ Optimize based on findings
