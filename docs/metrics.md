# ebpf-guard Metrics Reference

Complete reference for all Prometheus metrics exported by ebpf-guard.

## Overview

ebpf-guard exposes metrics at the `/metrics` endpoint (configurable via `server.metrics_path`). By default, authentication is **enabled** and requires a Bearer token.

## Authentication

### Default Behavior

- If `auth.bearer_token` is configured in the config file, that token is used
- If `auth.enabled` is `true` but no token is configured, a random 32-byte token is generated at startup and logged once at `WARN` level
- To disable authentication (not recommended for production), set `auth.enabled: false`

### Prometheus Scrape Configuration

```yaml
scrape_configs:
  - job_name: 'ebpf-guard'
    static_configs:
      - targets: ['ebpf-guard:9090']
    authorization:
      type: Bearer
      credentials: '<your-token-here>'
    # Or use credentials_file for better security
    # authorization:
    #   type: Bearer
    #   credentials_file: /etc/prometheus/ebpf-guard-token
```

## Metrics

### Event Metrics

#### `ebpf_guard_events_total`

| Attribute | Value |
|-----------|-------|
| **Type** | Counter |
| **Labels** | `type` (syscall\|network\|file), `pod`, `namespace` |
| **Description** | Total number of kernel events processed |

**Example:**
```promql
# Events per second by type
rate(ebpf_guard_events_total[5m])

# Events from a specific namespace
ebpf_guard_events_total{namespace="production"}
```

---

#### `ebpf_guard_events_dropped_total`

| Attribute | Value |
|-----------|-------|
| **Type** | Counter |
| **Labels** | `collector`, `reason` |
| **Description** | Total number of events dropped by reason |

**Example:**
```promql
# Total dropped events by collector
sum by (collector) (ebpf_guard_events_dropped_total)
```

---

### Alert Metrics

#### `ebpf_guard_alerts_total`

| Attribute | Value |
|-----------|-------|
| **Type** | Counter |
| **Labels** | `rule_id`, `severity` (warning\|critical) |
| **Description** | Total number of security alerts generated |

**Example Alert:**
```yaml
# Alert on high alert rate
groups:
  - name: ebpf-guard
    rules:
      - alert: HighSecurityAlertRate
        expr: rate(ebpf_guard_alerts_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High rate of security alerts"
```

---

### Profiler Metrics

#### `ebpf_guard_profiler_anomaly_score`

| Attribute | Value |
|-----------|-------|
| **Type** | Gauge |
| **Labels** | `pid`, `comm` (process name) |
| **Description** | Current anomaly score for each process (0.0-1.0) |

**Cardinality Limit:** 10,000 unique PID/comm combinations (configurable via `MaxAnomalyScoreSeries`)

**Example:**
```promql
# Processes with high anomaly scores
ebpf_guard_profiler_anomaly_score > 0.8

# Top 10 anomalous processes
topk(10, ebpf_guard_profiler_anomaly_score)
```

---

#### `ebpf_guard_learning_progress`

| Attribute | Value |
|-----------|-------|
| **Type** | Gauge |
| **Labels** | None |
| **Description** | Progress of the behavioral learning phase (0.0-1.0) |

**Example:**
```promql
# Alert when learning is complete
- name: LearningComplete
  rules:
    - alert: LearningComplete
      expr: ebpf_guard_learning_progress >= 1.0
      labels:
        severity: info
```

---

### BPF Metrics

#### `ebpf_guard_bpf_map_entries`

| Attribute | Value |
|-----------|-------|
| **Type** | Gauge |
| **Labels** | `map_name` |
| **Description** | Current number of entries in BPF maps |

**Example:**
```promql
# BPF map utilization
ebpf_guard_bpf_map_entries / 65536
```

---

### Collector Metrics

#### `ebpf_guard_collector_up`

| Attribute | Value |
|-----------|-------|
| **Type** | Gauge |
| **Labels** | `collector` (syscall\|network\|fileaccess) |
| **Description** | Whether the collector is up (1) or down/stub (0) |

**Example:**
```promql
# Alert when collector is down
- name: CollectorHealth
  rules:
    - alert: CollectorDown
      expr: ebpf_guard_collector_up == 0
      for: 1m
      labels:
        severity: critical
```

---

### System Metrics

#### `ebpf_guard_log_lines_total`

| Attribute | Value |
|-----------|-------|
| **Type** | Counter |
| **Labels** | `level` (debug\|info\|warn\|error) |
| **Description** | Total number of log lines by level |

---

#### `ebpf_guard_correlation_duration_seconds`

| Attribute | Value |
|-----------|-------|
| **Type** | Histogram |
| **Labels** | None |
| **Description** | Latency of event correlation in seconds |

**Buckets:** Default Prometheus buckets (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10)

**Example:**
```promql
# 99th percentile correlation latency
histogram_quantile(0.99, rate(ebpf_guard_correlation_duration_seconds_bucket[5m]))
```

---

## Metric Relabeling

For high-cardinality environments, consider relabeling:

```yaml
metric_relabel_configs:
  # Drop pod label for high-cardinality metrics if not needed
  - source_labels: [__name__]
    regex: 'ebpf_guard_events_total'
    target_label: pod
    replacement: ''
```

## Performance Considerations

1. **Anomaly Score Cardinality:** Limited to 10,000 series to prevent Prometheus OOM. Low-scoring entries are evicted when the limit is reached.

2. **Event Labels:** The `pod` and `namespace` labels are only populated when Kubernetes enrichment is enabled and the event can be associated with a pod.

3. **Dropped Events:** Monitor `ebpf_guard_events_dropped_total` to detect overload conditions.

## Troubleshooting

### Missing Metrics

1. Check if authentication is required:
   ```bash
   curl -H "Authorization: Bearer <token>" http://localhost:9090/metrics
   ```

2. Verify the collector is up:
   ```bash
   curl -H "Authorization: Bearer <token>" http://localhost:9090/health/ready
   ```

3. Check for BPF map exhaustion:
   ```promql
   ebpf_guard_bpf_map_entries / 65536 > 0.9
   ```

### High Cardinality

If Prometheus is using too much memory:

1. Check anomaly score series count:
   ```promql
   count(ebpf_guard_profiler_anomaly_score)
   ```

2. Verify cleanup is running (should be < 10,000)

3. Consider reducing `profiler.profile_ttl` to clean up stale profiles faster
