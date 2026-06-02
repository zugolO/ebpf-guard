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

#### `ebpf_guard_profiler_sequence_distance`

| Attribute | Value |
|-----------|-------|
| **Type** | Gauge |
| **Labels** | `pid`, `comm` (process name) |
| **Description** | Cosine distance between current and baseline syscall frequency vectors (0.0-1.0) |

**Purpose:** Detects anomalous syscall patterns by comparing the current syscall frequency distribution against a learned baseline. High values indicate the process is making syscalls in an unusual pattern.

**Configuration:**
```yaml
profiler:
  sequence:
    enabled: true       # Enable sequence profiling
    window_size: 64     # Number of syscalls in the frequency window
    threshold: 0.3      # Distance threshold for anomaly detection
```

**Example:**
```promql
# Processes with unusual syscall sequences
ebpf_guard_profiler_sequence_distance > 0.3

# Correlation with anomaly score
ebpf_guard_profiler_anomaly_score > 0.8 and ebpf_guard_profiler_sequence_distance > 0.3
```

**Alert Example:**
```yaml
groups:
  - name: ebpf-guard
    rules:
      - alert: SuspiciousSyscallSequence
        expr: ebpf_guard_profiler_sequence_distance > 0.5
        for: 30s
        labels:
          severity: warning
        annotations:
          summary: "Process showing unusual syscall pattern"
          description: "PID {{ $labels.pid }} ({{ $labels.comm }}) has syscall sequence distance of {{ $value }}"
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
| **Labels** | `collector` (syscall\|network\|fileaccess\|dns\|tls) |
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

#### `ebpf_guard_dns_queries_total`

| Attribute | Value |
|-----------|-------|
| **Type** | Counter |
| **Labels** | `qtype` (A\|AAAA\|TXT\|MX\|etc), `rcode` (NOERROR\|NXDOMAIN\|etc) |
| **Description** | Total number of DNS queries by QTYPE and RCODE |

**Purpose:** Monitor DNS query patterns and detect anomalies.

**Example:**
```promql
# DNS queries per second by type
rate(ebpf_guard_dns_queries_total[5m])

# NXDOMAIN rate (possible DGA or scanning)
sum(rate(ebpf_guard_dns_queries_total{rcode="NXDOMAIN"}[5m]))

# TXT queries (possible DNS tunneling)
rate(ebpf_guard_dns_queries_total{qtype="TXT"}[5m])
```

**Alert Example:**
```yaml
groups:
  - name: ebpf-guard-dns
    rules:
      - alert: HighDNSQueryRate
        expr: rate(ebpf_guard_dns_queries_total[5m]) > 1000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High DNS query rate detected"
          description: "DNS query rate exceeds 1000/sec for 5 minutes"
```

---

#### `ebpf_guard_dns_events_dropped_total`

| Attribute | Value |
|-----------|-------|
| **Type** | Counter |
| **Labels** | None |
| **Description** | Total number of DNS events dropped due to ring buffer overflow |

**Purpose:** Detect when DNS events are being lost due to high load.

**Example:**
```promql
# Alert on dropped DNS events
- name: DNSEventsDropped
  rules:
    - alert: DNSEventsDropped
      expr: rate(ebpf_guard_dns_events_dropped_total[5m]) > 0
      for: 1m
      labels:
        severity: warning
      annotations:
        summary: "DNS events are being dropped"
        description: "Ring buffer overflow detected - consider increasing buffer size"
```

---

### Watchdog Metrics

#### `ebpf_guard_heartbeat_timestamp_seconds`

| Attribute | Value |
|-----------|-------|
| **Type** | Gauge |
| **Labels** | None |
| **Description** | Unix timestamp of the last agent heartbeat |

**Purpose:** This metric is used by the `EbpfGuardAgentDown` alert to detect when the agent has stopped running.

**Example Alert:**
```yaml
# Alert when agent is down for more than 60 seconds
groups:
  - name: ebpf-guard
    rules:
      - alert: EbpfGuardAgentDown
        expr: time() - ebpf_guard_heartbeat_timestamp_seconds > 60
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "eBPF Guard agent is down"
          description: "eBPF Guard agent has not sent a heartbeat for more than 60 seconds"
```

---

#### `ebpf_guard_bpf_programs_loaded`

| Attribute | Value |
|-----------|-------|
| **Type** | Gauge |
| **Labels** | `program` (syscall\|network\|fileaccess) |
| **Description** | Whether each BPF program is loaded and attached (1) or not (0) |

**Example:**
```promql
# Check if any BPF program is detached
ebpf_guard_bpf_programs_loaded == 0
```

---

### Integrity Metrics

#### `ebpf_guard_integrity_findings_total`

| Attribute | Value |
|-----------|-------|
| **Type** | Gauge |
| **Labels** | `check` (ld_preload\|cron\|bashrc\|anon_exec) |
| **Description** | Number of integrity findings detected at startup by check type |

**Check Types:**

| Check | Description |
|-------|-------------|
| `ld_preload` | Entries in `/etc/ld.so.preload` (LD_PRELOAD hijack) |
| `cron` | Recently modified files in cron directories |
| `bashrc` | Recently modified root shell config files |
| `anon_exec` | Anonymous executable memory regions (shellcode injection) |

**Example Alert:**
```yaml
# Alert on integrity findings
groups:
  - name: ebpf-guard
    rules:
      - alert: EbpfGuardIntegrityFinding
        expr: ebpf_guard_integrity_findings_total > 0
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "eBPF Guard integrity finding detected"
          description: "Startup integrity scan detected potential persistence technique"
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

#### `ebpf_guard_memory_pressure_mode`

| Attribute | Value |
|-----------|-------|
| **Type** | Gauge |
| **Labels** | `mode` (low\|normal) |
| **Description** | Current memory pressure mode (1 = active, 0 = inactive) |

**Behavior:**
- When available memory drops below `watchdog.memory_pressure.low_memory_threshold` (default: 10%), the agent enters low-memory mode
- In low-memory mode: sequence profiling is disabled, BPF sampling rate reduced to 10%
- When available memory recovers above `watchdog.memory_pressure.recovery_threshold` (default: 20%), normal operation resumes

**Example Alert:**
```yaml
# Alert on memory pressure
groups:
  - name: ebpf-guard
    rules:
      - alert: EbpfGuardMemoryPressure
        expr: ebpf_guard_memory_pressure_mode{mode="low"} == 1
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "eBPF Guard in low-memory mode"
          description: "eBPF Guard has downgraded profiling due to memory pressure"
```

---

#### `ebpf_guard_lsm_blocks_total`

| Attribute | Value |
|-----------|-------|
| **Type** | Counter |
| **Labels** | `hook` (file_open\|socket_connect\|task_kill), `action` (allow\|block) |
| **Description** | Total number of LSM hook invocations and blocking decisions |

**Requirements:**
- Kernel 5.7+ with `CONFIG_BPF_LSM=y`
- LSM BPF enabled in kernel command line: `lsm=...,bpf`

**Example:**
```promql
# Block rate by hook type
rate(ebpf_guard_lsm_blocks_total{action="block"}[5m])
```

---

#### `ebpf_guard_tls_tracked_pids_total`

| Attribute | Value |
|-----------|-------|
| **Type** | Gauge |
| **Labels** | None |
| **Description** | Current number of PIDs tracked by the TLS collector (processes with libssl uprobes attached) |

**Purpose:** Indicates how many processes currently have TLS uprobes attached. Grows as new libssl-using processes are discovered; shrinks every 60s as dead PIDs are cleaned up.

**Example:**
```promql
# Monitor TLS uprobe attachment count
ebpf_guard_tls_tracked_pids_total

# Alert if TLS tracking grows unbounded (indicates cleanup goroutine failure)
- alert: EbpfGuardTLSPIDLeaking
  expr: ebpf_guard_tls_tracked_pids_total > 500
  for: 10m
  labels:
    severity: warning
  annotations:
    summary: "TLS collector tracking excessive PIDs"
    description: "TLS collector is tracking {{ $value }} PIDs — cleanup may not be running correctly"
```

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

#### `ebpf_guard_ratelimiter_states_total`

| Attribute | Value |
|-----------|-------|
| **Type** | Gauge |
| **Labels** | None |
| **Description** | Current number of active entries in the alert rate limiter state map |

**Purpose:** Each unique rule ID that has been evaluated gets one entry. The cleanup goroutine removes expired entries every 5 minutes. A continuously growing value indicates the cleanup loop is not running.

**Example:**
```promql
# Monitor rate limiter state growth
ebpf_guard_ratelimiter_states_total

# Alert if cleanup is not working
- alert: EbpfGuardRateLimiterLeak
  expr: ebpf_guard_ratelimiter_states_total > 10000
  for: 10m
  labels:
    severity: warning
  annotations:
    summary: "Rate limiter state map growing unbounded"
```

---

### Sprint 34.0 Metrics (Observability & Operational Excellence)

#### `ebpf_guard_event_queue_depth`

| Attribute | Value |
|-----------|-------|
| **Type** | Gauge |
| **Labels** | None |
| **Description** | Current event channel fill level as a fraction [0, 1]. Values near 1.0 indicate back-pressure. |

**Example:**
```promql
# Alert when queue is more than 80% full
ebpf_guard_event_queue_depth > 0.8
```

---

#### `ebpf_guard_correlation_latency_seconds`

| Attribute | Value |
|-----------|-------|
| **Type** | Histogram |
| **Labels** | None |
| **Description** | Latency of a single event through the correlation engine (rule evaluation + anomaly scoring). |

**Buckets:** 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0

**Example:**
```promql
# 99th percentile correlation latency
histogram_quantile(0.99, rate(ebpf_guard_correlation_latency_seconds_bucket[5m]))
```

---

#### `ebpf_guard_active_rules_total`

| Attribute | Value |
|-----------|-------|
| **Type** | Gauge |
| **Labels** | None |
| **Description** | Number of detection rules currently loaded in the rule engine. Drops to new count on hot-reload. |

---

#### `ebpf_guard_tracked_pids_total`

| Attribute | Value |
|-----------|-------|
| **Type** | Gauge |
| **Labels** | None |
| **Description** | Number of PIDs currently tracked by the profiler. Updated every 30 seconds. |

**Example:**
```promql
# Alert when approaching maxPIDs cap (default 65536)
ebpf_guard_tracked_pids_total > 58982
```

---

#### `ebpf_guard_profile_evictions_total`

| Attribute | Value |
|-----------|-------|
| **Type** | Counter |
| **Labels** | None |
| **Description** | Total number of LRU profile evictions triggered when the `maxPIDs` cap is reached. |

---

#### `ebpf_guard_profiler_memory_bytes`

| Attribute | Value |
|-----------|-------|
| **Type** | Gauge |
| **Labels** | None |
| **Description** | Estimated memory used by in-memory process profiles (struct overhead + map bucket estimate). |

---

#### `ebpf_guard_enforcement_actions_total`

| Attribute | Value |
|-----------|-------|
| **Type** | Counter |
| **Labels** | `action` (block\|kill\|throttle\|lsm_block) |
| **Description** | Total enforcement actions executed by action type. Only incremented on success. |

**Example:**
```promql
# Kill rate over last 5 minutes
rate(ebpf_guard_enforcement_actions_total{action="kill"}[5m])
```

---

#### `ebpf_guard_audit_log_dropped_total`

| Attribute | Value |
|-----------|-------|
| **Type** | Counter |
| **Labels** | None |
| **Description** | Total audit log entries dropped because the audit channel was full. Any non-zero value indicates the consumer is too slow. |

**Alert Example:**
```yaml
groups:
  - name: ebpf-guard
    rules:
      - alert: EbpfGuardAuditLogDropped
        expr: increase(ebpf_guard_audit_log_dropped_total[5m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Audit log entries are being dropped"
          description: "Enforcement audit entries are being lost — audit channel consumer may be stuck"
```

---

#### `ebpf_guard_store_alerts_total`

| Attribute | Value |
|-----------|-------|
| **Type** | Counter |
| **Labels** | None |
| **Description** | Total number of alerts successfully persisted to the alert store backend. |

---

#### `ebpf_guard_store_latency_seconds`

| Attribute | Value |
|-----------|-------|
| **Type** | Histogram |
| **Labels** | None |
| **Description** | Latency of alert store write operations (single `Store` or `StoreBatch` call). |

**Buckets:** 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0

---

#### `ebpf_guard_memory_pressure_ratio`

| Attribute | Value |
|-----------|-------|
| **Type** | Gauge |
| **Labels** | None |
| **Description** | Ratio of available memory to total memory (0.0–1.0). Lower values indicate higher memory pressure. Updated every 5 seconds. |

**Example:**
```promql
# Available memory below 15%
ebpf_guard_memory_pressure_ratio < 0.15
```

---

#### `ebpf_guard_bpf_program_reattach_total`

| Attribute | Value |
|-----------|-------|
| **Type** | Counter |
| **Labels** | None |
| **Description** | Total number of successful BPF program reattachments after the watchdog detected a detach event. |

---

### Alert Rules (built-in PrometheusRule)

The Helm chart ships `deploy/helm/ebpf-guard/templates/prometheusrule.yaml` with the following pre-configured alerts:

| Alert | Expression | Severity | Description |
|-------|-----------|----------|-------------|
| `EbpfGuardAgentDown` | `time() - ebpf_guard_heartbeat_timestamp_seconds > 60` | critical | Agent heartbeat stopped |
| `EbpfGuardMemoryPressure` | `ebpf_guard_memory_pressure_mode{mode="low"} == 1` | warning | Agent downgraded due to memory pressure |
| `CryptominerDetected` | `increase(ebpf_guard_alerts_total{rule_id=~"cryptominer.*"}[5m]) > 0` | critical | Cryptominer activity detected |
| `EbpfGuardEventDropHigh` | `rate(ebpf_guard_events_dropped_total[1m]) > 100` | warning | High event drop rate — consider increasing ring buffer or reducing load |
| `EbpfGuardQueueDepthHigh` | `ebpf_guard_event_queue_depth > 0.8` | warning | Event queue above 80% — correlation engine may be falling behind |
| `EbpfGuardAuditLogDropped` | `increase(ebpf_guard_audit_log_dropped_total[5m]) > 0` | critical | Audit log entries dropped — enforcement audit trail incomplete |
| `EbpfGuardTrackedPIDsHigh` | `ebpf_guard_tracked_pids_total > 58982` | warning | Tracked PIDs above 90% of default cap (65536) — LRU evictions imminent |

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
