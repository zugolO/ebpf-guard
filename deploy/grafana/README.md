# Grafana Dashboards for eBPF Guard

This directory contains the official Grafana dashboards for monitoring eBPF Guard runtime security metrics.

| File | Scope | Use when |
|------|-------|----------|
| `ebpf-guard-dashboard.json` | Single agent / single node | Debugging one agent, or a single-node install |
| `ebpf-guard-fleet-dashboard.json` | Whole fleet (all nodes/pods) | DaemonSet deployments — one pane for the whole cluster |

Both dashboards read from the same Prometheus metrics and can be installed side by side; the fleet
dashboard does not replace the single-node one.

## Single-Node Dashboard Overview

The single-node dashboard (`ebpf-guard-dashboard.json`) provides comprehensive visibility into:

- **Events/sec by type** — syscall, network, and file access event rates
- **Top 10 processes by anomaly score** — bar gauge showing highest-risk processes
- **Security alerts** — table view of alerts by rule ID and severity, plus alert rate trends
- **System health** — BPF map utilization, dropped events (backpressure indicator), memory usage
- **Learning progress** — count of PIDs in learning vs monitoring phases

## Fleet Dashboard Overview

The fleet dashboard (`ebpf-guard-fleet-dashboard.json`) aggregates across every agent Prometheus
scrapes — no per-agent scraping or manual dashboard-per-node setup required:

- **Fleet Summary** — agents up/down (from `ebpf_guard_heartbeat_timestamp_seconds`), total/critical
  alerts, fleet-wide alert rate, events/sec across nodes
- **Top-N Across the Fleet** — noisiest rules, most anomalous PIDs cross-fleet (keyed by Prometheus's
  `instance` label so the same PID number on two different nodes doesn't collide), top talkers by
  pod and by node
- **Agent Health & Drill-Down** — per-agent heartbeat age (up/down at a glance), an alerts table
  filterable by the `$namespace` / `$node` / `$pod` template variables, and a per-node event-rate
  timeseries for drilling into a single node or pod

It requires the `node` label added to `ebpf_guard_events_total` / `ebpf_guard_alerts_total` — see
[docs/metrics.md](../../docs/metrics.md#fleet-label-reference) for the full label reference.

## Import Methods

### Method 1: Grafana UI (Manual)

1. Open your Grafana instance
2. Navigate to **Dashboards → Import**
3. Upload `ebpf-guard-dashboard.json` (single-node) or `ebpf-guard-fleet-dashboard.json` (fleet), or paste the JSON content
4. Select your Prometheus data source
5. Click **Import**

### Method 2: Kubernetes ConfigMap (Recommended)

If using the eBPF Guard Helm chart with a Grafana sidecar that discovers dashboards by label
(e.g. the `grafana` chart's `sidecar.dashboards.enabled=true`):

```bash
# Enable the single-node dashboard ConfigMap
helm upgrade --install ebpf-guard ./deploy/helm/ebpf-guard \
  --set grafana.dashboard.enabled=true

# Also enable the fleet-wide dashboard ConfigMap (independent toggle — ship both)
helm upgrade --install ebpf-guard ./deploy/helm/ebpf-guard \
  --set grafana.dashboard.enabled=true \
  --set grafana.fleetDashboard.enabled=true
```

Each dashboard is provisioned as its own ConfigMap (`<release>-grafana-dashboard` and
`<release>-grafana-fleet-dashboard`), labeled `grafana_dashboard: "1"` by default so the sidecar
picks both up automatically. See `grafana.dashboard.*` and `grafana.fleetDashboard.*` in
`deploy/helm/ebpf-guard/values.yaml` to change the namespace or label.

### Method 3: Manual ConfigMap Creation

```bash
# Create the ConfigMap
kubectl create configmap ebpf-guard-dashboard \
  --from-file=ebpf-guard-dashboard.json \
  --namespace=monitoring

# Label for Grafana sidecar discovery
kubectl label configmap ebpf-guard-dashboard \
  grafana_dashboard=1 \
  --namespace=monitoring
```

### Method 4: Grafana Operator

If using Grafana Operator with `GrafanaDashboard` CRD:

```yaml
apiVersion: grafana.integreatly.org/v1beta1
kind: GrafanaDashboard
metadata:
  name: ebpf-guard-dashboard
  namespace: monitoring
spec:
  url: https://raw.githubusercontent.com/zugolO/ebpf-guard/main/deploy/grafana/ebpf-guard-dashboard.json
  datasources:
    - inputName: "DS_PROMETHEUS"
      datasourceName: "Prometheus"
```

## Dashboard Variables

The single-node dashboard includes:

| Variable | Description | Default |
|----------|-------------|---------|
| `datasource` | Prometheus data source | First available |
| `namespace` | Kubernetes namespace filter | All |
| `pod` | Pod name filter | All |

The fleet dashboard adds a `node` variable and chains the others to it:

| Variable | Description | Default |
|----------|-------------|---------|
| `datasource` | Prometheus data source | First available |
| `node` | Kubernetes node filter | All |
| `namespace` | Kubernetes namespace filter, scoped to `$node` | All |
| `pod` | Pod name filter, scoped to `$node`/`$namespace` | All |

## Key Metrics Reference

| Panel | Metric | Description |
|-------|--------|-------------|
| Events/sec | `ebpf_guard_events_total` | Event counter by type |
| Max Anomaly Score | `ebpf_guard_profiler_anomaly_score` | Highest anomaly score across all PIDs |
| Total Alerts | `ebpf_guard_alerts_total` | Cumulative alert counter |
| Top 10 Processes | `ebpf_guard_profiler_anomaly_score` | Processes sorted by anomaly score |
| PIDs in Learning | `ebpf_guard_profiler_anomaly_score < 0.8` | Count of PIDs still learning baseline |
| PIDs in Monitoring | `ebpf_guard_profiler_anomaly_score >= 0.8` | Count of PIDs in active monitoring |
| Alerts by Rule | `ebpf_guard_alerts_total` | Grouped by rule_id and severity |
| Alert Rate | `rate(ebpf_guard_alerts_total[1m])` | Alerts per minute by severity |
| BPF Map Utilization | `ebpf_guard_bpf_map_entries / ebpf_guard_bpf_map_size` | Percentage of BPF map capacity used |
| Dropped Events | `ebpf_guard_events_dropped_total` | Events dropped due to backpressure |
| Memory Usage | `process_resident_memory_bytes` | Agent RSS memory |

## Alert Thresholds

The dashboard uses the following visual thresholds:

- **Anomaly Score**: Green (< 0.5), Yellow (0.5-0.8), Red (> 0.8)
- **BPF Map Utilization**: Green (< 70%), Yellow (70-90%), Red (> 90%)
- **Dropped Events**: Any non-zero value warrants investigation

## Troubleshooting

### No data in panels

1. Verify eBPF Guard is running: `kubectl get pods -l app=ebpf-guard`
2. Check Prometheus scraping: `up{job="ebpf-guard"}` should be 1
3. Verify metric names match: `ebpf_guard_events_total` should exist

### High dropped events rate

- Indicates event processing backpressure
- Consider enabling BPF-side sampling in config
- Check CPU/memory limits on eBPF Guard pods

### High anomaly scores

- Normal during initial learning period (first hour)
- If persistent, review process behavior against baseline
- Check profiler configuration in Helm values

## Customization

To customize the dashboard:

1. Import and edit in Grafana UI
2. Export modified JSON
3. Update the ConfigMap or submit a PR

## Compatibility

- **Grafana**: 10.0+
- **Prometheus**: 2.40+
- **eBPF Guard**: 0.5.0+
