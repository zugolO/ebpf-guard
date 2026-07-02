# Deployment Guide

This guide covers deploying ebpf-guard to Kubernetes clusters.

## Prerequisites

- Kubernetes cluster (1.25+) with Linux nodes
- Kernel 5.15+ with BTF support (`CONFIG_DEBUG_INFO_BTF=y`)
- Container runtime: containerd, CRI-O, or Docker
- Helm 3.12+ (for Helm deployment)
- kubectl configured to access your cluster

## Quick Start

### Using Helm

1. Add the ebpf-guard Helm repository (when published):
   ```bash
   helm repo add ebpf-guard https://ebpf-guard.github.io/charts
   helm repo update
   ```

2. Install the chart:
   ```bash
   helm install ebpf-guard zugolO/ebpf-guard \
     --namespace ebpf-guard \
     --create-namespace
   ```

3. Verify installation:
   ```bash
   kubectl get pods -n ebpf-guard
   kubectl logs -n ebpf-guard -l app.kubernetes.io/name=ebpf-guard
   ```

### Using Raw Manifests

1. Apply the manifests:
   ```bash
   kubectl apply -f deploy/manifests/
   ```

2. Or use kustomize:
   ```bash
   kubectl apply -k deploy/manifests/
   ```

## Configuration

### Helm Values

Key configuration options via Helm values:

```yaml
# Enable Alertmanager integration
config:
  alerting:
    enabled: true
    webhook_url: "http://alertmanager:9093/api/v1/alerts"

# Adjust resource limits
resources:
  limits:
    cpu: 1000m
    memory: 512Mi

# Enable Prometheus ServiceMonitor
serviceMonitor:
  enabled: true
```

See `deploy/helm/ebpf-guard/values.yaml` for all options.

### Grafana Dashboards

Two dashboards ship in `deploy/grafana/` / `deploy/helm/ebpf-guard/dashboards/`: a single-node
dashboard for debugging one agent, and a fleet-wide dashboard that aggregates alerts, events, and
anomalies across every node/pod in the DaemonSet, driven entirely by Prometheus (no per-agent
scraping by hand). See [deploy/grafana/README.md](../deploy/grafana/README.md) for panel details.

Enable one or both as provisioned ConfigMaps (picked up by a Grafana sidecar that discovers
dashboards by label, e.g. `sidecar.dashboards.enabled=true` on the `grafana` chart):

```yaml
# values.yaml
grafana:
  dashboard:
    enabled: true       # single-node dashboard
  fleetDashboard:
    enabled: true        # fleet-wide dashboard
```

```bash
helm upgrade --install ebpf-guard ./deploy/helm/ebpf-guard \
  --set grafana.dashboard.enabled=true \
  --set grafana.fleetDashboard.enabled=true
```

Each is its own ConfigMap (`<release>-grafana-dashboard` / `<release>-grafana-fleet-dashboard`),
so either can be enabled independently. The fleet dashboard requires the `node` label on
`ebpf_guard_events_total` / `ebpf_guard_alerts_total` (present by default) — see
[docs/metrics.md](metrics.md#fleet-label-reference) for the full fleet label reference.

For a fleet-wide **terminal** view instead of (or alongside) Grafana, see `ebpf-guard dashboard
--fleet` in [docs/cli.md](cli.md#ebpf-guard-dashboard).

### Custom Rules

Add custom detection rules via Helm values:

```yaml
rules:
  rules:
    - id: custom_rule
      name: "Custom Detection Rule"
      description: "Detects specific behavior"
      event_type: syscall
      condition:
        field: nr
        op: equals
        values: [59]  # execve
      severity: warning
      action: alert
```

## Verification

### Check Pod Status

```bash
kubectl get pods -n ebpf-guard -o wide
```

### View Logs

```bash
kubectl logs -n ebpf-guard -l app.kubernetes.io/name=ebpf-guard -f
```

### Test Health Endpoints

```bash
# Port-forward to access metrics
kubectl port-forward -n ebpf-guard daemonset/ebpf-guard 9090:9090

# Check health
curl http://localhost:9090/health
curl http://localhost:9090/health/ready
curl http://localhost:9090/health/live

# View metrics
curl http://localhost:9090/metrics
```

## Troubleshooting

### Pods Stuck in CrashLoopBackOff

1. Check kernel version:
   ```bash
   kubectl get nodes -o wide
   ```
   Requires kernel 5.15+.

2. Verify BTF support:
   ```bash
   kubectl run debug --rm -it --image=alpine --restart=Never -- \
     ls /sys/kernel/btf/
   ```
   Should show `vmlinux`.

3. Check logs:
   ```bash
   kubectl logs -n ebpf-guard -l app.kubernetes.io/name=ebpf-guard --previous
   ```

### Missing Pod Metadata

Ensure RBAC permissions are correct:

```bash
kubectl auth can-i list pods --as=system:serviceaccount:ebpf-guard:ebpf-guard
```

Should return `yes`.

### High CPU/Memory Usage

Adjust resource limits and BPF map sizes:

```yaml
config:
  bpf:
    map_sizes:
      events: 32768  # Reduce from default 65536
      processes: 8192
```

## Uninstallation

### Helm

```bash
helm uninstall ebpf-guard -n ebpf-guard
kubectl delete namespace ebpf-guard
```

### Raw Manifests

```bash
kubectl delete -f deploy/manifests/
```

## Kubernetes Enricher Health Monitoring

The Kubernetes pod watcher that enriches events with pod metadata exposes four
Prometheus metrics. Monitor these to detect stale enrichment data before it
causes detection rules to evaluate against outdated namespace/label values.

### Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `ebpf_guard_k8s_enricher_cache_pods{node}` | Gauge | Unique pods currently tracked in the cache |
| `ebpf_guard_k8s_enricher_cache_staleness_seconds{node}` | Gauge | Seconds since the last successful sync |
| `ebpf_guard_k8s_enricher_last_sync_timestamp_seconds{node}` | Gauge | Unix timestamp of the last sync |
| `ebpf_guard_k8s_enricher_miss_total{node}` | Counter | Enrichment lookups with no matching pod |

The `node` label is set to the Kubernetes node name (`KUBERNETES_NODE_NAME` env var).

### Readiness Gate

`GET /health/ready` returns `503` when the enricher cache is stale
(last sync older than `2 × kubernetes.resync_period`). This prevents the agent
being treated as ready if it cannot enrich events with fresh metadata.

```bash
curl http://localhost:9090/health/ready
# {"status":"not ready","reason":"k8s enricher cache stale: last sync 12m3s ago (threshold 10m0s)"}
```

### Built-in Alerts (Helm)

Enable `prometheusRule.enabled: true` in your Helm values to get two enricher
alerts out of the box:

| Alert | Condition | Severity |
|-------|-----------|----------|
| `EbpfGuardK8sEnricherStale` | No sync for >10 min | warning |
| `EbpfGuardK8sEnricherHighMissRate` | >10 misses/sec for 5 min | warning |

### Wiring Metrics (programmatic)

When using ebpf-guard as a library, pass enricher metrics at construction time:

```go
import (
    "github.com/zugolO/ebpf-guard/internal/k8s"
    "github.com/zugolO/ebpf-guard/internal/exporter"
)

node := os.Getenv("KUBERNETES_NODE_NAME")
enricher, _ := k8s.NewEnricher(k8s.EnricherConfig{
    ResyncPeriod: 5 * time.Minute,
    Metrics: k8s.EnricherMetrics{
        CachePods:      exporter.K8sEnricherCachePods.WithLabelValues(node),
        CacheStaleness: exporter.K8sEnricherCacheStaleness.WithLabelValues(node),
        LastSync:       exporter.K8sEnricherLastSync.WithLabelValues(node),
        MissTotal:      exporter.K8sEnricherMissTotal.WithLabelValues(node),
    },
}, logger)
```

## Security Considerations

- ebpf-guard requires `privileged: true` to load eBPF programs
- Runs with `hostNetwork: true` and `hostPID: true` for process visibility
- Uses ClusterRole to read pod metadata across all namespaces
- Consider NetworkPolicies to restrict egress from ebpf-guard pods

## Production Checklist

- [ ] Configure Alertmanager webhook URL
- [ ] Enable Prometheus ServiceMonitor
- [ ] Set appropriate resource limits
- [ ] Configure PodDisruptionBudget (for future HA mode)
- [ ] Review and customize detection rules
- [ ] Set up log aggregation
- [ ] Configure monitoring dashboards
