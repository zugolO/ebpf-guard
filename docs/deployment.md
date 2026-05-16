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
   helm install ebpf-guard ebpf-guard/ebpf-guard \
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
