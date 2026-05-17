# Migration Guide

How to replace Falco, Tetragon, or KubeArmor with ebpf-guard in ≤ 10 minutes.

---

## From Falco

Falco is the most widely deployed open-source runtime security tool. ebpf-guard provides:

- **Rule importer** — converts Falco YAML rules to ebpf-guard format
- **Falco-compatible alert output** — webhook/notifier payload matches Falco's JSON schema
- **Prometheus metric aliases** — `falco_events_total` and `falco_dropped_events_total` are available

### Step 1 — Convert your Falco rules

```bash
# Preview (dry-run, no file written)
ebpf-guard rules import --from falco /etc/falco/rules.d/falco_rules.yaml --dry-run

# Convert and write output
ebpf-guard rules import --from falco /etc/falco/rules.d/falco_rules.yaml \
  --output /etc/ebpf-guard/imported-falco-rules.yaml
```

The importer reports conversion statistics:

```
Falco import: 42 rules processed
  converted:   38
  unsupported:  3
  disabled:     1

Unsupported rules (require manual conversion):
  RULE                       REASON
  complex_macro_rule         unsupported atom (macro reference): "spawned_process"
  ...
```

Rules with unsupported syntax (macros, `or`-level boolean logic, Lua filters) are listed
with the exact reason. Rewrite them manually using the
[ebpf-guard rule format](rules.md).

### Step 2 — Uninstall Falco

```bash
helm uninstall falco -n falco
# Wait for DaemonSet pods to terminate
kubectl wait --for=delete pod -l app=falco -n falco --timeout=120s
```

### Step 3 — Install ebpf-guard in Falco-compatibility mode

```bash
helm install ebpf-guard oci://ghcr.io/ebpf-guard/charts/ebpf-guard \
  --namespace ebpf-guard --create-namespace \
  --set migration.from=falco \
  --set rules.path=/etc/ebpf-guard/imported-falco-rules.yaml
```

Setting `migration.from=falco` automatically:

- Adds tolerations for `node-role.kubernetes.io/master` and `control-plane` nodes
- Sets `priorityClassName: system-node-critical` (same as Falco)
- Enables `compat.falco_output: true` — webhook alerts use Falco JSON schema
- Enables `compat.metric_aliases: [falco]` — `falco_events_total` metric is available

### Step 4 — Verify

```bash
# Check agent is running on all nodes
kubectl get pods -n ebpf-guard -o wide

# Check metrics (Falco alias)
kubectl port-forward -n ebpf-guard svc/ebpf-guard 9090:9090 &
curl -s http://localhost:9090/metrics | grep falco_events_total

# View recent alerts
ebpf-guard alerts --server http://localhost:9090 --token <token>
```

Your existing Grafana dashboards and PrometheusRule alerts that reference
`falco_events_total` will continue to work unchanged.

---

## From Tetragon

Tetragon uses `TracingPolicy` CRDs (Go structs, not YAML) — there is no automated
importer for Tetragon policies. Migration requires manual rule rewriting.

### Step 1 — Capture existing TracingPolicies

```bash
kubectl get tracingpolicies -A -o yaml > tetragon-policies.yaml
```

Use `tetragon-policies.yaml` as a reference to rewrite rules in
[ebpf-guard YAML format](rules.md).

### Step 2 — Uninstall Tetragon

```bash
helm uninstall tetragon -n kube-system
kubectl delete crd tracingpolicies.cilium.io tracingpoliciesnamespaced.cilium.io
```

### Step 3 — Install ebpf-guard in Tetragon-compatibility mode

```bash
helm install ebpf-guard oci://ghcr.io/ebpf-guard/charts/ebpf-guard \
  --namespace ebpf-guard --create-namespace \
  --set migration.from=tetragon
```

Setting `migration.from=tetragon` automatically:

- Adds `node-role.kubernetes.io/control-plane` toleration
- Sets `priorityClassName: system-node-critical`
- Enables `compat.metric_aliases: [tetragon]` — `tetragon_events_total` is available

### Step 4 — Verify Tetragon metric aliases

```bash
curl -s http://localhost:9090/metrics | grep tetragon_events_total
```

---

## From KubeArmor

KubeArmor uses `KubeArmorPolicy` CRDs. Partial conversion is supported via the
rule importer (file-level and process-level conditions map cleanly; network conditions
may require manual adjustment).

### Step 1 — Export KubeArmor policies

```bash
kubectl get kubearmorpolicies -A -o yaml > kubearmor-policies.yaml
```

Review and manually convert these to ebpf-guard YAML rules (see [rules.md](rules.md)).

### Step 2 — Uninstall KubeArmor

```bash
helm uninstall kubearmor -n kubearmor
kubectl delete crd kubearmorpolicies.security.kubearmor.com \
  kubearmorclusterpolicies.security.kubearmor.com \
  kubearmorhostpolicies.security.kubearmor.com
```

### Step 3 — Install ebpf-guard in KubeArmor-compatibility mode

```bash
helm install ebpf-guard oci://ghcr.io/ebpf-guard/charts/ebpf-guard \
  --namespace ebpf-guard --create-namespace \
  --set migration.from=kubearmor
```

Setting `migration.from=kubearmor` automatically:

- Adds `node-role.kubernetes.io/master` toleration
- Enables `compat.metric_aliases: [kubearmor]` — `kubearmor_events_total` is available

---

## Manual compat configuration

If you do not use Helm, configure compat directly in `config/config.yaml`:

```yaml
compat:
  # Emit Falco JSON schema from webhook/notifier instead of native format.
  # Enables zero-reconfiguration replacement of Falco for SIEM connectors.
  falco_output: false

  # Register Prometheus metric aliases for tool compatibility.
  # Supported values: "falco", "tetragon", "kubearmor"
  metric_aliases: []
  # metric_aliases: [falco]
```

### Falco JSON output example

When `compat.falco_output: true`, webhook POST bodies look like:

```json
{
  "time": "2024-01-15T12:00:00Z",
  "rule": "Sensitive File Read",
  "priority": "Warning",
  "output": "Sensitive file read detected (proc=nginx pid=1234)",
  "output_fields": {
    "proc.name": "nginx",
    "proc.pid": "1234",
    "evt.type": "open",
    "fingerprint": "sha256:abc123",
    "k8s.pod.name": "my-pod",
    "k8s.ns.name": "production",
    "rule.id": "rule_001"
  },
  "source": "ebpf-guard",
  "tags": ["filesystem"]
}
```

This is compatible with:

- Falco Sidekick (all outputs: Slack, PagerDuty, Elasticsearch, etc.)
- Custom webhook receivers written for Falco
- SIEM integrations that parse Falco JSON (Splunk, Elastic SIEM, etc.)

---

## Rule conversion reference

| Falco condition | ebpf-guard condition |
|---|---|
| `evt.type = execve` | `field: syscall_name`, `op: eq`, `values: [execve]` |
| `evt.type in (open, openat)` | `field: syscall_name`, `op: in`, `values: [open, openat]` |
| `fd.name contains "/etc/passwd"` | `field: file_path`, `op: contains`, `values: [/etc/passwd]` |
| `fd.name startswith "/proc"` | `field: file_path`, `op: prefix`, `values: [/proc]` |
| `proc.name in (nginx, apache2)` | `field: comm`, `op: in`, `values: [nginx, apache2]` |
| `proc.name = "bash"` | `field: comm`, `op: eq`, `values: [bash]` |
| `container.id != host` | `field: in_container`, `op: eq`, `values: ["true"]` |
| `fd.dport = 4444` | `field: dst_port`, `op: eq`, `values: ["4444"]` |
| `fd.sip in (192.168.1.0/24)` | `field: remote_ip`, `op: in_cidr`, `values: [192.168.1.0/24]` |

### Priority → Severity mapping

| Falco priority | ebpf-guard severity |
|---|---|
| CRITICAL, EMERGENCY, ALERT, ERROR | critical |
| WARNING, NOTICE, INFO, DEBUG | warning |

### Unsupported Falco constructs

The following Falco features do not have a direct equivalent and require manual rewriting:

- **Macros** (`spawned_process`, `open_file`, etc.) — inline the macro condition
- **Lists** (`proc.name in (web_servers)`) — expand to literal values
- **Top-level OR logic** — split into multiple rules with the same ID prefix
- **Sysdig filter operators** (`pmatch`, `bcontains`, `glob`) — use `regex` or `contains`
- **Lua exception filters** — not supported; omit or rewrite as a separate rule
