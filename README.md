# ebpf-guard

**Lightweight eBPF-based runtime security agent for Linux and Kubernetes.**

ebpf-guard intercepts kernel events in real time using eBPF programs, builds behavioral process profiles, detects anomalies, and forwards security alerts to Alertmanager — all without a kernel module and without a heavy dependency like Cilium.

---

## Why ebpf-guard

| Problem | Solution |
|---|---|
| You need runtime threat detection but Falco is too complex to operate | Single binary, one YAML config, runs as a DaemonSet |
| Tetragon requires the full Cilium stack | ebpf-guard has zero CNI dependency |
| You already have Prometheus + Alertmanager | Native integration: Prometheus metrics + Alertmanager webhook |
| Your team needs CIS Kubernetes compliance rules out of the box | `rules/cis-k8s.yaml` ships with the agent |
| You need to prove an alert was not tampered with | SHA-256 fingerprint on every alert payload |

---

## Key Features

- **Kernel-space event collection** — syscall tracing, TCP connect hooks, file open/read/write hooks via eBPF ring buffers. No polling, no `/proc` scraping.
- **Behavioral profiling** — per-process baseline built with EWMA; anomaly score emitted as a Prometheus gauge.
- **Rule-based detection** — YAML rules with hot-reload; supports field matching, regex, CIDR, and nested condition groups.
- **Alert fingerprinting** — SHA-256 fingerprint per alert for tamper detection and deduplication.
- **Kubernetes enrichment** — every alert is annotated with pod name and namespace from the K8s API.
- **mTLS to Alertmanager** — optional client certificate + CA bundle for secure alert delivery.
- **Bearer token auth** — `/metrics` and `/debug/pprof` are protected by default; token is auto-generated at startup if not configured.
- **BPF-side sampling** — configurable per-event-type drop rate in kernel space to cap overhead on high-traffic nodes.
- **Performance targets** — 10 000 events/sec sustained, < 100 MB heap, < 5 % CPU idle on a 4-core node.
- **Distroless container** — multi-stage build produces a minimal image with no shell.
- **AppArmor + seccomp** — enforce-mode profiles ship with the Helm chart.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  Linux Kernel (5.15+)                                            │
│                                                                  │
│  sys_enter_* ──►  syscall.bpf.c ──┐                             │
│  tcp_connect  ──►  network.bpf.c  ──┤  BPF Ring Buffer          │
│  file open    ──►  fileaccess.bpf.c┘  (with sampling)           │
└───────────────────────────┬─────────────────────────────────────┘
                            │ (cilium/ebpf)
┌───────────────────────────▼─────────────────────────────────────┐
│  ebpf-guard agent (Go)                                           │
│                                                                  │
│  Collector ──► CorrelationEngine ──► Profiler                   │
│  (syscall /      (16-shard buffer,    (EWMA baseline,           │
│   network /       rule matching,       anomaly score)           │
│   file)           fingerprinting)                                │
│                        │                                         │
│              K8s Enricher (pod / namespace)                      │
│                        │                                         │
│         ┌──────────────┼──────────────┐                         │
│         ▼              ▼              ▼                          │
│   Prometheus      Alertmanager    Enforcer                       │
│   /metrics         webhook        (kill /                        │
│   (Bearer auth)    (mTLS)          throttle)                     │
└──────────────────────────────────────────────────────────────────┘
```

### Component map

| Package | Role |
|---|---|
| `bpf/*.bpf.c` | eBPF C programs compiled with `clang -target bpf` |
| `internal/bpf` | eBPF loader, feature detection, BPF map limits, sampling config |
| `internal/collector` | Ring-buffer readers for syscall, network, file events |
| `internal/correlator` | Rule engine with 16-shard PID-keyed buffer and alert fingerprinting |
| `internal/profiler` | Per-process EWMA baseline + anomaly scoring |
| `internal/exporter` | Prometheus metrics, Alertmanager client, cardinality guard, alert silencer |
| `internal/enforcer` | Response actions: kill, throttle, block + audit log |
| `internal/k8s` | Pod watcher and metadata enricher |
| `internal/store` | Pluggable event store: memory, SQLite, OpenSearch |
| `internal/config` | Viper-based YAML config with hot-reload |
| `rules/` | Built-in CIS Kubernetes Benchmark rule set |
| `deploy/helm/` | Helm chart: DaemonSet, Secret, PDB, ServiceMonitor, VPA |
| `deploy/security/` | AppArmor and seccomp profiles |

---

## Requirements

| Dependency | Minimum version |
|---|---|
| Linux kernel | 5.15 LTS |
| Go | 1.23 |
| clang / llvm | 14 (for BPF compilation) |
| Kubernetes | 1.26 (for Helm deploy) |
| Helm | 3.x |

The agent does **not** require a kernel module, CAP_SYS_MODULE, or Cilium.

---

## Quick Start

### 1. Build

```bash
# Generate eBPF Go bindings (requires clang)
make generate

# Build the agent binary
make build

# Run tests with race detector
make test
```

### 2. Docker

```bash
make docker
# produces: ghcr.io/ebpf-guard/ebpf-guard:latest
```

### 3. Run locally (requires root and Linux)

```bash
sudo ./ebpf-guard --config config/config.yaml
```

### 4. Deploy to Kubernetes

```bash
# Default values
helm install ebpf-guard deploy/helm/ebpf-guard

# Hardened preset (Bearer auth + mTLS + AppArmor enforce + seccomp)
helm install ebpf-guard deploy/helm/ebpf-guard \
  -f deploy/helm/ebpf-guard/values-secure.yaml
```

---

## Configuration

```yaml
# config/config.yaml

log_level: info

collectors:
  syscall:  { enabled: true }
  network:  { enabled: true }
  file:     { enabled: true }

correlator:
  rules_path: config/rules.yaml
  buffer_size: 10000          # per-shard ring buffer depth

profiler:
  learning_window: 5m         # baseline learning period per PID
  anomaly_threshold: 2.5      # sigma; alerts above this score

sampling:
  enabled: false
  syscall_rate: 1             # 1 = all, N = 1-in-N, 0 = drop all
  network_rate: 1
  file_rate:    1

alertmanager:
  url: http://alertmanager:9093/api/v2/alerts
  # mTLS (optional)
  tls:
    cert_file: /etc/ebpf-guard/client.crt
    key_file:  /etc/ebpf-guard/client.key
    ca_file:   /etc/ebpf-guard/ca.crt

auth:
  enabled: true
  bearer_token: ""            # auto-generated at startup if empty

prometheus:
  listen: :9090
  path: /metrics
```

Sensitive values (`alertmanager.url`, `auth.bearer_token`) can be sourced from a Kubernetes Secret — see `deploy/helm/ebpf-guard/templates/secret.yaml`.

---

## Detection Rules

Rules live in `config/rules.yaml` and are hot-reloaded on file change.

```yaml
rules:
  - id: rule_001
    name: "Unexpected network egress"
    event_type: network
    condition:
      field: dport
      op: not_in
      values: [80, 443, 53]
    severity: warning
    action: alert

  - id: rule_002
    name: "Sensitive file read"
    event_type: file
    condition:
      field: filename
      op: prefix
      values: ["/etc/shadow", "/etc/passwd", "/proc/keys"]
    severity: critical
    action: alert
```

The built-in CIS Kubernetes Benchmark rule set is in `rules/cis-k8s.yaml`.

### Condition operators

| Operator | Meaning |
|---|---|
| `eq` / `neq` | Exact equality |
| `in` / `not_in` | Membership in value list |
| `prefix` | String prefix match |
| `regex` | RE2 regular expression (compiled and validated at load time) |
| `cidr` | CIDR membership for IP fields |
| `gt` / `lt` | Numeric comparison |

Conditions can be nested with `AND`/`OR` groups (`condition_group.sub_groups`).

---

## Prometheus Metrics

| Metric | Type | Description |
|---|---|---|
| `ebpf_guard_events_total` | Counter | Events received, labeled by type, pod, namespace |
| `ebpf_guard_events_dropped_total` | Counter | Events dropped by collector backpressure |
| `ebpf_guard_alerts_total` | Counter | Alerts fired, labeled by rule_id and severity |
| `ebpf_guard_profiler_anomaly_score` | Gauge | Anomaly score per PID and process name |
| `ebpf_guard_bpf_map_entries` | Gauge | Current BPF map entry count per map |

Full reference: [docs/metrics.md](docs/metrics.md)

Prometheus scrape config (with Bearer token):
```yaml
scrape_configs:
  - job_name: ebpf-guard
    bearer_token: <token>
    static_configs:
      - targets: ['ebpf-guard:9090']
```

---

## Security

- Responsible disclosure: see [SECURITY.md](SECURITY.md)
- Lock ordering reference: [docs/lock-ordering.md](docs/lock-ordering.md)
- Deployment hardening: [docs/deployment.md](docs/deployment.md)

At startup the agent logs a single security posture line:

```
INFO  security posture: mTLS=enabled auth=generated apparmor=enforce seccomp=enabled
```

---

## Makefile reference

| Target | Action |
|---|---|
| `make generate` | Run `bpf2go` for all `bpf/*.bpf.c` files |
| `make build` | `go build ./cmd/ebpf-guard` |
| `make test` | `go test ./... -race` |
| `make lint` | `golangci-lint run` |
| `make docker` | Build distroless image |
| `make helm-lint` | `helm lint deploy/helm/` |

---

## License

Apache 2.0
