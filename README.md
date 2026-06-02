# ebpf-guard

[![CI](https://github.com/zugolO/ebpf-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/zugolO/ebpf-guard/actions/workflows/ci.yml)
[![Release](https://github.com/zugolO/ebpf-guard/actions/workflows/release.yml/badge.svg)](https://github.com/zugolO/ebpf-guard/releases)
[![Go Version](https://img.shields.io/badge/go-1.23-blue)](https://golang.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev/spec/v1.0/levels)

**Lightweight eBPF-based runtime security agent for Linux and Kubernetes.**

ebpf-guard intercepts kernel events in real time using eBPF programs, builds behavioral process profiles, detects anomalies, and forwards security alerts to Alertmanager — all without a kernel module and without a heavy dependency like Cilium.

---

## Why ebpf-guard

| Problem | Solution |
|---|---|
| You need runtime threat detection but Falco is too complex to operate | Single binary, one YAML config, runs as a DaemonSet |
| Tetragon requires the full Cilium stack | ebpf-guard has zero CNI dependency |
| You already have Prometheus + Alertmanager | Native integration: Prometheus metrics + Alertmanager webhook |
| Your team needs CIS Kubernetes compliance rules out of the box | `rules/cis-k8s.yaml`, `rules/owasp-web.yaml`, `rules/container-escape.yaml` ship with the agent |
| You need to prove an alert was not tampered with | SHA-256 fingerprint on every alert payload |
| Your SIEM expects Falco JSON | `compat.falco_output: true` — transparent drop-in replacement |
| You want to understand what an alert means | `ebpf-guard explain <fingerprint>` — MITRE ATT&CK mapped explanations |
| You can't see inside HTTPS traffic | TLS uprobe inspection (opt-in) — plaintext captured before encryption |

---

## Key Features

- **Kernel-space event collection** — syscall tracing, TCP connect hooks, file open/read/write, DNS packet parsing, and TLS uprobe inspection via eBPF ring buffers. No polling, no `/proc` scraping.
- **Behavioral profiling** — per-process EWMA baseline + syscall sequence frequency vectors (cosine distance); anomaly scores emitted as Prometheus gauges.
- **Process lineage tracking** — detects attack chains like `nginx → bash → curl → python3`; configurable patterns in `rules/lineage-patterns.yaml`.
- **Rule-based detection** — YAML rules with hot-reload; supports field matching, regex, CIDR, nested condition groups. Rego/OPA engine for post-filter policy enrichment.
- **DNS monitoring** — BPF socket filter for DNS packets; DGA detection via Shannon entropy, DNS tunneling detection, C2 TLD rules.
- **TLS inspection** — uprobes on `SSL_write`/`SSL_read` capture plaintext before encryption (opt-in, requires `CAP_SYS_PTRACE`).
- **eBPF LSM enforcement** — kernel 5.7+ `lsm/bpf_file_open` and `lsm/bpf_socket_connect` hooks block operations *before* they execute; automatic fallback to nftables on older kernels.
- **nftables enforcement** — `google/nftables` netlink-based network blocking (no fork/exec); `CAP_NET_ADMIN` required.
- **Cryptominer detection** — outbound mining pool port/IP matching in BPF map; xmrig/minerd process name detection; DNS TXT query detection.
- **Alert fingerprinting** — SHA-256 fingerprint per alert for tamper detection and deduplication.
- **Alert explanation** — `ebpf-guard explain <fingerprint>` returns human-readable summary, mitigations, and MITRE ATT&CK mapping.
- **Falco compatibility** — import Falco rules (`ebpf-guard rules import --from falco`), emit Falco JSON output, expose Falco/Tetragon metric aliases.
- **Kubernetes enrichment** — every alert is annotated with pod name and namespace from the K8s API.
- **mTLS to Alertmanager** — optional client certificate + CA bundle for secure alert delivery.
- **Notification fanout** — Slack, Microsoft Teams, generic webhook (PagerDuty/Discord/SIEM) with parallel delivery.
- **Alert persistence** — pluggable store: in-memory, SQLite, or OpenSearch.
- **CLI subcommands** — `ebpf-guard alerts`, `status`, `rules list/reload/test/eval/import`, `explain`.
- **Bearer token auth** — `/metrics` and `/debug/pprof` are protected by default; token is auto-generated at startup if not configured.
- **BPF-side sampling** — configurable per-event-type drop rate in kernel space to cap overhead on high-traffic nodes.
- **Memory pressure auto-tuning** — automatically disables sequence profiling and reduces sampling when available RAM < 10%.
- **Startup integrity scan** — checks `/etc/ld.so.preload`, cron dirs, root shell configs, and anonymous executable memory regions for pre-existing compromise.
- **Heartbeat + BPF liveness** — `EbpfGuardAgentDown` Prometheus alert fires if heartbeat stalls; detects detached BPF programs and attempts re-attach.
- **Performance targets** — 10 000 events/sec sustained, < 100 MB heap, < 5 % CPU idle on a 4-core node; `BenchmarkProcessEvent` ~300 ns/op.
- **Distroless container** — multi-stage build produces a minimal image with no shell.
- **AppArmor + seccomp** — enforce-mode profiles ship with the Helm chart.
- **SLSA 3 releases** — cosign-signed images, SPDX + CycloneDX SBOM on every tagged release.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  Linux Kernel (5.15+)                                                │
│                                                                      │
│  sys_enter_*  ──►  syscall.bpf.c    ──┐                             │
│  tcp_connect  ──►  network.bpf.c    ──┤                             │
│  file open    ──►  fileaccess.bpf.c ──┤  BPF Ring Buffer            │
│  UDP port 53  ──►  dns.bpf.c        ──┤  (with per-type sampling)   │
│  SSL_write/read►  tls_uprobe.bpf.c  ──┤                             │
│  file/socket  ──►  lsm.bpf.c (5.7+)──┘  (pre-syscall enforcement)  │
└───────────────────────────┬──────────────────────────────────────────┘
                            │ (cilium/ebpf)
┌───────────────────────────▼──────────────────────────────────────────┐
│  ebpf-guard agent (Go)                                               │
│                                                                      │
│  Collector ──► CorrelationEngine ──► Profiler                       │
│  (syscall /      (16-shard buffer,    (EWMA + SequenceProfiler +    │
│   network /       YAML + Rego rules,   LineageTracker,              │
│   file / dns /    fingerprinting,      anomaly score)               │
│   tls / lsm)      rate limiting)                                     │
│                        │                                             │
│              K8s Enricher (pod / namespace)                          │
│                        │                                             │
│   ┌────────────────────┼──────────────────────┐                     │
│   ▼           ▼        ▼        ▼              ▼                     │
│ Prometheus  Alertmgr  Store  Notifier       Enforcer                │
│ /metrics    webhook   (mem/  (Slack/Teams/  (nftables/LSM/          │
│ (Bearer)    (mTLS)    SQLite/ webhook)       kill/throttle)         │
│                       OpenSrch)                                      │
│                        │                                             │
│                    Explainer                                         │
│               (MITRE ATT&CK mapped                                   │
│                human-readable output)                                │
└──────────────────────────────────────────────────────────────────────┘
```

### Component map

| Package | Role |
|---|---|
| `bpf/*.bpf.c` | eBPF C programs: syscall, network, file, DNS, TLS uprobe, LSM hooks |
| `internal/bpf` | eBPF loader, feature detection, BPF map limits, per-type sampling config |
| `internal/collector` | Ring-buffer readers for syscall, network, file, DNS, TLS, LSM events |
| `internal/correlator` | YAML rule engine with 16-shard PID buffer, alert fingerprinting, rate limiting, DNS entropy, mining pool detection |
| `internal/profiler` | Per-process EWMA baseline, syscall SequenceProfiler (cosine distance), LineageTracker (attack chains) |
| `internal/policy` | Rego/OPA embedded engine — post-filter policy enrichment and MITRE mapping |
| `internal/exporter` | Prometheus metrics, Alertmanager client (mTLS), cardinality guard, Slack/Teams/webhook notifiers, Falco-compat output |
| `internal/enforcer` | Response actions: kill, throttle, nftables block (`google/nftables`), LSM block |
| `internal/migration` | Falco rule importer — converts Falco YAML condition syntax to ebpf-guard format |
| `internal/explainer` | Alert explanation engine with Go templates and MITRE ATT&CK references |
| `internal/watchdog` | Heartbeat gauge, BPF program liveness checker, memory pressure auto-tuning |
| `internal/integrity` | Startup integrity scan: LD_PRELOAD, cron, bashrc, anonymous executable regions |
| `internal/k8s` | Pod watcher and metadata enricher |
| `internal/store` | Pluggable alert store: memory, SQLite, OpenSearch |
| `internal/config` | Viper-based YAML config with hot-reload |
| `rules/` | Built-in rule sets: CIS k8s, OWASP web, container escape, cryptominer, DNS threats, TLS patterns, lineage patterns |
| `rules/rego/` | Rego policy rules with OPA unit tests |
| `deploy/helm/` | Helm chart: DaemonSet, Secret, PDB, ServiceMonitor, VPA, PrometheusRule, Grafana dashboard |
| `deploy/security/` | AppArmor and seccomp profiles |
| `deploy/grafana/` | Pre-built Grafana dashboard JSON |

---

## Requirements

| Dependency | Minimum version | Notes |
|---|---|---|
| Linux kernel | 5.15 LTS | Core event collection |
| Linux kernel | 5.7+ | Required for eBPF LSM hooks (`CONFIG_BPF_LSM=y`) |
| Go | 1.23 | |
| clang / llvm | 14 | For BPF compilation (`make generate`) |
| Kubernetes | 1.26 | For Helm deploy |
| Helm | 3.x | |

**Optional capabilities:**
- `CAP_NET_ADMIN` — required for nftables enforcement
- `CAP_SYS_PTRACE` — required for TLS uprobe inspection

The agent does **not** require a kernel module, `CAP_SYS_MODULE`, or Cilium.

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
# produces: ghcr.io/zugolO/ebpf-guard:latest
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
  syscall:   { enabled: true }
  network:   { enabled: true }
  file:      { enabled: true }
  dns:       { enabled: true }
  tls:       { enabled: false }   # requires CAP_SYS_PTRACE
  lsm:       { enabled: auto }    # auto = enable if kernel 5.7+ supports BPF LSM

correlator:
  rules_path: config/rules.yaml
  buffer_size: 10000              # per-shard ring buffer depth

profiler:
  learning_window: 5m             # baseline learning period per PID
  anomaly_threshold: 2.5          # sigma; alerts above this score
  sequence:
    enabled: true
    window_size: 64
    threshold: 0.3
  lineage:
    enabled: true
    patterns_file: rules/lineage-patterns.yaml

policy:
  rego:
    enabled: false
    rules_dir: rules/rego/

sampling:
  enabled: false
  syscall_rate: 1                 # 1 = all, N = 1-in-N, 0 = drop all
  network_rate: 1
  file_rate:    1

alertmanager:
  url: http://alertmanager:9093/api/v2/alerts
  tls:                            # mTLS (optional)
    cert_file: /etc/ebpf-guard/client.crt
    key_file:  /etc/ebpf-guard/client.key
    ca_file:   /etc/ebpf-guard/ca.crt

notifications:
  slack:
    enabled: false
    webhook_url: ""
    min_severity: warning
  teams:
    enabled: false
    webhook_url: ""
  webhook:
    enabled: false
    url: ""

store:
  backend: memory               # memory | sqlite | opensearch
  sqlite:
    path: /var/lib/ebpf-guard/events.db

enforcer:
  block_backend: log            # log | nftables | lsm
  dry_run: false

auth:
  enabled: true
  bearer_token: ""              # auto-generated at startup if empty

compat:
  falco_output: false           # emit Falco-compatible JSON from webhook
  metric_aliases: []            # falco | tetragon | kubearmor

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
    tags: [network]

  - id: rule_002
    name: "Sensitive file read"
    event_type: file
    condition:
      field: filename
      op: prefix
      values: ["/etc/shadow", "/etc/passwd", "/proc/keys"]
    severity: critical
    action: alert
    tags: [file, cis-k8s]
```

### Built-in rule sets

| File | Coverage |
|---|---|
| `rules/cis-k8s.yaml` | CIS Kubernetes Benchmark |
| `rules/owasp-web.yaml` | OWASP Top 10 / web attacks (path traversal, SSRF, shell spawn) |
| `rules/container-escape.yaml` | Container escape attempts (mount, nsenter, /dev/mem) |
| `rules/cryptominer.yaml` | Cryptominer detection (mining pool ports/IPs, process names) |
| `rules/dns-threats.yaml` | DNS DGA, tunneling, C2 TLD, high-frequency queries |
| `rules/tls-patterns.yaml` | TLS plaintext credential leak, suspicious User-Agent |
| `rules/lineage-patterns.yaml` | Process lineage attack chains (configurable) |
| `rules/rego/` | Rego/OPA policies with built-in unit tests |

### Condition operators

| Operator | Meaning |
|---|---|
| `eq` / `neq` | Exact equality |
| `in` / `not_in` | Membership in value list |
| `prefix` | String prefix match |
| `regex` | RE2 regular expression (compiled and validated at load time) |
| `cidr` | CIDR membership for IP fields |
| `gt` / `lt` | Numeric comparison |
| `in_cidr` | IP-in-CIDR membership |

Conditions can be nested with `AND`/`OR` groups (`condition_group.sub_groups`).

### Falco rule import

```bash
ebpf-guard rules import --from falco /etc/falco/rules.d/*.yaml --output rules/imported.yaml
```

Converts Falco condition syntax (`evt.type`, `fd.name`, `proc.name`) to ebpf-guard YAML. Rules with unsupported syntax are emitted with `status: unsupported` and a hint. See [docs/migration.md](docs/migration.md).

### Rego/OPA rules

```bash
# Test all Rego rules
ebpf-guard rules test

# Evaluate rules against an event
ebpf-guard rules eval --input '{"type":"syscall","comm":"bash","ppid_comm":"nginx"}'

# MITRE ATT&CK coverage report
ebpf-guard rules mitre-coverage
```

See [docs/rules.md](docs/rules.md) for the full Rego authoring guide.

---

## Prometheus Metrics

| Metric | Type | Description |
|---|---|---|
| `ebpf_guard_events_total` | Counter | Events received, labeled by type, pod, namespace |
| `ebpf_guard_events_dropped_total` | Counter | Events dropped by collector backpressure |
| `ebpf_guard_alerts_total` | Counter | Alerts fired, labeled by rule_id and severity |
| `ebpf_guard_profiler_anomaly_score` | Gauge | EWMA anomaly score per PID and process name |
| `ebpf_guard_profiler_sequence_distance` | Gauge | Syscall sequence cosine distance per PID |
| `ebpf_guard_dns_queries_total` | Counter | DNS queries by QTYPE and RCODE |
| `ebpf_guard_lsm_blocks_total` | Counter | LSM hook invocations and blocking decisions |
| `ebpf_guard_heartbeat_timestamp_seconds` | Gauge | Unix timestamp of last agent heartbeat |
| `ebpf_guard_bpf_programs_loaded` | Gauge | Whether each BPF program is attached (1/0) |
| `ebpf_guard_integrity_findings_total` | Gauge | Startup integrity scan findings by check type |
| `ebpf_guard_memory_pressure_mode` | Gauge | Current memory pressure mode (low/normal) |
| `ebpf_guard_tls_tracked_pids_total` | Gauge | Number of PIDs with TLS uprobes attached |
| `ebpf_guard_ratelimiter_states_total` | Gauge | Number of active rate limiter state entries |
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

## CLI Reference

```bash
# Query recent alerts
ebpf-guard alerts --output table
ebpf-guard alerts --output json

# Show agent status and top anomalous processes
ebpf-guard status
ebpf-guard status top

# Explain an alert by fingerprint
ebpf-guard explain <sha256-fingerprint>
ebpf-guard explain --last
ebpf-guard explain --all --output markdown

# List/reload/test rules
ebpf-guard rules list
ebpf-guard rules reload
ebpf-guard rules test                          # runs OPA unit tests
ebpf-guard rules eval --input event.json       # test rules against event
ebpf-guard rules mitre-coverage                # MITRE ATT&CK coverage table
ebpf-guard rules import --from falco rules.yaml
```

Full reference: [docs/cli.md](docs/cli.md)

---

## Notifications

ebpf-guard can fan out alerts to Slack, Microsoft Teams, and any HTTP webhook in parallel:

```yaml
notifications:
  slack:
    enabled: true
    webhook_url: https://hooks.slack.com/services/...
    min_severity: warning
  teams:
    enabled: false
    webhook_url: https://...
  webhook:
    enabled: false
    url: https://my-siem.internal/ingest
    headers:
      Authorization: "Bearer xyz"
```

See [docs/notifications.md](docs/notifications.md).

---

## Falco Migration

Switch from Falco to ebpf-guard in under 10 minutes:

```bash
# 1. Import existing Falco rules
ebpf-guard rules import --from falco /etc/falco/rules.d/*.yaml --output rules/imported.yaml

# 2. Deploy with Falco compatibility mode
helm install ebpf-guard deploy/helm/ebpf-guard --set migration.from=falco
```

This automatically enables Falco JSON output, Falco metric aliases, and matching DaemonSet tolerations. See [docs/migration.md](docs/migration.md).

---

## Security

- Responsible disclosure: see [SECURITY.md](SECURITY.md)
- Lock ordering reference: [docs/lock-ordering.md](docs/lock-ordering.md)
- TLS inspection: [docs/tls-inspection.md](docs/tls-inspection.md)
- LSM enforcement: [docs/lsm-enforcement.md](docs/lsm-enforcement.md)
- Enforcement (nftables/kill/throttle): [docs/enforcement.md](docs/enforcement.md)

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
