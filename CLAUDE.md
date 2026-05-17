# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**ebpf-guard** is a lightweight eBPF-based runtime security agent for Linux/Kubernetes. It attaches kernel/userspace probes to collect events, correlates them against YAML detection rules, builds behavioral profiles via EWMA anomaly scoring, and exports alerts to Prometheus, Alertmanager, and notification backends. Runs as a single binary or Kubernetes DaemonSet — no kernel module, no Cilium dependency.

## Build & Development Commands

```bash
# Generate Go bindings from eBPF C source (requires clang 14+, linux-headers)
make generate

# Build the binary to build/ebpf-guard
make build

# Run all tests with race detector
make test
# or without race detector (some platforms)
make test-norace

# Run a single test package
go test -v -race ./internal/correlator/...

# Run a specific test
go test -v -race -run TestRuleEngine ./internal/correlator/...

# Lint (go vet + golangci-lint if available)
make lint

# Run the agent (requires root for eBPF)
sudo make run

# Run without kernel (for testing rules/logic)
./build/ebpf-guard --dry-run --config config/config.yaml

# Build Docker image
make docker

# Lint Helm charts
make helm-lint

# Run benchmarks
make bench
```

**Prerequisites for BPF development:** clang + llvm 14+, Linux kernel headers, Go 1.23+. `make generate` must be re-run after any change to `bpf/*.bpf.c` or `bpf/common.h`.

## Architecture

### Event Flow

```
Kernel (tracepoints/uprobes)
  └─ BPF ring buffer (256KB)
       └─ Collectors (per event type)
            └─ CorrelationEngine
                 ├─ RuleEngine (YAML rules → alerts)
                 ├─ Profiler (EWMA anomaly scoring)
                 └─ ShardedEventBuffer (16 PID-keyed shards)
                      └─ Exporters
                           ├─ Prometheus /metrics
                           ├─ Alertmanager webhook (mTLS)
                           ├─ Alert Store (memory/SQLite/OpenSearch)
                           └─ Notification fanout (Slack/Teams/webhook)
```

### Key Package Roles

| Package | Role |
|---|---|
| `cmd/ebpf-guard/` | Cobra CLI entry point; startup sequence, subcommands (`alerts`, `status`, `rules`, `explain`) |
| `internal/bpf/` | BPF program loader, kernel feature detection (BTF), map sizing, per-event sampling config |
| `internal/collector/` | Ring buffer readers for syscall, network, file, DNS, TLS, LSM events; `SyntheticCollector` for `--dry-run` mode |
| `internal/correlator/` | YAML rule engine, 16-shard PID-keyed buffer, SHA-256 fingerprinting, rate limiting, DNS entropy, mining pool detection |
| `internal/profiler/` | EWMA baseline learning, anomaly threshold scoring, `SequenceProfiler` (cosine distance on syscall vectors), `LineageTracker` (attack chain detection) |
| `internal/policy/` | Embedded Rego/OPA engine — post-filter policy evaluation and MITRE ATT&CK enrichment |
| `internal/exporter/` | Prometheus metrics, Alertmanager client (mTLS), HTTP API server, cardinality guard, Slack/Teams/webhook notifiers, Falco-compatible output, metric aliases |
| `internal/enforcer/` | Response actions: kill, throttle, nftables block (`google/nftables` netlink), LSM block |
| `internal/migration/` | Falco rule importer — converts Falco YAML condition syntax to ebpf-guard format |
| `internal/k8s/` | Pod watcher, metadata enricher (labels/annotations added to events) |
| `internal/store/` | Alert persistence — three swappable backends: memory, SQLite, OpenSearch |
| `internal/integrity/` | Startup integrity scan: LD_PRELOAD, cron dirs, root shell configs, anonymous executable memory regions |
| `internal/watchdog/` | Heartbeat gauge, BPF program liveness checking, memory pressure auto-tuning (`MemoryPressureWatcher`) |
| `internal/explainer/` | Alert explanation engine with Go templates, MITRE ATT&CK references, per-category YAML template files |
| `pkg/types/` | Canonical `Event`, `Alert`, `DNSEvent`, `TLSEvent` structs shared across packages |

### BPF Layer (`bpf/`)

- `syscall.bpf.c` — tracepoints on `sys_enter_*`
- `network.bpf.c` — `tcp_connect` kprobe
- `fileaccess.bpf.c` — file open/read/write hooks
- `tls_uprobe.bpf.c` — uprobes on OpenSSL/BoringSSL for plaintext TLS inspection (`SSL_write`, `SSL_read`)
- `dns.bpf.c` — socket filter for DNS packet parsing; early BPF-side filter (UDP dport 53 only)
- `lsm.bpf.c` — eBPF LSM hooks (`lsm/bpf_file_open`, `lsm/bpf_socket_connect`, `lsm/bpf_task_kill`) — kernel 5.7+ only
- `common.h` — shared C structs (`struct event` with type union, `ppid`, `parent_comm` fields) and helper macros

`make generate` compiles these via `bpf2go` and outputs `*_gen.go` files with typed Go map/program accessors.

### Detection Rules (`rules/*.yaml`)

Rules are YAML files loaded at startup and hot-reloaded on change (fsnotify). Structure:

```yaml
rules:
  - id: rule_001
    event_type: syscall | network | file | tls | dns
    condition:
      field: "event_field"
      op: in | not_in | eq | neq | prefix | regex | gt | lt | in_cidr | ...
      values: [...]
    # OR nested condition_group with AND/OR logic
    severity: warning | critical
    action: alert | block | kill | throttle | drop
    tags: [owasp, cve, container-escape, ...]  # optional; used for filtering and MITRE coverage
```

Condition operators are implemented in `internal/correlator/rules.go`. Regex patterns are compiled at rule load time (RE2). Unknown `field` names in conditions are rejected at load time.

Built-in rule sets: `cis-k8s.yaml`, `owasp-web.yaml`, `container-escape.yaml`, `cryptominer.yaml`, `dns-threats.yaml`, `tls-patterns.yaml`, `lineage-patterns.yaml`. Rego policies live in `rules/rego/`.

### Configuration (`internal/config/`)

Viper-based YAML loader. Key sections: `server`, `bpf` (map sizes), `rules` (path, hot_reload, rate limiting), `profiler` (learning_period, anomaly_threshold, ewma_weight, `sequence`, `lineage`), `alerting` (Alertmanager webhook mTLS), `kubernetes`, `auth` (bearer token — auto-generated 32-byte token if empty), `store` (backend: memory/sqlite/opensearch), `notifications` (Slack/Teams/webhook), `enforcer` (block_backend: log/nftables/lsm, dry_run), `collectors` (dns, tls, lsm enable flags), `policy.rego` (rules_dir, enabled), `compat` (falco_output, metric_aliases).

### Startup Sequence (`cmd/ebpf-guard/main.go`)

1. Parse flags (`--config`, `--log-level`, `--dry-run`)
2. Detect kernel BTF support and minimum kernel version
3. Load detection rules
4. Create correlation engine + profiler
5. Initialize collectors (or `SyntheticCollector` in dry-run)
6. Start K8s enricher (if enabled)
7. Start HTTP server with bearer auth
8. Main event loop: ring buffer → correlate → alert → export/store

### HTTP API

Bearer token authenticated. Endpoints: `GET/POST /alerts`, `GET /health`, `GET /metrics` (Prometheus), `GET /rules`, `GET /debug/pprof`.

## Testing Patterns

- Tests are in `_test.go` files co-located with the package they test
- E2E/integration tests live in `e2e/`
- `SyntheticCollector` (`internal/collector/`) is used in tests that need events without a real kernel
- Benchmarks target: correlation engine < X µs/op, profiler ProcessEvent < 10µs p99
- Race detector is always used in CI; run locally with `-race` flag

## Deployment

- **Docker:** multi-stage build → distroless final image
- **Kubernetes:** Helm chart in `deploy/helm/ebpf-guard/` — DaemonSet with RBAC, ConfigMap (rules + config), ServiceMonitor, PrometheusRule, Grafana dashboard
- **Security hardening:** AppArmor + seccomp profiles in `deploy/security/`; hardened Helm values in `values-secure.yaml`
- **Release:** tagged `v*` triggers GoReleaser + cosign signing + SLSA 3 SBOM + Helm OCI push
