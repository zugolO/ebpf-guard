# ebpf-guard

[![CI](https://github.com/zugolO/ebpf-guard/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/zugolO/ebpf-guard/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/zugolO/ebpf-guard/branch/main/graph/badge.svg)](https://codecov.io/gh/zugolO/ebpf-guard)
[![Release](https://img.shields.io/github/v/release/zugolO/ebpf-guard?include_prereleases&sort=semver)](https://github.com/zugolO/ebpf-guard/releases)
[![Go Version](https://img.shields.io/badge/go-1.23-blue)](https://golang.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev/spec/v1.0/levels)

**Lightweight eBPF-based runtime security agent for Linux and Kubernetes.**

ebpf-guard intercepts kernel events in real time using eBPF programs, builds behavioral process profiles, detects anomalies, and forwards security alerts to Alertmanager — all without a kernel module and without a heavy dependency like Cilium.

---

## Why ebpf-guard

| Problem | Solution |
|---|---|
| You need runtime threat detection with minimal operational overhead | Single binary, one YAML config, runs as a DaemonSet |
| You want zero CNI dependency | ebpf-guard is a standalone agent with no networking stack requirements |
| You already have Prometheus + Alertmanager | Native integration: Prometheus metrics + Alertmanager webhook |
| Your team needs CIS Kubernetes compliance rules out of the box | `rules/cis-k8s.yaml`, `rules/owasp-web.yaml`, `rules/container-escape.yaml` ship with the agent |
| You need to prove an alert was not tampered with | SHA-256 fingerprint on every alert payload |
| You want to understand what an alert means | `ebpf-guard explain <fingerprint>` — MITRE ATT&CK mapped explanations |
| You can't see inside HTTPS traffic | TLS uprobe inspection (opt-in) — plaintext captured before encryption |

---

## Key Features

- **Kernel-space event collection** — syscall tracing, TCP connect hooks, file open/read/write, DNS packet parsing, and TLS uprobe inspection via eBPF ring buffers. No polling, no `/proc` scraping.
- **io_uring monitoring** — kprobes on `io_uring_setup`/`io_uring_enter` close the blind spot that io_uring creates for tracepoint-based agents.
- **Privilege escalation detection** — tracks Linux capability changes (`setuid`, `setcap`, `capset`) and emits enriched events with old/new capability bitmasks and human-readable names.
- **GPU operation monitoring** — CUDA uprobes (`cuMemAlloc`, `cuMemFree`, `cuMemcpy*`, `cuLaunchKernel`) detect unauthorized GPU workloads (illicit model serving, GPU cryptomining).
- **Cloud audit log collection** — AWS CloudTrail (via SQS+S3), GCP Cloud Audit Logs (via Pub/Sub), and Azure Monitor Activity Log; normalized to the same `types.Event` pipeline as eBPF events.
- **JA3 / JA4 TLS fingerprinting** — socket-level kprobe captures TLS ClientHello; computes JA3, JA3S, and JA4 fingerprints for C2 framework detection (Cobalt Strike, Sliver, Mythic, etc.).
- **W3C Trace Context extraction** — parses `traceparent`/`tracestate` headers from TLS plaintext so security alerts can be correlated with distributed traces in your observability stack.
- **Behavioral profiling** — per-process EWMA baseline + syscall sequence frequency vectors (cosine distance); anomaly scores emitted as Prometheus gauges.
- **Process lineage tracking** — detects attack chains like `nginx → bash → curl → python3`; configurable patterns in `rules/lineage-patterns.yaml`.
- **Container drift detection** — captures a per-container behavioral baseline at startup; any new executable, network peer, or file path appearing after the baseline window is flagged as drift.
- **Hidden process detection** — compares the kernel task list (BPF `iter/task`, kernel 5.8+) against `/proc` enumeration; any PID present in the kernel but absent from `/proc` indicates a rootkit.
- **Canary / honeypot files** — synthetic lure files at attacker-probed paths (e.g. `/etc/shadow.canary`); any access generates a high-confidence critical alert.
- **OSINT feed enrichment** — fetches threat-intel feeds (IP/domain blocklists) on a configurable schedule and auto-generates correlator rules that are hot-reloaded without restart.
- **Auto-learn mode** — observe process behavior for a configurable window, then export as ebpf-guard YAML rules or a `seccomp` JSON profile (`ebpf-guard autolearn`).
- **Cross-node gossip protocol** — agents share IOCs (IPs, domains, file hashes) over a lightweight HTTP gossip ring; receiving a signal lowers the anomaly threshold on all peer nodes for the affected namespace.
- **Kubernetes Admission Webhook** — `ValidatingAdmissionWebhook` server evaluates pod specs against the same Rego policies used at runtime, blocking non-compliant workloads before scheduling (build tag: `rego`).
- **WASM detection plugins** — custom detection logic written in any language that compiles to WebAssembly; plugins are hot-loaded from `rules/custom/*.wasm` and run in a sandboxed wazero runtime with a 100 ms deadline per call. See [docs/wasm-plugins.md](docs/wasm-plugins.md).
- **Rule-based detection** — YAML rules with hot-reload; supports field matching, regex, CIDR, nested condition groups. Rego/OPA engine for post-filter policy enrichment.
- **Sigma rule import** — `sigma2ebpfguard` standalone binary converts Sigma open-standard detection rules to ebpf-guard YAML (`process_creation`, `network_connection`, `file_event`, `dns_query` logsources; all Sigma modifiers supported).
- **DNS monitoring** — BPF socket filter for DNS packets; DGA detection via Shannon entropy, DNS tunneling detection, C2 TLD rules.
- **TLS inspection** — uprobes on `SSL_write`/`SSL_read` capture plaintext before encryption (opt-in, requires `CAP_SYS_PTRACE`).
- **eBPF LSM enforcement** — kernel 5.7+ `lsm/bpf_file_open` and `lsm/bpf_socket_connect` hooks block operations *before* they execute; automatic fallback to nftables on older kernels.
- **nftables enforcement** — `google/nftables` netlink-based network blocking (no fork/exec); `CAP_NET_ADMIN` required.
- **Simulate mode** — `--simulate` flag runs the full enforcement pipeline but prints what would have been blocked/killed instead of executing any action; safe to run in production for policy evaluation.
- **Cryptominer detection** — outbound mining pool port/IP matching in BPF map; xmrig/minerd process name detection; DNS TXT query detection.
- **Alert fingerprinting** — SHA-256 fingerprint per alert for tamper detection and deduplication.
- **Alert explanation** — `ebpf-guard explain <fingerprint>` returns human-readable summary, mitigations, and MITRE ATT&CK mapping.
- **Attack simulation** — built-in MITRE ATT&CK scenario runner (`ebpf-guard simulate --scenario <id>`) generates synthetic events that should trigger known rules; used as detection smoke tests.
- **Analyst feedback** — `POST /alerts/<id>/feedback` marks an alert as a false positive; the `(rule_id, comm)` pair is suppressed immediately and persisted across restarts.
- **Falco rule import** — convert Falco rules to ebpf-guard format (`ebpf-guard rules import --from falco`); emit Falco-compatible JSON output and metric aliases.
- **Kubernetes enrichment** — every alert is annotated with pod name and namespace from the K8s API.
- **Container runtime enrichment** — for non-Kubernetes environments, attaches container name, image, and labels via CRI (containerd/CRI-O) or Docker socket.
- **mTLS to Alertmanager** — optional client certificate + CA bundle for secure alert delivery.
- **Notification fanout** — Slack, Microsoft Teams, generic webhook (PagerDuty/Discord/SIEM) with parallel delivery.
- **Alert persistence** — pluggable store: in-memory, SQLite, or OpenSearch.
- **Append-only audit log** — every enforcement action (kill, block, throttle) and rule reload is written to a rotating JSONL audit log for compliance and forensics.
- **CLI subcommands** — `ebpf-guard alerts`, `status`, `rules list/reload/test/eval/import`, `explain`, `autolearn`, `simulate`.
- **Interactive TUI** — `ebpf-guard tui` opens a live terminal dashboard (real-time alerts, top anomalous PIDs, event rate graphs) and a step-by-step rule wizard (build tag: `tui`).
- **Bearer token auth** — `/metrics` and `/debug/pprof` are protected by default; token is auto-generated at startup if not configured.
- **OpenAPI 3.0 spec** — embedded at `api/openapi.yaml`; served at `GET /api/openapi.yaml` for integration with API gateways and generated clients.
- **BPF-side sampling** — configurable per-event-type drop rate in kernel space to cap overhead on high-traffic nodes.
- **Memory pressure auto-tuning** — automatically disables sequence profiling and reduces sampling when available RAM < 10%.
- **Startup integrity scan** — checks `/etc/ld.so.preload`, cron dirs, root shell configs, and anonymous executable memory regions for pre-existing compromise.
- **Heartbeat + BPF liveness** — `EbpfGuardAgentDown` Prometheus alert fires if heartbeat stalls; detects detached BPF programs and attempts re-attach.
- **Performance targets** — 250 000 events/sec sustained (measured: 297 024 ev/s on Intel Xeon 2.80 GHz / 4 vCPU), < 100 MB heap, < 5 % CPU idle on a 4-core node; `BenchmarkProcessEvent` 538–735 ns/op, `BenchmarkCorrelationEngineParallel` ~1.4 µs/op.
- **Distroless container** — multi-stage build produces a minimal image with no shell.
- **AppArmor + seccomp** — enforce-mode profiles ship with the Helm chart.
- **SLSA 3 releases** — cosign-signed images + binaries, SPDX + CycloneDX SBOM, SLSA L3 provenance on every tagged release.

---

## Supply Chain Security

All release artifacts are signed with [cosign](https://github.com/sigstore/cosign)
keyless signing via Sigstore's public Fulcio CA. No private keys are stored
in the repository.

### Verify container image

```bash
cosign verify ghcr.io/zugolO/ebpf-guard:v0.1.0 \
  --certificate-identity-regexp="https://github.com/zugolO/ebpf-guard/" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```

### Verify binary (cosign)

```bash
cosign verify-blob \
  --bundle ebpf-guard-linux-amd64.cosign.bundle \
  --certificate-identity-regexp="https://github.com/zugolO/ebpf-guard/" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ebpf-guard-linux-amd64
```

### Verify SLSA L3 provenance

```bash
slsa-verifier verify-artifact ebpf-guard-linux-amd64 \
  --provenance-path ebpf-guard.intoto.jsonl \
  --source-uri github.com/zugolO/ebpf-guard \
  --source-tag v0.1.0
```

Full verification instructions and SBOM signing: [docs/security.md](docs/security.md#supply-chain-security--cosign--slsa).

---

## Performance

### Benchmark results (Intel Xeon 2.80 GHz / 4 vCPU)

| Benchmark | Result | Notes |
|---|---|---|
| `BenchmarkCorrelationEngine` | ~5.6 µs/op | Single-goroutine sequential ingest |
| `BenchmarkCorrelationEngineParallel` | ~1.4 µs/op | 4× GOMAXPROCS parallel ingest |
| `BenchmarkProcessEvent` (syscall) | 538 ns/op | Per-event EWMA profiler update |
| `BenchmarkProcessEvent` (network) | 735 ns/op | Per-event EWMA profiler update |
| `BenchmarkProcessEventParallel` | ~935 ns/op | 4× parallel profiler updates |
| `BenchmarkShardedBufferContention` | ~15 µs/op | 128-shard buffer under parallel writes |
| Sustained throughput (`TestPerformanceRegression`) | **297 024 ev/s** | 4 producers, nil rules, 60 s run |
| Peak heap memory | **44 MB** | At 297 024 ev/s sustained load |

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
| `bpf/*.bpf.c` | eBPF C programs: syscall, network, file, DNS, TLS uprobe, LSM hooks, io_uring, GPU uprobes, TLS ClientHello |
| `internal/bpf` | eBPF loader, feature detection, BPF map limits, per-type sampling config |
| `internal/collector` | Ring-buffer readers for syscall, network, file, DNS, TLS, LSM, io_uring, GPU, privesc, cloud audit (CloudTrail / GCP / Azure) events |
| `internal/correlator` | YAML rule engine with 16-shard PID buffer, alert fingerprinting, rate limiting, DNS entropy, mining pool detection |
| `internal/profiler` | Per-process EWMA baseline, syscall SequenceProfiler (cosine distance), LineageTracker (attack chains) |
| `internal/drift` | Container drift detection — baseline vs. runtime behavioral comparison |
| `internal/hidden` | Hidden process detection via BPF `iter/task` vs `/proc` comparison (rootkit indicator) |
| `internal/canary` | Canary/honeypot file monitoring — file-access alerts with periodic tamper verification |
| `internal/autolearn` | Auto-learn mode — observes process behavior and exports as YAML rules or seccomp JSON profile |
| `internal/gossip` | Cross-node IOC gossip protocol — shares IPs/domains/hashes and amplifies anomaly sensitivity on peer nodes |
| `internal/osint` | OSINT feed manager — fetches threat-intel blocklists and generates correlator rules with hot-reload |
| `internal/feedback` | Analyst false-positive feedback — suppresses `(rule_id, comm)` pairs; persisted to disk |
| `internal/audit` | Append-only rotating JSONL audit log for enforcement actions and rule reloads |
| `internal/simulate` | Simulate mode — enforcement dry-run that reports blocked actions without executing them |
| `internal/wasm` | WebAssembly detection plugin engine (wazero); sandboxed, 100 ms deadline, hot-reloaded from `rules/custom/` |
| `internal/admission` | Kubernetes `ValidatingAdmissionWebhook` — pre-deploy Rego policy enforcement (build tag: `rego`) |
| `internal/policy` | Rego/OPA embedded engine — post-filter policy enrichment and MITRE mapping |
| `internal/exporter` | Prometheus metrics, Alertmanager client (mTLS), cardinality guard, Slack/Teams/webhook notifiers, Falco-compat output |
| `internal/enforcer` | Response actions: kill, throttle, nftables block (`google/nftables`), LSM block |
| `internal/runtime` | Container metadata enricher via CRI (containerd/CRI-O) or Docker socket — for non-Kubernetes environments |
| `internal/ja3` | JA3 / JA3S / JA4 TLS ClientHello fingerprint computation |
| `internal/migration` | Falco rule importer — converts Falco YAML condition syntax to ebpf-guard format |
| `internal/ruletest` | Rule test framework with TAP v13 and JUnit XML output (`ebpf-guard rules test`) |
| `internal/tui` | Interactive terminal dashboard and rule-builder wizard (build tag: `tui`) |
| `internal/attacker` | Built-in MITRE ATT&CK attack simulation scenarios for end-to-end detection smoke tests |
| `internal/explainer` | Alert explanation engine with Go templates and MITRE ATT&CK references |
| `internal/watchdog` | Heartbeat gauge, BPF program liveness checker, memory pressure auto-tuning |
| `internal/integrity` | Startup integrity scan: LD_PRELOAD, cron, bashrc, anonymous executable regions |
| `internal/k8s` | Pod watcher and Kubernetes metadata enricher |
| `internal/store` | Pluggable alert store: memory, SQLite, OpenSearch |
| `internal/config` | Viper-based YAML config with hot-reload |
| `api/` | Embedded OpenAPI 3.0 specification (`api/openapi.yaml`); served at `GET /api/openapi.yaml` |
| `cmd/sigma2ebpfguard` | Standalone Sigma rule converter binary |
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

### Which deployment guide do I need?

| I want to... | Use this guide |
|---|---|
| Protect a single VPS (Hetzner, DigitalOcean, OVH, Linode) | [VPS guide](docs/platforms/vps.md) — 5 min, systemd install |
| Protect all containers on Coolify / CapRover / Dokploy | [PaaS guide](docs/platforms/coolify-caprover.md) — 10 min, runs alongside your PaaS |
| Run experimental sidecar on Fly.io | [Shared platform guide](docs/platforms/paas-limitations.md) — Firecracker VM notes |
| Understand limitations on Railway / Render / Heroku | [Shared platform guide](docs/platforms/paas-limitations.md) — what works, what doesn't |
| Deploy to Kubernetes (GKE, EKS, AKS) | Helm section above + [deployment docs](docs/deployment.md) |
| Try before installing (20-second test drive with synthetic events) | `docker run --rm -it ghcr.io/zugolo/ebpf-guard --dry-run` covers key attacks in one chunk |
| Install with one command (curl \| sh) | `curl -fsSL https://get.ebpf-guard.io \| sh` — auto-detects arch/kernel, installs systemd, starts monitoring |



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

Converts Falco condition syntax (`evt.type`, `fd.name`, `proc.name`) to ebpf-guard YAML. Rules with unsupported syntax are emitted with `status: unsupported` and a hint.

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
| `ebpf_guard_gpu_tracked_pids_total` | Gauge | Number of PIDs with GPU CUDA uprobes attached |
| `ebpf_guard_wasm_plugins_loaded` | Gauge | WASM detection plugins currently loaded |
| `ebpf_guard_wasm_plugin_evaluations_total` | Counter | WASM plugin evaluation calls, labeled by plugin_id and result |
| `ebpf_guard_wasm_plugin_latency_seconds` | Histogram | WASM plugin evaluation latency per plugin_id |
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
ebpf-guard rules test                          # runs OPA unit tests (TAP/JUnit XML output)
ebpf-guard rules eval --input event.json       # test rules against event
ebpf-guard rules mitre-coverage                # MITRE ATT&CK coverage table
ebpf-guard rules import --from falco rules.yaml

# Observe behavior and export as rules or seccomp profile
ebpf-guard autolearn --pid 1234 --duration 5m --output rules/learned.yaml
ebpf-guard autolearn --comm nginx --duration 10m --seccomp output/nginx-seccomp.json

# Run built-in MITRE ATT&CK detection smoke tests
ebpf-guard simulate --list                     # list available scenarios
ebpf-guard simulate --scenario privesc_setuid  # trigger a single scenario
ebpf-guard simulate --all                      # run all scenarios

# Interactive terminal dashboard and rule builder (requires build tag: tui)
ebpf-guard tui
ebpf-guard tui wizard                          # step-by-step rule creation wizard
```

### Sigma rule converter

`sigma2ebpfguard` is a standalone binary for batch-converting [Sigma](https://sigmahq.io) rules:

```bash
# Convert a directory of Sigma rules
sigma2ebpfguard ./sigma-rules/ --out ./rules/imported/

# Validate a single rule without writing output
sigma2ebpfguard rule.yml --validate

# Preview conversions without writing files
sigma2ebpfguard --dir ./sigma-rules/ --dry-run
```

Supported logsource categories: `process_creation`, `network_connection`, `file_event`, `dns_query`. Rules with unsupported syntax are emitted with `status: unsupported` and a conversion hint.

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

---

## Security

- Responsible disclosure: see [SECURITY.md](SECURITY.md)
- Lock ordering reference: [docs/lock-ordering.md](docs/lock-ordering.md)
- TLS inspection: [docs/tls-inspection.md](docs/tls-inspection.md)
- JA3/JA4 TLS fingerprinting: [docs/tls-inspection.md](docs/tls-inspection.md)
- LSM enforcement: [docs/lsm-enforcement.md](docs/lsm-enforcement.md)
- Enforcement (nftables/kill/throttle): [docs/enforcement.md](docs/enforcement.md)
- Privilege escalation detection: [docs/privesc-detection.md](docs/privesc-detection.md)
- Hidden process / rootkit detection: [docs/operations.md](docs/operations.md)
- Canary file configuration: [docs/canary.md](docs/canary.md)
- Container drift detection: [docs/drift.md](docs/drift.md)
- WASM detection plugins: [docs/wasm-plugins.md](docs/wasm-plugins.md)
- Kubernetes Admission Webhook: [docs/deployment.md](docs/deployment.md)
- OSINT feed enrichment: [docs/integrations.md](docs/integrations.md)
- Cross-node gossip: [docs/gossip.md](docs/gossip.md)
- Analyst feedback: [docs/feedback.md](docs/feedback.md)
- Multi-tenant / allowlist mode: [docs/multi-tenant.md](docs/multi-tenant.md), [docs/allowlist-mode.md](docs/allowlist-mode.md)
- Performance tuning: [docs/performance-tuning.md](docs/performance-tuning.md)
- Rule authoring guide: [docs/rule-authoring-guide.md](docs/rule-authoring-guide.md)

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
| `make bench` | Run all benchmarks (10 s / 3 runs) |
| `make bench-save-baseline` | Save current results as comparison baseline |
| `make bench-compare` | Compare HEAD vs baseline with `benchstat` |

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full version history including breaking changes, security fixes, and migration notes.

---

## License

Apache 2.0
