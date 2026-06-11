# Changelog

All notable changes to **ebpf-guard** are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/).

> **Config migration notes** per version live in [`internal/config/migrate.go`](internal/config/migrate.go).

---

## [Unreleased]

### Added
- CHANGELOG tracking with GoReleaser auto-generation (this file)
- Expanded test coverage for `osint/`, `drift/`, and `autolearn/` modules

---

## [0.9.0] - 2026-06-11

### Added
- OpenAPI 3.0 specification, embedded Swagger UI, and contract tests (`api/openapi.yaml`) (#107)
- Codecov hard CI gate: per-component coverage floors enforced on every pull request (#106)
- AES-256-GCM column-level encryption at rest for SQLite alert store (#96)
- Two-phase atomic hot-reload in the correlator with `ValidateFull` pre-flight check
- Rule-change and config hot-reload audit log written to `audit.log` (#98)
- E2E tests fully enabled in CI; replaced `RUN_E2E_TESTS` guard (#99)
- Configurable graceful-shutdown timeout (`config.server.shutdown_timeout`) (#101)
- Pre-audit operator checklist template (#100)
- Configurable memory-pressure thresholds (`config.watchdog`) (#102)
- Collector startup policy: fail-fast or degrade-gracefully on BPF load error (#103)

### Fixed
- OpenSearch client: TLS SNI hostname mismatch when connecting to HTTPS endpoints (#104)
- Event worker pool: bounded goroutine count prevents unbounded queue growth under spike load (#105)

---

## [0.8.0] - 2026-06-09

### Added
- Distributed trace IDs (W3C TraceContext) propagated through all alert fields (#79)
- Syscall allowlist / deny-unknown mode: block any syscall not in the explicit allowlist (#80)

### Changed
- Breaking: `config.profiler.sequence` now requires `enabled: true` to activate (previously always-on)

### Performance
- Store: severity-bucket index + result-slice pooling cuts `ListAlerts` latency by ~35% (#83)
- Correlator: no-match fast path improved from ~50 ns/op to ~20 ns/op via byType pre-index (#84)

---

## [0.7.0] - 2026-06-08

### Added
- Multi-tenant namespace isolation: rules and alerts scoped per Kubernetes namespace (#76)
- EWMA profiler state persistence — survives DaemonSet rolling upgrades with zero baseline loss (#73)
- SQLite retention policy, automated local backup, and backup Prometheus metrics (#78)
- GPU event detection rules (`rules/gpu.yaml`) and EWMA profiler tracking for cryptomining (#77)
- Per-rule event sampling under high load (`config.rules.sampling_rate`) (#75)
- Config validate/migrate CLI tooling for upgrade planning (`ebpf-guard config migrate`) (#74)
- `ebpf-guard rules test` framework: 14 built-in fixture suites for YAML rule unit-testing (#68)
- Rule library expanded to **502 rules** across all MITRE ATT&CK tactics (#67)
- Interactive TUI rule builder — generate rules from live events interactively (#57)
- CO-RE portability: BTF fallback for kernels 5.4–5.6 that lack `/sys/kernel/btf/vmlinux` (#56)
- Rule hot-reload metrics exposed to Prometheus (`ebpf_guard_rules_reloads_total`) (#55)
- EKS, GKE, AKS-specific managed-Kubernetes detection rules (#52)
- AWS CloudTrail and GCP Audit Logs event collectors (#51)
- Per-event BPF-side sampling (`config.bpf.sampling`) (#50)
- `proc.args` enrichment: full command-line read from `/proc/<pid>/cmdline` at exec time (#49)
- Declarative YAML rule unit-testing framework with `ebpf-guard rules test` (#48)

### Security
- Fixed constant-time comparison bypass in bearer-token auth (timing attack) (#71)
- Fixed SSRF in Alertmanager webhook client: URL allowlist + redirect rejection (#71)
- Bounded regex backtracking: compile-time limit on user-supplied patterns (#71)
- CodeQL and `govulncheck` added to CI on every push and pull request (#71)
- Gossip IOC intake hardened: schema validation, rate limiting, and silent JSON error fix (#72)

### Reliability
- Circuit breaker + in-memory fallback buffer for Alertmanager delivery (#70)
- Graceful shutdown: in-flight alerts are flushed before process exit (#71)
- DNS pre-filter in Go layer: benign DNS events skip Rego evaluation entirely (#69)

---

## [0.6.0] - 2026-06-06

### Added
- Container drift detection: per-container behavioral baseline with automatic lock after configurable window (`internal/drift/`) 
- Auto-profile generator: learns syscalls, network peers, file directories from live traffic and exports YAML allowlist rules + seccomp profiles (`internal/autolearn/`, `ebpf-guard learn`)
- Cross-node alert correlation via gossip protocol (`internal/gossip/`)
- eBPF self-telemetry: BPF program statistics exposed as Prometheus gauges
- Live rule replay against captured event streams
- Canary trap detection: synthetic decoy file/network access triggers (`internal/canary/`)
- OSINT threat-intel integration: MISP, OpenCTI, VirusTotal feed sync with auto-generated YAML blocklist rules (`internal/osint/`)
- `ebpf-guard simulate` — inject synthetic events for rule validation without a running kernel
- `ebpf-guard explain <fingerprint>` — MITRE ATT&CK-mapped human-readable alert explanation

---

## [0.5.0] - 2026-06-05

### Added
- Helm chart for Kubernetes DaemonSet deployment (`deploy/helm/ebpf-guard/`)
- Sliding-window alert deduplication in the correlator (configurable TTL)
- Async Rego policy evaluation via bounded worker pool (non-blocking hot path)
- BPF ring buffer auto-sizing from available system RAM at startup

### Performance
- Hot-path allocation elimination in `Ingest` and enforcement-cooldown paths
- Pool-based alert ID generation removes per-alert heap allocation
- Four additional throughput optimizations; sustained 297 000 ev/s on 4 vCPU

### Fixed
- Goroutine leak in K8s metadata enricher on watcher restart
- DNS LRU cache eviction: stale entries were not removed under memory pressure
- TOCTOU race in DNS cache read-then-write path

---

## [0.4.0] - 2026-06-04

### Added
- TUI dashboard (real-time event stream, rule status, alert history) via `ebpf-guard tui`
- `ebpf-guard simulate` mode for testing rules without a kernel
- Alert explainer engine with MITRE ATT&CK-mapped templates per alert category
- Rules wizard: interactive step-by-step YAML rule authoring

### Fixed
- Enforcement scheduler race: concurrent block + kill could double-kill a PID
- Rule hot-reload watcher panic on rapid successive YAML saves
- File descriptor leak in BPF program attachment loop

---

## [0.3.0] - 2026-06-04

### Added
- iptables enforcement backend (fallback when nftables/LSM unavailable)
- cgroupv2 process freeze enforcement backend
- `arch:` feedback loop: EWMA baseline updated from rule match rates
- Single `GetProcessTree` call per event (was once per enrichment step)

### Performance
- Rego context propagation fixed: eliminates redundant policy re-evaluations
- Dead Prometheus metrics removed: cardinality reduced by ~40 descriptors

---

## [0.2.0] - 2026-06-04

### Added
- Cross-node IOC gossip: indicators of compromise shared across DaemonSet pods
- eBPF self-telemetry metrics (program run count, duration histogram)
- Live rule replay against a captured event buffer
- Canary trap detection (D): decoy resource access triggers high-confidence alerts

### Fixed
- Restored broken CI builds after hot-path optimization merge
- OpenSearch: missing `_id` field caused silent document duplication
- Performance benchmark: was blocking CI due to missing timeout

---

## [0.1.0] - 2026-06-04

### Added
- eBPF ring-buffer collectors for syscall tracepoints, TCP connect kprobes, file open/read/write, DNS socket filter, and TLS uprobes (`SSL_write`/`SSL_read`)
- eBPF LSM hooks (`lsm/bpf_file_open`, `lsm/bpf_socket_connect`, `lsm/bpf_task_kill`) — kernel 5.7+, with nftables fallback
- YAML detection rule engine with hot-reload via `fsnotify`; operators: `in`, `not_in`, `eq`, `neq`, `prefix`, `suffix`, `regex`, `gt`, `lt`, `in_cidr`
- Built-in rule sets: `cis-k8s.yaml`, `owasp-web.yaml`, `container-escape.yaml`, `cryptominer.yaml`, `dns-threats.yaml`, `tls-patterns.yaml`, `lineage-patterns.yaml`
- Per-process EWMA behavioral baseline with anomaly scoring
- Syscall sequence profiler (cosine distance on frequency vectors)
- Process lineage tracker — detects attack chains (e.g. `nginx → bash → curl → python3`)
- DGA detection via Shannon entropy; DNS tunneling detection; mining pool TLD rules
- SHA-256 per-alert fingerprint for tamper detection and deduplication
- Prometheus `/metrics` endpoint with 60+ gauge/counter/histogram descriptors
- Alertmanager webhook delivery with optional mTLS (client cert + CA bundle)
- Slack, Microsoft Teams, and generic webhook (PagerDuty/Discord/SIEM) notification fanout
- Alert persistence: in-memory, SQLite, and OpenSearch backends
- Rego/OPA post-filter policy engine with MITRE ATT&CK enrichment (`rules/rego/`)
- Kubernetes pod metadata enrichment (pod name, namespace, labels)
- Bearer-token HTTP API (`/alerts`, `/health`, `/metrics`, `/rules`, `/debug/pprof`)
- `ebpf-guard alerts`, `status`, `rules list/reload/test/eval/import` CLI subcommands
- Falco rule importer (`ebpf-guard rules import --from falco`) and Falco JSON output compatibility
- BPF-side per-event-type sampling (`config.bpf.sampling`) to cap overhead on high-traffic nodes
- Memory-pressure auto-tuning: disables sequence profiling and reduces sampling under RAM pressure
- Startup integrity scan: checks `LD_PRELOAD`, cron directories, root shell configs, anonymous executable memory regions
- Heartbeat watchdog + BPF liveness check; `EbpfGuardAgentDown` alert on stall or program detachment
- Multi-stage Docker build → distroless final image
- AppArmor and seccomp profiles for the Helm chart (`deploy/security/`)
- Auto-generated 32-byte bearer token when `auth.token` is not configured

---

[Unreleased]: https://github.com/zugolO/ebpf-guard/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/zugolO/ebpf-guard/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/zugolO/ebpf-guard/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/zugolO/ebpf-guard/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/zugolO/ebpf-guard/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/zugolO/ebpf-guard/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/zugolO/ebpf-guard/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/zugolO/ebpf-guard/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/zugolO/ebpf-guard/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/zugolO/ebpf-guard/releases/tag/v0.1.0
