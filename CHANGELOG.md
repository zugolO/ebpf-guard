# Changelog

All notable changes to **ebpf-guard** are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/).

> **Config migration notes** per version live in [`internal/config/migrate.go`](internal/config/migrate.go).

---

## [Unreleased]

### Added
- Two artifacts (wave 9, D15): **core** (default image/chart/`make docker`, built without the `rego` tag, `policy.rego.enabled: false`) and **full** (image tag `-full`, `make docker-full`, Helm `image.variant: full`; Rego is then switched on with `config.policy.rego.enabled: true` — the chart refuses to render the core image with Rego on). Runtime flags `ebpf_guard_runtime_flag{flag="rego_built|rego_config|rego_active|sequence_profiler"}` say what actually runs; `ebpf_guard_memory_pressure_sequence_profilers` says whether the memory-pressure watcher's level 1 has anything to shed
- `rules/optional/`: 46 rules that have no event source in the shipped build (34 `cloud_audit`, 9 `gpu`, 3 `iouring`) moved out of the shipped rule set (they are not embedded, not checksummed, not in the image/chart/packages); copy them into `rules.path` together with their collector to use them
- Overload behaviour (wave 8.8): proportional `bpf.overload_shed` controller sheds bulk file events in the kernel by queue pressure instead of letting the pipeline collapse past its ceiling; the file sampler (`bpf.sampling.file_rate` / CPU watcher / controller) now applies only to "hot" processes (`bpf.sampling.hot_pid_threshold`, default 300 events per 100 ms) and never to mutations (chmod/unlink/rename/truncate/rmdir). `/health` reports `degraded` while shedding. New metrics `ebpf_guard_overload_shed_{divisor,active,steps_total}`, `ebpf_guard_file_hot_shed_total`, `ebpf_guard_events_dropped_fraction_10s`, `ebpf_guard_cpu_watchdog_base_cores`, `ebpf_guard_ingest_worker_bulk_dropped_total`
- Load-probe counters `ebpf_guard_load_probe_events_total` / `ebpf_guard_load_probe_event_age_seconds` for processes whose comm starts with `w88` (measurement harness only)

### Changed
- `policy.rego.enabled` defaults to `false` and `profiler.sequence.enabled` defaults to `false` in every hardware profile (wave 9, D15/D4b); both remain opt-in
- LSM audit trail (`bpf/lsm.bpf.c`) records denials only: `lsm/task_kill` (always allows) no longer writes a ring-buffer record per signal, only the counter `ebpf_guard_lsm_blocks_total{hook="task_kill",action="allow"}` (wave 9, D17; needs `make generate`)
- `web_path_traversal_process` is merged into `owasp_path_traversal` (wave 9, D18): the merged rule keeps the union of web-worker comm families and encoding forms
- `drift_dangerous_syscall`, `sigma_seccomp_filter_install`, `sensitive_file_read`, `drift_exec_from_system_bin` and `anomaly_detection` get a `man-db-unit-child` exception keyed on the kernel-assigned systemd unit (`proc.systemd_unit = man-db.service`) instead of comm
- Degraded visibility is now judged by loss RATE over a 10 s window (bulk: >= 1% and >= 10 events; protected: any drop) instead of "any drop in the last 5 s"
- CPU pressure watcher scales its thresholds by the cgroup CPU quota (`cpu.max` / `cfs_quota_us`) when one is set, not by the host core count; level 2 no longer cuts syscall/network sampling unless `shed_protected` is set
- A bulk event for a ingest worker whose channel is full is dropped (and counted as `ingest/worker_full`) when its pid dominates that worker, instead of stalling the single bulk dispatcher for every other pid

- `adaptive_load` is disabled in the shipped `config/config.yaml` (the controller cuts syscall/network and is not wired in the agent); `open` and file mutations are never discarded by the file sampler or, under overload, by the bulk queue/worker hops

### Fixed
- `CPUPressureWatcher` (issue #211 follow-up): CPU budget is now measured as an absolute percentage of a single core instead of a percentage of total host CPU, so the same default thresholds behave identically on a 1-core VPS and an 8-core box instead of scaling with unrelated hardware capacity
- Widened hysteresis for CPU pressure load-shedding: raised default thresholds (40%/70%/20% of one core), grew the smoothing window to 30s, and added a `min_dwell` floor (default 30s) so the state machine no longer flaps every 10-15s under bursty attack traffic, which was cutting file/syscall/network visibility exactly while an attack was in progress
- `enterAllShedMode` now documents explicitly that `lsm`/exec/canary hooks are never shed regardless of pressure level, since those are the highest-value sources for the attacks most likely to spike CPU
- Added a `CPU Pressure Level` panel to the Grafana dashboard so operators can see load-shedding oscillation instead of only finding it in logs

---

## [0.10.0-alpha] - 2026-06-25

### Added
- `server.pprof_stage_labels` (measurement mode, needs `enable_pprof`): pprof label `stage` on the event and alert path (collector, router, ingest worker, rules, anomaly, Rego, incidents, dispatch, HTTP) so CPU profiles split by stage; state exposed as `ebpf_guard_runtime_flag{flag="pprof_stage_labels"}`. Off by default (see `docs/pprof.md`)
- CHANGELOG tracking with GoReleaser auto-generation (this file)
- Expanded test coverage for `osint/`, `drift/`, and `autolearn/` modules
- Wire-format unit tests for the `internal/bpf` ring-buffer parsers (`ParsePrivescEvent`, `ParseIOUringEvent`, `ParseBpfMonitorEvent`, `ParseKmodEvent`, `ParseCgroupEscapeEvent`, `ParseTlsClientHelloEvent`) and the `pkg/types` helpers
- Kernel-independent event parsing split into testable `*_parse.go` files (network, TLS, DNS) so the kernel-only collector glue is codecov-ignored while the decode logic is unit-tested

### Fixed
- GoReleaser `ldflags` now inject the correct `main.Version`/`main.Commit`/`main.BuildTime` symbols, so release binaries report the git tag instead of the fallback version

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
