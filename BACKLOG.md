# Backlog

Tracking file for open improvement tasks. Each item links to its GitHub issue.
Categories: performance/bug fixes, new detection mechanisms, and indie-developer UX.

## Performance & Bug Fixes

| Issue | Title | Area | Priority |
|---|---|---|---|
| [#146](https://github.com/zugolO/ebpf-guard/issues/146) | DNS analyzer called up to 4x per event in `getFieldValue` | `internal/correlator/rules.go` | High |
| [#147](https://github.com/zugolO/ebpf-guard/issues/147) | Increase ring buffer size from 256KB to 2-4MB | `bpf/common.h` | High |
| [#148](https://github.com/zugolO/ebpf-guard/issues/148) | `syscall_args` hash map overflows under burst — switch to LRU_HASH 32K | `bpf/syscall.bpf.c` | Medium |
| [#149](https://github.com/zugolO/ebpf-guard/issues/149) | Rate limiter serializes all rules through a single mutex | `internal/correlator/ratelimiter.go` | Medium |
| [#150](https://github.com/zugolO/ebpf-guard/issues/150) | LineageTracker performs up to 16 /proc syscalls per alert | `internal/profiler/lineage.go` | Medium |
| [#151](https://github.com/zugolO/ebpf-guard/issues/151) | Regex cache leaks stale compiled patterns on hot-reload | `internal/correlator/rules.go` | Medium |
| [#152](https://github.com/zugolO/ebpf-guard/issues/152) | Rego queue overflow silently falls back to synchronous eval in hot path | `internal/correlator/engine.go` | Medium |
| [#153](https://github.com/zugolO/ebpf-guard/issues/153) | Time-based-only cleanup of cooldown/dedup maps + tight enforce queue sizing | `internal/correlator/engine.go` | Medium |

### Details

- **#146** — Enriched DNS fields (`qname_entropy`, `qname_dga_score`, `qname_digit_ratio`, `qname_subdomain_count`) each re-run `AnalyzeDomain()`. Cache the analysis result once per event evaluation (~4x speedup for DNS rules).
- **#147** — At 100k+ events/sec the 256KB ring buffer fills within milliseconds of userspace stall, silently dropping events. Raise the default and make it configurable.
- **#148** — `BPF_MAP_TYPE_HASH` with 10240 entries drops events during bursts; switch to `BPF_MAP_TYPE_LRU_HASH` with 32768 and expose the map-full counter as a metric.
- **#149** — `Allow()` funnels every rule through one global mutex; shard per rule ID or use `sync.Map` for lock-free reads.
- **#150** — `buildChainFromProc()` walks up to 8 ancestors with 2 /proc reads per level; cache pid→(comm, ppid) and prefer BPF-provided parent info.
- **#151** — Hot-reload copies the entire prior regex cache including patterns from removed rules; also reject non-compiling patterns at load time instead of silently matching false.
- **#152** — When `regoQueue` is full, evaluation runs synchronously inside `Ingest` adding 5ms+ latency; add occupancy gauge, warning logs, configurable queue size.
- **#153** — Cooldown/dedup maps are only cleaned on a 25-60s timer (unbounded growth between ticks); add high-water-mark eviction and grow the enforce queue from 1024.

## New Detection Mechanisms

| Issue | Title | Priority |
|---|---|---|
| [#154](https://github.com/zugolO/ebpf-guard/issues/154) | io_uring activity monitoring — close the syscall-tracing blind spot | High |
| [#155](https://github.com/zugolO/ebpf-guard/issues/155) | Hidden process detection (kernel task list vs /proc diff) | Medium |
| [#156](https://github.com/zugolO/ebpf-guard/issues/156) | bpf() syscall monitoring — detect malicious eBPF program loading | Medium |
| [#157](https://github.com/zugolO/ebpf-guard/issues/157) | JA3/JA4 TLS fingerprinting for C2 detection | Medium |
| [#158](https://github.com/zugolO/ebpf-guard/issues/158) | Real-time container drift detection against image manifest | High |
| [#159](https://github.com/zugolO/ebpf-guard/issues/159) | Markov-chain syscall sequence modeling alongside cosine distance | Low |

### Details

- **#154** — Malware increasingly uses io_uring to bypass syscall tracepoints (known Falco blind spot). Probe `io_uring_enter`/`io_uring_setup`, emit synthetic syscall-equivalent events, ship an allowlist-based default rule.
- **#155** — Enumerate tasks via `bpf_iter/task` (kernel 5.8+) and diff against /proc; a PID visible to the kernel but hidden from /proc is a critical rootkit indicator.
- **#156** — Trace `bpf(BPF_PROG_LOAD)`/`BPF_MAP_CREATE` to catch eBPF rootkits (TripleCross, ebpfkit, boopkit); allowlist own programs, optionally enforce via `lsm/bpf`.
- **#157** — Compute JA3/JA4 ClientHello fingerprints to identify C2 frameworks (Cobalt Strike, Sliver) without decryption; new `ja3`/`ja4` fields on `TLSEvent` plus a `tls-fingerprints.yaml` rule set.
- **#158** — Extend `internal/drift/` to snapshot executable paths from image layers at container start and alert (or kill) when a binary not present in the image is executed.
- **#159** — Add first-order transition-probability modeling per workload to `SequenceProfiler` to catch order-level anomalies cosine distance misses; must stay within the <10µs p99 ProcessEvent budget.

## Indie-Developer / Zero-Config UX

| Issue | Title | Priority |
|---|---|---|
| [#160](https://github.com/zugolO/ebpf-guard/issues/160) | One-command install — curl \| sh and docker run with zero config | High |
| [#161](https://github.com/zugolO/ebpf-guard/issues/161) | Discord and Telegram notifiers | High |
| [#162](https://github.com/zugolO/ebpf-guard/issues/162) | Simple mode — auto-enforcement for unambiguous threats out of the box | Medium |
| [#163](https://github.com/zugolO/ebpf-guard/issues/163) | Plain-language alert mode for non-security users | Medium |
| [#164](https://github.com/zugolO/ebpf-guard/issues/164) | Deployment guides for indie platforms (VPS, Coolify, Railway, Fly.io, CapRover) | Medium |

### Details

- **#160** — Zero-to-protected in under 60 seconds: install script with embedded sane defaults, no config file required, cosign-verified binary.
- **#161** — Webhook-based Discord notifier (rich embeds) and Telegram Bot API notifier, reusing the existing notifier interface, rate limiting, and per-severity thresholds.
- **#162** — `mode: simple` preset that auto-kills high-confidence threats (cryptominers, confirmed reverse shells, webshell chains) with safety rails: rule + lineage confirmation required, 24h dry-run preview, plain-language action notifications.
- **#163** — Add a `plain` explainer style: "What happened / Why it matters / What to do now" per alert, with MITRE/technical detail layered behind a details field.
- **#164** — Copy-paste guides under `docs/platforms/` for Hetzner/VPS, Coolify, CapRover, Dokploy, plus an honest limitations section for managed PaaS (Railway/Fly.io) where host eBPF access is unavailable.
