# Backlog

Tracking file for open improvement tasks. Each item mirrors the full description of its GitHub issue.
Categories: performance/bug fixes, new detection mechanisms, and indie-developer UX.

## Performance & Bug Fixes

### [#146](https://github.com/zugolO/ebpf-guard/issues/146) — perf(correlator): DNS analyzer called up to 4x per event in getFieldValue

**Problem**

In `internal/correlator/rules.go` (~lines 912-929), `getFieldValue()` calls `globalDNSAnalyzer.AnalyzeDomain()` separately for each enriched DNS field (`qname_entropy`, `qname_dga_score`, `qname_digit_ratio`, `qname_subdomain_count`). A rule referencing multiple enriched fields re-runs the full entropy + n-gram analysis up to 4 times per event.

**Fix**

Lazily compute the `AnalyzeDomain` result once per event evaluation and reuse it for all DNS-derived fields (local cached variable or per-event analysis struct).

**Impact**

~4x reduction in DNS rule evaluation cost on the hot path.

### [#147](https://github.com/zugolO/ebpf-guard/issues/147) — perf(bpf): increase ring buffer size from 256KB to 2-4MB

**Problem**

`bpf/common.h` defines the events ring buffer as `256 * 1024` (256KB). At 100k+ events/sec with ~1KB events the buffer fills in single-digit milliseconds of userspace stall, causing silent event loss. Modern multi-core nodes easily exceed this rate.

**Fix**

- Increase default to 2-4MB (`__uint(max_entries, 2 * 1024 * 1024)` or higher).
- Ideally make it configurable via `bpf` config section and document the memory tradeoff.

**Impact**

Eliminates event loss under burst traffic; directly improves detection reliability.

### [#148](https://github.com/zugolO/ebpf-guard/issues/148) — perf(bpf): syscall_args hash map overflows under burst — switch to LRU_HASH 32K

**Problem**

`bpf/syscall.bpf.c` (~line 30) declares `syscall_args` as `BPF_MAP_TYPE_HASH` with `max_entries = 10240`. Under bursts (many tasks in unfinished syscalls) the map overflows, `record_map_full()` increments and events are silently dropped.

**Fix**

- Switch to `BPF_MAP_TYPE_LRU_HASH` with `max_entries = 32768`.
- Surface the map-full counter as a Prometheus metric so drops are visible.

### [#149](https://github.com/zugolO/ebpf-guard/issues/149) — perf(correlator): rate limiter serializes all rules through a single mutex

**Problem**

`internal/correlator/ratelimiter.go` (~lines 78-92): `Allow()` acquires a global `rl.mu` for the per-rule state map lookup on every call. Under parallel rule evaluation this single mutex becomes a contention point, then `state.allow()` acquires a second lock.

**Fix**

Use `sync.Map` for lock-free reads of existing rule states, or shard the state map by rule ID hash (same pattern as the dedup map / ShardedEventBuffer).

### [#150](https://github.com/zugolO/ebpf-guard/issues/150) — perf(profiler): LineageTracker performs up to 16 /proc syscalls per alert

**Problem**

`internal/profiler/lineage.go` (~lines 268-286): `buildChainFromProc()` walks up to `maxDepth` (8) ancestors, reading `/proc/<pid>/comm` and `/proc/<pid>/status` per level — up to 16 syscalls per alert when BPF parent info is missing. At 1k alerts/sec this is 16k extra syscalls/sec.

**Fix**

- Cache pid → (comm, ppid) mappings with TTL/eviction on process exit.
- Prefer BPF-provided `ppid`/`parent_comm` from `struct event` whenever available, falling back to /proc only on cache miss.

### [#151](https://github.com/zugolO/ebpf-guard/issues/151) — bug(correlator): regex cache leaks stale compiled patterns on hot-reload

**Problem**

`internal/correlator/rules.go` (~lines 288-312): on rule hot-reload, ALL entries from the prior engine's `regexCache` are copied into the new engine, including patterns from removed rules. Repeated reloads accumulate dead compiled regex objects indefinitely.

Additionally, `matchesRegex()` (~lines 1037-1045) silently returns false for patterns missing from the cache (failed compilation) instead of surfacing an error at load time.

**Fix**

- On reload, copy only patterns referenced by the new rule set (collect used patterns first).
- Reject rules with non-compiling regex patterns at load time (consistent with unknown-field rejection).

### [#152](https://github.com/zugolO/ebpf-guard/issues/152) — perf(correlator): Rego queue overflow silently falls back to synchronous eval in hot path

**Problem**

`internal/correlator/engine.go` (~lines 1370-1378): when `regoQueue` is full, evaluation falls back to synchronous `evaluateRegoPolicies()` inside `Ingest`, adding 5ms+ latency per event. Only a drop counter is incremented — no visibility into queue pressure before it saturates.

**Fix**

- Export queue occupancy as a gauge; log a warning when occupancy exceeds ~90%.
- Make `RegoQueueSize` configurable; consider adaptive worker scaling based on observed drops.

### [#153](https://github.com/zugolO/ebpf-guard/issues/153) — perf(correlator): time-based-only cleanup of cooldown/dedup maps + tight enforce queue sizing

**Problem**

Two related operational issues in `internal/correlator/engine.go`:

1. **Cleanup is interval-based only** (~lines 749-762): cooldown and dedup maps are cleaned every 25-60s regardless of size. With 10k+ transient processes the maps grow unbounded between ticks.
2. **Enforce queue sized at 1024** (~line 513): at high enforcement-action rates this holds only ~100ms of work before overflow drops.

**Fix**

- Add a high-water-mark check that triggers early eviction (e.g. at 80% of max entries).
- Increase enforce queue to 4096 and/or make it configurable; export queue depth metric.

## New Detection Mechanisms

### [#154](https://github.com/zugolO/ebpf-guard/issues/154) — feat(detection): io_uring activity monitoring — close the syscall-tracing blind spot

**Motivation**

Modern malware increasingly uses io_uring to perform file and network I/O without issuing the traditional syscalls that tracepoint-based agents observe. This is a known blind spot in Falco and most eBPF security tools — covering it is a strong differentiator.

**Proposal**

- Attach probes to `io_uring_enter` / `io_uring_setup` and (where feasible) trace SQE opcodes (openat, connect, send/recv, write).
- Emit synthetic syscall-equivalent events into the existing pipeline so current rules apply.
- Ship a default rule: alert on io_uring usage by processes outside an allowlist (databases, high-perf servers).

**References**

- "io_uring is a security blind spot" research (ARMO, 2025 — `curing` rootkit PoC).

### [#155](https://github.com/zugolO/ebpf-guard/issues/155) — feat(detection): hidden process detection (kernel task list vs /proc diff)

**Motivation**

Rootkits (LKM and LD_PRELOAD based) hide processes from /proc. An eBPF agent can enumerate tasks directly from the kernel and detect the discrepancy — complements the existing `rootkit-detection.yaml` rule set and `internal/integrity/` startup scan.

**Proposal**

- Use a BPF task iterator (`bpf_iter/task`, kernel 5.8+) to enumerate live tasks.
- Periodically diff against /proc enumeration; any PID visible to the kernel but absent from /proc → critical alert (hidden process).
- Integrate as a periodic check in `internal/integrity/` or a new `internal/hidden/` package, with configurable interval.

### [#156](https://github.com/zugolO/ebpf-guard/issues/156) — feat(detection): bpf() syscall monitoring — detect malicious eBPF program loading

**Motivation**

eBPF-based rootkits (TripleCross, ebpfkit, boopkit) load their own BPF programs to hide traffic and processes. The agent itself uses eBPF, so it is well positioned to watch the `bpf()` syscall.

**Proposal**

- Trace `bpf(BPF_PROG_LOAD)` / `BPF_MAP_CREATE` calls: capture caller comm, pid, program type, and attach type.
- Allowlist the agent's own programs and known-good loaders (cilium, systemd, etc.).
- Alert (severity: critical) on unexpected XDP/TC/kprobe program loads — these are the types rootkits use to hide network traffic.
- Optional LSM enforcement: `lsm/bpf` hook to block unauthorized loads (kernel 5.7+).

### [#157](https://github.com/zugolO/ebpf-guard/issues/157) — feat(detection): JA3/JA4 TLS fingerprinting for C2 detection

**Motivation**

JA3/JA4 ClientHello fingerprints identify C2 frameworks (Cobalt Strike, Sliver, Mythic) without decrypting traffic. We already parse TLS via uprobes (`bpf/tls_uprobe.bpf.c`) and have a TLS event type — fingerprinting is a natural extension.

**Proposal**

- Parse ClientHello fields (TLS version, cipher suites, extensions, EC params) from the socket-level capture or a new TC/socket-filter program.
- Compute JA3 (MD5) and JA4 hashes, add `ja3`/`ja4` fields to `TLSEvent` in `pkg/types`.
- Ship a `tls-fingerprints.yaml` rule set with known-bad fingerprints; support `in`/`not_in` matching on the new fields.
- Optionally integrate threat-intel feed refresh via the existing `internal/osint/` package.

### [#158](https://github.com/zugolO/ebpf-guard/issues/158) — feat(detection): real-time container drift detection against image manifest

**Motivation**

Executing a binary that was not present in the container image at start time is one of the highest-signal runtime indicators (dropped payload, webshell, cryptominer). `internal/drift/` exists — extend it to full image-manifest comparison.

**Proposal**

- On container start, snapshot the set of executable paths from the image layers (via containerd/CRI API or overlayfs lower-dir walk).
- On every exec event, check whether the binary path/inode existed in the baseline; alert on drift with severity critical.
- Support an allowlist for legitimate runtime-generated binaries (JIT, package installs in dev clusters).
- Wire into the enforcer for optional `kill`/`block` response.

### [#159](https://github.com/zugolO/ebpf-guard/issues/159) — feat(profiler): Markov-chain syscall sequence modeling alongside cosine distance

**Motivation**

`SequenceProfiler` currently uses cosine distance over syscall frequency vectors, which captures *what* syscalls run but not their *order*. Markov-chain transition modeling catches subtler deviations (e.g. shellcode performing syscalls in an unusual order while keeping similar frequencies).

**Proposal**

- During the learning period, build a first-order transition probability matrix per workload key (syscall N → syscall N+1).
- At detection time, compute the log-likelihood of observed transition windows; score windows below a learned threshold as anomalous.
- Combine with the existing cosine score (weighted sum or max) and feed into the EWMA anomaly pipeline.
- Keep memory bounded: cap matrix to top-K syscalls per workload, reuse the existing LRU profile eviction.

**Performance target**

Must stay within the existing ProcessEvent < 10µs p99 budget — transition lookup is O(1) per event.

## Indie-Developer / Zero-Config UX

### [#160](https://github.com/zugolO/ebpf-guard/issues/160) — feat(ux): one-command install — curl | sh and docker run with zero config

**Motivation**

Target audience expansion: solo developers and small teams (incl. AI-assisted/"vibe-coded" projects) who will never write a YAML config. For them, installation friction IS the product. Goal: from zero to protected in under 60 seconds.

**Proposal**

- `curl -fsSL https://get.ebpf-guard.io | sh` — detects arch/kernel, downloads signed binary, installs systemd unit, starts with built-in defaults.
- `docker run --privileged ghcr.io/zugolo/ebpf-guard` one-liner that just works.
- No config file required: embedded sane defaults (all built-in rule sets enabled, memory store, auto-generated auth token printed once).
- First-run output: friendly summary of what is being monitored + where alerts go.
- Verify script integrity (checksum pinned in script, cosign-signed binary).

**Acceptance**

A user with no security background gets working runtime protection with a single command on Ubuntu/Debian/RHEL and any Docker host.

### [#161](https://github.com/zugolO/ebpf-guard/issues/161) — feat(notifications): Discord and Telegram notifiers

**Motivation**

The Slack/Teams/webhook fanout (`internal/exporter/`) covers enterprises, but indie developers and small teams live in Discord and Telegram. These are the primary channels for the solo-dev audience.

**Proposal**

- **Discord**: webhook-based notifier (rich embeds: severity color, rule, process tree, suggested action). Config: `notifications.discord.webhook_url`.
- **Telegram**: Bot API notifier (`bot_token` + `chat_id`), Markdown-formatted alerts with severity emoji.
- Reuse the existing notifier interface and rate-limiting/dedup so a noisy rule doesn't flood a channel.
- Both should support a per-severity minimum threshold (e.g. only `critical` to Telegram).

**Acceptance**

Alert fires → message appears in Discord/Telegram within seconds, readable on a phone, with enough context to act.

### [#162](https://github.com/zugolO/ebpf-guard/issues/162) — feat(ux): simple mode — auto-enforcement for unambiguous threats out of the box

**Motivation**

Users without a security background won't triage alerts. For a small, curated set of unambiguous threats, the right default is to stop the attack, not just report it.

**Proposal**

- New `--simple` flag / `mode: simple` config preset:
  - Auto-`kill` for high-confidence detections: known cryptominer binaries/pools (`cryptominer.yaml`), reverse shells with confirmed outbound connection, webshell spawn chains (`webshell-detection.yaml` + lineage confirmation).
  - Everything else stays `alert`-only.
- Safety rails: require BOTH a rule match AND lineage/profiler confirmation before auto-kill (reuse `LineageTracker`); never kill PID 1 or allowlisted system processes; global enforcement rate cap.
- Every enforcement action produces a plain-language notification: what was killed, why, and how to allowlist if it was a false positive.
- `dry_run` preview for the first 24h by default ("would have killed X") before enforcement activates.

**Acceptance**

A cryptominer dropped into a container is killed automatically within seconds, with a clear notification — zero configuration.

### [#163](https://github.com/zugolO/ebpf-guard/issues/163) — feat(explainer): plain-language alert mode for non-security users

**Motivation**

`internal/explainer/` already generates explanations with MITRE references — great for SOC analysts, opaque for a developer who has never heard of T1059. The alert itself should tell a non-expert what happened and what to do.

**Proposal**

- Add a `plain` explanation style to the explainer templates: e.g. instead of "Execution: T1059.004 detected" → "Someone started an interactive shell from your `node` web process. This usually means your app was exploited. Recommended: restart the container and check for an unpatched dependency."
- Three sections per alert: **What happened** / **Why it matters** / **What to do now** (concrete commands where possible).
- Keep MITRE/technical detail available behind a `details` field — don't remove it, layer it.
- Default to plain style in simple mode (see related simple-mode issue), technical style otherwise.

**Acceptance**

A developer reading the alert on their phone understands the incident and the next step without googling MITRE IDs.

### [#164](https://github.com/zugolO/ebpf-guard/issues/164) — docs: deployment guides for indie platforms — Hetzner/VPS, Coolify, Railway, Fly.io, CapRover

**Motivation**

The docs target Kubernetes/Helm users, but the solo-dev audience deploys to cheap VPSes and PaaS-style platforms. Meeting them where they deploy drives adoption (and ADOPTERS.md entries).

**Proposal**

Write copy-paste guides under `docs/platforms/`:

- **Plain VPS (Hetzner/DigitalOcean/OVH)**: systemd install, Docker host protection.
- **Coolify / CapRover / Dokploy**: protecting all containers on a self-hosted PaaS node.
- **Railway / Fly.io / Render**: document what is and isn't possible (eBPF needs host access — clarify shared-runtime limitations honestly, offer sidecar/host patterns where supported).
- Each guide: install, connect Discord/Telegram notifications, verify with a safe test (e.g. simulated suspicious exec), expected resource usage.
- Add a "Which guide do I need?" decision table to the README.

**Acceptance**

Each guide completable in <10 minutes by a developer with no security background.
