# ebpf-guard vs Falco vs Tetragon vs KubeArmor — when to pick what

This is an honest comparison.  Every project listed has real strengths and real
gaps.  Use it as a decision tree, not marketing copy.

---

## TL;DR decision tree

```
Do you already run Falco in production?
  └─ Yes → Keep it.  Add ebpf-guard only if you need WASM plugins, EWMA
            anomaly scoring, or TLS plaintext inspection without MITM.

Is Cilium already managing your CNI?
  └─ Yes → Tetragon is a natural fit (same agent, shared maps, low overhead).
            ebpf-guard adds value for TLS inspection and behavioral profiling
            but requires a separate DaemonSet.

Do you need kernel-level mandatory-access enforcement (block, not just alert)?
  └─ Yes → KubeArmor or Tetragon (both have mature LSM enforcement).
            ebpf-guard has nftables/LSM enforcement but it is newer.

Do you need sandboxed user-extensibility?
  └─ Yes → ebpf-guard is currently the only option with WASM plugin isolation.

Do you need behavioral anomaly detection (EWMA baselines + lineage)?
  └─ Yes → ebpf-guard or Tracee (Aqua).  Falco/Tetragon are rule-only.

Do you run on ARM64, s390x, or kernels < 5.8?
  └─ Yes → Falco (widest kernel/arch support via kernel module fallback).
```

---

## Feature matrix

| Feature | ebpf-guard | Falco | Tetragon | KubeArmor |
|---------|-----------|-------|----------|-----------|
| **Detection engine** | YAML rules + WASM plugins + EWMA anomaly | YAML rules | Go policies (TracingPolicy CRD) | YAML policies |
| **WASM plugin isolation** | ✅ wazero sandbox | ❌ native C/Go plugins (no sandbox) | ❌ | ❌ |
| **Behavioral profiling** | ✅ EWMA + sequence + lineage | ❌ | ❌ | ❌ |
| **TLS plaintext inspection** | ✅ SSL_write/SSL_read uprobes | via plugin (native) | ❌ | ❌ |
| **DNS monitoring** | ✅ socket filter, entropy scoring | ✅ | ✅ | ✅ |
| **Kernel version minimum** | 5.4 (full: 5.7 for LSM) | 4.14+ (eBPF), any (module) | 5.4+ | 5.4+ (BPF); 4.15+ (AppArmor) |
| **ARM64 support** | ✅ | ✅ | ✅ | ✅ |
| **Kernel module fallback** | ❌ eBPF-only | ✅ | ❌ | ❌ |
| **Block / enforce** | ✅ nftables + LSM | ✅ (via plugin) | ✅ native | ✅ AppArmor/SELinux/BPF-LSM |
| **MITRE ATT&CK enrichment** | ✅ Rego/OPA | via tags | via policies | via tags |
| **Multi-tenant auth** | ✅ namespace-scoped tokens | ❌ | ❌ | ❌ |
| **Cross-node correlation** | ✅ gossip amplification | ❌ | ❌ | ❌ |
| **Falco rule import** | ✅ Sigma importer | — | ❌ | ❌ |
| **Helm chart** | ✅ | ✅ | ✅ | ✅ |
| **CNCF project** | Sandbox (pending) | Graduated | Incubating | Sandbox |
| **License** | Apache-2.0 | Apache-2.0 | Apache-2.0 | Apache-2.0 |
| **Kernel module** | None | Optional | None | None |
| **Cilium dependency** | None | None | Optional (recommended) | None |

---

## Detailed comparisons

### ebpf-guard vs Falco

**Choose Falco when:**
- You are already running Falco and have an investment in Falco rules.  Use
  `ebpf-guard rules import --source sigma` to evaluate a migration path.
- You need kernel support going back to 4.14 or require a kernel module
  fallback for kernels without eBPF ringbuffer.
- You rely on the Falco plugin ecosystem (AWS CloudTrail, GitHub, etc.) and
  don't need the ebpf-guard equivalents.

**Choose ebpf-guard when:**
- You want WASM plugin isolation: third-party or community-contributed
  detection logic runs in a 16 MiB sandbox with a 100 ms timeout.  A
  malformed Falco plugin can segfault the agent process.
- You want anomaly detection without writing Prometheus recording rules:
  EWMA baselines learn per-PID syscall frequency; deviations generate alerts
  automatically.
- You need TLS plaintext inspection without a proxy: ebpf-guard attaches
  uprobes to `SSL_write`/`SSL_read` in the process memory to see plaintext
  before encryption/after decryption.

### ebpf-guard vs Tetragon

**Choose Tetragon when:**
- You already deploy Cilium for CNI/network policy.  Tetragon runs as part of
  the Cilium agent and shares BPF maps, avoiding a second DaemonSet and
  duplicate kernel programs.
- You need fine-grained TCP/IP enforcement integrated with Cilium network
  policies.
- Your policy team prefers a Kubernetes CRD-native workflow
  (`TracingPolicy` resources) over YAML rule files.

**Choose ebpf-guard when:**
- You do not run Cilium and don't want to introduce it for observability alone.
- You need WASM plugins, behavioral profiling, or TLS plaintext inspection
  (Tetragon has none of these).
- You want Prometheus-native metrics and a built-in HTTP API without deploying
  the Hubble UI or Grafana Cilium dashboards.

### ebpf-guard vs KubeArmor

**Choose KubeArmor when:**
- Mandatory-access enforcement is the primary requirement: KubeArmor's
  AppArmor/SELinux/BPF-LSM enforcement is mature and battle-tested.
- You want a Kubernetes-native policy model where policies are CRDs and
  enforcement is declarative.
- You operate on kernels < 5.7 where eBPF LSM is not available.

**Choose ebpf-guard when:**
- Detection and anomaly scoring are more important than enforcement.
  ebpf-guard is detection-first; enforcement is additive.
- You need WASM extensibility or behavioral profiling.
- You want a single binary that handles detection, profiling, Alertmanager
  integration, and notification fanout without an operator component.

---

## Benchmark numbers

The table below uses the reproducible benchmark harness from `docs/benchmark-competitor-analysis.md`.
Run `make bench` on identical hardware to reproduce.

| Metric | ebpf-guard | Notes |
|--------|-----------|-------|
| Rule evaluation latency (p99) | < 5 µs | correlation engine, 100 rules |
| WASM plugin evaluation (p99) | ~53 µs | one plugin, fresh-instance model |
| Profiler ProcessEvent (p99) | < 10 µs | EWMA update + anomaly check |
| BPF ring buffer drop rate | 0% at 50k events/s | 256 KB buffer, adaptive sampling |

For a head-to-head CPU overhead comparison see `docs/benchmark-competitor-analysis.md`.

---

## Migration path from Falco

1. Run both agents side-by-side in `--dry-run` mode for one week.
2. Use `ebpf-guard rules import --source sigma` to import your Sigma/Falco
   rules.
3. Compare alert output with the attack simulator:
   `ebpf-guard attack-sim --run-all`
4. Once parity is confirmed, disable Falco and promote ebpf-guard to
   enforcement mode.

---

*Last updated: 2026-06-12.  Open a PR to correct any inaccuracy.*
