# Container Drift Detection

The drift detector compares container runtime behaviour against a per-container baseline captured during an initial learning window. Once the window closes, any deviation from the observed baseline — a new syscall, new binary, new library, new network destination, or new filesystem directory — is reported as a `DriftAlert` and converted to a standard `types.Alert` for the store and exporters.

## Concepts

### Baseline Learning Window

When a container is first seen (identified by `ContainerID` from Kubernetes enrichment), a `ContainerBaseline` is created. For the duration of `baseline_window`, all events for that container are recorded without alerting:

| What's recorded | Source event |
|---|---|
| Syscall numbers | `EventSyscall` |
| Executable paths (`/bin/`, `/sbin/`, `/usr/bin/`, …) | `EventFileAccess` |
| Shared library paths (`.so` suffix or `/lib/` prefix) | `EventFileAccess` |
| Outbound IP addresses and TCP ports | `EventTCPConnect` |
| Accessed filesystem directories | `EventFileAccess` |

After `baseline_window` elapses, the baseline is locked. Subsequent events that deviate from the recorded sets are reported as drift.

### Drift Types

| `DriftType` | Trigger | Default Severity |
|---|---|---|
| `new_syscall` | Syscall number not seen during baseline | `warning` |
| `new_exec` | Binary in a system exec path not in baseline | `critical` |
| `new_library` | Shared library not loaded during baseline | `warning` |
| `new_network` | Outbound IP+port pair not in baseline | `warning` |
| `new_file_dir` | Directory access not in baseline | `warning` |

`new_exec` is rated `critical` because loading an unexpected binary is a strong indicator of container escape, supply chain compromise, or living-off-the-land attacks.

## Configuration

```yaml
profiler:
  enabled: true

# Drift is configured inside the profiler section.
# The Detector is wired into the correlation engine automatically
# when kubernetes.enabled = true and the profiler is enabled.
drift:
  enabled: true
  baseline_window: 5m       # How long to observe before locking the baseline
  stale_ttl: 1h             # How long after baseline expiry before a container is purged
```

`drift.enabled` defaults to `false`. The Detector is only useful when Kubernetes enrichment is active (events must carry a `ContainerID`); events without enrichment are silently skipped.

## Interaction With the EWMA Profiler

The EWMA profiler (`internal/profiler`) maintains per-process behavioural baselines using exponentially-weighted moving averages and emits `anomaly_detection` alerts when a process deviates from its learned pattern.

Drift detection is **complementary, not redundant**:

| Aspect | Drift detector | EWMA profiler |
|---|---|---|
| Scope | Per-container (K8s-aware) | Per-process comm |
| Baseline method | Hard set captured during window | Continuous EWMA update |
| Sensitivity | Binary — in or out of baseline | Continuous score against threshold |
| False-positive risk | Low (new exec/lib is rare in healthy containers) | Higher for noisy processes |
| Best for | Container escape, supply chain, lateral movement | Unusual syscall bursts, reconnaisance loops |

When both modules are active, a container-escape attempt (new exec + anomalous syscall pattern) will fire alerts from both. This is intentional; the two alert types carry different `RuleID` prefixes (`drift_*` and `anomaly_detection`) so they can be correlated downstream.

Gossip amplification signals (if gossip is enabled) also interact: when a `drift_new_exec` alert fires, its alert is broadcast to peers, which temporarily lower their anomaly threshold for the same Kubernetes namespace. See `docs/gossip.md` for details.

## Operational Guidance

### Choosing `baseline_window`

| Workload type | Recommended window |
|---|---|
| Short-lived jobs (batch, CI runners) | 30 s – 2 m |
| Web services (stable steady state) | 5 m (default) |
| Stateful services (DB, ML training) | 10 – 30 m |
| Very dynamic containers | Disable drift, rely on EWMA |

A window that is too short may fail to observe all legitimate paths (e.g. lazy-loaded libraries), causing false positives. A window that is too long delays detection.

### Reducing False Positives

1. **Library lazy loading.** Many runtimes (JVM, Python, Go) load libraries on first use rather than at startup. Use a window long enough to cover a typical startup + initial request cycle.
2. **Init containers.** If your workload runs an init container that execs tools not present in the main container, ensure the init container uses a different `ContainerID` (it will in Kubernetes) so its baseline doesn't pollute the main container's baseline.
3. **Sidecar containers.** Each sidecar has its own `ContainerID` and its own independent baseline.
4. **Rolling deploys.** Each new Pod starts a fresh baseline learning window. This is correct behaviour — a new image version may have new binaries.

### Metrics

| Metric | Description |
|---|---|
| `ebpf_guard_drift_detected_total{type, namespace}` | Total drift alerts partitioned by type and Kubernetes namespace |
| `ebpf_guard_drift_baselines_total` | Number of container baselines currently tracked |
| `ebpf_guard_drift_baselines_locked_total` | Number of baselines past their learning window (drift-detection active) |

Use `ebpf_guard_drift_baselines_locked_total / ebpf_guard_drift_baselines_total` to gauge what fraction of your fleet is past the learning window and being actively monitored.

### Memory Overhead

Each `ContainerBaseline` stores in-memory sets of integers (syscall numbers, ports) and strings (paths, IPs). For a typical web service that makes 50 distinct syscalls, opens 20 libraries, and connects to 5 destinations, a baseline uses roughly 10–30 KB of RAM. For a 1 000-container node, total overhead is approximately 10–30 MB, within the watchdog's memory pressure thresholds.

Stale baselines (containers that have stopped) are purged when `stale_ttl` elapses past their baseline expiry. Set `stale_ttl` to slightly longer than your longest-lived container.
