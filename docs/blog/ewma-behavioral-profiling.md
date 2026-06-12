# How ebpf-guard learns what "normal" looks like — EWMA behavioral profiling and lineage tracking

*Published: 2026-06-12*

Most eBPF security tools work by matching events against rules: "alert if
process X opens /etc/shadow."  Rules are great for known-bad patterns but miss
the unknown.  ebpf-guard adds a second layer: it learns a behavioral baseline
for every process and flags deviations, even when no rule matches.

This post walks through the EWMA profiler and lineage tracker — the two
components that give ebpf-guard anomaly detection without ML complexity.

---

## The problem: rules miss unknown unknowns

A rule engine is a finite state machine.  It matches what you anticipated.
Sophisticated attackers deliberately avoid matching rules:

- They use LOLBins (living-off-the-land binaries) already on the system.
- They execute payloads that look like legitimate traffic to a rule author.
- They pivot slowly over hours to stay below burst-rate thresholds.

Behavioral profiling catches these cases by asking: *does this process behave
like it did yesterday?*

---

## EWMA: a lightweight per-PID baseline

EWMA stands for **Exponentially Weighted Moving Average**.  The idea is simple:
instead of remembering every event ever seen (expensive), maintain a running
average that gives more weight to recent observations and exponentially forgets
old ones.

For each PID, ebpf-guard tracks syscall frequency as a rolling average:

```
new_average = α × current_rate + (1 - α) × old_average
```

where `α` (the EWMA weight, default 0.1) controls how quickly the baseline
adapts.  A low `α` means the baseline adapts slowly and is harder to game by a
patient attacker.

An **anomaly score** is computed as the normalised distance from the current
rate to the EWMA baseline.  When the score exceeds `anomaly_threshold`
(default: 3.0 standard deviations), an alert fires.

### Learning period

The profiler silently absorbs events for `learning_period` seconds (default
3600 s) before scoring.  This avoids false positives during startup or after a
new deployment, when the baseline is still noisy.

```yaml
profiler:
  enabled: true
  learning_period: 3600
  ewma_weight: 0.1
  anomaly_threshold: 3.0
```

### Why not a full time-series model?

For a single-binary security agent running on every node of a cluster,
memory is precious.  A proper time-series model (Prophet, ARIMA) would consume
tens of MB per PID.  EWMA requires two float64 values per PID — order of
magnitude smaller — and is O(1) to update.

---

## SequenceProfiler: catching behaviour chains

Frequency anomalies catch "too many of X."  But some attacks look normal in
frequency yet are anomalous in *sequence*: a shell that never calls `execve`
suddenly does, then immediately calls `ptrace`.

The `SequenceProfiler` maintains a **sliding window** of the last N syscall
numbers seen per PID and represents each window as a normalised vector.  It
computes the **cosine distance** between the current window and the PID's
historical window:

```
distance = 1 - (A · B) / (|A| × |B|)
```

A distance above `sequence.threshold` (default: 0.8) indicates the syscall
pattern has changed significantly.

```yaml
profiler:
  sequence:
    enabled: true
    window_size: 20
    threshold: 0.8
```

---

## LineageTracker: attack chains across generations

The most dangerous attacks aren't single-process events — they are process
chains: a web server spawns a shell, which spawns a downloader, which drops a
binary, which calls back to C2.  No individual link looks alarming in isolation.

The `LineageTracker` builds a **parent-process tree** using `ppid` and
`parent_comm` fields from the BPF events.  It correlates alerts along the tree:
if PID 1234 fires a network alert, and PID 1234's grandparent is `nginx`, the
lineage score is elevated.

When the lineage depth (number of anomalous ancestors) exceeds
`lineage.max_depth` within a `lineage.ttl` window, ebpf-guard emits a
`LINEAGE_ATTACK_CHAIN` alert with the full chain in `details`.

```yaml
profiler:
  lineage:
    enabled: true
    ttl: 300s
    max_depth: 5
```

---

## Putting it all together

At runtime, every event passes through three profiler stages in sequence:

```
Event
  └─ EWMA scorer   → alert if frequency anomaly
  └─ SequenceProfiler → alert if syscall pattern changed
  └─ LineageTracker → alert if attack chain depth exceeded
       └─ CorrelationEngine → aggregate + export
```

All three stages run synchronously in < 10 µs p99 (see benchmarks).

---

## False positive management

Behavioral profiling inherently has false positives.  ebpf-guard provides
several knobs:

- **`min_learning_samples`**: ignore PIDs with fewer than N events — short-lived
  processes should not establish a baseline.
- **`profile_ttl`**: evict PID profiles after this duration of inactivity.
- **Rate limiting** (`rules.rate_limit_alerts`): cap alert output during
  noisy periods like deployments.
- **`--simulate` mode**: count what *would* fire without actually alerting.
  Run for 24 h after enabling the profiler to tune thresholds before going live.

```bash
ebpf-guard --simulate --simulate-duration 24h --config config/config.yaml
```

---

## What's next

The current EWMA model is per-PID and per-syscall-frequency.  Planned
improvements include:

- Per-container profile aggregation (normalise across replicas).
- Network peer novelty scoring (alert on first-time outbound IP per image).
- User-mode plugins (WASM) that can implement custom scoring functions.

See [docs/wasm-plugins.md](wasm-plugins.md) for the WASM extension point.
