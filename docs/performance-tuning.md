# Performance Tuning

This guide covers strategies for running ebpf-guard efficiently under high event rates.

## Per-Rule Event Sampling

Under high event rates, evaluating every rule against every event can consume significant CPU — especially for high-frequency `warning`-severity rules on common syscalls (`read`, `write`, etc.).

Per-rule sampling lets you evaluate only a fraction of matching events for a rule, reducing CPU load while preserving statistical visibility.

### YAML Configuration

```yaml
rules:
  - id: rule_dns_lookup_volume
    event_type: dns
    severity: warning
    condition:
      field: qname
      op: prefix
      values: [""]
    action: alert
    sampling:
      rate: 0.1          # evaluate 10% of matching events
      mode: random       # "random" (default) or "hash_pid"
```

| Field | Type | Default | Description |
|---|---|---|---|
| `sampling.rate` | float | `1.0` | Fraction of events to evaluate `(0.0, 1.0]`. `1.0` disables sampling. |
| `sampling.mode` | string | `random` | `random` — uniform random draw per event. `hash_pid` — FNV(PID \|\| time) for deterministic per-PID sampling. |

### Sampling Modes

**`random`**: Each event is independently evaluated with probability `rate`. Distribution is correct over time but individual PIDs may be over- or under-represented in any short window.

**`hash_pid`**: Uses a FNV-1 32-bit hash of `(PID || timestamp >> 30)` to decide. The same PID is consistently sampled or skipped within ~1-second windows, preventing alert storms from a single hot process while preserving per-PID statistical correctness.

### Backward-Compatible Flat Fields

The older flat fields continue to work:

```yaml
sample_rate: 0.1           # equivalent to sampling.rate: 0.1
sample_deterministic: true # equivalent to sampling.mode: hash_pid
```

The nested `sampling` block takes precedence when both are present.

### Non-Goals

- `critical`-severity rules are **never** subject to sampling (enforced by the engine and adaptive sampler).
- Sampling does not cause complete loss of an event class — it only reduces the *evaluation* rate for a specific rule.

---

## Global Adaptive Sampling

The adaptive sampler monitors CPU utilization and automatically reduces sample rates for `warning`-severity rules when the system is under load. `critical`-severity rules are always evaluated at 100%.

### Configuration

```yaml
rules:
  adaptive_sampling:
    enabled: true
    trigger_cpu_percent: 80    # activate when CPU > 80%
    warning_sample_rate: 0.25  # evaluate 25% of warning-rule events
    critical_sample_rate: 1.0  # always evaluate critical rules (cannot be changed)
    check_interval: 5s         # how often to sample CPU utilization
```

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Enable adaptive sampling. |
| `trigger_cpu_percent` | `80.0` | CPU threshold `[0, 100]` that activates downsampling. |
| `warning_sample_rate` | `0.25` | Rate applied to `warning` rules when active. |
| `critical_sample_rate` | `1.0` | Always `1.0` — critical rules are never downsampled. |
| `check_interval` | `5s` | CPU check cadence. |

### Behaviour

1. A background goroutine polls CPU utilization every `check_interval`.
2. When CPU exceeds `trigger_cpu_percent`, all `warning`-severity rules are overridden to `warning_sample_rate`.
3. When CPU drops back below the threshold, overrides are cleared and rules return to their individually configured rates.
4. Adaptive overrides are **additive** with per-rule static rates — the stricter of the two is always applied.

---

## Sampling Metrics

| Metric | Labels | Description |
|---|---|---|
| `ebpf_guard_rule_sampled_total` | `rule_id`, `mode` | Events that passed the sampling gate and were evaluated. |
| `ebpf_guard_rule_skipped_total` | `rule_id`, `mode` | Events dropped by the sampling gate (condition not evaluated). |

These counters are only incremented when `sampling.rate < 1.0`. Rules running at full rate contribute zero label cardinality.

### Example Prometheus queries

```promql
# Effective evaluation rate for a rule (fraction that passed sampling)
rate(ebpf_guard_rule_sampled_total{rule_id="rule_dns_lookup_volume"}[1m])
  /
(rate(ebpf_guard_rule_sampled_total{rule_id="rule_dns_lookup_volume"}[1m]) +
 rate(ebpf_guard_rule_skipped_total{rule_id="rule_dns_lookup_volume"}[1m]))

# Total skipped events across all sampling modes
sum by (rule_id) (rate(ebpf_guard_rule_skipped_total[5m]))
```

---

## BPF-Side Sampling

In addition to rule-level sampling, the BPF layer supports kernel-side event dropping via `internal/bpf/sampling.go`. This reduces ring-buffer pressure before events even reach userspace:

```yaml
bpf:
  syscall_sample_rate: 1   # 1-in-N for syscall events (1 = all, 10 = 10%)
  network_sample_rate: 1
  file_sample_rate: 1
```

BPF-side sampling is coarser (per event type, not per rule) and should be used in addition to, not instead of, per-rule sampling for fine-grained control.

---

## Recommended Tuning Workflow

1. **Baseline**: run with full evaluation (`sampling.rate: 1.0`) and observe CPU with `ebpf_guard_correlation_duration_seconds`.
2. **Identify hot rules**: sort `rate(ebpf_guard_rule_sampled_total[5m])` descending to find high-frequency rules.
3. **Apply static sampling** to `warning`-severity rules with high event rates.
4. **Enable adaptive sampling** as a safety net for unexpected load spikes.
5. **Verify alert quality**: compare alert rates before and after sampling with a 5% margin tolerance.
