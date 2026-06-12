# Surviving event storms — adaptive sampling, backpressure, and the overflow budget

*Published: 2026-06-12*

A production Kubernetes node can generate 100,000+ eBPF events per second
during a `kubectl exec` interactive session, a container image build, or a
CI job.  A security agent that drops to alerting on only a fraction of events
during storms is worse than useless — it gives a false sense of coverage.

ebpf-guard uses a layered approach to stay alive under burst load while
maintaining guaranteed coverage for high-severity events.

---

## Layer 1: BPF ring buffer backpressure

The BPF ring buffer (`perf_event_array` replacement, kernel 5.8+) is
pre-allocated at 256 KB per CPU by default.  When the userspace consumer (our
ring buffer reader goroutine) falls behind, the kernel drops new events and
increments a counter in the map.

ebpf-guard reads this counter every second and exposes it as a Prometheus gauge:

```
ebpf_guard_bpf_ring_buffer_drops_total
```

When drops exceed a configurable threshold, the `MemoryPressureWatcher`
automatically reduces the `SequenceProfiler` window size or disables it
entirely.  The core rule engine is never disabled.

```yaml
watchdog:
  memory_pressure:
    enabled: true
    low_memory_threshold: 0.75       # 75% heap → reduce sequence window
    disable_sequence_threshold: 0.85 # 85% heap → disable sequence profiler
    disable_all_threshold: 0.95      # 95% heap → disable all anomaly scoring
```

---

## Layer 2: per-event-type sampling

Not all events are equally valuable.  A `write` syscall on a `nginx` worker
at 50k/s carries little signal; a `ptrace` syscall on any process is always
interesting.

BPF programs can be configured with per-event-type sample rates:

```yaml
bpf:
  sampling:
    syscall: 100      # every 100th syscall event
    network: 1        # every network event (never sampled)
    file: 10          # every 10th file event
    dns: 1            # every DNS event
    tls: 1            # every TLS event
    privesc: 1        # every privilege escalation
```

Sampling is implemented in the BPF program using a per-CPU counter modulo the
sample rate — no userspace involvement, zero latency penalty on the hot path.

Critical event types (privesc, kmod_load, cgroup_esc) are hardcoded to
sample rate 1 and cannot be changed via config to prevent accidental
misconfiguration.

---

## Layer 3: event queue and bounded worker pool

Between the ring buffer reader and the correlation engine sits a bounded Go
channel (`eventCh`) of configurable depth:

```yaml
bpf:
  event_queue_depth: 10000  # default: correlator.buffer_size
  overflow_policy: drop     # drop | block
```

Under sustained overload, `overflow_policy: drop` discards the oldest events
(FIFO queue drop) and increments:

```
ebpf_guard_event_queue_overflows_total
```

`overflow_policy: block` provides backpressure to the ring buffer reader,
which will in turn let the kernel ring buffer fill up and drop at BPF level.
Use `block` when you prefer to lose events at the kernel level (with accurate
drop counters) rather than silently in Go.

Alert I/O (store + forward) runs in a bounded worker pool:

```yaml
bpf:
  max_concurrent_events: 4096
```

When the pool is saturated, dispatch is dropped and counted in
`ebpf_guard_event_queue_overflows_total`.

---

## Layer 4: alert rate limiting

Even if every event is processed, a single noisy rule can flood alert storage.

```yaml
rules:
  rate_limit_alerts: true
  rate_limit_window: 60       # seconds
  max_alerts_per_window: 100  # per rule per window
```

Rate limiting is implemented in the correlator with per-rule sliding windows.
Dropped alerts increment `ebpf_guard_rate_limited_alerts_total{rule_id=...}`.

Additionally, the correlator has a global per-second cap:

```yaml
correlator:
  max_alerts_per_second: 500
```

---

## The overflow budget: what to watch

Deploy these Prometheus alerts to detect when the overflow budget is being
consumed:

```yaml
# Alert when BPF ring buffer drops > 1% of events.
- alert: EBPFGuardRingBufferDropping
  expr: rate(ebpf_guard_bpf_ring_buffer_drops_total[5m]) > 0.01 * rate(ebpf_guard_events_total[5m])
  for: 5m
  labels:
    severity: warning

# Alert when the event queue is regularly overflowing.
- alert: EBPFGuardQueueOverflow
  expr: rate(ebpf_guard_event_queue_overflows_total[5m]) > 10
  for: 2m
  labels:
    severity: warning

# Alert when anomaly scoring is auto-disabled due to memory pressure.
- alert: EBPFGuardAnomalyScoringDisabled
  expr: ebpf_guard_memory_pressure_profiler_disabled == 1
  labels:
    severity: warning
```

A Grafana dashboard shipping in `deploy/helm/ebpf-guard/` includes these panels
pre-wired.

---

## Sizing the ring buffer

The default 256 KB ring buffer is tuned for < 10k events/s.  For higher
rates:

```yaml
bpf:
  ring_buffer_size_pages: 2048   # 2048 × 4 KB = 8 MB
```

The ring buffer is allocated from non-pageable kernel memory.  At 8 MB × 128
CPUs = 1 GB, you will hit MEMLOCK limits.  Raise them in the DaemonSet spec:

```yaml
securityContext:
  capabilities:
    add: [SYS_ADMIN]
resources:
  limits:
    memory: 512Mi
```

Or use BTF-based map sizing to automatically scale ring buffer size with the
number of CPUs:

```yaml
bpf:
  auto_size_maps: true
```

---

## Benchmark numbers

These figures are from the reproducible benchmark harness (`make bench`):

| Scenario | Event rate | CPU overhead | Drop rate |
|----------|------------|-------------|-----------|
| Idle node | < 100/s | < 0.01% | 0% |
| Active webapp | ~5k/s | ~0.3% | 0% |
| CI job / build | ~50k/s | ~1.5% | 0% |
| Kernel compile | ~200k/s | ~4% | < 0.1% |

Tested on a 4-core VM (c5.xlarge, 4 GB RAM, kernel 6.1).  Your results will
vary with event mix, rule count, and WASM plugin load.

For a reproducible benchmark comparing ebpf-guard overhead against Falco and
Tetragon, see `docs/benchmark-competitor-analysis.md`.
