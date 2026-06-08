# Operations Guide

## Graceful Shutdown

ebpf-guard performs an ordered, time-bounded shutdown when it receives `SIGTERM` or `SIGINT`. This ensures that alerts generated in the final seconds before shutdown are not silently lost.

### Shutdown Sequence

1. **Stop BPF collectors** — ring-buffer readers are closed so no new kernel events enter the pipeline.
2. **Drain enforcement queue** (≤ 5 s) — in-flight kill/block/throttle actions are allowed to complete.
3. **Drain Rego evaluation queue** (≤ 5 s) — async OPA enrichment workers finish so all generated alerts include MITRE ATT&CK context.
4. **Flush correlation engine** — the remaining `pending` alert buffer is written to the alert store and forwarded to Alertmanager / notification backends.
5. **Flush alert store** — for SQLite, a WAL checkpoint is triggered so data is durable even after an ungraceful OS restart.
6. **Flush Alertmanager** — any batched or in-flight webhook deliveries are completed.
7. **Close notification fanout** — Slack / Teams / webhook backends are drained.
8. **Cleanup enforcement chains** — nftables / iptables rules installed by the enforcer are removed.
9. **Shutdown HTTP server** — in-flight API requests are drained.

The entire procedure has a **30-second budget**. Individual steps that exceed their sub-budget are logged as warnings but do not block the overall shutdown.

### Kubernetes: `terminationGracePeriodSeconds`

The default Kubernetes `terminationGracePeriodSeconds` is 30 s, which matches the shutdown budget.  For deployments with high alert rates or slow Alertmanager endpoints, increase this to 60 s to give the flush steps more headroom:

```yaml
# deploy/helm/ebpf-guard/values.yaml
daemonset:
  terminationGracePeriodSeconds: 60
```

Or directly in the DaemonSet spec:

```yaml
spec:
  template:
    spec:
      terminationGracePeriodSeconds: 60
```

> **Recommendation**: set `terminationGracePeriodSeconds` to at least **30 s** (default) and increase to **60 s** if Alertmanager webhook latency regularly exceeds 5 s.

### Shutdown Metric

The `ebpf_guard_shutdown_duration_seconds` Prometheus gauge records the wall-clock time of the last graceful shutdown. Scrape this value after a rolling update or node drain to confirm shutdown completed within budget:

```promql
ebpf_guard_shutdown_duration_seconds
```

Values above 28 s indicate the shutdown is approaching the budget limit and `terminationGracePeriodSeconds` should be increased.

### Alert Loss Prevention

The shutdown sequence guarantees zero alert loss under normal conditions:

| Scenario | Guarantee |
|---|---|
| Alert buffered in engine pending queue | Flushed in step 4 |
| Alert in async Rego evaluation | Drained in step 3, then flushed in step 4 |
| Alert batched for Alertmanager | Delivered in step 6 |
| Alert written to SQLite WAL | Checkpointed in step 5 |

If the node is hard-killed (OOM killer, power loss) before shutdown completes, SQLite WAL data written with `synchronous=NORMAL` is safe against OS crashes but not against power failures. For power-loss safety, set `synchronous=FULL` in the SQLite pragma configuration (at the cost of higher write latency).

## Rolling Updates

During a DaemonSet rolling update, the `ebpf-guard` pod on each node receives `SIGTERM` and has `terminationGracePeriodSeconds` to complete the shutdown sequence. The new pod starts on the same node only after the old pod terminates. There is a brief window (typically < 1 s) where neither pod is running; events during this window are not captured. This is expected behaviour for eBPF-based agents.

To minimise the gap, use `maxUnavailable: 0` and `maxSurge: 1` in the rolling update strategy — note this requires nodes to temporarily run two DaemonSet pods.
