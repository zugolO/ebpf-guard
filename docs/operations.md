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

## Zero-Downtime Upgrades: Preserving the EWMA Learning Period

By default each pod restart re-enters the learning phase (`profiler.learning_period`, default 1 hour), during which anomaly detection is suppressed. On a 100-node cluster a rolling update means up to 100 h of aggregate reduced coverage.

### EWMA State Persistence

Enable state persistence to save the learned behavioral baseline to the node's local disk on graceful shutdown and restore it on the next start:

```yaml
# deploy/helm/ebpf-guard/values.yaml
profilerStatePersistence:
  enabled: true
  hostPath: /var/lib/ebpf-guard   # directory on the node
```

Also set the matching config option in `config.yaml`:

```yaml
profiler:
  state_persistence:
    enabled: true
    path: /var/lib/ebpf-guard/profiler-state.json
```

When enabled:

1. On shutdown the agent writes the full EWMA profile (all workload baselines) and learning state to `/var/lib/ebpf-guard/profiler-state.json`.
2. On startup the agent reads the state file. If it is **fresh** (age < 2 × `learning_period`), the learning phase is skipped immediately and anomaly detection resumes from the saved baseline.
3. Stale files (age ≥ 2 × `learning_period`) are silently ignored and the agent starts fresh — this prevents a cold node from scoring against a stale baseline after a long outage.

Monitor the restore outcome:

```promql
# 1 = state was loaded; 0 = fresh start (learning period will apply)
ebpf_guard_profiler_state_restored
```

### Safe Upgrade Runbook

For security-sensitive clusters where even a brief learning window is unacceptable:

1. **Before the upgrade**, verify the current learning state is complete on every node:
   ```promql
   ebpf_guard_learning_progress == 1
   ```
2. **Enable state persistence** (see above) and roll out the change in a preparatory upgrade so the first restart already saves state.
3. **Perform the upgrade**. The rolling update writes state on shutdown and restores it on startup — no learning window on restart.
4. **After each node update**, confirm the metric:
   ```promql
   ebpf_guard_profiler_state_restored == 1
   ```
   A value of `0` after startup means the state was missing or stale; monitor `ebpf_guard_learning_progress` until it returns to `1`.

### Alternative: `OnDelete` Update Strategy

For the most conservative approach (security-critical clusters), switch to the `OnDelete` strategy so nodes are updated one-by-one under human supervision:

```yaml
updateStrategy:
  type: OnDelete
```

Manual procedure per node:

```bash
# 1. Cordon the node so no new workloads schedule
kubectl cordon <node>

# 2. Wait for the learning period to complete (check metric)
watch -n 10 kubectl exec -n ebpf-guard ds/ebpf-guard -- \
  curl -s http://localhost:9090/metrics | grep learning_progress

# 3. Delete the pod (triggers graceful shutdown + state save if persistence is enabled)
kubectl delete pod -n ebpf-guard -l app.kubernetes.io/name=ebpf-guard \
  --field-selector spec.nodeName=<node>

# 4. The DaemonSet controller will NOT restart the pod (OnDelete strategy).
#    Apply the new manifest:
kubectl set image ds/ebpf-guard ebpf-guard=zugolO/ebpf-guard:<new-tag> -n ebpf-guard

# 5. The new pod starts and restores state (if persistence is enabled).
#    Uncordon when learning_progress = 1
kubectl uncordon <node>
```

### BPF Program Continuity Metric

Track whether BPF programs remain attached after an upgrade with:

```promql
# Alert when BPF programs are unexpectedly unloaded
ebpf_guard_collector_up{collector="syscall"} == 0
ebpf_guard_collector_up{collector="network"} == 0
```

Set up a Prometheus alert for these to catch failed BPF attachment during upgrades.

## SQLite Alert Store: Backup and Retention

### Why Backup Matters

The SQLite alert store writes to a single file on the node's local disk. When a DaemonSet pod is evicted, the node fails, or the persistent volume is lost, all stored alerts are permanently gone unless a backup exists. Configure backup and retention to protect historical alert data.

### Retention Policy

Two complementary retention controls are available:

| Setting | Purpose |
|---|---|
| `store.sqlite.max_alerts` | Hard row cap — oldest rows pruned when count exceeds limit |
| `store.sqlite.retention_period` | Time-based purge — alerts older than this are deleted |

Both run on the same `vacuum_interval` cadence (default 1 h). Configure both for defense-in-depth:

```yaml
store:
  backend: sqlite
  sqlite:
    path: /var/lib/ebpf-guard/alerts.db
    max_alerts: 100000       # never exceed 100k rows
    retention_period: 168h   # delete alerts older than 7 days
    vacuum_interval: 1h      # run maintenance (WAL checkpoint + pruning) hourly
```

### Periodic Local Backup

Enable automatic database backups to a second path (e.g. a different volume or a host path mounted as a separate PVC):

```yaml
store:
  sqlite:
    backup:
      enabled: true
      path: /backup/alerts.db   # destination file; directory must exist
      interval: 1h              # how often to create a new backup
```

The backup uses SQLite's `VACUUM INTO` command, which produces a defragmented, WAL-free copy without blocking ongoing reads or writes. The destination file is overwritten on each run; use a volume with its own snapshot policy for versioned history.

> **Tip**: Mount `/backup` from a separate PersistentVolumeClaim so backups survive pod eviction even if the primary data volume is lost.

### Backup Metrics

Monitor backup health with these Prometheus metrics:

| Metric | Type | Description |
|---|---|---|
| `ebpf_guard_store_backup_last_success_timestamp` | Gauge | Unix timestamp of the last successful backup |
| `ebpf_guard_store_backup_duration_seconds` | Histogram | Time taken to complete each backup |
| `ebpf_guard_store_size_bytes` | Gauge | Approximate database size (page_count × page_size) |

Example alert — fire if no successful backup in 2 hours:

```yaml
# deploy/helm/ebpf-guard/templates/prometheusrule.yaml
- alert: SQLiteBackupStale
  expr: |
    time() - ebpf_guard_store_backup_last_success_timestamp > 7200
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "SQLite backup has not succeeded in 2 hours"
    description: "Check that the backup destination path is writable and the backup volume has free space."
```

Track database growth to plan volume capacity:

```promql
ebpf_guard_store_size_bytes / 1024 / 1024
```

### Restore Procedure

1. **Identify the backup file** on the node or in the backup volume:
   ```bash
   ls -lh /backup/alerts.db
   ```

2. **Stop the agent** to prevent writes during restore:
   ```bash
   kubectl delete pod -n ebpf-guard -l app.kubernetes.io/name=ebpf-guard \
     --field-selector spec.nodeName=<node>
   ```

3. **Copy the backup over the primary database**:
   ```bash
   # On the node (via kubectl debug or a maintenance pod)
   cp /backup/alerts.db /var/lib/ebpf-guard/alerts.db
   # Remove stale WAL and SHM files if present
   rm -f /var/lib/ebpf-guard/alerts.db-wal /var/lib/ebpf-guard/alerts.db-shm
   ```

4. **Restart the agent**. The DaemonSet controller will create a new pod automatically.

5. **Verify** alert counts via the API:
   ```bash
   curl -H "Authorization: Bearer <token>" \
     http://<node-ip>:9090/alerts | jq length
   ```

### WAL Mode and Crash Safety

The store opens with `_journal_mode=WAL` and `_synchronous=NORMAL`. This configuration:

- Allows concurrent reads during writes (no reader/writer blocking).
- Is safe against OS crashes (WAL is replayed on next open).
- Is **not** safe against power loss on hardware without battery-backed write cache.

For power-loss safety at the cost of higher write latency, set `synchronous=FULL` in the SQLite pragma configuration.
