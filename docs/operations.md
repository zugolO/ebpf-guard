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

The total budget and per-step drain caps are configurable. Individual steps that exceed their sub-budget are logged as warnings but do not block the overall shutdown.

### Configuring the Shutdown Timeout

Set the shutdown budget in `config/config.yaml`:

```yaml
server:
  shutdown_timeout: 30s           # total budget; valid range [5s, 300s], default 30s
  shutdown_drain_enforcement: 5s  # enforcer queue drain cap, default 5s
  shutdown_drain_rego: 5s         # OPA evaluation drain cap, default 5s
```

Override at runtime with the `--shutdown-timeout` flag (takes precedence over config):

```bash
ebpf-guard --shutdown-timeout 60s --config config/config.yaml
```

The flag accepts standard Go duration strings: `30s`, `2m`, `90s`, etc.

### Kubernetes: `terminationGracePeriodSeconds`

The default Kubernetes `terminationGracePeriodSeconds` is 30 s, which matches the default shutdown budget.  For deployments with high alert rates or slow Alertmanager endpoints, increase both values together:

```yaml
# deploy/helm/ebpf-guard/values.yaml
daemonset:
  terminationGracePeriodSeconds: 60
```

And in `config/config.yaml`:

```yaml
server:
  shutdown_timeout: 55s  # leave a 5 s margin before Kubernetes force-kills the pod
```

Or directly in the DaemonSet spec:

```yaml
spec:
  template:
    spec:
      terminationGracePeriodSeconds: 60
```

> **Recommendation**: set `terminationGracePeriodSeconds` to at least **30 s** (default) and increase to **60 s** if Alertmanager webhook latency regularly exceeds 5 s. Always set `server.shutdown_timeout` to at least 5 s less than `terminationGracePeriodSeconds` to avoid a hard kill mid-shutdown.

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

---

## Encryption at Rest (SQLite)

ebpf-guard supports AES-256-GCM column-level encryption for sensitive alert fields
(`message`, `details`, `labels`). Indexable metadata (`severity`, `timestamp`,
`rule_id`, `pid`, `namespace`) is stored in plaintext so queries remain efficient.

### Enabling Encryption

Add the following to your `config.yaml`:

```yaml
store:
  backend: sqlite
  sqlite:
    path: /var/lib/ebpf-guard/events.db
    encryption:
      enabled: true
      key_env: "EBPF_GUARD_DB_KEY"   # or key_file: /run/secrets/db-key
```

The key must be a **64-character hex string** (or a base64 string that decodes to
exactly 32 bytes):

```bash
# Generate a new key (requires openssl)
openssl rand -hex 32
# Example output: a3f1c2...  (64 hex chars)
```

**Never hard-code the key in config files.** Use one of:
- `key_env` — an environment variable set outside the config (systemd unit, pod spec)
- `key_file` — a file readable only by the agent user (e.g. a Kubernetes Secret mount)

### Kubernetes Secret (Helm)

Create a Secret and reference it via `keySecretRef` in `values.yaml`:

```bash
kubectl create secret generic ebpf-guard-db-key \
  --namespace ebpf-guard \
  --from-literal=encryption-key=$(openssl rand -hex 32)
```

```yaml
# values.yaml
config:
  store:
    sqlite:
      encryption:
        enabled: true
        key_env: EBPF_GUARD_DB_KEY
        keySecretRef:
          name: ebpf-guard-db-key
          key: encryption-key
```

The Helm chart injects the secret value as the `EBPF_GUARD_DB_KEY` environment variable
in each DaemonSet pod automatically.

### Startup Behaviour

| Configuration | Startup log |
|---|---|
| Encryption enabled, key loaded | `INFO sqlite: column-level AES-256-GCM encryption enabled` |
| Encryption **disabled** | `WARN sqlite: encryption at rest is disabled — alert data … stored in plaintext` |
| Key misconfigured | Fatal error — agent exits rather than starting with broken encryption |

### Key Rotation Procedure

Rotating the encryption key requires a full re-encryption of the database because
AES-GCM is not key-agnostic. Perform rotation during a maintenance window:

1. **Provision the new key** in your secret manager / Kubernetes Secret but do **not**
   yet update the agent configuration.

2. **Take a plaintext backup** while the old key is still active:
   ```bash
   # On the node
   sqlite3 /var/lib/ebpf-guard/events.db "VACUUM INTO '/tmp/alerts-plaintext.db'"
   ```

3. **Stop the agent** to prevent writes during migration:
   ```bash
   kubectl delete pod -n ebpf-guard -l app.kubernetes.io/name=ebpf-guard \
     --field-selector spec.nodeName=<node>
   ```

4. **Re-encrypt the backup** with the new key using the provided migration script:
   ```bash
   EBPF_GUARD_OLD_KEY=<old-hex-key> \
   EBPF_GUARD_NEW_KEY=<new-hex-key> \
   ebpf-guard store reencrypt \
     --input  /tmp/alerts-plaintext.db \
     --output /var/lib/ebpf-guard/events.db
   ```
   > **Note:** The `store reencrypt` subcommand is planned for v1.1. Until then,
   > delete and recreate the database — historical alerts will be lost — or use
   > SQLite's `.dump` / `.read` with a manual re-insertion script.

5. **Update the secret** so the new key is active and **restart the agent**.

6. **Verify** a sample alert is readable:
   ```bash
   curl -H "Authorization: Bearer <token>" \
     http://<node-ip>:9090/alerts?limit=1 | jq .
   ```

7. **Revoke / delete the old key** from your secret manager.

### Migration: Plaintext → Encrypted

Rows written before encryption was enabled are stored in plaintext. When the agent
starts with encryption enabled it will decrypt new rows normally and fall back to
returning plaintext values for legacy rows (a `DEBUG` log entry is emitted per row).

To fully migrate legacy data, follow the key rotation procedure above treating the
"old key" as absent (step 4 reads plaintext, writes encrypted).

## Audit Log

ebpf-guard writes an **append-only JSONL audit log** for every rule-set change and config hot-reload. This provides a tamper-evident record for forensic investigations ("were the detection rules modified before the incident?") and compliance audits.

### Events Logged

| `event` value      | When emitted |
|--------------------|--------------|
| `rules_loaded`     | Agent startup — initial rule-file load |
| `rules_reloaded`   | Hot-reload triggered by fsnotify (rule file changed on disk) |
| `config_reloaded`  | Config file changed and hot-reloaded |

### Log Format

Each line is a JSON object:

```json
{
  "timestamp":      "2026-06-09T12:34:56Z",
  "event":          "rules_reloaded",
  "source":         "fsnotify",
  "rules_file":     "/etc/ebpf-guard/rules/owasp-web.yaml",
  "rules_added":    3,
  "rules_removed":  1,
  "rules_modified": 2,
  "old_rule_ids":   ["rule_042", "rule_043"],
  "new_rule_ids":   ["rule_042", "rule_043", "rule_044", "rule_045"],
  "checksum_before": "sha256:abc...",
  "checksum_after":  "sha256:def..."
}
```

`old_rule_ids` and `new_rule_ids` are omitted when `include_rule_diffs: false`.

### Configuration

```yaml
audit:
  enabled: true
  path: "/var/log/ebpf-guard/audit.jsonl"
  max_size_mb: 100          # rotate to audit.jsonl.1 at this size
  include_rule_diffs: true  # log full rule-ID lists in addition to counts
```

### Kubernetes / Helm

Enable the audit log by setting `auditLog.enabled: true` in your Helm values. The chart will:

1. Mount a `hostPath` volume at `auditLog.hostDir` (default: `/var/log/ebpf-guard`) on each node.
2. Inject `audit.enabled: true` and `audit.path: <hostDir>/audit.jsonl` into the agent ConfigMap.

```yaml
# values.yaml
auditLog:
  enabled: true
  hostDir: /var/log/ebpf-guard
```

The host directory is created as `DirectoryOrCreate`. Configure your log shipper (Fluentd, Vector, Filebeat) to tail `*.jsonl` files from that directory for SIEM ingestion.

### Retention

The audit log is rotated (renamed to `<path>.1`) when it reaches `max_size_mb`. Only one rotation backup is kept. For longer retention, configure your log shipper to forward entries to a central store before the `.1` file is overwritten, or mount a larger host path and increase `max_size_mb`.
