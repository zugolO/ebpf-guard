# Alert Feedback and False-Positive Suppression

The feedback module (`internal/feedback`) implements an analyst-driven false-positive (FP) suppression loop. When an analyst reviews an alert and marks it as a false positive, the agent adds the `(ruleID, comm)` pair to a suppression set. Future alerts matching that pair are silently dropped before reaching the store or exporters.

This is distinct from rule editing: suppression is process-specific and does not prevent the rule from firing for other processes.

## How It Works

1. The analyst calls `POST /api/v1/alerts/{id}/feedback` with a `verdict` of `false_positive` or `true_positive`.
2. The `feedback.Manager.Submit()` method records the feedback and, for `false_positive` verdicts, adds a suppression entry keyed by `(ruleID, comm)`.
3. `Manager.IsSuppressed(ruleID, comm)` is checked in the alert pipeline. Suppressed alerts are dropped and logged at debug level.
4. All feedback records are persisted to a YAML file (`export_path`) so suppressions survive agent restarts.

For `anomaly_detection` alerts (which use a generic rule ID), suppression is keyed on `comm` only — a single analyst action silences all future anomaly alerts from that process name.

## API

```
POST /api/v1/alerts/{id}/feedback
Authorization: Bearer <token>
Content-Type: application/json

{
  "verdict": "false_positive",
  "reason": "nginx health-check pattern, not an attack"
}
```

Response:

```json
{
  "alert_id": "alert-abc123",
  "verdict": "false_positive",
  "suppressed": true
}
```

`suppressed: true` indicates a new suppression was added. `suppressed: false` on a `false_positive` verdict means the `(ruleID, comm)` pair was already suppressed from a prior submission.

## Configuration

```yaml
feedback:
  enabled: true
  export_path: /var/lib/ebpf-guard/feedback.yaml   # YAML file for persistence (empty = in-memory only)
```

When `export_path` is empty, suppressions are held in memory and lost on restart. For production use, set a persistent path on a mounted volume.

## Suppression Semantics

| Scenario | Suppressed? |
|---|---|
| Same `ruleID` + same `comm` | Yes |
| Same `ruleID` + different `comm` | No |
| Different `ruleID` + same `comm` | No |
| `anomaly_detection` rule + same `comm` | Yes (comm-only key) |
| `true_positive` verdict | Never — only `false_positive` suppresses |

## Persistence Format

The YAML file contains all historical feedback records and is idempotent:

```yaml
records:
  - alert_id: alert-abc123
    verdict: false_positive
    rule_id: rule_042
    comm: nginx
    timestamp: 2026-06-01T12:34:56Z
    reason: health-check pattern
  - alert_id: alert-def456
    verdict: true_positive
    rule_id: rule_001
    comm: bash
    timestamp: 2026-06-01T13:00:00Z
```

On startup, `Manager.LoadFromFile()` replays all `false_positive` records to rebuild the suppression set. Editing the YAML file directly is supported; restart the agent to pick up changes.

## Operational Notes

- **Suppression is permanent.** There is currently no expiry on suppression entries. To re-enable alerts for a `(ruleID, comm)` pair, delete the corresponding record from the YAML file and restart the agent.
- **Wildcard suppression via comm.** Suppression matches the `comm` field (the process name, limited to 15 characters by the kernel). If two different binaries share the same `comm`, they are suppressed together. Use specific rule IDs to narrow scope.
- **Metrics.** The number of active suppressions is visible via the `SuppressionCount()` method; expose it in your monitoring dashboard by adding a gauge in the exporter if needed.
- **Not a replacement for rule tuning.** Feedback suppression is a last resort for noisy rules in specific environments. Prefer adjusting rule conditions (adding `comm` or `namespace` filters) when the false-positive source is structural.
