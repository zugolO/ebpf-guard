# ebpf-guard CLI Reference

The `ebpf-guard` command-line interface provides tools for interacting with the agent, querying alerts, checking status, and managing rules.

## Global Flags

```
  -c, --config string    Config file path (default "/etc/ebpf-guard/config.yaml")
  -l, --log-level string Log level (debug, info, warn, error) (default "info")
      --dry-run          Run in dry-run mode with synthetic events (no eBPF)
  -h, --help             Help for ebpf-guard
  -v, --version          Version for ebpf-guard
```

## Commands

### `ebpf-guard` (default)

Run the ebpf-guard agent. This is the main mode of operation.

```bash
# Run with default config
sudo ebpf-guard

# Run with custom config
sudo ebpf-guard --config /path/to/config.yaml

# Run in dry-run mode (no eBPF required)
ebpf-guard --dry-run

# Run with debug logging
sudo ebpf-guard --log-level debug
```

---

### `ebpf-guard alerts`

Query and display recent security alerts from the agent.

```bash
ebpf-guard alerts [flags]
```

#### Flags

```
  -h, --help              Help for alerts
  -l, --limit int         Maximum number of alerts to show (default 50)
      --namespace string  Filter by namespace
  -o, --output string     Output format (table|json|wide|yaml) (default "table")
      --pod string        Filter by pod name
      --rule string       Filter by rule ID
      --severity string   Filter by severity (warning|critical)
  -s, --server string     Server address (default "http://localhost:9090")
      --since string      Show alerts since duration (default "1h")
  -t, --token string      Bearer token for authentication
```

#### Examples

```bash
# Show recent alerts as table
ebpf-guard alerts

# Show alerts in JSON format
ebpf-guard alerts --output json

# Filter by severity
ebpf-guard alerts --severity critical

# Filter by pod and namespace
ebpf-guard alerts --pod nginx-abc123 --namespace production

# Show more alerts
ebpf-guard alerts --limit 100 --since 24h

# Query specific server with authentication
ebpf-guard alerts --server http://agent:9090 --token "my-token"
```

#### Output Formats

**table** (default):
```
TIME      SEVERITY  RULE      PID   COMM   MESSAGE
15:04:05  CRITICAL  rule_001  1234  nginx  Sensitive file read detected
15:03:12  WARNING   rule_002  5678  bash   Unexpected network egress
```

**wide**:
```
TIME                 SEVERITY  RULE      RULE NAME              PID   COMM   POD          NAMESPACE   MESSAGE
2024-01-15 15:04:05  CRITICAL  rule_001  Sensitive file read    1234  nginx  web-pod-abc  production  Sensitive file read detected
```

**json**:
```json
[
  {
    "id": "alert-1",
    "timestamp": "2024-01-15T15:04:05Z",
    "rule_id": "rule_001",
    "severity": "critical",
    "pid": 1234,
    "comm": "nginx",
    "message": "Sensitive file read detected"
  }
]
```

---

### `ebpf-guard alerts get`

Get detailed information about a specific alert.

```bash
ebpf-guard alerts get <alert-id> [flags]
```

#### Flags

```
  -h, --help          Help for get
  -o, --output string Output format (yaml|json) (default "yaml")
  -s, --server string Server address (default "http://localhost:9090")
  -t, --token string  Bearer token for authentication
```

#### Examples

```bash
# Get alert details
ebpf-guard alerts get alert-abc123

# Get alert as JSON
ebpf-guard alerts get alert-abc123 --output json
```

---

### `ebpf-guard alerts export`

Export alerts in Common Event Format (CEF) for SIEM integration.

```bash
ebpf-guard alerts export [flags]
```

#### Flags

```
  -h, --help            Help for export
  -o, --output string   Output file (default: stdout)
      --severity string Filter by severity
  -s, --server string   Server address (default "http://localhost:9090")
      --since string    Export alerts since duration (default "24h")
  -t, --token string    Bearer token for authentication
```

#### Examples

```bash
# Export all alerts from last 24 hours
ebpf-guard alerts export

# Export to file
ebpf-guard alerts export --output alerts.cef

# Export only critical alerts from last 7 days
ebpf-guard alerts export --severity critical --since 168h --output critical.cef

# Import into Splunk
ebpf-guard alerts export --since 24h | splunk add oneshot -sourcetype cef -
```

---

### `ebpf-guard status`

Show ebpf-guard agent status including health, collectors, and profiler state.

```bash
ebpf-guard status [flags]
```

#### Flags

```
  -h, --help              Help for status
  -i, --interval int      Watch interval in seconds (default 5)
  -o, --output string     Output format (table|json|yaml) (default "table")
  -s, --server string     Server address (default "http://localhost:9090")
  -t, --token string      Bearer token for authentication
  -w, --watch             Watch status continuously
```

#### Examples

```bash
# Show status
ebpf-guard status

# Watch status continuously (refreshes every 5 seconds)
ebpf-guard status --watch

# JSON output for scripting
ebpf-guard status --output json

# Watch with custom interval
ebpf-guard status --watch --interval 10
```

#### Output Example

```
=== Health ===
Healthy:   true
Ready:     true
Uptime:    2h15m30s
Store:     healthy

=== Collectors ===
NAME        HEALTHY  ERROR
syscall     true     -
network     true     -
fileaccess  true     -

=== Profiler ===
Learning Progress:  85.5%
Active Profiles:    12
```

---

### `ebpf-guard status top`

Show top processes by anomaly score.

```bash
ebpf-guard status top [flags]
```

#### Flags

```
  -h, --help          Help for top
  -i, --interval int  Watch interval in seconds (default 2)
  -n, --limit int     Number of processes to show (default 10)
  -s, --server string Server address (default "http://localhost:9090")
  -t, --token string  Bearer token for authentication
  -w, --watch         Watch continuously
```

#### Examples

```bash
# Show top 10 processes by anomaly score
ebpf-guard status top

# Show top 20 processes
ebpf-guard status top --limit 20

# Watch top processes continuously
ebpf-guard status top --watch
```

#### Output Example

```
PID    COMM        SCORE
1234   nginx       0.8543
5678   python3     0.7211
9012   curl        0.6542
```

---

### `ebpf-guard rules list`

List all loaded detection rules.

```bash
ebpf-guard rules list [flags]
```

#### Flags

```
  -h, --help              Help for list
  -o, --output string     Output format (table|json|yaml) (default "table")
  -s, --server string     Server address (default "http://localhost:9090")
      --severity string   Filter by severity
      --tag string        Filter by tag
  -t, --token string      Bearer token for authentication
```

#### Examples

```bash
# List all rules
ebpf-guard rules list

# List rules in JSON format
ebpf-guard rules list --output json

# Filter by tag
ebpf-guard rules list --tag owasp

# Filter by severity
ebpf-guard rules list --severity critical
```

#### Output Example

```
ID        NAME                           SEVERITY  ACTION  TAGS
rule_001  Unexpected network egress      warning   alert   -
rule_002  Sensitive file read            critical  alert   -
owasp_001 OWASP: Path Traversal Attempt  critical  alert   owasp, path-traversal, cwe-22
```

---

### `ebpf-guard rules get`

Get detailed information about a specific rule.

```bash
ebpf-guard rules get <rule-id> [flags]
```

#### Flags

```
  -h, --help          Help for get
  -o, --output string Output format (yaml|json) (default "yaml")
  -s, --server string Server address (default "http://localhost:9090")
  -t, --token string  Bearer token for authentication
```

#### Examples

```bash
# Get rule details
ebpf-guard rules get rule_001

# Get rule as JSON
ebpf-guard rules get rule_001 --output json
```

#### Output Example

```yaml
ID:          rule_001
Name:        Unexpected network egress
Description: Process opened TCP connection to unknown destination
Event Type:  network
Severity:    warning
Action:      alert
Tags:        []

Condition:
  Field:   dport
  Operator: not_in
  Values:  80, 443, 53
```

---

### `ebpf-guard rules reload`

Trigger hot-reload of detection rules.

```bash
ebpf-guard rules reload [flags]
```

#### Flags

```
  -h, --help          Help for reload
  -s, --server string Server address (default "http://localhost:9090")
  -t, --token string  Bearer token for authentication
```

#### Examples

```bash
# Reload rules
ebpf-guard rules reload

# Reload with authentication
ebpf-guard rules reload --token "my-token"
```

---

### `ebpf-guard dashboard`

Interactive live terminal UI (bubbletea) showing events, alerts, and rule statistics in real time.
Requires a build with `-tags tui` (`make build` includes it by default; see `make generate`/`Makefile`
for build tags). Falls back to a clear error ("not compiled in — build with -tags tui") otherwise.

```bash
ebpf-guard dashboard [flags]
```

#### Flags

```
      --config string           Path to config file (default "config/config.yaml")
      --dry-run                 Use synthetic events instead of real eBPF probes
      --fleet string            Comma-separated list of agent base URLs to fan out to; enables fleet mode
      --fleet-token string      Bearer token for every fleet agent (default: $EBPF_GUARD_TOKEN)
      --fleet-interval duration How often to poll each fleet agent (default 3s)
      --log-level string        Log level (default "warn", to keep the TUI clean)
  -h, --help                    Help for dashboard
```

#### Single-agent mode (default)

Runs the full local agent pipeline (collectors + correlation engine) and renders alerts/events as
they're generated on this node:

```bash
# Live view of this agent, real eBPF probes
sudo ebpf-guard dashboard

# Live view without a kernel, using synthetic events
ebpf-guard dashboard --dry-run
```

#### Fleet mode (`--fleet`)

Fleet mode turns the dashboard into a client-side fan-out viewer: instead of running local
collectors, it polls the `/api/v1/alerts` REST API of every agent endpoint given (once per
`--fleet-interval`) and merges their alert streams into a single live view, tagging each alert
with its source node/pod so an operator gets one pane across the whole DaemonSet without standing
up a separate aggregation service.

```bash
# Fan out across two agents
ebpf-guard dashboard --fleet http://node-a:9090,http://node-b:9090

# With auth (agents share one bearer token in fleet mode)
export EBPF_GUARD_TOKEN="my-secret-token"
ebpf-guard dashboard --fleet http://node-a:9090,http://node-b:9090,http://node-c:9090

# Poll less/more aggressively (default 3s)
ebpf-guard dashboard --fleet http://node-a:9090,http://node-b:9090 --fleet-interval 5s
```

In a Kubernetes cluster, resolve one endpoint per DaemonSet pod (e.g. via `kubectl get pods -o
wide -l app=ebpf-guard` and each pod's IP:port, or a headless Service that returns one A record
per pod) and pass the resulting list to `--fleet`.

Fleet mode adds a fifth tab, **Fleet**, listing every configured agent with its up/down status
(derived from whether the last poll succeeded), attributed node, how many distinct alerts have
been observed from it, and when it was last seen — so a dead or unreachable agent is visible
immediately rather than silently missing from the merged alert stream. The **Alerts** tab shows
`pod=` and `node=` next to every alert so its origin is unambiguous when multiple agents are
merged into one view.

Fleet mode does not require Kubernetes enrichment on the remote agents: alerts without pod/node
metadata are attributed to the polled endpoint's `host:port` instead, so it also works against a
handful of bare-metal/VM agents.

**Keybindings:**

```
Tab / 1-5   switch panel (Alerts, Events, Top Rules, Status, Fleet)
j/k or ↑/↓  scroll
p           pause live updates
q           quit
```

## Environment Variables

The CLI respects the following environment variables:

| Variable | Description |
|----------|-------------|
| `EBPF_GUARD_SERVER` | Default server address (overrides `http://localhost:9090`) |
| `EBPF_GUARD_TOKEN` | Default bearer token for authentication |

## Authentication

If the agent is configured with bearer token authentication, you must provide the token for all commands:

```bash
# Using flag
ebpf-guard alerts --token "my-secret-token"

# Using environment variable
export EBPF_GUARD_TOKEN="my-secret-token"
ebpf-guard alerts
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Connection error (agent not running) |
| 3 | Authentication error |

## API Endpoints

The CLI communicates with the agent via the following REST API endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health status |
| `/api/v1/alerts` | GET | List alerts with filters |
| `/api/v1/alerts/{id}` | GET | Get single alert |
| `/api/v1/alerts/export/cef` | GET | Export alerts in CEF format |
| `/api/v1/status` | GET | Agent status |
| `/api/v1/rules` | GET | List loaded rules |
| `/api/v1/rules/reload` | POST | Trigger rules reload |

## Examples

### Daily Security Check

```bash
#!/bin/bash
# daily-check.sh

echo "=== Security Alerts (Last 24h) ==="
ebpf-guard alerts --since 24h --output table

echo ""
echo "=== Critical Alerts ==="
ebpf-guard alerts --severity critical --since 24h

echo ""
echo "=== Agent Status ==="
ebpf-guard status
```

### Export to SIEM

```bash
#!/bin/bash
# export-to-siem.sh

# Export last hour's alerts to Splunk
ebpf-guard alerts export --since 1h | \
  curl -H "Authorization: Splunk <token>" \
       -d @- \
       https://splunk.example.com:8088/services/collector/event

# Export critical alerts to file for archival
ebpf-guard alerts export --severity critical --since 24h --output /var/log/ebpf-guard/critical-$(date +%Y%m%d).cef
```

### Monitor Top Anomalies

```bash
# Watch top anomalous processes
ebpf-guard status top --watch --interval 5
```
