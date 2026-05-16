# Notifications Configuration Guide

This guide explains how to configure ebpf-guard to send security alerts to Slack, Microsoft Teams, and generic webhooks.

## Overview

ebpf-guard supports multiple notification backends that operate in parallel. When a security alert is generated, it is sent to:

1. Alertmanager (if configured)
2. All enabled notification backends (Slack, Teams, Webhook)

Each backend has its own configuration and can filter alerts by severity.

## Configuration

Add the `notifications` section to your `config.yaml`:

```yaml
notifications:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
    channel: "#security-alerts"
    min_severity: warning
  teams:
    enabled: true
    webhook_url: "https://outlook.office.com/webhook/..."
    min_severity: critical
  webhook:
    enabled: true
    url: "https://my-siem.internal/alerts"
    headers:
      Authorization: "Bearer ${WEBHOOK_TOKEN}"
      X-Custom-Header: "ebpf-guard"
    template: ""
    min_severity: warning
```

## Slack Setup

### 1. Create a Slack App

1. Go to [api.slack.com/apps](https://api.slack.com/apps)
2. Click **Create New App** → **From scratch**
3. Name your app (e.g., "ebpf-guard") and select your workspace

### 2. Enable Incoming Webhooks

1. In the left sidebar, click **Incoming Webhooks**
2. Toggle **Activate Incoming Webhooks** to On
3. Click **Add New Webhook to Workspace**
4. Select the channel where alerts should be posted (e.g., `#security-alerts`)
5. Click **Allow**

### 3. Copy the Webhook URL

Copy the **Webhook URL** and add it to your `config.yaml`:

```yaml
notifications:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/T00/B00/XXX"
    channel: "#security-alerts"
    min_severity: warning
```

### Slack Message Format

Alerts are sent as Block Kit messages with:
- Header with alert name and emoji (🚨)
- Rule ID and severity
- Process name and PID
- Kubernetes pod/namespace (if available)
- Alert description
- Fingerprint for tamper detection

Severity colors:
- **Warning**: Orange
- **Critical**: Red

## Microsoft Teams Setup

### 1. Create an Incoming Webhook

1. In Teams, go to the channel where you want alerts
2. Click **...** (More options) → **Connectors**
3. Find **Incoming Webhook** and click **Configure**
4. Name it "ebpf-guard" and upload an icon (optional)
5. Click **Create**

### 2. Copy the Webhook URL

Copy the webhook URL and add it to your `config.yaml`:

```yaml
notifications:
  teams:
    enabled: true
    webhook_url: "https://outlook.office.com/webhook/..."
    min_severity: warning
```

### Teams Message Format

Alerts are sent as Adaptive Cards with:
- Header with alert name and severity color
- Description text
- Fact set with metadata (Rule ID, severity, process, pod, namespace)
- Fingerprint for tamper detection

Severity colors:
- **Warning**: Yellow (`warning`)
- **Critical**: Red (`attention`)

## Generic Webhook

The generic webhook notifier allows integration with any HTTP endpoint that accepts POST requests, including:

- PagerDuty Events API
- Discord webhooks
- Custom SIEM endpoints
- Internal alerting systems

### Configuration

```yaml
notifications:
  webhook:
    enabled: true
    url: "https://events.pagerduty.com/v2/enqueue"
    headers:
      Authorization: "Token token=${PAGERDUTY_TOKEN}"
      Content-Type: "application/json"
    template: |
      {
        "routing_key": "${PAGERDUTY_ROUTING_KEY}",
        "event_action": "trigger",
        "payload": {
          "summary": "{{.RuleName}}: {{.Message}}",
          "severity": "{{.Severity}}",
          "source": "ebpf-guard",
          "custom_details": {
            "rule_id": "{{.RuleID}}",
            "pid": {{.PID}},
            "process": "{{.Comm}}",
            "fingerprint": "{{.Fingerprint}}"
          }
        }
      }
    min_severity: critical
```

### Default Template

If no custom template is provided, the default JSON format is:

```json
{
  "alert": {
    "id": "alert-uuid",
    "rule_id": "rule_001",
    "rule_name": "Sensitive File Read",
    "severity": "critical",
    "message": "Process nginx read /etc/shadow",
    "timestamp": "2024-01-15T10:30:00Z",
    "pid": 1234,
    "comm": "nginx",
    "fingerprint": "sha256:abc123..."
  },
  "source": "ebpf-guard",
  "version": "1.0"
}
```

### Template Variables

Available template variables:

| Variable | Type | Description |
|----------|------|-------------|
| `.ID` | string | Alert unique identifier |
| `.RuleID` | string | Rule identifier |
| `.RuleName` | string | Human-readable rule name |
| `.Severity` | string | `warning` or `critical` |
| `.Message` | string | Alert description |
| `.Timestamp` | string | RFC3339 formatted time |
| `.PID` | uint32 | Process ID |
| `.Comm` | string | Process name |
| `.Fingerprint` | string | SHA-256 fingerprint |
| `.Pod` | string | Kubernetes pod name (if available) |
| `.Namespace` | string | Kubernetes namespace (if available) |
| `.ContainerID` | string | Container ID (if available) |
| `.Details` | map | Additional alert details |

### Template Functions

- `json` - JSON-encode a value (useful for messages with quotes)

Example:
```
{{.Message | json}}
```

## Severity Filtering

Each backend supports `min_severity` filtering:

- `warning` - Send both warning and critical alerts (default)
- `critical` - Send only critical alerts

Example configuration for different severities per backend:

```yaml
notifications:
  slack:
    enabled: true
    webhook_url: "..."
    min_severity: warning      # Send everything to Slack
  teams:
    enabled: true
    webhook_url: "..."
    min_severity: critical     # Only critical to Teams
  webhook:
    enabled: true
    url: "..."
    min_severity: critical     # Only critical to PagerDuty
```

## Security Considerations

### Webhook URL Security

- Treat webhook URLs as secrets
- Use environment variables or Kubernetes Secrets
- Rotate webhook URLs periodically
- Restrict network access to webhook endpoints

### Example with Kubernetes Secrets

```yaml
# secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: ebpf-guard-notifications
type: Opaque
stringData:
  slack-webhook: "https://hooks.slack.com/services/..."
  teams-webhook: "https://outlook.office.com/webhook/..."
```

```yaml
# config.yaml
notifications:
  slack:
    enabled: true
    webhook_url: "${SLACK_WEBHOOK_URL}"
```

```yaml
# deployment.yaml
env:
  - name: SLACK_WEBHOOK_URL
    valueFrom:
      secretKeyRef:
        name: ebpf-guard-notifications
        key: slack-webhook
```

## Troubleshooting

### Check Notifications are Enabled

Look for this log line at startup:
```
INFO notification backends configured backends=[slack,teams]
```

If you see:
```
WARN no notification backends configured
```

Check that:
1. `enabled: true` is set for the backend
2. `webhook_url` (Slack/Teams) or `url` (webhook) is not empty

### Test Notifications

Use the dry-run mode to test notifications without eBPF:

```bash
ebpf-guard --dry-run --config config.yaml
```

### Common Issues

| Issue | Solution |
|-------|----------|
| Alerts not appearing | Check `min_severity` filter; verify webhook URL |
| 401 Unauthorized | Check authentication headers |
| 404 Not Found | Verify webhook URL is correct |
| Connection timeout | Check network connectivity and firewall rules |
| Invalid JSON in template | Validate template with `ValidateWebhookTemplate()` |

### Debug Logging

Enable debug logging to see notification send attempts:

```bash
ebpf-guard --log-level debug --config config.yaml
```

Look for:
```
DEBUG alert sent successfully notifier=slack rule_id=rule_001
WARN failed to send alert notifier=teams rule_id=rule_001 error=...
```

## Migration from Alertmanager

If you're currently using only Alertmanager, you can add notification backends alongside it:

```yaml
alerting:
  enabled: true
  webhook_url: "http://alertmanager:9093/webhook"
  # ... other Alertmanager settings

notifications:
  slack:
    enabled: true
    webhook_url: "..."
```

Alerts will be sent to both Alertmanager and Slack.
