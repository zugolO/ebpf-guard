# ebpf-guard explain

The `explain` feature provides human-readable explanations for security alerts, including context, severity justification, actionable mitigations, and MITRE ATT&CK mappings. This helps operators understand what happened, why it's dangerous, and what to do next.

## Overview

Unlike traditional security tools that only show raw alert data, ebpf-guard's explain feature:

- **Provides context** about the detected activity
- **Explains severity** with clear reasoning
- **Suggests mitigations** with specific commands
- **Maps to MITRE ATT&CK** for threat intelligence correlation
- **Supports multiple output formats** (text, JSON, Markdown)

## Usage

### CLI Commands

```bash
# Explain a specific alert by fingerprint
ebpf-guard explain sha256:abc123def456

# Explain the most recent alert
ebpf-guard explain --last

# Explain all alerts from the last hour
ebpf-guard explain --all

# Output as JSON
ebpf-guard explain <fingerprint> --output json

# Output as Markdown
ebpf-guard explain <fingerprint> --output markdown
```

### REST API

```bash
# Get explanation for an alert by ID
curl http://localhost:9090/api/v1/alerts/<alert-id>/explain

# Get explanation by fingerprint
curl http://localhost:9090/api/v1/explain/<fingerprint>
```

Response format:
```json
{
  "alert": { ... },
  "explanation": {
    "summary": "Web server nginx spawned a shell process (PID 1234)",
    "detail": "The web server process nginx (PID 1234...)...",
    "severity": "critical",
    "severity_why": "Critical severity because web server spawning shell...",
    "mitigations": [
      "Immediately investigate process nginx (PID 1234)...",
      "Check web server access logs for suspicious requests..."
    ],
    "references": [
      "https://attack.mitre.org/techniques/T1190/"
    ],
    "mitre": {
      "tactic": "Initial Access",
      "technique_id": "T1190",
      "technique": "Exploit Public-Facing Application",
      "url": "https://attack.mitre.org/techniques/T1190/"
    }
  }
}
```

## Example Output

### Text Format (Default)

```
Web server nginx spawned a shell process (PID 1234)
====================================================

SEVERITY: CRITICAL
Why: Critical severity because web server spawning shell is a classic indicator 
of successful remote code execution (RCE) exploitation.

DETAIL:
The web server process nginx (PID 1234, parent: nginx) spawned a shell process. 
This is highly suspicious behavior as web servers should not typically spawn 
interactive shells. This pattern is commonly associated with successful 
exploitation of web applications...

MITIGATIONS:
  1. Immediately investigate process nginx (PID 1234) and its parent nginx
  2. Check web server access logs for suspicious requests
  3. Review process tree: ps auxf | grep -A5 -B5 1234
  4. Check for webshells: find /var/www -name '*.php' | xargs grep -l 'system'
  5. Consider isolating pod web-app-xyz in namespace production

REFERENCES:
  - https://attack.mitre.org/techniques/T1190/
  - https://attack.mitre.org/techniques/T1505/003/

MITRE ATT&CK:
  Tactic:    Initial Access
  Technique: T1190 - Exploit Public-Facing Application
  URL:       https://attack.mitre.org/techniques/T1190/
```

### JSON Format

```json
[
  {
    "alert": { ... },
    "explanation": {
      "summary": "Web server nginx spawned a shell process",
      "detail": "The web server process nginx...",
      "severity": "critical",
      "severity_why": "Critical severity because...",
      "mitigations": [...],
      "references": [...],
      "mitre": {
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique": "Exploit Public-Facing Application",
        "url": "https://attack.mitre.org/techniques/T1190/"
      }
    }
  }
]
```

### Markdown Format

```markdown
# Web server nginx spawned a shell process (PID 1234)

**Severity:** CRITICAL

**Why:** Critical severity because web server spawning shell...

## Detail

The web server process nginx (PID 1234)...

## Mitigations

- Immediately investigate process nginx (PID 1234)
- Check web server access logs...

## References

- [https://attack.mitre.org/techniques/T1190/](https://attack.mitre.org/techniques/T1190/)

## MITRE ATT&CK

- **Tactic:** Initial Access
- **Technique:** T1190 - Exploit Public-Facing Application
- **URL:** [https://attack.mitre.org/techniques/T1190/](https://attack.mitre.org/techniques/T1190/)
```

## MITRE ATT&CK Coverage

To see which MITRE ATT&CK tactics and techniques are covered by the loaded rules:

```bash
ebpf-guard rules mitre-coverage
```

Output:
```
MITRE ATT&CK Coverage
=====================

TACTIC              TECHNIQUE ID    TECHNIQUE NAME
------              -------------   ----------------
Initial Access      T1190           Exploit Public-Facing Application
Execution           T1059           Command and Scripting Interpreter
Persistence         T1505           Server Software Component
Credential Access   T1003           OS Credential Dumping
Discovery           T1087           Account Discovery
Command and Control T1071           Application Layer Protocol
Exfiltration        T1041           Exfiltration Over C2 Channel
Impact              T1529           System Shutdown/Reboot

Total: 8 tactics, 15 techniques covered
```

## Template System

Explanations are generated from YAML templates stored in `internal/explainer/templates/`. Each template contains:

- **ID**: Unique identifier matching rule IDs or patterns
- **Summary**: One-line description
- **Detail**: Detailed explanation of the threat
- **Severity**: Severity level with justification
- **Mitigations**: Actionable steps to investigate and remediate
- **References**: Links to MITRE ATT&CK and other resources
- **MITRE**: ATT&CK tactic and technique mapping

### Template Variables

Templates support Go template syntax with these variables:

- `{{.RuleID}}` - The rule ID that triggered
- `{{.RuleName}}` - Human-readable rule name
- `{{.Severity}}` - Alert severity
- `{{.PID}}` - Process ID
- `{{.Comm}}` - Process name (command)
- `{{.PPID}}` - Parent process ID
- `{{.ParentComm}}` - Parent process name
- `{{.Pod}}` - Kubernetes pod name
- `{{.Namespace}}` - Kubernetes namespace
- `{{.Message}}` - Alert message
- `{{.Fingerprint}}` - Alert fingerprint

### Template Functions

- `{{.Comm | upper}}` - Convert to uppercase
- `{{.Comm | lower}}` - Convert to lowercase
- `{{.Comm | title}}` - Convert to title case

## Categories

Templates are organized by threat category:

### Lineage (`templates/lineage.yaml`)
Process parent-child relationship anomalies:
- `lineage_web_shell_spawn` - Web server spawning shell
- `lineage_shell_network_tool` - Shell spawning network tools
- `lineage_shell_interpreter` - Shell spawning interpreters

### File (`templates/file.yaml`)
Sensitive file access patterns:
- `file_etc_passwd_read` - Reading /etc/passwd
- `file_etc_shadow_read` - Reading /etc/shadow (critical)
- `file_path_traversal` - Path traversal attempts
- `file_sensitive_write` - Writes to sensitive locations

### Network (`templates/network.yaml`)
Network anomalies:
- `network_unexpected_egress` - Unexpected outbound connections
- `network_ssrf_attempt` - Potential SSRF

### DNS (`templates/dns.yaml`)
DNS threat patterns:
- `dns_dga_detected` - DGA domain queries
- `dns_tunneling` - DNS tunneling detection
- `dns_suspicious_tld` - Suspicious TLD queries

### Container (`templates/container.yaml`)
Container escape attempts:
- `container_mount_escape` - Mount syscall from container
- `container_nsenter_escape` - nsenter usage
- `container_sysrq_trigger` - Write to sysrq-trigger

### TLS (`templates/tls.yaml`)
TLS inspection findings:
- `tls_basic_auth_exposed` - Credentials in TLS traffic
- `tls_suspicious_user_agent` - Suspicious User-Agent

### Sequence (`templates/sequence.yaml`)
Syscall sequence anomalies:
- `sequence_anomaly_detected` - Behavioral anomaly

## Performance

The explainer is designed for zero overhead on the event processing path:

- **No hot path impact**: Explanations are generated only on explicit request
- **Template caching**: Templates are loaded once at 
