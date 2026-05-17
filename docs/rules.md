# Rego Policy Authoring Guide

This guide explains how to write and test Rego policies for ebpf-guard's Policy-as-Code engine.

## Overview

ebpf-guard uses [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) Rego language for defining security policies. Rego policies are evaluated **after** YAML-based rule filtering, ensuring OPA's performance overhead only applies to confirmed alerts, not raw events.

## Architecture

```
Raw Events (10k/sec)
    ↓
YAML Correlator (filters 99.9%)
    ↓
Confirmed Alerts (~10/sec)
    ↓
Rego Engine (policy enrichment)
    ↓
Enhanced Alerts with MITRE mapping
```

**Performance Target:** < 500µs p99 for Rego evaluation using pre-compiled policies.

## Directory Structure

```
rules/rego/
├── base.rego           # Helper functions and base package
├── lineage.rego        # Process lineage detection rules
├── network.rego        # Network-based detection rules
├── file.rego           # File access detection rules
├── dns.rego            # DNS threat detection rules
└── test/
    ├── lineage_test.rego   # Unit tests for lineage rules
    └── network_test.rego   # Unit tests for network rules
```

## Writing Rego Policies

### Basic Structure

```rego
package ebpf_guard.lineage

# Rule definition
rules[{"rule_id": "my_rule", "severity": "critical", "message": msg, "action": "alert", "mitre_technique": "T1059", "matched": true}] {
    # Conditions
    input.event.parent_comm == "nginx"
    input.comm == "bash"
    
    # Message construction
    msg := sprintf("Shell spawned from nginx: pid=%d", [input.pid])
}
```

### Input Schema

The `input` variable contains the alert structure:

```rego
input := {
    "id": "alert-123",
    "rule_id": "yaml_rule_001",
    "rule_name": "Suspicious Activity",
    "severity": "warning",
    "pid": 1234,
    "comm": "bash",
    "message": "Original alert message",
    "details": {...},
    "trace_id": "abc-123",
    "enrichment": {
        "pod_name": "my-pod",
        "namespace": "production",
        "pod_uid": "...",
        "node_name": "node-1",
        "labels": {...},
        "annotations": {...},
        "container_id": "..."
    },
    "event": {
        "type": 1,  # EventSyscall=1, EventTCPConnect=2, EventFileAccess=3
        "timestamp": 1234567890,
        "pid": 1234,
        "tgid": 1234,
        "ppid": 1000,
        "uid": 1000,
        "comm": "bash",
        "parent_comm": "nginx",
        "syscall": {...},    # If type=1
        "network": {...},    # If type=2
        "file": {...},       # If type=3
        "tls": {...},        # If type=4
        "dns": {...}         # If type=5
    }
}
```

### Event Type-Specific Fields

#### Syscall Event

```rego
input.event.syscall.nr   # Syscall number
input.event.syscall.ret  # Return value
input.event.syscall.args # Array of 6 arguments
```

#### Network Event

```rego
input.event.network.saddr  # Source IP (16 bytes, IPv4 in first 4)
input.event.network.daddr  # Destination IP (16 bytes)
input.event.network.sport  # Source port
input.event.network.dport  # Destination port
input.event.network.proto  # Protocol number
input.event.network.family # Address family (2=IPv4, 10=IPv6)
```

#### File Event

```rego
input.event.file.filename  # File path (256 bytes)
input.event.file.flags     # Open flags
input.event.file.mode      # File mode
input.event.file.op        # Operation (0=open, 1=read, 2=write)
```

#### DNS Event

```rego
input.event.dns.qname         # Query name (domain)
input.event.dns.qtype         # Query type (1=A, 28=AAAA, 16=TXT)
input.event.dns.rcode         # Response code (0=success, 3=NXDOMAIN)
input.event.dns.direction     # 0=query, 1=response
input.event.dns.response_ips  # Array of IP strings
```

### Helper Functions

The `base.rego` file provides common helper functions:

```rego
# Port checks
is_privileged_port(port)  # port < 1024
is_mining_port(port)      # 3333, 3334, 45700, 45560, 14444

# Path checks
is_sensitive_path(path)       # /etc/shadow, /etc/passwd, etc.
is_container_escape_path(path)  # /proc/1/root, etc.

# Process checks
is_shell(comm)        # bash, sh, zsh, python, perl, ruby
is_webserver(comm)    # nginx, apache, httpd, lighttpd, caddy
is_database(comm)     # mysql, postgres, mongodb, redis-server
is_miner(comm)        # xmrig, minerd, cgminer, etc.

# IP checks
is_private_ip(ip_bytes)  # 10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x

# String utilities
shannon_entropy(s)    # Calculate Shannon entropy
```

### Rule Severity and Action

**Severity levels:**
- `"critical"` - High-priority security events requiring immediate attention
- `"warning"` - Suspicious but not critical events

**Actions:**
- `"alert"` - Generate an alert (default)
- `"block"` - Block the operation (requires enforcement enabled)
- `"log"` - Log only, no alert

### MITRE ATT&CK Mapping

Always include the MITRE technique ID when applicable:

```rego
mitre_technique := "T1059"  # Command and Scripting Interpreter
```

Common technique IDs:
- `T1059` - Command and Scripting Interpreter
- `T1190` - Exploit Public-Facing Application
- `T1496` - Resource Hijacking (cryptomining)
- `T1003` - OS Credential Dumping
- `T1548` - Abuse Elevation Control Mechanism
- `T1611` - Escape to Host
- `T1071` - Application Layer Protocol
- `T1568.002` - Dynamic Resolution: DGA

## Testing Policies

### Running Tests

```bash
# Run all OPA tests
ebpf-guard rules test

# Run with verbose output
ebpf-guard rules test --verbose

# Run tests from custom directory
ebpf-guard rules test --rules-dir /path/to/rego
```

### Writing Unit Tests

Create test files in `rules/rego/test/` with the naming convention `*_test.rego`:

```rego
package ebpf_guard.lineage.test

import data.ebpf_guard.lineage

# Test: Reverse shell from nginx to bash
test_reverse_shell_nginx_bash {
    input := {
        "pid": 1234,
        "comm": "bash",
        "event": {
            "parent_comm": "nginx",
            "type": 1
        }
    }
    
    rules := lineage.rules
    count(rules) > 0
    rules[0].rule_id == "reverse_shell_webserver"
    rules[0].severity == "critical"
}

# Test: No match - normal process
test_no_match_normal_process {
    input := {
        "pid": 1234,
        "comm": "nginx",
        "event": {
            "parent_comm": "systemd",
            "type": 1
        }
    }
    
    rules := lineage.rules
    count(rules) == 0
}
```

### Evaluating Policies

Test policies against specific input without running the full agent:

```bash
# Evaluate against a specific event
ebpf-guard rules eval --input '{"type":"syscall","comm":"bash","ppid_comm":"nginx"}'

# Evaluate network event
ebpf-guard rules eval --input '{"type":"network","comm":"xmrig","network":{"dport":3333}}'
```

## Best Practices

### 1. Use Early Returns

Structure rules to fail fast:

```rego
# Good - early return if no file event
rules[...] {
    input.event.file              # Check event type first
    is_sensitive_path(input.event.file.filename)
    input.event.file.op == 2      # write operation
    ...
}
```

### 2. Leverage Helper Functions

Reuse helpers from `base.rego`:

```rego
# Good - use existing helpers
rules[...] {
    is_shell(input.comm)
    is_webserver(input.event.parent_comm)
    ...
}
```

### 3. Include Context in Messages

Provide actionable information:

```rego
# Good - includes relevant details
msg := sprintf("Shell %s spawned from %s (pid=%d, namespace=%s)", 
    [input.comm, input.event.parent_comm, input.pid, input.enrichment.namespace])
```

### 4. Test Edge Cases

Write tests for both positive and negative cases:

```rego
# Positive test - should match
test_suspicious_lineage {
    input := {"comm": "bash", "event": {"parent_comm": "nginx"}}
    count(lineage.rules) > 0
}

# Negative test - should not match
test_normal_lineage {
    input := {"comm": "worker", "event": {"parent_comm": "nginx"}}
    count(lineage.rules) == 0
}
```

### 5. Document Complex Logic

Add comments for non-obvious conditions:

```rego
# Detect cryptominer connections to known pool ports
# MITRE ATT&CK: T1496 - Resource Hijacking
rules[...] {
    input.event.network
    is_mining_port(input.event.network.dport)
    not is_private_ip(input.event.network.daddr)  # Exclude internal testing
    ...
}
```

## Performance Considerations

### Pre-compilation

Policies are compiled once at startup using `rego.PrepareForEval()`. Hot-reload updates the compiled query atomically.

### Evaluation Scope

Rego policies are evaluated **only on alerts**, not raw events:

- Raw events: ~10,000/sec
- YAML filter: passes ~0.1% (10/sec)
- Rego evaluation: ~10/sec

This ensures OPA's ~50-200µs evaluation cost doesn't impact the hot path.

### Benchmarking

Run benchmarks to verify performance:

```bash
go test ./internal/policy/... -bench=BenchmarkRegoEvaluate -benchmem
```

Target: p99 < 500µs per evaluation.

## Migration from YAML Rules

Existing YAML rules can be gradually migrated to Rego:

1. **Phase 1:** Implement new rules in Rego alongside YAML
2. **Phase 2:** Test Rego rules with `ebpf-guard rules test`
3. **Phase 3:** Enable Rego evaluation in config
4. **Phase 4:** Remove equivalent YAML rules

YAML rules remain useful for high-volume filtering, while Rego provides:
- More expressive conditions
- Built-in testing framework
- MITRE ATT&CK mapping
- Better composability

## Troubleshooting

### Policy Not Matching

1. Check input structure matches expected schema
2. Verify package name is correct (e.g., `package ebpf_guard.lineage`)
3. Use `ebpf-guard rules eval` to debug

### Performance Issues

1. Check benchmark: `go test ./internal/policy/... -bench=.`
2. Simplify complex rules
3. Ensure early returns are used

### Test Failures

1. Run with `--verbose` flag
2. Check test input structure matches actual input
3. Verify imports are correct

## References

- [OPA Policy Language](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [Rego Built-in Functions](https://www.openpolicyagent.org/docs/latest/policy-reference/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [ebpf-guard Architecture](../AGENTS.md)
