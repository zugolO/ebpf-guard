# Enforcement Documentation

This document describes the enforcement capabilities of ebpf-guard, including network blocking via nftables, process termination, and cgroup-based throttling.

## Overview

ebpf-guard supports three types of enforcement actions:

1. **Block** - Network traffic blocking via nftables (kernel-level)
2. **Kill** - Process termination via SIGKILL
3. **Throttle** - CPU rate limiting via cgroups v2

## Configuration

Enforcement is configured in the `enforcement` section of the config file:

```yaml
enforcement:
  # Enable enforcement actions
  enabled: true
  
  # Network blocking backend: "log", "nftables", or "iptables"
  # - "log": Only log actions, no actual blocking (default, safe)
  # - "nftables": Use nftables via netlink (requires CAP_NET_ADMIN)
  # - "iptables": Use iptables (legacy, not recommended)
  block_backend: nftables
  
  # Dry-run mode: log actions without executing them
  dry_run: false
  
  # Enable specific action types
  enable_block: true
  enable_kill: true
  enable_throttle: true
```

## Required Capabilities

Different enforcement actions require different Linux capabilities:

| Action | Required Capability | Notes |
|--------|---------------------|-------|
| Block (nftables) | `CAP_NET_ADMIN` | For netlink socket operations |
| Block (iptables) | `CAP_NET_ADMIN` | For iptables command execution |
| Kill | `CAP_KILL` | Or run as root / same UID as target |
| Throttle | `CAP_SYS_ADMIN` | For cgroup v2 manipulation |

### Kubernetes Deployment

When deploying to Kubernetes, add the required capabilities to the security context:

```yaml
securityContext:
  privileged: false
  capabilities:
    add:
      - NET_ADMIN    # For nftables blocking
      - SYS_ADMIN    # For cgroup throttling
      - KILL         # For process termination
```

## nftables Backend

The nftables backend uses the `github.com/google/nftables` library to communicate with the kernel via netlink sockets. This approach:

- **No fork/exec overhead**: Direct netlink communication
- **Fast**: ~1-5ms per rule operation
- **Atomic**: Changes are applied atomically
- **Safe**: Automatic cleanup on agent shutdown

### How It Works

1. On startup, ebpf-guard creates an nftables table named `ebpf-guard` (if not exists)
2. An output chain is created in the `inet` family (supports both IPv4 and IPv6)
3. When a block action is triggered, a rule is added to drop traffic from the offending UID
4. On agent shutdown, all rules are removed

### Manual Verification

To verify nftables rules are working:

```bash
# List all tables
nft list tables

# Show ebpf-guard table
nft list table inet ebpf-guard

# Show active rules
nft list ruleset
```

### Troubleshooting

**Error: "operation not permitted"**
- Ensure `CAP_NET_ADMIN` is granted
- Check if running in a restricted environment (some containers block netlink)

**Error: "protocol not supported"**
- nftables requires kernel 3.13+ with `CONFIG_NETFILTER` enabled
- Check: `zgrep CONFIG_NETFILTER /proc/config.gz` or `/boot/config-*`

**Rules not blocking traffic**
- Verify the rule is in the correct chain (output)
- Check if other rules have higher priority
- Use `nft monitor` to trace rule evaluation

## Process Termination (Kill)

The kill action sends `SIGKILL` to the offending process. This is immediate and cannot be caught or ignored by the target process.

### Safety Considerations

- PID reuse is possible but unlikely within short timeframes
- The enforcer validates the process exists before sending the signal
- System processes (PID 0, kernel threads) are excluded

### Verification

```bash
# Check if process was killed
ps aux | grep <pid>

# Check audit logs
cat /var/log/ebpf-guard/audit.log | jq '. | select(.action == "kill")'
```

## Cgroup Throttling

The throttle action limits CPU usage by writing to the cgroup v2 `cpu.max` file.

### How It Works

1. Find the cgroup path for the target process via `/proc/<pid>/cgroup`
2. Write `"10000 100000"` to `cpu.max` (10ms per 100ms = 10% CPU)
3. The process continues running but at reduced CPU capacity

### Requirements

- cgroup v2 must be mounted at `/sys/fs/cgroup`
- The agent must have write access to the target cgroup

### Verification

```bash
# Check cgroup v2 availability
ls /sys/fs/cgroup/cgroup.controllers

# View process cgroup
cat /proc/<pid>/cgroup

# Check current CPU limit
cat /sys/fs/cgroup/<cgroup-path>/cpu.max
```

## Dry-Run Mode

Dry-run mode is useful for testing rules without affecting production workloads:

```yaml
enforcement:
  enabled: true
  dry_run: true
  block_backend: nftables
```

In dry-run mode:
- Actions are logged at WARN level
- No actual blocking/killing/throttling occurs
- Audit entries are still generated with `success: true`

## Rule Examples

### Block Cryptominer Network Traffic

```yaml
rules:
  - id: block_cryptominer
    name: "Block cryptominer network"
    description: "Block network traffic from detected cryptominers"
    event_type: network
    condition:
      field: dport
      op: in
      values: [3333, 4444, 14444]
    severity: critical
    action: block  # Requires enforcement.enable_block=true
```

### Kill Malicious Process

```yaml
rules:
  - id: kill_reverse_shell
    name: "Kill reverse shell"
    description: "Terminate processes spawning reverse shells"
    event_type: network
    condition:
      field: dport
      op: in
      values: [4444, 5555, 6666]
    severity: critical
    action: kill  # Requires enforcement.enable_kill=true
```

### Throttle Abusive Process

```yaml
rules:
  - id: throttle_scanner
    name: "Throttle port scanner"
    description: "CPU throttle processes performing port scans"
    event_type: network
    condition:
      field: dport
      op: gt
      values: ["10000"]
    severity: warning
    action: throttle  # Requires enforcement.enable_throttle=true
```

## Performance Considerations

| Action | Latency | Overhead | Notes |
|--------|---------|----------|-------|
| Block (nftables) | 1-5ms | Negligible | One-time rule addition |
| Kill | <1ms | Negligible | Single syscall |
| Throttle | 5-10ms | Negligible | File write to cgroupfs |

All enforcement actions are performed asynchronously to the event processing path. The correlator generates alerts; enforcement happens in a separate goroutine.

## Security Best Practices

1. **Start with dry-run mode** to validate rules before enabling enforcement
2. **Use specific rules** - broad rules may block legitimate traffic
3. **Monitor audit logs** - all enforcement actions are logged
4. **Test in staging** - verify enforcement works in your environment
5. **Have a rollback plan** - document how to disable enforcement quickly

## Troubleshooting

### Enable Debug Logging

```yaml
server:
  enable_debug: true
```

Then check `/debug/state` endpoint for enforcer status.

### Check Audit Logs

```bash
# View all enforcement actions
cat /var/log/ebpf-guard/audit.log | jq .

# Filter by action type
cat /var/log/ebpf-guard/audit.log | jq '. | select(.action == "block")'

# Filter by result
cat /var/log/ebpf-guard/audit.log | jq '. | select(.success == false)'
```

### Common Issues

**"action block is disabled"**
- Set `enforcement.enable_block: true` in config

**"enforcer: init nftables: ..."**
- Check capabilities (CAP_NET_ADMIN)
- Verify nftables is available: `which nft`

**"process not found"**
- Process may have already exited
- Check PID reuse timing

**"write cpu.max: permission denied"**
- Need CAP_SYS_ADMIN for cgroup manipulation
- Verify cgroup v2 is in use: `mount | grep cgroup`

## Migration from iptables

If you're currently using iptables for blocking, consider migrating to nftables:

```bash
# Old iptables approach (slow, fork/exec)
iptables -A OUTPUT -m owner --uid-owner 1000 -j DROP

# New nftables approach (fast, netlink)
nft add rule inet ebpf-guard output skuid 1000 drop
```

ebpf-guard handles this migration automatically when you set `block_backend: nftables`.

---

## `networkpolicy` — Auto-Generated Kubernetes NetworkPolicy (issue #117)

When a rule fires with `action: networkpolicy`, ebpf-guard generates a Kubernetes
`NetworkPolicy` isolating the affected pod and either sends it for review or applies
it directly via the Kubernetes API.

### Rule syntax

```yaml
rules:
  - id: crypto_c2_detected
    event_type: network
    condition:
      field: "dst_ip"
      op: "in"
      values: ["@mining_pools"]
    severity: critical
    action: networkpolicy
```

### Modes

| Mode | Behaviour |
|---|---|
| `suggest` (default) | Generates the YAML and sends it via Slack/Teams/webhook for human review |
| `apply` | Applies the policy directly via the Kubernetes API |

### Generated policy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ebpf-guard-quarantine-<pod>-<namespace>-<alertID[:8]>
  namespace: <namespace>
  annotations:
    ebpf-guard/alert-id: "<alertID>"
    ebpf-guard/rule-id: "<ruleID>"
spec:
  podSelector:
    matchLabels: <pod-labels>   # from K8s enricher; falls back to kubernetes.io/pod-name
  policyTypes: [Egress]
  egress: []                    # deny all egress
```

### Configuration

```yaml
enforcer:
  networkpolicy:
    enabled: true
    mode: "suggest"           # suggest | apply
    auto_cleanup_after: "1h"  # delete applied policies after TTL (0 disables)
    dry_run: false
```

### RBAC (apply mode)

In `apply` mode the agent needs `networkpolicies` write permission. Enable it in the
Helm chart values:

```yaml
enforcement:
  networkpolicy:
    enabled: true   # adds networkpolicies create/delete to the ClusterRole
```

The agent validates at startup that the `networkpolicies` write RBAC is available when
`mode: apply` is configured; it exits with a clear error if the permission is missing.

### Auto-cleanup

When `auto_cleanup_after` is non-zero and `mode: apply`, a background goroutine deletes
policies older than the TTL. After an agent restart, policies already in the cluster
must be cleaned up manually if the TTL elapsed during downtime.

---

## References

- [nftables documentation](https://wiki.nftables.org/)
- [cgroup v2 documentation](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
- [Linux capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Kubernetes NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
