# Privilege Escalation Detection

ebpf-guard detects runtime privilege escalation by tracking Linux capability
changes at the kernel level. This covers `capset(2)`, `setuid`/`setgid`, SUID
binary execution, and any other path that calls `commit_creds` inside the kernel.

## How It Works

### BPF Programs (`bpf/privesc.bpf.c`)

Two BPF programs collaborate to track capability changes:

| Program | Hook | Purpose |
|---|---|---|
| `tracepoint__sys_enter_capset` | `tracepoint/syscalls/sys_enter_capset` | Baseline: record existing caps for new PIDs before capset executes |
| `kprobe__commit_creds` | `kprobe/commit_creds` | Authoritative: fires on every kernel credential commit regardless of the syscall path |

The `commit_creds` kprobe is the primary source. It fires when:
- `capset(2)` completes
- `setuid(2)` / `setgid(2)` change privileges
- `execve(2)` applies SUID/SGID bits
- Any internal kernel path changes process credentials

A BPF hash map (`pid_caps`) stores the last-seen effective capability bitmask
per PID. When `commit_creds` fires, it computes the delta between old and new
capability sets, and only emits an event when the set actually changed. This
keeps the event rate low — only genuine changes are reported.

### Wire Format

`EVENT_TYPE_PRIVESC` (type=6) events reuse the syscall union in the common BPF
struct. Old and new capability bitmasks are packed into `args[0]` and `args[1]`
respectively. This avoids extending the packed C struct layout shared between
kernel and userspace.

### Go Side

The `PrivescCollector` (`internal/collector/privesc.go`) reads events from the
ring buffer and converts the raw bitmasks to `types.PrivescEvent`:

```go
type PrivescEvent struct {
    OldCaps uint64  // effective caps before the change
    NewCaps uint64  // effective caps after the change
}
```

The `CapsToNames()` helper converts a bitmask to human-readable names
(`["CAP_SYS_ADMIN", "CAP_NET_RAW"]`) for debug logging and alert details.

## Detection Rules (`rules/privesc.yaml`)

| Rule ID | Trigger | Severity |
|---|---|---|
| `privesc_sys_admin_gained` | CAP_SYS_ADMIN gained at runtime | critical |
| `privesc_net_raw_gained` | CAP_NET_RAW gained outside init | warning |
| `privesc_sys_module_gained` | CAP_SYS_MODULE gained (rootkit path) | critical |
| `privesc_sys_ptrace_gained` | CAP_SYS_PTRACE gained (credential theft) | critical |
| `privesc_caps_drop_all` | Drop-all + re-gain (evasion pattern) | warning |
| `privesc_setuid_gained` | CAP_SETUID or CAP_SETGID gained | critical |

### Rule Syntax

Two new condition operators are available for `privesc` events:

- **`caps_gained`** — matches if any listed capability appears in `new_caps &^ old_caps` (set in new but not old)
- **`caps_dropped`** — matches if any listed capability appears in `old_caps &^ new_caps` (set in old but not new)

Example rule:

```yaml
rules:
  - id: my_sys_admin_rule
    name: "CAP_SYS_ADMIN gained"
    description: "Runtime acquisition of CAP_SYS_ADMIN"
    event_type: privesc
    condition:
      field: caps
      op: caps_gained
      values:
        - CAP_SYS_ADMIN
    severity: critical
    action: alert
    tags: [mitre:T1548.001, privesc]
```

Supported field names for `privesc` event conditions:

| Field | Type | Description |
|---|---|---|
| `caps` | hex string | New capability bitmask (for standard operators) |
| `uid` | integer string | Process UID |
| `comm` | string | Process name |

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Abuse Elevation Control Mechanism: Setuid and Setgid | T1548.001 | Gaining SETUID/SETGID or SYS_ADMIN caps |
| Process Injection | T1055 | SYS_PTRACE used for code injection |
| Boot or Logon Autostart: Kernel Modules | T1547.006 | SYS_MODULE used to load rootkit |

## Kubernetes Considerations

In Kubernetes, containers typically have a fixed capability set established at
startup via the pod `securityContext`. Any runtime capability change is
therefore unexpected and should be treated as a high-confidence indicator.

The `PrivescCollector` is enabled by default when the BPF programs load
successfully. It requires:
- Linux kernel 5.15+ (BTF/CO-RE)
- `CAP_BPF` + `CAP_PERFMON` (or `CAP_SYS_ADMIN`) for the agent

## Demo

```bash
# Simulate capability gain (requires root)
sudo setcap cap_net_raw+ep /tmp/test_binary

# Watch for alert
ebpf-guard alerts --follow
```

Expected alert within 3 seconds:

```json
{
  "rule_id": "privesc_net_raw_gained",
  "severity": "warning",
  "comm": "setcap",
  "message": "CAP_NET_RAW gained outside container init"
}
```
