# eBPF LSM Enforcement

This document describes the eBPF LSM (Linux Security Module) enforcement feature introduced in Sprint 22.0. LSM hooks provide **pre-execution** enforcement, allowing the agent to block operations before they occur, unlike kprobes which only observe after the fact.

## Overview

Traditional kprobe-based enforcement can only react to events after they happen. LSM BPF hooks allow ebpf-guard to:

1. **Block file access** before the file is opened (`lsm/bpf_file_open`)
2. **Block network connections** before they are established (`lsm/bpf_socket_connect`)
3. **Audit and optionally block** process termination (`lsm/bpf_task_kill`)
4. **Detect kernel module loads** before execution (`lsm/kernel_module_request`, `lsm/kernel_read_file`) — Sprint 33.0
5. **Detect container cgroup escape** at the moment of cgroup migration (`lsm/cgroup_attach_task`) — Sprint 33.0

## Hook Summary

| Hook | BPF file | Purpose | Sprint |
|------|----------|---------|--------|
| `lsm/bpf_file_open` | `lsm.bpf.c` | Block file open for blocklisted PIDs | 22.0 |
| `lsm/bpf_socket_connect` | `lsm.bpf.c` | Block TCP connect for blocklisted PIDs | 22.0 |
| `lsm/bpf_task_kill` | `lsm.bpf.c` | Audit signal delivery | 22.0 |
| `lsm/kernel_module_request` | `lsm.bpf.c` | Detect automatic module load requests | 33.0 |
| `lsm/kernel_read_file` | `lsm.bpf.c` | Detect module file reads (insmod path) | 33.0 |
| `tp/sched/sched_process_exec` | `lsm.bpf.c` | Record initial cgroup ID per PID at exec | 33.0 |
| `lsm/cgroup_attach_task` | `cgroup.bpf.c` | Detect process migration to different cgroup | 33.0 |

## Comparison: LSM vs kprobe Enforcement

| Feature | LSM BPF | kprobe |
|---------|---------|--------|
| Timing | Pre-execution | Post-execution |
| Return value | Can deny operation | Read-only |
| Overhead | < 1 µs per syscall | ~0.5 µs per syscall |
| Kernel requirement | 5.7+ with CONFIG_BPF_LSM | 4.18+ |
| Fallback | Automatic to nftables | N/A |

## Kernel Requirements

### Minimum Requirements

- **Kernel version:** 5.7 or later
- **Kernel config:** `CONFIG_BPF_LSM=y`
- **LSM stack:** Must include `bpf` in the active LSMs

### Checking LSM Support

```bash
# Check if BPF LSM is enabled in kernel config
zgrep CONFIG_BPF_LSM /boot/config-$(uname -r)
# Expected: CONFIG_BPF_LSM=y

# Check active LSMs
cat /sys/kernel/security/lsm
# Expected output should include "bpf": capability,selinux,bpf
```

### Enabling BPF LSM

If `bpf` is not in the active LSMs, add it to the kernel command line:

```bash
# Edit /etc/default/grub or equivalent
GRUB_CMDLINE_LINUX="lsm=lockdown,capability,selinux,bpf"

# Update grub and reboot
grub2-mkconfig -o /boot/grub2/grub.cfg
reboot
```

**Note:** The order of LSMs matters. Place `bpf` last to ensure it can override decisions from other LSMs.

## Configuration

```yaml
# config.yaml
collectors:
  lsm:
    # "auto" - enables if kernel supports (default)
    # "true" - requires kernel support, fails if unavailable
    # "false" - disables LSM hooks
    enabled: auto

watchdog:
  memory_pressure:
    enabled: true
    check_interval: 5
    low_memory_threshold: 10.0  # % available memory
    recovery_threshold: 20.0    # % available memory
```

## How It Works

### BPF Maps

1. **`lsm_blocklist`** (`BPF_MAP_TYPE_LRU_HASH`)
   - Key: PID (uint32)
   - Value: Set of blocked path hashes
   - Automatically evicts old entries (bounded memory)

2. **`lsm_agent_whitelist`** (`BPF_MAP_TYPE_HASH`)
   - Key: PID (uint32)
   - Value: Always allow (uint8 = 1)
   - Prevents the agent from blocking itself

### Hook Behavior

#### bpf_file_open

```c
// Pseudocode of BPF logic
LSM_PROBE(bpf_file_open, struct file *file) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Fast path: agent PID always allowed
    if (is_agent_pid(pid))
        return 0;  // Allow
    
    // Fast path: not in blocklist
    if (!bpf_map_lookup_elem(&lsm_blocklist, &pid))
        return 0;  // Allow
    
    // Check if path is in blocklist for this PID
    u64 path_hash = hash_path(file->f_path);
    if (is_blocked(pid, path_hash))
        return -EPERM;  // Block!
    
    return 0;  // Allow
}
```

**Performance:**
- Empty blocklist: ~50ns per file open (single map lookup)
- With entries: ~100ns (additional hash comparison)

#### bpf_socket_connect

Similar logic for network connections:
- Fast path for non-blocklisted PIDs
- IP/port check for blocklisted PIDs
- Returns `-EPERM` to block connection

#### bpf_task_kill

Audit-only by default:
- Logs kill syscalls for security audit
- Can be configured to block specific signal/PID combinations

## Enforcement Flow

```
Alert Generated
       |
       v
+-------------+     No      +------------------+
| LSM Available?| --------> | Use nftables     |
+-------------+             | (post-execution) |
       | Yes                +------------------+
       v
+-------------+
| Add PID to  |
| lsm_blocklist|
+-------------+
       |
       v
+-------------+
| LSM Hook    |
| Blocks on   |<---- Next syscall
| Next access |
+-------------+
```

## Fallback Behavior

If LSM is unavailable, the enforcer automatically falls back to nftables:

```yaml
enforcement:
  block_backend: "nftables"  # Used when LSM unavailable
```

## Metrics

| Metric | Description |
|--------|-------------|
| `ebpf_guard_lsm_blocks_total{hook,action}` | LSM hook invocations |
| `ebpf_guard_memory_pressure_mode{mode}` | Memory pressure state |

## Troubleshooting

### LSM Not Available

```bash
# Check kernel version
uname -r  # Must be >= 5.7

# Check kernel config
zgrep CONFIG_BPF_LSM /proc/config.gz  # or /boot/config-$(uname -r)

# Check active LSMs
cat /sys/kernel/security/lsm
```

### Agent Blocking Itself

The agent automatically adds its own PID to `lsm_agent_whitelist`. If this fails:

1. Check agent logs for "failed to whitelist agent PID"
2. Verify BPF map is accessible: `bpftool map show`

### High Overhead

If LSM hooks cause noticeable overhead:

1. Check if blocklist is too large: `bpftool map dump id <lsm_blocklist_id>`
2. Verify fast path is working (most PIDs should not be in blocklist)
3. Consider using nftables fallback for high-volume blocking

## Security Considerations

1. **Privileged Operation:** LSM BPF requires `CAP_SYS_ADMIN` and `CAP_BPF`
2. **Audit Trail:** All LSM blocks are logged with PID, comm, and target
3. **Self-Protection:** Agent PID is always whitelisted to prevent self-denial
4. **Memory Bounds:** LRU map ensures bounded memory usage for blocklist

## Migration from nftables

To migrate from nftables to LSM enforcement:

1. Verify kernel support (see above)
2. Set `collectors.lsm.enabled: auto` (default)
3. Restart agent
4. Check logs: "LSM BPF enabled, using pre-execution enforcement"
5. Monitor `ebpf_guard_lsm_blocks_total` metric

To force LSM and fail if unavailable:

```yaml
collectors:
  lsm:
    enabled: true  # Will exit if kernel doesn't support LSM BPF
```

---

## Sprint 33.0: Kernel Module Load & Container Cgroup Escape Detection

### Kernel Module Load Detection

Two LSM hooks in `bpf/lsm.bpf.c` cover both paths by which a module enters the kernel:

| Hook | Triggered by |
|------|-------------|
| `kernel_module_request` | Automatic modprobe requests (`request_module()` in kernel) |
| `kernel_read_file` (id=READING_MODULE) | Direct `insmod` / `finit_module` syscall path |

Both emit a `kmod_event` (type `EVENT_TYPE_KMOD_LOAD`) to the `lsm_events` ring buffer. The Go `KmodCollector` reads from this buffer and forwards `types.KmodEvent` into the correlation engine.

**Key fields in `KmodEvent`:**

| Field | Description |
|-------|-------------|
| `mod_name` | Module name (from `kernel_module_request`) or file basename (from `kernel_read_file`) |
| `from_tmpfs` | `true` when the module path starts with `/tmp` or `/dev/shm` |
| `parent_comm` | Immediate parent process name |

**Fallback for kernel < 5.7:** `KmodCollector` auto-detects LSM availability. If LSM BPF is unavailable it attaches the `sys_enter_init_module` tracepoint instead, which covers the `insmod` path. The `kernel_module_request` path (auto-load) is only available with LSM.

**Detection rules** — `rules/kernel-integrity.yaml`:

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `kmod_unexpected_parent` | critical | Parent is not `modprobe`/`kmod`/`depmod` |
| `kmod_load_from_tmpfs` | critical | Module loaded from `/tmp` or `/dev/shm` |
| `kmod_load_nonroot` | critical | Loader process UID > 0 |
| `kmod_suspicious_name` | critical | Dot-prefixed, random hex, or numeric name |
| `kmod_from_container` | critical | Any module load from a non-modprobe process |

MITRE ATT&CK: **T1547** (Boot or Logon Autostart Execution: Kernel Modules and Extensions), **T1611** (Escape to Host).

### Container Cgroup Escape Detection

`bpf/cgroup.bpf.c` implements `lsm/cgroup_attach_task`. At exec time, `lsm.bpf.c` records each PID's cgroup ID in `pid_initial_cgroup`. When `cgroup_attach_task` fires, it compares the destination cgroup ID to the recorded initial ID. Any divergence emits a `cgroup_escape_event` (type `EVENT_TYPE_CGROUP_ESC`) to the `cgroup_events` ring buffer.

This detects the **CVE-2022-0492** class of escapes:

```
Container process
  → writes to /sys/fs/cgroup/memory/release_agent
  → moves itself to root cgroup  ← DETECTED HERE by cgroup_attach_task
  → triggers release_agent (executes as root on host)
```

**Key fields in `CgroupEscapeEvent`:**

| Field | Description |
|-------|-------------|
| `init_cgroup_id` | Cgroup ID recorded at exec time (container's cgroup) |
| `new_cgroup_id` | Destination cgroup ID (root cgroup = 1) |

**Detection rules** — `rules/container-escape.yaml`:

| Rule ID | Severity | Action | Description |
|---------|----------|--------|-------------|
| `container_escape_cgroup_migrate` | critical | alert | Any cgroup migration |
| `container_escape_cgroup_to_root` | critical | **block** | Migration to root cgroup (ID=1) |

The `block` action on `container_escape_cgroup_to_root` returns `-EPERM` from the LSM hook before the migration completes, preventing the release_agent technique entirely.

### BPF Map Sharing

`pid_initial_cgroup` is written by `lsm.bpf.c` (exec tracepoint) and read by `cgroup.bpf.c` (attach hook). The Go loader pins both maps to the same kernel map object so the write-at-exec / read-at-migrate pattern works across BPF object boundaries.
