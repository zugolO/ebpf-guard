# Syscall Allowlist Mode (deny-unknown)

## Overview

Allowlist mode flips the detection model: instead of only alerting on known-bad syscalls,
the agent learns the **normal syscall set** for each workload during a training window and
then alerts on **any syscall that was never observed**. This is a stronger security posture
for well-known, stable workloads (web servers, databases, sidecars).

## Configuration

```yaml
profiler:
  syscall_allowlist:
    enabled: true

    # "learning" during the learning window, auto-switches to "enforcing" after.
    mode: learning

    # Action taken on violations after learning: "alert", "block", or "kill".
    enforcing_action: alert

    # Separate allowlist per (comm, namespace, app_label) tuple.
    # Set to false for a single global allowlist (rarely useful).
    per_workload: true

    # Duration (seconds) the agent records syscalls before enforcing.
    # Should be at least 1–2x the workload's startup + warm-up time.
    learning_period: 3600   # 1 hour

    # Minimum number of syscall events required before learning may complete.
    # Guards against nodes that received very little traffic before the timer expired.
    min_samples: 100

    # Profiles with fewer unique syscalls than this threshold generate a
    # "sparse_profile" warning — the workload may not have been exercised
    # enough to build a reliable allowlist.
    sparse_threshold: 10

    # Syscall numbers always permitted, never alerted (even if not seen during learning).
    # Useful for benign syscalls that appear rarely or only under load.
    global_allow:
      - 0    # read
      - 1    # write
      - 3    # close
      - 9    # mmap
      - 11   # munmap
      - 21   # access
      - 231  # exit_group

    # Syscall numbers always alerted, regardless of the learned profile.
    # Override to force alerts for high-risk syscalls even in trusted workloads.
    global_deny:
      - 101  # ptrace
      - 310  # process_vm_readv
      - 311  # process_vm_writev

    # Path for JSON state persistence across pod restarts.
    # Leave empty to disable persistence (re-learns from scratch after each restart).
    persist_path: /var/lib/ebpf-guard/allowlist-state.json
```

## How It Works

### Learning Phase

During `learning_period` the agent records every unique syscall number observed for each
workload (`per_workload: true`) or globally (`per_workload: false`). The workload key is
the tuple `(comm, k8s_namespace, app_label)` — the same key used by the behavioral
anomaly detector — so all replicas of a workload share one profile.

Learning completes when **both** conditions are met:
1. `learning_period` seconds have elapsed since the first event for the workload.
2. At least `min_samples` syscall events have been observed.

Once learning completes the profile is locked and the agent switches to **enforcing mode**.

### Enforcing Phase

Every subsequent syscall event is checked against the learned set. A violation is generated
when a syscall number is:
- **Not in the learned set** (source: `"unknown"`), or
- **In `global_deny`** (source: `"global_deny"`, fires even during learning).

Syscalls in `global_allow` are never alerted regardless of the profile.

### Alerts

Violations produce an alert with `rule_id: "auto_allowlist_violation"`:

```json
{
  "rule_id": "auto_allowlist_violation",
  "rule_name": "Syscall Allowlist Violation",
  "severity": "warning",
  "message": "Unknown syscall 439 not in learned allowlist for workload prod/nginx",
  "details": {
    "syscall_nr": 439,
    "source": "unknown",
    "workload": "nginx|prod|nginx",
    "action": "alert"
  }
}
```

### Sparse Profile Alerts

If a profile completes learning with fewer than `sparse_threshold` unique syscalls, a
warning is logged and the `ebpf_guard_allowlist_sparse_profiles_total` counter is
incremented. This indicates the workload may not have been fully exercised during the
learning window — consider extending `learning_period` or increasing load during training.

## Metrics

| Metric | Labels | Description |
|--------|--------|-------------|
| `ebpf_guard_allowlist_violations_total` | `workload`, `syscall` | Counter of allowlist violations |
| `ebpf_guard_allowlist_sparse_profiles_total` | — | Profiles that finished learning below `sparse_threshold` |

Example Prometheus query — top violating syscalls:

```promql
topk(10, sum by (syscall) (rate(ebpf_guard_allowlist_violations_total[5m])))
```

## State Persistence

When `persist_path` is set, the agent saves all learned profiles to a JSON file:
- **Every 5 minutes** while running.
- **On graceful shutdown**.
- **On startup**, restoring previously enforcing profiles immediately (no re-learning needed).

This means a pod restart does not reset a completed profile to learning mode.

## False Positive Guidance

Allowlist mode will fire on legitimate syscall diversity if the workload was not fully
exercised during training. Common causes:

| Symptom | Remedy |
|---------|--------|
| Alert on `sched_yield` / `futex` after deploying a new library | Increase `learning_period` or add syscall to `global_allow` |
| Alert on `openat` during log rotation | Run log rotation during the learning window |
| Alerts on cold-path error-handling syscalls | Trigger error paths during learning (chaos testing) |
| Profile marked sparse on short-lived jobs | Use `per_workload: false` or set `min_samples: 0` |

## Use Cases

- **Distroless containers**: learning period of 30 min is usually sufficient; enforcing
  `kill` stops shellcode execution that uses unexpected syscalls.
- **Web servers (nginx, Envoy)**: only `read`, `write`, `epoll_wait`, `sendmsg`, `recvmsg`,
  `accept4`, and a handful of others are needed — a very tight allowlist.
- **Security-hardened sidecars**: run in `alert` mode first for a week, review violations,
  then switch to `block`.

## Interaction with seccomp

ebpf-guard allowlist mode operates in **userspace** and complements kernel-level seccomp
profiles. The two mechanisms are independent:

- seccomp provides a hard kernel-enforced block (zero userspace cost after load).
- ebpf-guard allowlist provides **runtime observability** and can alert even when the syscall
  is not blocked — useful for building the seccomp profile or catching drift after a profile
  is deployed.

A common workflow: use ebpf-guard allowlist mode in `alert` for one week, export the
`allowed_syscalls` list from the persisted JSON state, and convert it to a seccomp profile
for production enforcement.
