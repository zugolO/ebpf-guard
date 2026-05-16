# Security Profiles

This directory contains security profiles for running ebpf-guard in production environments.

## Seccomp Profile

The `seccomp.json` profile restricts system calls to the minimum required for ebpf-guard operation.

### Usage

```bash
# Run with seccomp profile
docker run --security-opt seccomp=seccomp.json ebpf-guard:latest

# In Kubernetes
securityContext:
  seccompProfile:
    type: Localhost
    localhostProfile: ebpf-guard/seccomp.json
```

### Required Syscalls

The profile allows syscalls in these categories:
- **Process management**: `clone`, `execve`, `exit`, `wait4`
- **Memory management**: `mmap`, `mprotect`, `munmap`, `brk`
- **File operations**: `openat`, `read`, `write`, `close`, `stat`
- **Network**: `socket`, `bind`, `connect`, `accept4`, `sendto`, `recvfrom`
- **eBPF specific**: `bpf`, `perf_event_open`
- **Container runtime**: `mount`, `umount2`, `pivot_root`

## AppArmor Profile

The `apparmor.profile` provides mandatory access control for ebpf-guard.

### Usage

```bash
# Load the profile
sudo apparmor_parser -r -W apparmor.profile

# Run with profile
docker run --security-opt apparmor=ebpf-guard ebpf-guard:latest

# In Kubernetes
securityContext:
  appArmorProfile:
    type: Localhost
    localhostProfile: ebpf-guard
```

### Profile Features

- **Capabilities**: Minimal set including `bpf`, `sys_admin`, `net_admin`
- **Network**: Full network access for event collection
- **Filesystem**: Read access to system directories, write to BPF maps
- **eBPF**: Full access to BPF syscalls and tracing
- **Deny rules**: Blocks writes to sensitive files

## Security Hardening Checklist

- [ ] Use seccomp profile
- [ ] Use AppArmor profile
- [ ] Run as non-root user (with required capabilities)
- [ ] Drop unnecessary capabilities
- [ ] Use read-only root filesystem
- [ ] Mount BPF filesystem as read-only where possible
- [ ] Enable audit logging
- [ ] Regular security scans with Trivy

## Capability Requirements

| Capability | Purpose |
|------------|---------|
| `bpf` | Load and manage eBPF programs |
| `perfmon` | Access perf events for tracing |
| `sys_admin` | Mount BPF filesystem, access debugfs |
| `net_admin` | Network configuration and monitoring |
| `sys_resource` | Resource limits and scheduling |
| `ipc_lock` | Lock memory for eBPF maps |

## Troubleshooting

If ebpf-guard fails to start with security profiles:

1. Check audit logs: `sudo ausearch -m avc -ts recent`
2. Run in complain mode: `aa-complain ebpf-guard`
3. Review denied syscalls: `sudo cat /proc/<pid>/status | grep Seccomp`
