# Canary Trap Detection

Canary files are synthetic lures planted at paths that attackers commonly probe during post-compromise reconnaissance (e.g. `/etc/shadow.canary`, `/root/.ssh/id_rsa.canary`). Any file-access event touching one of these paths generates a high-confidence critical alert. A periodic verification loop additionally detects tampering (deletion or content modification) and emits alerts independently of eBPF event collection.

## How It Works

1. At startup, `canary.Manager.Setup()` creates each configured lure file (when `auto_create: true`) and records its SHA-256 hash and file mode as a tamper baseline.
2. Detection rules are generated at runtime via `Manager.Rules()` and merged into the correlation engine — no static rule file is required.
3. `Manager.Start()` launches a background goroutine that re-hashes each lure file every `verify_interval`. If a file is missing or its hash/mode differs from the baseline, an alert is emitted and the `ebpf_guard_canary_files_intact{path}` gauge drops to `0`.

## Configuration

```yaml
canary:
  enabled: true
  auto_create: true         # Create lure files on startup (requires write access to their paths)
  verify_interval: 60s      # How often to re-check lure file integrity
  alert_on_tamper: true     # Emit alert when tampering is detected during periodic verification
  alert_severity: critical  # Severity applied to all canary alerts
  files:                    # Leave empty to use the built-in default set
    - /etc/shadow.canary
    - /tmp/.secret_key
    - /var/run/.admin_socket
    - /root/.ssh/id_rsa.canary
    - /etc/passwd.canary
```

`canary.enabled` defaults to `false`; the module is not active unless explicitly enabled.

## Default Lure File Set

| Path | Simulates |
|---|---|
| `/etc/shadow.canary` | Password hash file |
| `/tmp/.secret_key` | Credentials dropped in temp |
| `/var/run/.admin_socket` | Privileged Unix socket |
| `/root/.ssh/id_rsa.canary` | SSH private key |
| `/etc/passwd.canary` | User account database |

These paths are chosen because automated attack tooling (linPEAS, LaZagne, mimikatz ports) commonly reads them during privilege escalation and credential harvesting.

## Alerts

Two alert categories are generated:

| Rule ID | Trigger | Severity |
|---|---|---|
| `canary_001` … `canary_N` | eBPF file-access event hitting a lure path | `alert_severity` (default `critical`) |
| `canary_tampered` | Periodic verify finds file missing or modified | `alert_severity` |

The first category fires immediately via the correlation engine. The second fires even if eBPF collection is unavailable (for example, if the agent is run with `--dry-run`).

## Operational Notes

- **Root required for default paths.** `/etc/shadow.canary` and `/root/.ssh/id_rsa.canary` need root write access. In a container, run with the file-system mounted as read-only except the specific paths, or choose paths writable by the agent UID.
- **Kubernetes DaemonSet.** Mount lure files via `hostPath` volumes so they persist on the node across Pod restarts. Add an `initContainer` with `canary.auto_create: true` to create them on first boot.
- **`auto_create: false`.** Use this when lure files are managed externally (e.g. by an Ansible playbook). The verify loop still detects tampering relative to the hash captured at startup — which requires the file to already exist.
- **`verify_interval` tuning.** Shorter intervals increase tamper-detection sensitivity at the cost of extra `stat`+`read` syscalls. The default 60 s adds negligible overhead (< 1 µs/file on modern storage).
- **Alert deduplication.** The tamper alert fires on every verify cycle while the file remains missing or modified. Configure Alertmanager grouping or the `rate_limit` section of the rule config to suppress repeat alerts if desired.

## Placement Strategy

Canary files are most effective when they look legitimate enough to attract automated tools but are never accessed by real workloads. Recommended approach:

1. Place lures at paths read by common post-exploit scripts but not by the application.
2. Verify that no legitimate service reads the lure paths by reviewing file-access events in `--dry-run` mode before enabling `auto_create`.
3. In multi-tenant Kubernetes clusters, use per-namespace paths (e.g. `/data/tenant-a/.canary`) to attribute the attacker's namespace.
