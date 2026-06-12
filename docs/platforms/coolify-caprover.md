# Deploy ebpf-guard on Coolify / CapRover / Dokploy

> Copy-paste guide for self-hosted PaaS platforms. Time to complete: **under 10 minutes**.

If you run a self-hosted PaaS (Coolify, CapRover, Dokploy, or similar) on a single
VPS or bare-metal server, ebpf-guard protects **all containers** on that host —
including the PaaS management containers and your application containers.

Because these platforms share a single Linux host, ebpf-guard installed directly
on the host sees every container automatically via eBPF.

---

## Prerequisites

- A server running **Ubuntu 22.04+** or **Debian 12+**
- Kernel **5.15+** (`uname -r`)
- Your PaaS already installed and running (Coolify, CapRover, or Dokploy)
- Root or sudo access

---

## Step 1: Install ebpf-guard alongside your PaaS

Follow the VPS guide ([vps.md](vps.md)) Steps 1-3, with this PaaS-optimized config:

```yaml
# /etc/ebpf-guard/config.yaml — PaaS-optimized config

rules:
  path: ""                    # use all 40 built-in rule sets

notifications:
  discord:
    enabled: true
    webhook_url: "https://discord.com/api/webhooks/YOUR_URL"
    min_severity: warning
  telegram:
    enabled: false
    bot_token: ""
    chat_id: ""
    min_severity: critical

# Simple mode with PaaS-specific allowlists
simple_mode:
  enabled: true
  dry_run_duration: "24h"
  max_kills_per_minute: 2     # slightly higher for multi-app servers
  allowlist_comms:
    - coolify                  # Coolify
    - caprover                 # CapRover
    - dokploy                  # Dokploy
    - docker                   # Docker daemon
    - containerd               # Container runtime
    - traefik                  # Common reverse proxy
    - caddy                    # Common reverse proxy
    - nginx-proxy              # Common reverse proxy
    - certbot                  # SSL renewal
    - node                     # Node.js apps (broad — refine per-app if needed)
    - python3                  # Python apps
    - ruby                     # Ruby apps

store:
  backend: memory

auth:
  enabled: true
```

---

## Step 2: Understanding how ebpf-guard sees your PaaS

ebpf-guard monitors at the **kernel level**, not the Docker/container level. On a
PaaS host:

- **Every container process** is visible automatically — no per-app configuration
- **PaaS management containers** (Traefik, Caddy, database containers) are also monitored
- **Reverse shell from a compromised app** (`node` → `bash` → `curl`) is detected even if the attacker hides from `docker ps`
- **Container escapes** (mount, nsenter, cgroup manipulation) are detected before the attacker reaches the host

Your PaaS apps don't need any changes — ebpf-guard sees their syscalls regardless.

---

## Step 3: Platform-specific notes

### Coolify

```
Coolify runs on a single Docker host (or Docker Swarm). ebpf-guard is installed
on the host alongside Coolify. The Coolify UI, database containers, and your apps
all share the kernel — everything is monitored.
```

**Recommended:** Add `postgres`, `redis`, `mariadb`, `mysql` to `simple_mode.allowlist_comms`
to avoid false positives from database process operations.

### CapRover

```
CapRover uses Docker Swarm under the hood. Install ebpf-guard on every Swarm node
for full coverage. On a single-node CapRover install, one agent covers everything.
```

**Recommended:** CapRover apps are named `srv-captain--YOURAPP`. If ebpf-guard
flags unexpected shells from these containers, check your app's deployment logs
first — some build processes legitimately spawn shells.

### Dokploy

```
Dokploy manages Docker Compose stacks. Install ebpf-guard on the host. If you
have multiple Dokploy nodes, install on each one.
```

**Recommended:** Dokploy's Traefik integration often spawns certificate renewal
processes. Add `traefik` and `certbot` to `simple_mode.allowlist_comms`.

---

## Step 4: Verify with a safe test

### Test 1: Simulated webshell

```bash
# Create a test that looks like nginx → bash
cp /bin/sleep /tmp/shell-test
# In a different terminal, start a process named "node" then "bash"
(sleep 0.1 && exec -a bash /tmp/shell-test 120) &
PID=$!
exec -a node /bin/true 2>/dev/null  # runs too fast to matter
```

Check for alerts:
```bash
sudo journalctl -u ebpf-guard | grep "web_shell_spawn\|shell_spawn"
```

Kill the test:
```bash
kill $PID 2>/dev/null
```

### Test 2: Simulated cryptominer connection

```bash
# Create a process connecting to a mining pool port
# (This only works if you have nc/ncat installed)
exec -a xmrig nc -z time.google.com 3333 2>/dev/null &
```

Check `journalctl -u ebpf-guard` for `cryptominer` alerts.

---

## Step 5: Go live

After monitoring the dry-run output for 24 hours:

1. Review: `sudo journalctl -u ebpf-guard --since "24 hours ago" | grep "would have killed"`
2. If no unexpected false positives, disable dry-run:
   ```yaml
   simple_mode:
     dry_run_duration: "0"
   ```
3. Restart: `sudo systemctl restart ebpf-guard`

---

## Expected resource usage

| Metric | Typical (3-app PaaS server) |
|---|---|
| **CPU overhead** | < 3% on a 4-core VPS |
| **Memory** | ~50-80 MB RSS (more apps = slightly more memory for process profiles) |
| **Disk** | ~5 MB (binary + config), <100 MB if SQLite store is used |
| **Network** | Outbound webhooks only (Discord/Telegram) — < 100KB/day |

ebpf-guard uses BPF-side event sampling to automatically reduce overhead when
event rates spike (e.g., during app deployments). No manual tuning needed.

---

## Troubleshooting

### "My CI/CD pipeline triggers false positives"
During deploys, containers may legitimately spawn shells or download tools. Solutions:
1. **Allowlist the CI/CD comms**: add `git`, `npm`, `pip`, `composer`, `docker` to `simple_mode.allowlist_comms`
2. **Use the learning period**: set `simple_mode.dry_run_duration` to `"168h"` (1 week) while you observe
3. **Tag your CI/CD containers** and add rules that exclude them by container label

### "Too many network alerts from my reverse proxy"
Traefik/Caddy/Nginx legitimately connect to many destinations. Solutions:
1. The default config already allowlists these comms — check your `allowlist_comms`
2. For CIDR-level exceptions, add custom rules to `/etc/ebpf-guard/rules/allowlist.yaml`

### "Disk space is growing"
If you enabled SQLite store (`store.backend: sqlite`), check:
```bash
ls -lh /var/lib/ebpf-guard/events.db
```
Set retention in config:
```yaml
store:
  backend: sqlite
  sqlite:
    path: /var/lib/ebpf-guard/events.db
    max_alerts: 10000
    retention_period: "7d"
```

---

## Next steps

- [Connect Telegram for phone alerts](vps.md)
- [View plain-language alert explanations](vps.md)
- [Add per-app custom rules](https://github.com/zugolO/ebpf-guard#configuration)
