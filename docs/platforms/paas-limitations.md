# Deploy ebpf-guard on Railway / Fly.io / Render

> Honest guide about what works and what doesn't on shared-runtime PaaS platforms.
> Time to read: **5 minutes**.

---

## The honest truth about eBPF on shared platforms

**ebpf-guard needs direct Linux kernel access.** eBPF programs run inside the
kernel and can monitor the entire system. On shared-runtime platforms (Railway,
Fly.io, Render, Heroku), your application shares a kernel with other tenants,
and you typically **cannot** load eBPF programs.

| Platform | Direct kernel access? | ebpf-guard possible? | Recommendation |
|---|---|---|---|
| **Railway** | No (shared kernel, Firecracker microVM) | No | Protect the CI/CD pipeline or deploy target |
| **Fly.io** | Yes (per-app Firecracker VM with own kernel) | **Yes**, with limitations | Deploy as a sidecar VM |
| **Render** | No (shared infrastructure) | No | Protect the build/deploy pipeline |
| **Heroku** | No (shared dynos) | No | Protect the staging/production VPS |
| **Vercel / Netlify** | No (serverless / edge functions) | No | N/A — serverless can't run eBPF |

---

## Platform-specific guidance

### Fly.io — possible with sidecar pattern

Fly.io gives each app its own Firecracker VM with a dedicated kernel. You can
run ebpf-guard as a **sidecar app** that monitors your main application VM.

**Limitations on Fly.io:**
- The Firecracker VM has a stripped-down kernel — some eBPF features may be missing
- LSM hooks (`lsm/bpf_file_open`) require `CONFIG_BPF_LSM=y`, which Fly VMs may not have
- The VM has no Docker socket — container enrichment won't work
- You can only monitor your own VM, not the host

**Setup (experimental):**

```toml
# fly.toml — sidecar pattern
app = "myapp-with-guard"

[experimental]
cmd = ["/app/start.sh"]

[[vm]]
  size = "shared-cpu-1x"

[mounts]
  source = "ebpf_guard_data"
  destination = "/var/lib/ebpf-guard"

[processes]
  app = "node dist/server.js"
  guard = "/usr/local/bin/ebpf-guard --config /etc/ebpf-guard/config.yaml"
```

**What you CAN detect on Fly.io:**
- Cryptominer binaries running in your VM
- Webshells and reverse shells from your web processes
- Suspicious syscall sequences (anomaly detection)
- Privilege escalation attempts (capability changes)
- Sensitive file access (/etc/shadow, /etc/passwd)

**What you CANNOT detect on Fly.io:**
- Attacks on other apps on the same physical machine (different VM)
- Container escapes (no containers to escape from)
- Network-level attacks across VMs (you can only see your own network)
- Docker/containerd-level enrichments

### Railway / Render / Heroku — indirect protection

Since you can't run ebpf-guard directly on these platforms, protect the
**surrounding infrastructure**:

```
                    ┌─────────────────────┐
                    │  Your CI/CD (GitHub  │
                    │  Actions, GitLab CI) │
                    │      ↓              │
                    │  ebpf-guard scans   │
                    │  build artifacts     │
                    └─────────┬───────────┘
                              │ deploys to
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
   ┌────▼────┐          ┌────▼────┐          ┌─────▼────┐
   │ Railway │          │ Render  │          │  Heroku  │
   │  (app)  │          │  (app)  │          │  (app)   │
   └─────────┘          └─────────┘          └──────────┘
                              │
                      ┌───────▼───────┐
                      │  Your Database │
                      │  (Supabase,    │
                      │   PlanetScale, │
                      │   Neon, etc.)  │
                      └───────────────┘
```

**What you should do instead:**

1. **Protect your CI/CD pipeline**: run ebpf-guard in CI to scan built containers
   for known malware signatures before deploying to Railway/Render/Heroku.

2. **Protect your database**: if your Railway/Render app connects to an external
   database (Supabase, PlanetScale, Neon), consider running ebpf-guard on a
   **jump host or bastion** that proxies database connections and monitors for
   SQL injection, credential theft, and data exfiltration patterns.

3. **Monitor from a side VPS**: deploy a cheap VPS ($5/mo Hetzner/DigitalOcean)
   that runs ebpf-guard and receives syslog/CEF alerts from your PaaS apps via
   the `notifications.syslog_cef` integration. At minimum, you get alerting even
   if you can't do enforcement.

4. **Use the PaaS-native security features**: Railway has secret scanning, Render
   has private services with internal networking, Fly.io has WireGuard networking.
   Layer ebpf-guard's rule set thinking onto these: audit your app's outbound
   connections, check for unexpected processes in deploy logs, monitor for
   unexpected outbound data volume.

---

## The architecture decision tree

```
Can you install kernel-level software on your host?
│
├── YES → Use the VPS guide (docs/platforms/vps.md)
│   │
│   ├── I run Docker → works perfectly
│   ├── I run Kubernetes → use the Helm chart instead
│   └── I run Coolify/CapRover/Dokploy → use the PaaS guide (docs/platforms/coolify-caprover.md)
│
└── NO (shared platform / serverless)
    │
    ├── I'm on Fly.io → experimental sidecar possible (see above)
    │
    └── I'm on Railway/Render/Heroku/Vercel
        │
        ├── Protect your CI/CD pipeline (scan images before deploy)
        ├── Protect your database with a jump host
        ├── Deploy a $5 side-VPS for alert monitoring
        └── Use platform-native security features as first line of defense
```

---

## Testing on Fly.io (experimental)

If you want to try ebpf-guard on Fly.io:

1. **Deploy a test app** with the sidecar pattern above
2. **Enable simple mode with extended dry-run** (1 week):
   ```yaml
   simple_mode:
     enabled: true
     dry_run_duration: "168h"  # 1 week observation
   ```
3. **Run the safe test** from the VPS guide to verify detection works
4. **Check Fly.io-specific metrics**: memory pressure may be higher on smaller VMs;
   consider `bpf.max_concurrent_events: 1024` on `shared-cpu-1x` instances

---

## Expected limitations on shared platforms

| Feature | Available on Fly.io? | Notes |
|---|---|---|
| Syscall tracing | ✅ Yes | Works on any Linux kernel 5.15+ |
| Network monitoring | ✅ Yes | TCP connect events visible |
| File access monitoring | ✅ Yes | open/read/write events |
| DNS monitoring | ✅ Yes | DNS packet capture via socket filter |
| TLS inspection | ⚠️ Limited | Requires `CAP_SYS_PTRACE` — may not be available |
| LSM enforcement | ❌ No | Requires `CONFIG_BPF_LSM=y` in kernel config |
| nftables enforcement | ❌ No | VM has no access to host nftables |
| Container enrichment | ❌ No | No Docker/CRI socket in Firecracker VM |
| Kubernetes enrichment | ❌ No | No K8s API on Fly.io |
| Process kill enforcement | ✅ Yes | SIGKILL works within the VM |

---

## Setting up Discord and Telegram notifications

Whether you're running ebpf-guard on Fly.io or on a side VPS watching a
Railway/Render app, alert notifications land on your phone in seconds.

### Discord

1. In your Discord server, go to **Server Settings → Integrations → Webhooks → New Webhook**.
2. Copy the webhook URL.
3. Add it to your config (or environment):

```yaml
notifications:
  discord:
    enabled: true
    webhook_url: "https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN"
    min_severity: "warning"   # "warning" or "critical" — omit for all alerts
```

**Verification:** Run the safe test from the VPS guide (`sudo sh -c 'echo test > /etc/cron.d/ebpf-guard-test'`),
then delete it. A warning alert should appear in your Discord channel within a few seconds.

### Telegram

1. Message **@BotFather** on Telegram: `/newbot` → follow the prompts → copy the **bot token**.
2. Add your new bot to a group or start a DM, then visit
   `https://api.telegram.org/bot<TOKEN>/getUpdates` to find your **chat_id**.
3. Add to your config:

```yaml
notifications:
  telegram:
    enabled: true
    bot_token: "123456:ABCdef..."
    chat_id: "-100123456789"   # group chat_id is negative; DM chat_id is positive
    min_severity: "critical"   # recommended: only critical to Telegram to reduce noise
```

**Verification:** Same safe test as above — a formatted Telegram message should arrive within seconds.

---

## Summary

- **Fly.io users**: try the sidecar pattern for per-VM protection (syscall, network, file monitoring work)
- **Railway/Render/Heroku users**: protect your CI/CD and deploy a side VPS for alert monitoring
- **Everyone**: Discord/Telegram notifications work regardless of where ebpf-guard runs — get alerts on your phone even from a $5 side VPS
