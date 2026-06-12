# Deploy ebpf-guard on a Plain VPS

> Copy-paste guide for Hetzner, DigitalOcean, OVH, Linode, Vultr, or any Linux VPS.
> Time to complete: **under 5 minutes**.

This guide protects the Docker host and all containers running on it. You'll get
runtime threat detection for cryptominers, webshells, reverse shells, container
escapes, and suspicious network activity — with alerts delivered to Discord or Telegram.

---

## Prerequisites

- A Linux VPS running **Ubuntu 22.04+** or **Debian 12+** (ARM or x86)
- Kernel **5.15+** (check: `uname -r`)
- Root or sudo access
- Docker installed (optional — ebpf-guard protects Docker containers automatically)

---

## Step 1: Install ebpf-guard

```bash
# Download the latest binary (x86_64)
curl -fsSL -o /tmp/ebpf-guard https://github.com/zugolO/ebpf-guard/releases/latest/download/ebpf-guard-linux-amd64

# For ARM64 (Raspberry Pi, AWS Graviton, etc.)
# curl -fsSL -o /tmp/ebpf-guard https://github.com/zugolO/ebpf-guard/releases/latest/download/ebpf-guard-linux-arm64

# Make it executable and install
sudo install -m 755 /tmp/ebpf-guard /usr/local/bin/ebpf-guard
```

Verify the install:

```bash
ebpf-guard version
```

---

## Step 2: Create a minimal config

ebpf-guard can run with zero config (built-in defaults), but you'll want to connect
notifications. Create `/etc/ebpf-guard/config.yaml`:

```yaml
# /etc/ebpf-guard/config.yaml — minimal VPS config

# Enable all built-in rule sets
rules:
  path: ""                    # use embedded rules (all 40 rule files loaded automatically)

# Discord notifications (pick one or both)
notifications:
  discord:
    enabled: true
    webhook_url: "https://discord.com/api/webhooks/YOUR_WEBHOOK_URL"
    min_severity: warning

  telegram:
    enabled: false
    bot_token: "123456:ABC-DEF"
    chat_id: "-100123456"
    min_severity: critical   # only critical to Telegram to avoid noise

# Simple mode: auto-kill cryptominers, webshells, reverse shells
simple_mode:
  enabled: true
  dry_run_duration: "24h"    # first 24h: log only, don't kill

# Store alerts in memory (lightweight, no disk)
store:
  backend: memory

# Protect the metrics endpoint with auto-generated token
auth:
  enabled: true
```

---

## Step 3: Install the systemd service

```bash
sudo tee /etc/systemd/system/ebpf-guard.service << 'EOF'
[Unit]
Description=ebpf-guard Runtime Security Agent
Documentation=https://github.com/zugolO/ebpf-guard
After=network-online.target docker.service containerd.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ebpf-guard --config /etc/ebpf-guard/config.yaml
Restart=always
RestartSec=10
LimitNOFILE=65536
LimitMEMLOCK=infinity
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_SYS_PTRACE CAP_SYS_RESOURCE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/ebpf-guard /var/log/ebpf-guard

# Allow BPF maps and programs
MountFlags=shared
ExecStartPre=/bin/mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true

[Install]
WantedBy=multi-user.target
EOF
```

Start the agent:

```bash
sudo mkdir -p /var/lib/ebpf-guard /var/log/ebpf-guard
sudo systemctl daemon-reload
sudo systemctl enable --now ebpf-guard
```

Check it's running:

```bash
sudo systemctl status ebpf-guard
sudo journalctl -u ebpf-guard -f
```

---

## Step 4: Verify the installation

### A safe test (simulated cryptominer)

This creates a harmless process that looks like a cryptominer to ebpf-guard:

```bash
# Create a test process named "xmrig" that just sleeps
cp /bin/sleep /tmp/xmrig-test
/tmp/xmrig-test 60 &
```

Within seconds you should see:
1. **A log entry**: `simple: would have killed (dry-run)` in `journalctl -u ebpf-guard`
2. **A Discord/Telegram notification** explaining what happened

After verification, clean up:

```bash
kill %1 2>/dev/null
rm /tmp/xmrig-test
```

### Check metrics

```bash
# Get the auto-generated token
sudo journalctl -u ebpf-guard --no-pager | grep "admin_token"

# Then check metrics
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:9090/metrics | grep ebpf_guard
```

### Check alerts via the API

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:9090/api/v1/alerts
```

---

## Step 5: Go live (after 24h dry-run)

After 24 hours of observation:

1. **Review what would have been killed**: check `journalctl -u ebpf-guard | grep "would have killed"`
2. **If everything looks correct**, disable dry-run:

```yaml
# /etc/ebpf-guard/config.yaml
simple_mode:
  enabled: true
  dry_run_duration: "0"   # remove the dry-run window
```

3. **Restart**: `sudo systemctl restart ebpf-guard`

Now cryptominers, webshells, and reverse shells will be **automatically killed**
within seconds of detection.

---

## Expected resource usage

| Resource | Typical usage |
|---|---|
| **CPU** | < 2% on a 2-core VPS at idle |
| **Memory** | ~40-60 MB RSS |
| **Disk** | < 5 MB for binary + systemd unit (no log files unless audit log enabled) |

---

## Troubleshooting

### "BPF program load failed"
Your kernel might be too old. Check:
```bash
uname -r  # must be 5.15+
```
On older VPS images, upgrade the kernel:
```bash
# Ubuntu
sudo apt install linux-generic-hwe-22.04 && sudo reboot

# Debian
sudo apt install linux-image-amd64 && sudo reboot
```

### "Permission denied" on BPF operations
The systemd unit needs `CAP_BPF`. Verify:
```bash
sudo systemctl show ebpf-guard | grep AmbientCapabilities
```

### Discord webhook not receiving
```bash
# Test your webhook URL directly
curl -X POST YOUR_WEBHOOK_URL \
  -H "Content-Type: application/json" \
  -d '{"content": "ebpf-guard test message"}'
```

### Too many alerts
If you're getting noise, add `simple_mode` allowlists:
```yaml
simple_mode:
  allowlist_comms: ["node", "java", "ruby", "my-app"]
```

---

## Next steps

- [Connect notifications to Discord + Telegram](https://github.com/zugolO/ebpf-guard#configuration)
- [Add custom allowlist rules](https://github.com/zugolO/ebpf-guard#configuration)
- [Deploy to Kubernetes with Helm](https://github.com/zugolO/ebpf-guard#4-deploy-to-kubernetes)
- [View alert explanations in plain language](https://github.com/zugolO/ebpf-guard#alert-explanation)
