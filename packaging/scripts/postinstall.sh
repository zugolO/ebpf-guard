#!/bin/sh
# Runs after the .deb/.rpm package installs its files.
set -e

if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload || true
	systemctl enable ebpf-guard.service || true
fi

cat <<'EOF'
ebpf-guard installed.

  Start it:      systemctl start ebpf-guard
  View logs:      journalctl -u ebpf-guard -f
  Config example: /etc/ebpf-guard/config.yaml.example
  Rules:          /etc/ebpf-guard/rules/
  Local tuning:   /etc/ebpf-guard/local-tuning.yaml.example

By default the unit runs with --zero-config (embedded defaults, hardware-
aware auto-tuning). Copy config.yaml.example to config.yaml and edit
/lib/systemd/system/ebpf-guard.service's ExecStart to point at it if you
need Alertmanager, Slack, or Teams notifications.
EOF
