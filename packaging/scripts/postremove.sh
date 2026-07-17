#!/bin/sh
# Runs after the .deb/.rpm package removes its files. Stops/disables the
# service on removal; /var/lib/ebpf-guard and /var/log/ebpf-guard (and any
# /etc/ebpf-guard files marked noreplace) are left in place so an upgrade or
# reinstall doesn't lose state.
set -e

if command -v systemctl >/dev/null 2>&1; then
	systemctl stop ebpf-guard.service 2>/dev/null || true
	systemctl disable ebpf-guard.service 2>/dev/null || true
	systemctl daemon-reload || true
fi
