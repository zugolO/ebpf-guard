#!/usr/bin/env bash
# =============================================================
# demo/setup-vps.sh — prepare VPS for the ebpf-guard live demo
#
# Installs build dependencies, compiles BPF programs via the
# existing scripts/compile_bpf.sh, then builds the binary.
# Also installs Docker and starts the OWASP Juice Shop target
# (demo/docker-compose.yml) alongside the lightweight
# target-app/app.py.
#
# Run as root from the repo root:
#   sudo ./demo/setup-vps.sh
# =============================================================
set -euo pipefail

GRN='\033[0;32m'; YLW='\033[1;33m'; RED='\033[0;31m'; RST='\033[0m'
ok()   { echo -e "${GRN}[ok]${RST}  $*"; }
info() { echo -e "${YLW}[..]${RST}  $*"; }
die()  { echo -e "${RED}[!!]${RST}  $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Must run as root"
cd "$(dirname "${BASH_SOURCE[0]}")/.."

KERNEL=$(uname -r)
info "Kernel: $KERNEL  |  Arch: $(uname -m)"

# ─── 1. System packages ───────────────────────────────────────
info "Installing build dependencies..."
apt-get update -qq
apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev \
    "linux-headers-${KERNEL}" \
    "linux-tools-${KERNEL}" linux-tools-common linux-tools-generic \
    make git curl ca-certificates python3
ok "Build dependencies installed"

# ─── 2. Go 1.23+ ─────────────────────────────────────────────
export PATH="/usr/local/go/bin:${HOME}/go/bin:$PATH"
if go version 2>/dev/null | grep -qE "go1\.(2[3-9]|[3-9][0-9])"; then
    ok "Go already installed: $(go version)"
else
    GO_VERSION="1.23.4"
    info "Installing Go $GO_VERSION..."
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz
    rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tar.gz && rm /tmp/go.tar.gz
    echo 'export PATH=/usr/local/go/bin:$HOME/go/bin:$PATH' >> /etc/profile.d/go.sh
    ok "Go installed: $(go version)"
fi

# ─── 3. bpf2go ───────────────────────────────────────────────
if ! command -v bpf2go &>/dev/null && [[ ! -f "${HOME}/go/bin/bpf2go" ]]; then
    info "Installing bpf2go..."
    go install github.com/cilium/ebpf/cmd/bpf2go@latest
fi
export PATH="${HOME}/go/bin:$PATH"
ok "bpf2go: $(bpf2go 2>&1 | head -1 || echo 'ready')"

# ─── 4. Docker + Juice Shop target ────────────────────────────
if command -v docker &>/dev/null; then
    ok "Docker already installed: $(docker --version)"
else
    info "Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
    ok "Docker installed: $(docker --version)"
fi

info "Starting Juice Shop target (docker compose)..."
docker compose -f demo/docker-compose.yml up -d
ok "Juice Shop starting on 127.0.0.1:3000"

# ─── 5. Compile BPF programs (reuses scripts/compile_bpf.sh) ─
info "Compiling BPF C programs..."
bash scripts/compile_bpf.sh
ok "BPF programs compiled"

# ─── 6. Run bpf2go to generate Go bindings ───────────────────
info "Generating Go bindings (make generate)..."
make generate
ok "Go bindings generated"

# ─── 7. Build binary ─────────────────────────────────────────
info "Building ebpf-guard binary..."
make build
ok "Binary ready: $(ls -lh build/ebpf-guard)"

# ─── 8. Firewall — protect vulnerable demo app ports ─────────
info "Restricting demo target ports to localhost..."
for PORT in 8080 3000; do
    iptables -C INPUT -p tcp --dport "$PORT" -s 127.0.0.1 -j ACCEPT 2>/dev/null || \
        iptables -I INPUT -p tcp --dport "$PORT" -s 127.0.0.1 -j ACCEPT
    iptables -C INPUT -p tcp --dport "$PORT" -j DROP 2>/dev/null || \
        iptables -A INPUT -p tcp --dport "$PORT" -j DROP
done
ok "Ports 8080, 3000 restricted to localhost"

echo ""
echo -e "${GRN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo -e "${GRN}  Setup complete! Run the demo:${RST}"
echo ""
echo "  # 1. Start ebpf-guard (real eBPF)"
echo "  sudo ./build/ebpf-guard --config config/config.yaml &"
echo "  ADMIN_TOKEN=\$(awk -F= '/admin/{print \$2}' /run/ebpf-guard/token)"
echo ""
echo "  # 2. Start vulnerable target"
echo "  python3 demo/target-app/app.py &"
echo "  # Juice Shop is already running: http://localhost:3000"
echo ""
echo "  # 3. Launch attacks"
echo "  ./demo/attack-scripts/attack.sh localhost:8080 localhost:9090 \"\$ADMIN_TOKEN\""
echo -e "${GRN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
