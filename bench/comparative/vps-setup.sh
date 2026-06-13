#!/usr/bin/env bash
# bench/comparative/vps-setup.sh — bootstrap a VPS for ebpf-guard benchmarks
#
# Tested on Ubuntu 22.04 / kernel 6.1 LTS, x86-64.
# Run as root (or with sudo) on the VPS before bench/comparative/run.sh.
#
# USAGE
#   curl -fsSL <raw-url>/bench/comparative/vps-setup.sh | sudo bash
#   # or after cloning the repo:
#   sudo bench/comparative/vps-setup.sh [--skip-competitors] [--go-version 1.23.4]

set -euo pipefail

# ─── Pinned versions (must match run.sh) ─────────────────────────────────────
readonly FALCO_VERSION="0.38.1"
readonly TETRAGON_VERSION="1.1.0"
readonly TRACEE_VERSION="0.21.0"
readonly DEFAULT_GO_VERSION="1.23.4"

# ─── Flags ───────────────────────────────────────────────────────────────────
SKIP_COMPETITORS=false
GO_VERSION="$DEFAULT_GO_VERSION"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-competitors) SKIP_COMPETITORS=true; shift ;;
    --go-version)       GO_VERSION="$2";       shift 2 ;;
    --help)
      echo "Usage: $0 [--skip-competitors] [--go-version X.Y.Z]"
      echo "  --skip-competitors   Install only Go + system tools, skip Falco/Tetragon/Tracee"
      echo "  --go-version X.Y.Z   Go version to install (default: ${DEFAULT_GO_VERSION})"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

log()  { echo "[$(date +%H:%M:%S)] $*"; }
die()  { echo "[$(date +%H:%M:%S)] ERROR: $*" >&2; exit 1; }
ok()   { echo "[$(date +%H:%M:%S)] OK: $*"; }

# ─── 1. System requirements check ────────────────────────────────────────────
log "Checking system..."

[[ "$(uname -s)" == "Linux" ]] || die "This script requires Linux."
[[ "$(uname -m)" == "x86_64" ]] || die "This script requires x86-64."
[[ "$(id -u)" -eq 0 ]] || die "Run as root: sudo $0 $*"

KERNEL_VERSION=$(uname -r)
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)
log "Kernel: $KERNEL_VERSION"

if [[ "$KERNEL_MAJOR" -lt 5 || ( "$KERNEL_MAJOR" -eq 5 && "$KERNEL_MINOR" -lt 15 ) ]]; then
  die "Kernel 5.15+ required for full eBPF+BTF support (got $KERNEL_VERSION)"
fi

if [[ -f /sys/kernel/btf/vmlinux ]]; then
  ok "BTF available: $(wc -c < /sys/kernel/btf/vmlinux) bytes"
else
  die "/sys/kernel/btf/vmlinux not found — kernel not compiled with CONFIG_DEBUG_INFO_BTF"
fi

# ─── 2. APT packages ─────────────────────────────────────────────────────────
log "Installing system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  build-essential \
  clang-14 llvm-14 \
  linux-headers-"$(uname -r)" \
  linux-tools-"$(uname -r)" linux-tools-common \
  curl wget ca-certificates \
  bc jq \
  time \
  git \
  2>&1 | tail -5

# Symlink clang-14 → clang if no default clang present
if ! command -v clang >/dev/null 2>&1; then
  update-alternatives --install /usr/bin/clang   clang   /usr/bin/clang-14   100
  update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-14 100
fi
ok "System packages installed"

# ─── 3. Go ───────────────────────────────────────────────────────────────────
INSTALLED_GO=""
if command -v go >/dev/null 2>&1; then
  INSTALLED_GO=$(go version | awk '{print $3}' | tr -d 'go')
fi

if [[ "$INSTALLED_GO" == "$GO_VERSION" ]]; then
  ok "Go $GO_VERSION already installed"
else
  log "Installing Go $GO_VERSION..."
  GO_TAR="go${GO_VERSION}.linux-amd64.tar.gz"
  curl -fsSL -o "/tmp/${GO_TAR}" "https://go.dev/dl/${GO_TAR}"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "/tmp/${GO_TAR}"
  rm -f "/tmp/${GO_TAR}"

  # Add to PATH for this session and for future logins
  export PATH="/usr/local/go/bin:$PATH"
  if ! grep -q '/usr/local/go/bin' /etc/profile.d/go.sh 2>/dev/null; then
    echo 'export PATH="/usr/local/go/bin:$PATH"' > /etc/profile.d/go.sh
  fi
  ok "Go $(go version) installed"
fi

# ─── 4. Competitor tools ──────────────────────────────────────────────────────
if [[ "$SKIP_COMPETITORS" == "true" ]]; then
  log "Skipping competitor installs (--skip-competitors)"
else

  # Falco
  if falco --version 2>&1 | grep -q "${FALCO_VERSION}" 2>/dev/null; then
    ok "Falco ${FALCO_VERSION} already installed"
  else
    log "Installing Falco ${FALCO_VERSION}..."
    curl -fsSL -o /tmp/falco.deb \
      "https://github.com/falcosecurity/falco/releases/download/${FALCO_VERSION}/falco_${FALCO_VERSION}_amd64.deb"
    dpkg -i /tmp/falco.deb || apt-get -f install -y -qq
    rm -f /tmp/falco.deb
    ok "Falco $(falco --version 2>&1 | head -1)"
  fi

  # Tetragon
  if tetragon version 2>&1 | grep -q "${TETRAGON_VERSION}" 2>/dev/null; then
    ok "Tetragon ${TETRAGON_VERSION} already installed"
  else
    log "Installing Tetragon ${TETRAGON_VERSION}..."
    curl -fsSL -o /tmp/tetragon.tar.gz \
      "https://github.com/cilium/tetragon/releases/download/v${TETRAGON_VERSION}/tetragon-linux-amd64.tar.gz"
    tar -C /usr/local/bin -xzf /tmp/tetragon.tar.gz --strip-components=1 tetragon
    rm -f /tmp/tetragon.tar.gz
    chmod +x /usr/local/bin/tetragon
    ok "Tetragon $(tetragon version 2>&1 | head -1)"
  fi

  # Tracee
  if tracee version 2>&1 | grep -q "${TRACEE_VERSION}" 2>/dev/null; then
    ok "Tracee ${TRACEE_VERSION} already installed"
  else
    log "Installing Tracee ${TRACEE_VERSION}..."
    curl -fsSL -o /usr/local/bin/tracee \
      "https://github.com/aquasecurity/tracee/releases/download/v${TRACEE_VERSION}/tracee-linux-amd64"
    chmod +x /usr/local/bin/tracee
    ok "Tracee $(tracee version 2>&1 | head -1)"
  fi

fi

# ─── 5. Version summary ───────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════"
echo "  VPS setup complete — version summary"
echo "══════════════════════════════════════════════════"
echo "  Kernel  : $(uname -r)"
echo "  BTF     : $(wc -c < /sys/kernel/btf/vmlinux) bytes"
echo "  Go      : $(go version 2>/dev/null | awk '{print $3}' || echo 'NOT FOUND')"
echo "  clang   : $(clang --version 2>/dev/null | head -1 || echo 'NOT FOUND')"
echo "  perf    : $(perf --version 2>/dev/null || echo 'NOT FOUND')"
if [[ "$SKIP_COMPETITORS" == "false" ]]; then
  echo "  Falco   : $(falco --version 2>/dev/null | head -1 || echo 'NOT FOUND')"
  echo "  Tetragon: $(tetragon version 2>/dev/null | head -1 || echo 'NOT FOUND')"
  echo "  Tracee  : $(tracee version 2>/dev/null | head -1 || echo 'NOT FOUND')"
fi
echo "══════════════════════════════════════════════════"
echo ""
echo "Next steps:"
echo "  1. Clone the repo (or rsync from your machine):"
echo "       git clone <repo-url> /opt/ebpf-guard && cd /opt/ebpf-guard"
echo "  2. Build ebpf-guard:"
echo "       make generate && make build"
echo "  3. Run benchmarks (algorithm-only, no root needed):"
echo "       bench/comparative/run.sh --ci"
echo "  4. Run full end-to-end sweep (root required):"
echo "       sudo bench/comparative/run.sh --sweep"
echo ""