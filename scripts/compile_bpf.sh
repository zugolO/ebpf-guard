#!/usr/bin/env bash
# compile_bpf.sh — Compile all BPF C programs to .o object files.
#
# Run this on a machine that has:
#   - clang 14+ with BPF target support
#   - libbpf development headers (libbpf-dev)
#   - /sys/kernel/btf/vmlinux (for generating vmlinux.h)
#
# Usage:
#   ./scripts/compile_bpf.sh
#   # or with custom clang:
#   CLANG=clang-16 ./scripts/compile_bpf.sh
#
# Output:
#   internal/bpf/*.bpf.o   — compiled BPF object files
#   bpf/vmlinux.h          — BTF type header (regenerated if stale/missing)
#
# After running this script, the generated .o files can be embedded into the
# Go binary via //go:embed (see internal/bpf/loader.go) or used directly by
# bpf2go to produce Go bindings.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BPF_DIR="${REPO_ROOT}/bpf"
OUT_DIR="${REPO_ROOT}/internal/bpf"
CLANG="${CLANG:-clang}"
BPFTOOL="${BPFTOOL:-bpftool}"

# Detect architecture
UNAME_M="$(uname -m)"
case "${UNAME_M}" in
  aarch64) BPF_ARCH="arm64"; BPF_ARCH_DEF="__TARGET_ARCH_arm64"; SYS_INCLUDE="/usr/include/aarch64-linux-gnu" ;;
  *)       BPF_ARCH="x86";   BPF_ARCH_DEF="__TARGET_ARCH_x86_64"; SYS_INCLUDE="/usr/include/x86_64-linux-gnu" ;;
esac

CFLAGS="-O2 -g -Wall -target bpf -D${BPF_ARCH_DEF} -I${BPF_DIR} -I/usr/include -I${SYS_INCLUDE}"

echo "==> Checking prerequisites..."

if ! command -v "${CLANG}" &>/dev/null; then
  echo "Error: ${CLANG} not found. Install clang: apt-get install clang llvm" >&2
  exit 1
fi

CLANG_VERSION=$("${CLANG}" --version | head -1 | grep -oP '\d+\.\d+\.\d+' | head -1 | cut -d. -f1)
if [[ "${CLANG_VERSION:-0}" -lt 14 ]]; then
  echo "Warning: clang version ${CLANG_VERSION} detected; 14+ recommended for BPF CO-RE." >&2
fi

echo "==> Generating vmlinux.h from running kernel BTF..."
if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
  echo "Error: /sys/kernel/btf/vmlinux not found." >&2
  echo "  The kernel must be built with CONFIG_DEBUG_INFO_BTF=y." >&2
  echo "  On Ubuntu: use HWE kernel 5.15+ or linux-image-generic." >&2
  exit 1
fi

if ! command -v "${BPFTOOL}" &>/dev/null; then
  echo "Error: ${BPFTOOL} not found. Install: apt-get install linux-tools-generic" >&2
  exit 1
fi

"${BPFTOOL}" btf dump file /sys/kernel/btf/vmlinux format c > "${BPF_DIR}/vmlinux.h"
echo "  Written: ${BPF_DIR}/vmlinux.h ($(wc -l < "${BPF_DIR}/vmlinux.h") lines)"

mkdir -p "${OUT_DIR}"

compile_one() {
  local src="$1"
  local name
  name="$(basename "${src}" .bpf.c)"
  local out="${OUT_DIR}/${name}.bpf.o"

  echo "  [CC] ${name}.bpf.c -> internal/bpf/${name}.bpf.o"
  # shellcheck disable=SC2086
  "${CLANG}" ${CFLAGS} -c "${src}" -o "${out}"
}

echo "==> Compiling BPF programs (arch=${BPF_ARCH})..."

BPF_SOURCES=(
  "${BPF_DIR}/syscall.bpf.c"
  "${BPF_DIR}/network.bpf.c"
  "${BPF_DIR}/fileaccess.bpf.c"
  "${BPF_DIR}/privesc.bpf.c"
  "${BPF_DIR}/dns.bpf.c"
  "${BPF_DIR}/iouring.bpf.c"
  "${BPF_DIR}/bpf_monitor.bpf.c"
  "${BPF_DIR}/lsm.bpf.c"
  "${BPF_DIR}/cgroup.bpf.c"
  "${BPF_DIR}/hidden_process.bpf.c"
  "${BPF_DIR}/tls_clienthello.bpf.c"
  "${BPF_DIR}/tls_uprobe.bpf.c"
  "${BPF_DIR}/xdp_block.bpf.c"
  "${BPF_DIR}/gpu_uprobe.bpf.c"
)

ERRORS=0
for src in "${BPF_SOURCES[@]}"; do
  if compile_one "${src}"; then
    :
  else
    echo "  [FAIL] ${src}" >&2
    ERRORS=$((ERRORS + 1))
  fi
done

if [[ ${ERRORS} -gt 0 ]]; then
  echo "==> ${ERRORS} BPF program(s) failed to compile." >&2
  exit 1
fi

echo "==> All BPF programs compiled successfully."
echo ""
echo "Next steps:"
echo "  1. Run 'make generate' to produce Go bindings via bpf2go"
echo "     (requires /root/go/bin/bpf2go — install with: go install github.com/cilium/ebpf/cmd/bpf2go@latest)"
echo "  2. Delete internal/bpf/syscall_bpf_gen.go (stub file replaced by generated files)"
echo "  3. Run 'go build ./...' to verify"
