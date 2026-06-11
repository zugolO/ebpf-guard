#!/bin/sh
# Runs inside the virtme-ng kernel VM as root.
# Loads all BPF objects using the smoke binary and reports results.
set -eu

SMOKE_BINARY="${SMOKE_BINARY:-./smoke-amd64}"
BPF_OBJECTS_DIR="${BPF_OBJECTS_DIR:-./bpf-objects}"
KERNEL_VERSION="${KERNEL_VERSION:-unknown}"
REPORT_FILE="smoke-report-${KERNEL_VERSION}-$(uname -m).json"

echo "=== ebpf-guard kernel smoke suite ==="
echo "Kernel: $(uname -r)"
echo "Arch:   $(uname -m)"
echo "Objects: ${BPF_OBJECTS_DIR}"
echo ""

# Mount debugfs and tracefs — required for some BPF program types.
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true

# Run the smoke binary with JSON output so CI can parse results.
"${SMOKE_BINARY}" \
  --bpf-dir "${BPF_OBJECTS_DIR}" \
  --json \
  | tee "${REPORT_FILE}"

EXIT_CODE=$?

echo ""
if [ "${EXIT_CODE}" -eq 0 ]; then
  echo "PASS — all BPF objects loaded successfully (or degraded gracefully)"
else
  echo "FAIL — one or more BPF objects failed to load"
fi

exit "${EXIT_CODE}"
