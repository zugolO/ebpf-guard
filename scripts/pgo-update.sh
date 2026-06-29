#!/usr/bin/env bash
# pgo-update.sh — Regenerate default.pgo from hot-path benchmarks.
#
# Usage:
#   ./scripts/pgo-update.sh [--benchtime 2s] [--out default.pgo]
#
# This script captures CPU profiles from the correlator and profiler packages
# (the event-parsing → correlation hot path) and merges them into a single
# pprof profile that Go's compiler reads automatically when building with
# -pgo=auto (the default since Go 1.21).
#
# Run after significant changes to RuleEngine.EvaluateInto, EWMA scoring,
# or any function that appears in the top-10 of 'go tool pprof default.pgo'.
#
# Prerequisites: go 1.21+, no kernel/BPF required.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH_TIME="${BENCH_TIME:-2s}"
OUTPUT="${1:-${REPO_ROOT}/default.pgo}"
TMPDIR_WORK="$(mktemp -d)"
trap 'rm -rf "${TMPDIR_WORK}"' EXIT

log() { printf '[pgo-update] %s\n' "$*" >&2; }

# Hot-path packages and the benchmark filter.
PKGS=(
  "./internal/correlator/"
  "./internal/profiler/"
)
BENCH_FILTER="BenchmarkRuleEval|BenchmarkProcessEvent|BenchmarkIsLearningComplete"

PROFILES=()

for pkg in "${PKGS[@]}"; do
  safe="${pkg//\//_}"
  safe="${safe//./_}"
  out="${TMPDIR_WORK}/cpu-${safe}.pprof"

  log "Capturing CPU profile: ${pkg} (benchtime=${BENCH_TIME})"
  if go test \
      -bench="${BENCH_FILTER}" \
      -benchtime="${BENCH_TIME}" \
      -run='^$' \
      -count=1 \
      -cpuprofile="${out}" \
      "${pkg}" \
      > /dev/null 2>&1; then
    PROFILES+=("${out}")
    log "  → captured: ${out} ($(stat -c%s "${out}") bytes)"
  else
    log "  WARNING: profile capture failed for ${pkg}, skipping"
  fi
done

if [[ ${#PROFILES[@]} -eq 0 ]]; then
  log "ERROR: all profile captures failed; default.pgo not updated"
  exit 1
fi

log "Merging ${#PROFILES[@]} profile(s) into ${OUTPUT}..."
go tool pprof -proto "${PROFILES[@]}" > "${OUTPUT}"

SIZE="$(stat -c%s "${OUTPUT}")"
log "Done: ${OUTPUT} (${SIZE} bytes)"
log ""
log "Verify with:  go tool pprof -top ${OUTPUT}"
log "Rebuild with: make build   (PGO is picked up automatically)"
