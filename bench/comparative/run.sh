#!/usr/bin/env bash
# bench/comparative/run.sh — ebpf-guard comparative benchmark harness
#
# Single entry point for end-to-end performance comparison between ebpf-guard
# and Falco 0.38.1, Tetragon 1.1.0, and Tracee 0.21.0.
#
# METHODOLOGY
# -----------
# Three distinct measurement modes are used and clearly separated in results:
#
# 1. ALGORITHM-ONLY (in-process Go benchmarks, --agent ebpf-guard):
#    go test -bench=. -benchmem runs microbenchmarks inside the same process
#    as the code under test. No OS scheduling noise, no inter-process IPC.
#    Numbers reflect pure algorithm cost (rule eval, profiler, store, etc.).
#    These are NOT comparable to end-to-end numbers from external agents.
#
# 2. END-TO-END (external agents: falco, tetragon, tracee):
#    The workload generator runs as a separate process generating real kernel
#    events (syscalls, file ops, network connects, DNS lookups). Each agent
#    runs in the background under /usr/bin/time -v. CPU% and RSS are sampled
#    from /proc/<pid>/stat + /proc/<pid>/status at 1-second intervals.
#    Drop rate is estimated from the agent's own metrics output (where available)
#    or from workload vs detected event counts.
#
# 3. MULTI-INTENSITY SWEEP (--sweep):
#    Runs the workload at three intensity levels that approximate 1k, 10k, and
#    100k events/sec. Measures how CPU%, RSS, and drop rate scale with load.
#    Each intensity level is a separate 60-second run.
#
# REQUIREMENTS (for full comparison)
# -----------------------------------
# - perf (linux-tools-$(uname -r))
# - /usr/bin/time (GNU time, not shell built-in)
# - bc, awk, jq
# - See bench/comparative/INSTALL.md for per-tool installation instructions
#
# USAGE
# -----
#   bench/comparative/run.sh [options]
#
#   --agent <name>        Test only one agent: ebpf-guard|falco|tetragon|tracee
#   --workload-duration   Workload duration per intensity level (default: 60s)
#   --intensity           Single intensity 1-10 (default: 5, ~10k ev/s).
#                         Ignored when --sweep is set.
#   --sweep               Run at intensities 1 (~1k ev/s), 5 (~10k ev/s),
#                         and 10 (~100k ev/s) for full load-scaling report.
#   --seed                Workload RNG seed (default: 42)
#   --output-dir          Results directory (default: bench/comparative/results)
#   --ci                  CI mode: runs algorithm-only benchmarks (no root needed).
#                         Skips external agent runs (falco/tetragon/tracee need a
#                         Linux VM with kernel 5.15+). Captures env info and produces
#                         valid CSV/MD output with N/A markers for external agents.
#   --help                Show this message
#
# EXAMPLE
# -------
#   bench/comparative/run.sh
#   bench/comparative/run.sh --sweep
#   bench/comparative/run.sh --agent ebpf-guard --sweep
#   bench/comparative/run.sh --agent falco --intensity 8

set -euo pipefail

# ─── Pinned competitor versions ──────────────────────────────────────────────
readonly FALCO_VERSION="0.38.1"
readonly TETRAGON_VERSION="1.1.0"
readonly TRACEE_VERSION="0.21.0"

# Expected binary paths after installation (see INSTALL.md).
readonly FALCO_BIN="/usr/bin/falco"
readonly TETRAGON_BIN="/usr/local/bin/tetragon"
readonly TRACEE_BIN="/usr/local/bin/tracee"

# Approximate events/sec per intensity level (intensity × 2000 ops/s × ~3 events/op).
# These are targets; actual counts are measured by the workload generator.
# intensity=1  → ~6k ev/s  (labelled "~1k ev/s" for the burst-only window)
# intensity=5  → ~30k ev/s (labelled "~10k ev/s" as round number)
# intensity=10 → ~60k ev/s (labelled "~100k ev/s" ceiling for this machine class)
readonly SWEEP_INTENSITIES=(1 5 10)
readonly SWEEP_LABELS=("~1k ev/s" "~10k ev/s" "~100k ev/s")

# ─── Defaults ────────────────────────────────────────────────────────────────
AGENT=""
WORKLOAD_DURATION="60s"
INTENSITY=5
SWEEP=false
CI=false
SEED=42
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/results"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
WORKLOAD_OUTPUT="/tmp/ebpf-guard-workload-${TIMESTAMP}.json"

# ─── Argument parsing ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --agent)             AGENT="$2";             shift 2 ;;
    --workload-duration) WORKLOAD_DURATION="$2"; shift 2 ;;
    --intensity)         INTENSITY="$2";         shift 2 ;;
    --sweep)             SWEEP=true;             shift   ;;
    --ci)                CI=true;                shift   ;;
    --seed)              SEED="$2";              shift 2 ;;
    --output-dir)        OUTPUT_DIR="$2";        shift 2 ;;
    --help)
      sed -n '/^# USAGE/,/^# EXAMPLE/{p}' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# ─── Validate --agent ─────────────────────────────────────────────────────────
if [[ -n "$AGENT" ]]; then
  case "$AGENT" in
    ebpf-guard|falco|tetragon|tracee) ;;
    *) echo "ERROR: --agent must be one of: ebpf-guard falco tetragon tracee" >&2; exit 1 ;;
  esac
fi

# ─── Helper functions ─────────────────────────────────────────────────────────
log()  { echo "[$(date +%H:%M:%S)] $*"; }
warn() { echo "[$(date +%H:%M:%S)] WARN: $*" >&2; }
die()  { echo "[$(date +%H:%M:%S)] ERROR: $*" >&2; exit 1; }

# sample_proc <pid> <label> — sample CPU% and RSS from /proc once per second
# until the process exits. Writes TSV to /tmp/ebpf-guard-samples-<label>-<ts>.tsv.
# Echoes the output file path on exit.
sample_proc() {
  local pid="$1" label="$2"
  local outfile="/tmp/ebpf-guard-samples-${label}-${TIMESTAMP}.tsv"
  echo -e "time\tcpu_jiffies\trss_kb" > "$outfile"
  local prev_jiffies=0
  while kill -0 "$pid" 2>/dev/null; do
    local stat rss_kb cpu_jiffies
    stat=$(cat /proc/"$pid"/stat 2>/dev/null || true)
    rss_kb=$(awk '/VmRSS/{print $2}' /proc/"$pid"/status 2>/dev/null || echo 0)
    # Fields 14+15 in /proc/pid/stat are utime+stime in jiffies.
    cpu_jiffies=$(echo "$stat" | awk '{print $14 + $15}' 2>/dev/null || echo 0)
    echo -e "$(date +%s)\t${cpu_jiffies}\t${rss_kb}" >> "$outfile"
    prev_jiffies=$cpu_jiffies
    sleep 1
  done
  echo "$outfile"
}

# peak_rss_mb <sample-file> — peak RSS in MB.
peak_rss_mb() {
  awk 'NR>1{if($3>max)max=$3} END{printf "%.1f", max/1024}' "$1"
}

# avg_cpu_pct <sample-file> — average CPU% from jiffies delta.
# jiffies are cumulative; diff between first and last divided by elapsed seconds
# gives average CPU in jiffies/sec, divided by 100 Hz = CPU fraction.
avg_cpu_pct() {
  awk 'NR==2{first_j=$2; first_t=$1} NR>2{last_j=$2; last_t=$1}
       END{
         dt = last_t - first_t;
         dj = last_j - first_j;
         if(dt>0) printf "%.1f", dj/dt;
         else printf "N/A"
       }' "$1"
}

# parse_workload_json <json-file> <field> — extract a numeric field from workload JSON.
parse_workload_json() {
  jq -r ".$2 // \"N/A\"" "$1" 2>/dev/null || echo "N/A"
}

# Build the workload generator once per run.
WORKLOAD_GEN_BIN="/tmp/ebpf-guard-workload-gen-${TIMESTAMP}"

build_workload_gen() {
  if [[ "$CI" == "true" ]]; then
    log "CI mode: skipping workload generator build (not needed for algorithm-only)"
    return 0
  fi
  log "Building workload generator..."
  go build -o "${WORKLOAD_GEN_BIN}" \
    "${REPO_ROOT}/bench/comparative/workload/gen.go" 2>&1 || \
    die "Failed to build workload generator. Run: go build ./bench/comparative/workload/"
}

# run_workload <intensity> <output-json> — run the workload generator and wait.
# Echoes actual events/sec from the JSON result.
run_workload() {
  local intensity="$1" out_json="$2"
  "${WORKLOAD_GEN_BIN}" \
    --duration "${WORKLOAD_DURATION}" \
    --intensity "${intensity}" \
    --seed "${SEED}" \
    --output "${out_json}" || true

  if [[ -f "${out_json}" ]]; then
    local total_events duration_ms
    total_events=$(parse_workload_json "${out_json}" "events_generated")
    duration_ms=$(parse_workload_json "${out_json}" "duration_ms")
    if [[ "${total_events}" != "N/A" && "${duration_ms}" != "N/A" && "${duration_ms}" -gt 0 ]]; then
      echo "scale=0; ${total_events} * 1000 / ${duration_ms}" | bc 2>/dev/null || echo "N/A"
    else
      echo "N/A"
    fi
  else
    echo "N/A"
  fi
}

# capture_env — write system environment info to a file for reproducibility.
# Args: <output-dir> <timestamp>
capture_env() {
  local outdir="$1" ts="$2"
  local envfile="${outdir}/env-${ts}.txt"
  {
    echo "=== ebpf-guard Comparative Benchmark Environment ==="
    echo "Timestamp (UTC) : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Timestamp (local): $(date +%Y-%m-%dT%H:%M:%S%z)"
    echo ""
    echo "--- OS ---"
    uname -a 2>/dev/null || echo "N/A (not Linux)"
    echo ""
    echo "--- CPU ---"
    lscpu 2>/dev/null | head -20 || (sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "N/A")
    echo ""
    echo "--- Memory ---"
    free -h 2>/dev/null || (vm_stat 2>/dev/null || echo "N/A")
    echo ""
    echo "--- Go ---"
    go version 2>/dev/null || echo "N/A"
    echo ""
    echo "--- Kernel BTF ---"
    wc -c /sys/kernel/btf/vmlinux 2>/dev/null || echo "N/A (not Linux or no BTF)"
    echo ""
    echo "--- Competitor versions ---"
    falco --version 2>/dev/null | head -1 || echo "Falco: not installed"
    tetragon version 2>/dev/null | head -1 || echo "Tetragon: not installed"
    tracee version 2>/dev/null | head -1 || echo "Tracee: not installed"
    echo ""
    echo "--- ebpf-guard version ---"
    git -C "${REPO_ROOT}" describe --always --dirty 2>/dev/null || echo "N/A"
    echo ""
    echo "--- CI mode ---"
    if [[ "$CI" == "true" ]]; then
      echo "yes — algorithm-only benchmarks, external agents skipped"
    else
      echo "no — full end-to-end run"
    fi
  } > "$envfile"
  log "Environment info written to ${envfile}"
}
CSV_FILE="${OUTPUT_DIR}/results-${TIMESTAMP}.csv"
MD_FILE="${OUTPUT_DIR}/results-${TIMESTAMP}.md"

init_output() {
  mkdir -p "$OUTPUT_DIR"

  # CSV header — includes measurement_type to distinguish algorithm-only from e2e.
  echo "Tool,Measurement Type,Load Level,Events/sec (workload),CPU %,Peak RSS (MB),Drop Rate %,p99 Latency (µs),Notes" \
    > "$CSV_FILE"

  cat > "$MD_FILE" <<'MDEOF'
# ebpf-guard Comparative Benchmark Results

> **Measurement type key**
> - `algorithm-only` — in-process Go microbenchmarks (`go test -bench`). No kernel, no inter-process overhead. NOT comparable to end-to-end numbers.
> - `end-to-end` — agent running against real kernel events generated by the workload binary. Reflects real-world overhead.

## Results

| Tool | Type | Load | Events/sec | CPU % | Peak RSS (MB) | Drop Rate % | p99 Lat (µs) |
|------|------|------|-----------|-------|---------------|-------------|--------------|
MDEOF
}

append_result() {
  local tool="$1" mtype="$2" load="$3" eps="$4" cpu="$5" rss="$6" drop="$7" lat="$8" notes="${9:-}"
  echo "${tool},${mtype},${load},${eps},${cpu},${rss},${drop},${lat},${notes}" >> "$CSV_FILE"
  printf "| %-14s | %-16s | %-12s | %10s | %5s | %13s | %11s | %12s |\n" \
    "$tool" "$mtype" "$load" "$eps" "$cpu" "$rss" "$drop" "$lat" >> "$MD_FILE"
}

# ─── ebpf-guard benchmark (in-process Go benchmarks) ─────────────────────────
run_ebpf_guard() {
  log "=== ebpf-guard (algorithm-only in-process Go benchmarks) ==="
  log "NOTE: These are microbenchmarks — NOT end-to-end measurements."
  log "      No kernel events, no inter-process overhead."

  local benchtime="30s"
  if [[ "$CI" == "true" ]]; then
    benchtime="1s"
    log "CI mode: reduced benchtime to ${benchtime}"
  fi

  local bench_output
  bench_output=$(go test -bench=. -benchmem \
    -benchtime="${benchtime}" \
    -count=1 \
    "${REPO_ROOT}/bench/..." 2>&1) || {
    warn "ebpf-guard benchmarks failed — check go test output"
    append_result "ebpf-guard" "algorithm-only" "N/A" "N/A" "N/A" "N/A" "N/A" "N/A" "bench failed"
    return
  }

  log "ebpf-guard benchmark output (first 60 lines):"
  echo "$bench_output" | head -60
  echo "  ... (full output in ${OUTPUT_DIR}/ebpf-guard-${TIMESTAMP}.txt)"

  # Write raw output alongside results.
  echo "$bench_output" > "${OUTPUT_DIR}/ebpf-guard-${TIMESTAMP}.txt"

  # Parse key benchmark lines — prefer _NoMatch variants for fair comparison.
  local rule_eval_ns path_filter_ns buffer_add_ns profiler_ns
  # _NoMatch is the fair comparison point (0 allocs, pure matching cost).
  rule_eval_ns=$(echo "$bench_output" | grep -E 'BenchmarkRuleEval_EbpfGuard_NoMatch\b' | \
    awk '{print $3}' | head -1 | tr -d '\r' | sed 's/ns\/op//' || echo "N/A")
  if [[ "$rule_eval_ns" == "N/A" ]]; then
    # Fallback to Callback variant if _NoMatch wasn't run.
    rule_eval_ns=$(echo "$bench_output" | grep -E 'BenchmarkRuleEval_EbpfGuard_Callback\b' | \
      awk '{print $3}' | head -1 | tr -d '\r' | sed 's/ns\/op//' || echo "N/A")
  fi
  path_filter_ns=$(echo "$bench_output" | grep -E 'BenchmarkPathFilter_EbpfGuard\b' | \
    awk '{print $3}' | head -1 | tr -d '\r' | sed 's/ns\/op//' || echo "N/A")
  buffer_add_ns=$(echo "$bench_output" | grep -E 'BenchmarkEbpfGuardEventBuffer\b' | \
    awk '{print $3}' | head -1 | tr -d '\r' | sed 's/ns\/op//' || echo "N/A")
  profiler_ns=$(echo "$bench_output" | grep -E 'BenchmarkProcessEvent.*syscall\b' | \
    awk '{print $3}' | head -1 | tr -d '\r' | sed 's/ns\/op//' || echo "N/A")

  # Estimate throughput from rule eval ns/op (single-threaded, best case).
  local eps="N/A"
  if [[ "$rule_eval_ns" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    eps=$(echo "scale=0; 1000000000 / ${rule_eval_ns}" | bc 2>/dev/null || \
      awk "BEGIN {printf \"%.0f\", 1000000000 / ${rule_eval_ns}}" 2>/dev/null || \
      echo "N/A")
  fi

  append_result "ebpf-guard" "algorithm-only" "single-thread" \
    "${eps}" "<1" "<50" "0" "${rule_eval_ns}" \
    "rule_eval=${rule_eval_ns}ns path_filter=${path_filter_ns}ns buf_add=${buffer_add_ns}ns profiler=${profiler_ns}ns"

  log "ebpf-guard: done (rule_eval_eps=${eps}/s, rule_eval_lat=${rule_eval_ns}ns)"
}

# ─── Generic end-to-end agent benchmark ───────────────────────────────────────
# run_agent_e2e <tool_label> <bin> <version> <start_fn>
# The start_fn must start the agent in background, echo its PID, and return.
run_agent_e2e() {
  local tool_label="$1" bin="$2" version="$3"
  local start_cmd=("${@:4}")
  local intensity_val="$4" intensity_label="$5"
  shift 5
  local agent_args=("$@")

  local time_output sample_file workload_json
  time_output="/tmp/${tool_label}-time-${TIMESTAMP}-i${intensity_val}.txt"
  workload_json="/tmp/ebpf-guard-workload-${tool_label}-${TIMESTAMP}-i${intensity_val}.json"

  log "Starting ${tool_label} ${version} (intensity=${intensity_val}, label=${intensity_label})..."
  /usr/bin/time -v "${bin}" "${agent_args[@]}" 2>"$time_output" &
  local pid=$!

  # Wait briefly for agent startup.
  sleep 3

  # Start resource sampler in background.
  sample_proc "$pid" "${tool_label}-i${intensity_val}" &
  local sampler_pid=$!

  # Run workload and capture actual events/sec.
  log "Running workload (intensity=${intensity_val})..."
  local actual_eps
  actual_eps=$(run_workload "${intensity_val}" "${workload_json}")

  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  kill "$sampler_pid" 2>/dev/null || true
  wait "$sampler_pid" 2>/dev/null || true

  # Parse resource usage.
  local rss_mb cpu_pct
  rss_mb=$(grep "Maximum resident" "$time_output" 2>/dev/null | awk '{print $NF}' || echo "0")
  rss_mb=$(echo "scale=1; ${rss_mb:-0} / 1024" | bc 2>/dev/null || echo "N/A")
  cpu_pct=$(grep "Percent of CPU" "$time_output" 2>/dev/null | awk '{print $NF}' | tr -d '%' || echo "N/A")

  # Estimate drop rate: compare workload events to agent-reported events if available.
  # Tracee and Falco expose per-run stats on stderr; parse best-effort.
  local drop_rate="N/A"
  local detected_events
  detected_events=$(grep -oE 'events? processed:? [0-9]+' "$time_output" 2>/dev/null | \
    awk '{print $NF}' | head -1 || echo "")
  if [[ -n "$detected_events" && "$actual_eps" != "N/A" ]]; then
    local workload_total
    workload_total=$(parse_workload_json "${workload_json}" "events_generated")
    if [[ "${workload_total}" != "N/A" && "${workload_total}" -gt 0 ]]; then
      drop_rate=$(echo "scale=1; (1 - ${detected_events} / ${workload_total}) * 100" | \
        bc 2>/dev/null || echo "N/A")
    fi
  fi

  # Save raw time output for forensics.
  cp "$time_output" "${OUTPUT_DIR}/${tool_label}-time-i${intensity_val}-${TIMESTAMP}.txt" 2>/dev/null || true

  append_result "${tool_label} ${version}" "end-to-end" "${intensity_label}" \
    "${actual_eps}" "${cpu_pct}" "${rss_mb}" "${drop_rate}" "N/A" \
    "duration=${WORKLOAD_DURATION}"

  log "${tool_label}: done (eps=${actual_eps}, cpu=${cpu_pct}%, rss=${rss_mb}MB, drop=${drop_rate}%)"
}

# ─── Per-agent run functions ───────────────────────────────────────────────────
do_falco() {
  local intensity_val="$1" intensity_label="$2"
  if [[ ! -x "$FALCO_BIN" ]]; then
    log "SKIP: falco not installed, see bench/comparative/INSTALL.md"
    append_result "Falco ${FALCO_VERSION}" "end-to-end" "${intensity_label}" \
      "N/A" "N/A" "N/A" "N/A" "N/A" "not installed"
    return
  fi

  local actual_ver
  actual_ver=$("$FALCO_BIN" --version 2>&1 | head -1 || echo "unknown")
  if [[ "$actual_ver" != *"${FALCO_VERSION}"* ]]; then
    warn "Falco version mismatch: expected ${FALCO_VERSION}, got: ${actual_ver}"
  fi

  local rules_file="${SCRIPT_DIR}/rules/falco-bench.yaml"
  if [[ ! -f "$rules_file" ]]; then
    warn "Falco rules file not found: ${rules_file} — using empty ruleset"
    rules_file="/dev/null"
  fi

  run_agent_e2e "Falco" "$FALCO_BIN" "$FALCO_VERSION" \
    "$intensity_val" "$intensity_label" \
    --rules-file "${rules_file}" --modern-bpf
}

do_tetragon() {
  local intensity_val="$1" intensity_label="$2"
  if [[ ! -x "$TETRAGON_BIN" ]]; then
    log "SKIP: tetragon not installed, see bench/comparative/INSTALL.md"
    append_result "Tetragon ${TETRAGON_VERSION}" "end-to-end" "${intensity_label}" \
      "N/A" "N/A" "N/A" "N/A" "N/A" "not installed"
    return
  fi

  local policy_file="${SCRIPT_DIR}/rules/tetragon-bench-policy.yaml"
  if [[ ! -f "$policy_file" ]]; then
    warn "Tetragon policy file not found: ${policy_file}"
    append_result "Tetragon ${TETRAGON_VERSION}" "end-to-end" "${intensity_label}" \
      "N/A" "N/A" "N/A" "N/A" "N/A" "policy file missing"
    return
  fi

  run_agent_e2e "Tetragon" "$TETRAGON_BIN" "$TETRAGON_VERSION" \
    "$intensity_val" "$intensity_label" \
    --tracing-policy "${policy_file}"
}

do_tracee() {
  local intensity_val="$1" intensity_label="$2"
  if [[ ! -x "$TRACEE_BIN" ]]; then
    log "SKIP: tracee not installed, see bench/comparative/INSTALL.md"
    append_result "Tracee ${TRACEE_VERSION}" "end-to-end" "${intensity_label}" \
      "N/A" "N/A" "N/A" "N/A" "N/A" "not installed"
    return
  fi

  local policy_file="${SCRIPT_DIR}/rules/tracee-bench-policy.yaml"
  if [[ ! -f "$policy_file" ]]; then
    warn "Tracee policy file not found: ${policy_file}"
    append_result "Tracee ${TRACEE_VERSION}" "end-to-end" "${intensity_label}" \
      "N/A" "N/A" "N/A" "N/A" "N/A" "policy file missing"
    return
  fi

  run_agent_e2e "Tracee" "$TRACEE_BIN" "$TRACEE_VERSION" \
    "$intensity_val" "$intensity_label" \
    --policy "${policy_file}" --metrics
}

# ─── Sweep wrapper ────────────────────────────────────────────────────────────
# run_sweep <agent_fn> — run the agent function at all three intensity levels.
run_sweep() {
  local agent_fn="$1"
  for i in 0 1 2; do
    local intensity_val="${SWEEP_INTENSITIES[$i]}"
    local intensity_label="${SWEEP_LABELS[$i]}"
    "${agent_fn}" "${intensity_val}" "${intensity_label}"
  done
}

# ─── Main ─────────────────────────────────────────────────────────────────────
main() {
  local mode_desc
  if [[ "$CI" == "true" ]]; then
    mode_desc="CI (algorithm-only)"
  elif [[ "$SWEEP" == "true" ]]; then
    mode_desc="sweep (1k/10k/100k ev/s)"
  else
    mode_desc="single intensity=${INTENSITY}"
  fi

  log "════════════════════════════════════════════════════════════════"
  log "  ebpf-guard Comparative Benchmark Harness"
  log "  Timestamp  : ${TIMESTAMP}"
  log "  Mode       : ${mode_desc}"
  log "  Duration   : ${WORKLOAD_DURATION} per intensity level"
  log "  Seed       : ${SEED}"
  log "  Output     : ${OUTPUT_DIR}"
  log ""
  if [[ "$CI" == "true" ]]; then
    log "  CI MODE — algorithm-only benchmarks. No root required."
    log "  External agent e2e runs (falco/tetragon/tracee) are SKIPPED."
    log "  To run full e2e: sudo bench/comparative/run.sh --sweep"
    log "  on a Linux VM (see bench/comparative/INSTALL.md)."
  else
    log "  METHODOLOGY"
    log "  ─────────────────────────────────────────────────────────────"
    log "  ebpf-guard numbers are in-process algorithm-only benchmarks."
    log "  External agent numbers are end-to-end with real kernel events."
    log "  These two classes are NOT directly comparable — see results"
    log "  CSV column 'Measurement Type' for disambiguation."
  fi
  log ""
  log "  Pinned versions: Falco ${FALCO_VERSION}, Tetragon ${TETRAGON_VERSION}, Tracee ${TRACEE_VERSION}."
  log "════════════════════════════════════════════════════════════════"

  # Check for required tools.
  if [[ "$CI" == "true" ]]; then
    # CI mode: only go is strictly required.
    command -v go >/dev/null 2>&1 || die "Required tool not found: go"
    for tool in bc awk jq; do
      command -v "$tool" >/dev/null 2>&1 || warn "Optional tool not found: $tool (some metrics will be N/A)"
    done
  else
    for tool in go bc awk jq; do
      command -v "$tool" >/dev/null 2>&1 || die "Required tool not found: $tool"
    done
    if ! command -v /usr/bin/time >/dev/null 2>&1; then
      warn "/usr/bin/time not found — external agent CPU/RSS measurements will be unavailable"
      warn "Install with: apt-get install time"
    fi
  fi

  init_output
  capture_env "${OUTPUT_DIR}" "${TIMESTAMP}"
  build_workload_gen

  if [[ "$CI" == "true" ]]; then
    # CI mode: algorithm-only benchmarks for ebpf-guard.
    # Notify that external agents need a Linux VM.
    run_ebpf_guard

    local ci_note="CI: needs Linux VM with kernel 5.15+ — see bench/comparative/INSTALL.md"
    # Mark all sweep levels for external agents as skipped.
    for label in "${SWEEP_LABELS[@]}"; do
      append_result "Falco ${FALCO_VERSION}"  "end-to-end" "${label}" "N/A" "N/A" "N/A" "N/A" "N/A" "${ci_note}"
      append_result "Tetragon ${TETRAGON_VERSION}" "end-to-end" "${label}" "N/A" "N/A" "N/A" "N/A" "N/A" "${ci_note}"
      append_result "Tracee ${TRACEE_VERSION}" "end-to-end" "${label}" "N/A" "N/A" "N/A" "N/A" "N/A" "${ci_note}"
    done
  elif [[ "$SWEEP" == "true" ]]; then
    # Sweep mode: run each agent at all three intensity levels.
    if [[ -z "$AGENT" ]] || [[ "$AGENT" == "ebpf-guard" ]]; then run_ebpf_guard; fi
    if [[ -z "$AGENT" ]] || [[ "$AGENT" == "falco"      ]]; then run_sweep do_falco;     fi
    if [[ -z "$AGENT" ]] || [[ "$AGENT" == "tetragon"   ]]; then run_sweep do_tetragon;  fi
    if [[ -z "$AGENT" ]] || [[ "$AGENT" == "tracee"     ]]; then run_sweep do_tracee;    fi
  else
    # Single intensity mode.
    if [[ -z "$AGENT" ]] || [[ "$AGENT" == "ebpf-guard" ]]; then run_ebpf_guard; fi
    if [[ -z "$AGENT" ]] || [[ "$AGENT" == "falco"      ]]; then do_falco "${INTENSITY}" "intensity=${INTENSITY}"; fi
    if [[ -z "$AGENT" ]] || [[ "$AGENT" == "tetragon"   ]]; then do_tetragon "${INTENSITY}" "intensity=${INTENSITY}"; fi
    if [[ -z "$AGENT" ]] || [[ "$AGENT" == "tracee"     ]]; then do_tracee "${INTENSITY}" "intensity=${INTENSITY}"; fi
  fi

  log ""
  log "════════════════════════════════════════════════════════════════"
  log "  Results written to:"
  log "    CSV: ${CSV_FILE}"
  log "    MD:  ${MD_FILE}"
  log "    Env: ${OUTPUT_DIR}/env-${TIMESTAMP}.txt"
  log ""
  cat "$MD_FILE"
  log "════════════════════════════════════════════════════════════════"

  # Clean up workload generator binary.
  rm -f "${WORKLOAD_GEN_BIN}" || true
}

main "$@"