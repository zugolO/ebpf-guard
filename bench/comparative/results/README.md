# bench/comparative/results/

This directory contains raw CSV and Markdown outputs from `bench/comparative/run.sh`.

## File naming

```
results-YYYYMMDD-HHMMSS.csv   — machine-readable results table
results-YYYYMMDD-HHMMSS.md    — human-readable Markdown table
ebpf-guard-YYYYMMDD-HHMMSS.txt — raw `go test -bench` output for ebpf-guard
<tool>-time-i<N>-YYYYMMDD-HHMMSS.txt — raw `/usr/bin/time -v` output per agent per intensity
```

## Reproducing results

### Automated (recommended)

```bash
# Provision the reference VM (Ubuntu 22.04, kernel 6.1, 4 vCPU, 8 GB RAM)
vagrant up

# Run the full sweep (1k / 10k / 100k events/sec for all agents)
vagrant ssh -c "cd /vagrant && sudo bench/comparative/run.sh --sweep"

# Or run only ebpf-guard without root (algorithm-only benchmarks)
vagrant ssh -c "cd /vagrant && bench/comparative/run.sh --agent ebpf-guard"
```

Results are written to this directory via the VirtualBox shared folder.

### Manual (on a Linux host)

```bash
# Install competitor tools (see INSTALL.md)

# Run the full sweep (requires root for eBPF agents)
sudo bench/comparative/run.sh --sweep

# Single intensity, ebpf-guard only (no root)
bench/comparative/run.sh --agent ebpf-guard
```

## Measurement types

Results include a `Measurement Type` column. Values:

| Type | Description |
|------|-------------|
| `algorithm-only` | In-process Go microbenchmarks (`go test -bench`). No kernel, no IPC. Reflects pure algorithm cost. **Not directly comparable** to end-to-end numbers. |
| `end-to-end` | Agent running against real kernel events from the workload generator. Reflects real-world CPU%, RSS, and drop rate. |

## Load levels (sweep mode)

| Label | Intensity | Target ops/sec | Approx events/sec |
|-------|-----------|----------------|-------------------|
| `~1k ev/s`   | 1  | 2,000  | ~6,000 |
| `~10k ev/s`  | 5  | 10,000 | ~30,000 |
| `~100k ev/s` | 10 | 20,000 | ~60,000 |

Actual events/sec is recorded from the workload generator's JSON output (field `events_generated / duration_ms`).

## Reference hardware

Benchmark credibility requires a fixed hardware spec. Results in this directory
should always include a companion `env-*.txt` capturing:

```
uname -a
lscpu
free -h
cat /sys/kernel/btf/vmlinux | wc -c   # confirms BTF present
go version
falco --version
tetragon version
tracee version
```

The Vagrantfile provisions a standardised VM matching this spec:
- OS: Ubuntu 22.04 LTS
- Kernel: 6.1 LTS (HWE)
- CPUs: 4 vCPUs
- RAM: 8 GB
- Go: 1.23.0
- clang: 14.0

## Interpreting drop rate

Drop rate is estimated as `1 - detected_events / workload_events_generated`.
Where an agent does not expose per-run event counts, drop rate is reported as `N/A`.

A non-zero drop rate at low intensity (`~1k ev/s`) indicates a structural problem
(BPF ring buffer too small, agent startup lag, or rule evaluation slower than event arrival rate).

## Adding a new run

Commit the dated CSV and MD files. Do not delete old runs — they provide a
longitudinal record. If hardware changes, add a note to the commit message.