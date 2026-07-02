# Benchmark report — `main` @ f0413d4 (2026-07-02)

Full benchmark pass over the `main` branch: unit/race test suite, synthetic
micro-benchmarks, full-pipeline load tests, and a live-agent attack simulation
with detection-latency measurement.

## Environment

| | |
|---|---|
| CPU | Intel Xeon @ 2.10 GHz, 4 vCPU |
| RAM | 15 GiB |
| Kernel | Linux 6.18.5 (sandbox VM, **no kernel BTF** — real eBPF attach unavailable, see “Limitations”) |
| Go | 1.25.0 (PGO enabled via `default.pgo`) |
| Rules | all 572 built-in rules loaded unless noted |

## 1. Test suite — are the bugs fixed?

`go test -race ./...`: **33/33 packages pass, zero data races.**

The only failures under `-race` are the two e2e performance-target tests
(`TestPerformanceRegression`, `TestSustainedThroughput`) — expected, because
the race detector costs ~8× on this hot path and CI intentionally runs these
without `-race` (`ci.yml:608`). Re-run without the race detector, **both pass
with 4× headroom over the target**:

| Test | Target | Measured | Result |
|---|---|---|---|
| TestPerformanceRegression | ≥ 250 000 ev/s | **1 053 414 ev/s** (63.2M events / 60 s, 0 dropped) | PASS |
| TestSustainedThroughput | ≥ 237 500 ev/s | **1 052 596 ev/s** (0 dropped) | PASS |
| TestMemoryProfileAtLoad | peak < 100 MB | **1 113 518 ev/s**, peak heap 13.4 MB | PASS |
| TestShardedLockContention | p99 < 5 µs | 2 612 276 ev/s, **p99 contention 0 µs** (128 shards) | PASS |
| TestLoadFullPipelineThroughput | ≥ 2 000 ev/s | 16 095 ev/s (collector-rate-limited by design), RSS 53.4 MiB, 620/620 alerts persisted | PASS |

Issue tracker state: **no open bugs** — the only 3 open issues (#225, #226,
#227) are experimental research spikes.

## 2. Synthetic micro-benchmarks

### Correlation engine (headline, CI settings, `-benchtime=10s`)

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| CorrelationEngine 1k–20k eps | 626–646 | 208 | 1 |
| CorrelationEngineParallel | 667 | 208 | 1 |
| ShardedBufferContention | 214 | 2 | 0 |
| Ingest_NoMatch_Syscall | 981 | 272 | 2 |
| Ingest_Match_Syscall | 1 302 | 286 | 2 |
| RuleEval_NoMatchByType | 6.7 | 0 | 0 |
| RuleEval_NoMatchByCond | 31 | 0 | 0 |
| RuleEval_Match | 61 | 0 | 0 |
| RuleEval_MultiRule | 209 | 0 | 0 |

### Profiler (target: ProcessEvent < 10 µs p99)

| Benchmark | ns/op | allocs/op |
|---|---|---|
| ProcessEvent | 723 | 0 |
| ProcessEventSyscall | 620 | 0 |
| ProcessEventFileAccess | 698 | 1 |
| ProcessEventParallel | 958 | 0 |
| IsLearningComplete | 1.4 | 0 |

### BPF ring-buffer parsers

| Benchmark | ns/op |
|---|---|
| ParseSyscallEvent / Into | 11.2 / 9.2 |
| ParseNetworkEvent / Into | 7.0 / 4.4 |
| ParseFileaccessEvent / Into | 18.3 / 7.9 |

### Alert store (memory backend)

| Benchmark | ns/op | allocs/op |
|---|---|---|
| Store | 2 978 | 3 |
| StoreBatch (100) | 161 677 | 331 |
| Query | 12 953 | 1 |
| QueryBySeverity | 7 579 | 1 |
| QueryByID | 489 | 2 |
| Count | 0.7 | 0 |

### DNS / DGA hot paths

| Benchmark | ns/op |
|---|---|
| AnalyzeDomain | 42 |
| NgramScore | 128 |
| DNSPrefilter benign (cached) | 274 |
| DNSPrefilter DGA (cached) | 94 |
| MiningPool IP / domain lookup | 829 / 41 |

## 3. Attack simulation — detection speed

All 7 built-in `attack-sim` scenarios were driven through the production
correlation engine with **all 572 rules loaded** (2 000 iterations each,
varying PID; measured with `benchmark-harness/`).

### Detection compute latency (synchronous rule evaluation per attack event)

| Scenario (MITRE) | p50 | p95 | p99 | max |
|---|---|---|---|---|
| privesc-cap-sys-admin (T1548.001) | 1.5 µs | 2.3 µs | 5.4 µs | 21 µs |
| kmod-load (T1547.006) | 3.3 µs | 5.4 µs | 11 µs | 26 µs |
| container-escape-ptrace (T1611) | 7.1 µs | 11.8 µs | 24 µs | 316 µs |
| cryptominer-pool-connect (T1496) | 9.6 µs | 15 µs | 26 µs | 53 µs |
| dga-dns-query (T1568.002) | 17.9 µs | 29.5 µs | 40 µs | 78 µs |
| sensitive-file-read (T1003.008) | 40 µs | 60 µs | 75 µs | 183 µs |
| ldpreload-drop (T1574.006) | 65 µs | 98 µs | 138 µs | 906 µs |

Every scenario was detected (alerts fire until the per-rule rate limit of
10 alerts/min kicks in — by design).

### End-to-end alert delivery (production async path)

`IngestAsync → PID-partitioned worker pool → Flush`, polled at 1 ms:
**p50 ≈ 99.7 ms, p95 ≈ 101 ms for every scenario.** The floor is
`localFlushInterval = 100 ms` (`internal/correlator/engine.go:914`) — workers
batch alerts locally and flush on a 100 ms tick, so wall-clock time from attack
event to alert availability is “detection in µs + ≤ 100 ms batching”.

### Sustained mixed-load throughput (all 572 rules + anomaly profiler)

2 M mixed benign syscall/network/file events through `IngestAsync`:
**125 856 ev/s** on 4 vCPU; RSS grew 21.6 → 31.4 MiB. (The 1.05 M ev/s numbers
in section 1 are the engine tests with their own event mix; this harness run
includes rules + anomaly detection + per-event allocation in the caller.)

## 4. Live agent (dry-run mode, full production stack)

Agent run as a real process: HTTP server + bearer auth, all 572 rules,
synthetic collector (~10 ev/s), memory store, canary files, watchdog.

| Metric | Value |
|---|---|
| CPU (60 s average) | **1.2 % of one core** |
| RSS | 92–96 MiB stable |
| Startup → ready | ~3 s |
| `GET /api/v1/alerts?limit=100` ×300 | p50 0.66 ms, p95 0.94 ms, p99 2.3 ms |
| Alerts stored during run | 1000+ (synthetic suspicious events correctly alerted) |
| Event queue | depth 0, capacity 16 384, 0 dropped |
| Auth | viewer token correctly rejected from `/alerts` write scope; 401 without token |

## 5. Bugs found during this pass

1. **`attack-sim` expects rule IDs that no longer exist.** Scenario
   expectations reference `container_escape_ptrace`, `cryptominer_pool_connect`,
   `dns_dga_query`, `ldpreload_injection`, `kmod_from_tmpfs` — none exist in
   `rules/`. Detection itself works (each scenario fires 2–12 equivalent
   current rules), but `attack-sim --run-all` reports 5/7 FAIL purely from
   stale IDs (`internal/attacker/scenarios.go`).
2. **`attack-sim --verify` and `demo/attack-scripts/attack.sh` poll `/alerts`,
   which returns 404** — the API only serves `/api/v1/alerts`
   (`internal/exporter/api.go:25`, `internal/attacker/runner.go` `pollAlerts`).
   Verified against the live agent: verify mode times out with zero rules seen
   even while the agent stores alerts.
3. **Fresh clone cannot run `make generate`/`make build` without a BTF-enabled
   kernel.** `bpf/vmlinux.h` is not committed (it is `.gitignore`d) even though
   the Makefile comment says to commit it so builds work without BTF. Also, a
   pregenerated vmlinux.h (libbpf/vmlinux.h, 6.19) is missing
   `struct io_uring_params` (needed by `iouring.bpf.c`) and a concrete
   `struct cgroup` (needed by `cgroup.bpf.c`); both had to be appended manually
   for this run.

## Limitations of this run

The sandbox kernel exposes no BTF (`/sys/kernel/btf/vmlinux` absent) and the
BTF-hub is unreachable under the network policy, so **real kernel probe attach
could not be exercised**; the agent correctly fails fast with a clear
remediation message. Kernel-side overhead (BPF programs, ring buffer) is
therefore not covered here — userspace pipeline numbers above start at the
collector/ring-buffer parse boundary. `e2e/kernel-smoke` on a BTF-enabled
host remains the gap to close.

## Reproduction

```bash
go test -race ./...                                  # unit + race
go test -run 'TestPerformanceRegression|TestSustainedThroughput' ./e2e/   # no -race
go test -run='^$' -bench=. -benchtime=10s ./e2e/     # headline benchmarks
go run ./benchmark-harness                           # attack latency harness
./build/ebpf-guard attack-sim --run-all --config <cfg>
```
