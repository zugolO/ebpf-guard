# Capacity and overload behaviour (wave 8.8)

Measured with the `w88-load.sh` ladder on the ebaka2 test node (4 cores; the generator shares them with the agent, so absolute numbers are a floor, not a product limit). The generator emits a node-like mix (~78% file, ~21% syscall, ~2% network events; one operation ≈ 1.5 agent events). Background stream of the node with no generator: **≈ 630 events/s in the pod, ≈ 4 100 events/s on the host run** (the host agent also sees the node's own k3s traffic). On the pod ladders the step 0 has no probe and no control processes.

Two quantities are kept apart because they are different things:

- **Drops** — events the agent lost (`ebpf_guard_events_dropped_total`, except `path_denylist`, which is filtering). Unplanned.
- **Shed by design** — file events of "hot" processes (> `bpf.sampling.hot_pid_threshold` open/read/write events per 100 ms, default 300) that the in-kernel sampler discarded while the CPU watcher or the overload controller asked for it (`ebpf_guard_file_hot_shed_total{outcome="shed"}`, per process in `…_by_comm_total` and one journal line per process). `open` and mutations (chmod/unlink/rename/truncate/rmdir) are never shed. `/health` reads `degraded` for as long as shedding is on.

| pod `limits.cpu` | first shedding at (ops/s → events/s) | drops reach 1% at | processed ceiling (events/s) | past the ceiling |
|---|---|---|---|---|
| 500m (chart default) | 5 000 → 8.6k (CPU watcher, 6% shed) | 12 500 ops/s → 15k | **18.1k at 20 000 ops/s** | **collapses**: 11.6k at 30 000, 7.3k at 45 000 (0.40 of the ceiling) |
| 1 | 5 000 → 8.9k (2.6% shed) | 45 000 ops/s → 37k | ≈ 37k at 45 000 ops/s | **collapses too**: 0.64 of the ceiling at 60 000, 0.43 at max |
| 2 | 15 000 → 22k (10% shed) | 45 000 ops/s → 41.6k | ≈ 48.9k (unbounded generator) | not reached |

Reading the table:
- The previous version of this page listed 6 400 events/s "loss-free" for 1 core against 8 000 for 500m. That was a measurement artefact: shedding by design was counted as loss, the 1 core ladder had a probe at 1 000 ops/s and 8 controls on step 0, and the CPU profile ran inside the steps. With drops and shedding counted separately, capacity grows with the limit (500m → 1 → 2 cores: 15k → 37k → 41.6k events/s at 1% drops).
- At 500m the protected events of one noisy process alone exceed the 0.5-core budget at ≥ 30 000 ops/s; protected classes are never shed, so the pod cannot hold a plateau there. Whether the chart default should rise is the owner's decision; it was not changed.
- The 2 core ladder ends before its ceiling, so "no collapse" there is a lower bound. At 1 core the attack pack under 20 000 ops/s keeps recall 16/16 (500m: 12/16).
- Idle volume: with `bpf.sampling.file_rate: 50` (the Go/chart default when the key is absent) the new sampler lets non-hot processes through, so idle events and CPU double (134 → 288 events/s, 0.0185 → 0.0355 s/s); with the shipped `file_rate: 1` they are equal (278 → 290 events/s).
