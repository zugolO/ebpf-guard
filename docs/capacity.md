# Capacity and overload behaviour (wave 8.8)

Measured with the `w88-load.sh` ladder on the ebaka2 test node (4 cores; the generator shares them with the agent, so absolute numbers are a floor, not a product limit; node idle stayed ≥ 18% on every judged step, so the ladders were not CPU-starved by the box). Every number below is printed by the emitter (`w88-load-report.py`, lines 8.8.2 and 8.8.Т). The generator emits a node-like mix (~78% file, ~21% syscall, ~2% network events; one operation ≈ 1.5 agent events). Background stream of the node with no generator: **≈ 630 events/s in the pod, ≈ 4 100 events/s on the host run** (the host agent also sees the node's own k3s traffic). On the pod ladders the step 0 has no probe and no control processes.

Two quantities are kept apart because they are different things:

- **Drops** — events the agent lost (`ebpf_guard_events_dropped_total`, except `path_denylist`, which is filtering). Unplanned.
- **Shed by design** — file events of "hot" processes (> `bpf.sampling.hot_pid_threshold` open/read/write events per 100 ms, default 300) that the in-kernel sampler discarded while the CPU watcher or the overload controller asked for it (`ebpf_guard_file_hot_shed_total{outcome="shed"}`, per process in `…_by_comm_total` and one journal line per process). `open` and mutations (chmod/unlink/rename/truncate/rmdir) are never shed. `/health` reads `degraded` for as long as shedding is on.

Default since wave 8.8 (owner decision of 18.10.2026): chart `resources.limits.cpu: 1` (requests unchanged) and `bpf.sampling.file_rate: 1`.

| pod `limits.cpu` | first shedding at (ops/s → events/s) | drops reach 1% at | processed ceiling (events/s) | past the ceiling | attack pack under 20 000 ops/s |
|---|---|---|---|---|---|
| **1 (chart default)** | 5 000 → 8.7k (2.6% shed) | 45 000 ops/s → 37.6k | **37.6k at 45 000 ops/s** | **collapses**: 25.1k at 60 000 (0.67 of the ceiling), 15.4k at max (0.41) | recall 16/16, composition equal to the baseline (8.8.6 PASS) |
| 2 | 15 000 → 21.9k (10% shed) | 45 000 ops/s → 42.3k | ≈ 47.8k at 60 000 ops/s | no collapse: 43.5k at max (1.03 of the point of first loss) | recall 16/16, composition equal |
| 500m (economy profile) | 5 000 → 8.5k (6.3% shed) | 12 500 ops/s → 15.6k | **18.5k at 20 000 ops/s** | **collapses**: 10.1k at 30 000, 7.5k at 45 000 (0.48 of the ceiling) | **recall 12/16** (see warning) |

**Economy profile (`resources.limits.cpu: 500m`).** The old chart default stays available as an explicit choice for quiet nodes. Its ceiling is about **18 thousand events/s** (≈ 20 000 ops/s of the ladder's node-like mix). Past it the pod loses detection, not just volume: under 20 000 ops/s of background load plus a hot attacker the attack pack fell to **12/16** (missed: `host_mount`, `log_tamper`, `module_plant`, `ssh_keys` positive controls; 26 rule types dropped out). At 500m the protected events of one noisy process alone exceed the 0.5-core budget at ≥ 30 000 ops/s; protected classes are never shed. Do not use 500m on a node that can sustain ≳ 15 thousand events/s.

Reading the table:
- Drops and shedding are counted separately (shedding by design is not loss); capacity grows with the limit (500m → 1 → 2 cores: 15.6k → 37.6k → 42.3k events/s at 1% drops).
- A pod at 1 core still collapses past its ceiling (0.41 of it at the unbounded generator); closing that is wave 9 item В8 (queue sharding), not a limit change. Controls (8 processes, 50 ops/s each) at 2× capacity lose single events (1 core: up to 6 of ~6 000, 0.13%; 2 cores: up to 57, 1.2% at 1.8×); the plan's "0 events" is also unmet on the host (14–29 events) and is moved to В8.
- Idle volume: with the default `file_rate: 1` an old and a new binary are equal (278 → 290 events/s, CPU 1.016×). With an explicit `bpf.sampling.file_rate: 50` the sampler lets non-hot processes through and idle CPU doubles (0.0185 → 0.0355 s/s); keep 50 only for a conscious volume trade-off.
- The earlier page listed 6 400 events/s "loss-free" for 1 core against 8 000 for 500m: a measurement artefact (shedding counted as loss, probe at 1 000 ops/s on step 0, profile inside the steps).
