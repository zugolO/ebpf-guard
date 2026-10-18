# Capacity and overload behaviour (wave 8.8)

Measured with the `w88-load.sh` ladder on the ebaka2 test node (4 cores; the generator shares them with the agent, so absolute numbers are a floor, not a product limit; node idle stayed ≥ 18% on every judged step, so the ladders were not CPU-starved by the box). Every number below is printed by the emitter (`w88-load-report.py`, lines 8.8.2 and 8.8.Т). The generator emits a node-like mix (~78% file, ~21% syscall, ~2% network events; one operation ≈ 1.5 agent events). Background stream of the node with no generator: **≈ 630 events/s in the pod, ≈ 4 100 events/s on the host run** (the host agent also sees the node's own k3s traffic). On the pod ladders the step 0 has no probe and no control processes.

Two quantities are kept apart because they are different things:

- **Drops** — events the agent lost (`ebpf_guard_events_dropped_total`, except `path_denylist`, which is filtering). Unplanned.
- **Shed by design** — file events of "hot" processes (> `bpf.sampling.hot_pid_threshold` open/read/write events per 100 ms, default 300) that the in-kernel sampler discarded while the CPU watcher or the overload controller asked for it (`ebpf_guard_file_hot_shed_total{outcome="shed"}`, per process in `…_by_comm_total` and one journal line per process). `open` and mutations (chmod/unlink/rename/truncate/rmdir) are never shed. `/health` reads `degraded` for as long as shedding is on.

Default since wave 8.8 (owner decision of 18.10.2026): chart `resources.limits.cpu: 1` (requests unchanged) and `bpf.sampling.file_rate: 1`.

| pod `limits.cpu` | first shedding at (ops/s → events/s) | drops reach 1% at | processed ceiling (events/s) | past the ceiling | attack pack under 20 000 ops/s |
|---|---|---|---|---|---|
| **1 (chart default)** | 5 000 → 8.8k (2.6% shed) | 30 000 ops/s → 32.0k | **≈ 43.5k at 60 000 ops/s** | no collapse: 42.3k at max (1.26 of the point of first loss) | recall 16/16, composition equal to the baseline (8.8.6 PASS) |
| 2 | 15 000 → 21.9k (10% shed) | 45 000 ops/s → 47.0k | ≈ 53.1k at max | no collapse: 53.1k at max (1.10 of the point of first loss) | recall 16/16, composition equal |
| 500m (economy profile) | 5 000 → 8.5k (6.3% shed) | 12 500 ops/s → 15.6k | **18.5k at 20 000 ops/s** | **collapses**: 10.1k at 30 000, 7.5k at 45 000 (0.48 of the ceiling) | **recall 12/16** (see warning) |

**Economy profile (`resources.limits.cpu: 500m`).** The old chart default stays available as an explicit choice for quiet nodes. Its ceiling is about **18 thousand events/s** (≈ 20 000 ops/s of the ladder's node-like mix). Past it the pod loses detection, not just volume: under 20 000 ops/s of background load plus a hot attacker the attack pack fell to **12/16** (missed: `host_mount`, `log_tamper`, `module_plant`, `ssh_keys` positive controls; 26 rule types dropped out). At 500m the protected events of one noisy process alone exceed the 0.5-core budget at ≥ 30 000 ops/s; protected classes are never shed. Do not use 500m on a node that can sustain ≳ 15 thousand events/s.

Reading the table:
- Drops and shedding are counted separately (shedding by design is not loss); capacity grows with the limit (500m → 1 → 2 cores: 15.6k → 37.6k → 42.3k events/s at 1% drops).
- The 1-core and 2-core rows are from the run of 18.10.2026 with the queue cap below; the 500m row was measured before it.
- **Why a pod used to collapse past its ceiling (fixed).** Under overload both event queues (protected and bulk) fill up. With the old depth of 65 536 each, the queued events (≈ 36 MiB of live, pointer-dense heap) on top of the working heap (≈ 45 MiB) pushed the agent against the pod's Go soft memory limit (`GOMEMLIMIT`, 85 MiB at `limits.memory: 192Mi`), and the garbage collector ran back to back: up to a third of the 1-core budget went to marking, so fewer events were processed and the queues stayed full (1 core: 25.1k at 60 000 ops/s, 15.4k at max). Under a Go memory limit the agent now caps each queue so that both full queues take at most 5% of the limit (≈ 7 700 events at 85 MiB; journal line `event queue depth capped by the Go memory limit`). The host has no memory limit and keeps 65 536. The attack pack peaks at 392 (1 core) and 493 (2 cores) queued events in a pod.
- Controls (8 processes, 50 ops/s each) at 2× capacity still lose events (1 core: up to 465 of ~4 600, 10% at 2.25× = 45 000 ops/s; 2 cores: up to 168, 3.6% at 60 000; host: 31, 0.67%); the plan's "0 events" is wave 9 item В8. Past 2× the cap loses fewer control events than before (1 core at 60 000: 30–50% instead of 47–59%).
- Losses inside the kernel ring buffer (`reason="ringbuf_full"`) now also turn `/health` to `degraded`; before, only losses in userspace did.
- Idle volume: with the default `file_rate: 1` an old and a new binary are equal (278 → 290 events/s, CPU 1.016×). With an explicit `bpf.sampling.file_rate: 50` the sampler lets non-hot processes through and idle CPU doubles (0.0185 → 0.0355 s/s); keep 50 only for a conscious volume trade-off.
- The earlier page listed 6 400 events/s "loss-free" for 1 core against 8 000 for 500m: a measurement artefact (shedding counted as loss, probe at 1 000 ops/s on step 0, profile inside the steps).
