# Hardware-Aware Profiles

ebpf-guard ships three built-in tuning presets — `lite`, `balanced`, and
`production` — so a single binary works well from a 1-vCPU/1GB VPS up to a
dedicated production host, without hand-tuning BPF map sizes or profiler
limits. This is what makes `curl ... | sh` (see [Install](#one-command-install))
produce a working agent with no config file at all.

## Choosing a profile

Precedence, highest first:

1. `--profile lite|balanced|production` flag
2. `profile:` key in the config file
3. Autodetection from `nproc` and `/proc/meminfo`

Autodetection only ever picks `lite` or `balanced` — `production` implies a
deliberately sized deployment and must be requested explicitly.

| Host | Autodetected profile |
|---|---|
| 1 CPU, or ≤ ~2.2GB RAM | `lite` |
| everything else | `balanced` |

The resolved profile, the reason it was chosen, and the detected CPU/RAM are
logged once at startup:

```
level=INFO msg="hardware profile resolved" profile=lite source=autodetect \
  reason="detected 1 CPU(s) / 1024MB RAM (lite threshold: <=1 CPU(s) or <=2200MB RAM)" \
  cpus=1 mem_total_mb=1024 bpf_events_map=8192 ...
```

and available at runtime via `GET /debug/state` (requires
`server.enable_debug: true`) under the `hardware_profile` key.

## What each profile sets

| Setting | `lite` | `balanced` (default) | `production` |
|---|---|---|---|
| `bpf.map_sizes.events` | 8192 | 65536 | 131072 |
| `bpf.map_sizes.processes` | 2048 | 16384 | 32768 |
| `bpf.map_sizes.connections` | 4096 | 32768 | 65536 |
| `profiler.max_tracked_pids` | 256 | 4096 | 8192 |
| `profiler.sequence.enabled` | false | true | true |
| `profiler.lineage.enabled` | true (off — see note) | true | true |
| `GOMEMLIMIT` | ~40% of detected RAM | unset (Go default) | unset |
| `GOGC` | 50 | unset (100) | unset |

`lite` targets roughly 60-90MB RSS in steady state; `balanced` is the
pre-existing default (~150-200MB); `production` gives a larger starting
point for a dedicated node, still tunable further by hand.

## Overriding individual fields

A profile only fills in defaults — any value you set explicitly in the
config file always wins for that field, even under an active profile. For
example, to run `lite` sizing everywhere but keep a larger event map:

```yaml
profile: lite
bpf:
  map_sizes:
    events: 32768   # overrides the lite preset's 8192
```

## One-command install

```bash
curl -fsSL https://raw.githubusercontent.com/zugolO/ebpf-guard/main/scripts/install.sh | sh
```

The installer downloads (or builds) the binary, installs a systemd unit, and
intentionally does **not** write a `profile:` key — the agent autodetects
hardware on every start, so a VPS resized later automatically picks up the
right preset on the next restart. Pass `EBPF_GUARD_PROFILE=production` in
the environment (or edit the systemd unit's `ExecStart` to add `--profile
production`) to pin it explicitly.
