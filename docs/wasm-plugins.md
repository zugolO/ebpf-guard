# WASM Detection Plugins

ebpf-guard supports sandboxed WebAssembly (WASM) detection plugins loaded from
the `rules/custom/` directory at startup.  Plugins are compiled `.wasm`
binaries that implement a small, stable ABI; the host (wazero) isolates each
invocation in its own linear-memory instance so a buggy or malicious plugin
cannot affect the agent process.

Plugins run in full isolation: a buggy or malicious plugin cannot crash the agent.

---

## Table of contents

1. [Quick start](#quick-start)
2. [Plugin ABI v1](#plugin-abi-v1)
3. [Writing a plugin in Go (TinyGo)](#writing-a-plugin-in-go-tinygo)
4. [Writing a plugin in Rust](#writing-a-plugin-in-rust)
5. [Companion `.meta.yaml` manifest](#companion-metayaml-manifest)
6. [Config wiring](#config-wiring)
7. [Plugin lifecycle](#plugin-lifecycle)
8. [Resource limits and performance budget](#resource-limits-and-performance-budget)
9. [Failure isolation semantics](#failure-isolation-semantics)
10. [Validating a plugin before deployment](#validating-a-plugin-before-deployment)
11. [Running in CI](#running-in-ci)
12. [Troubleshooting](#troubleshooting)

---

## Quick start

```bash
# 1. Build the example Go plugin (requires TinyGo 0.33+)
cd pkg/plugin-sdk/examples/detect_privesc
tinygo build -o detect_privesc.wasm -target wasi .

# 2. Copy to your rules directory
cp detect_privesc.wasm           rules/custom/
cp detect_privesc.meta.yaml      rules/custom/

# 3. Validate the ABI and do a dry-run
ebpf-guard plugins validate rules/custom/detect_privesc.wasm

# 4. Run the agent (plugins are loaded automatically)
sudo ebpf-guard --config config/config.yaml
```

---

## Plugin ABI v1

A compliant plugin `.wasm` binary must export the following functions.

### Required exports

| Export | Signature | Description |
|--------|-----------|-------------|
| `malloc` | `(size i32) → i32` | Allocate `size` bytes in linear memory; return pointer. |
| `evaluate` | `(ptr i32, len i32) → i32` | Evaluate event JSON at `[ptr:ptr+len]`. Return **1** on match, **0** otherwise. |

### Recommended exports (read only on match)

| Export | Signature | Description |
|--------|-----------|-------------|
| `free` | `(ptr i32)` | Release memory allocated by `malloc`.  If absent the host does not free. |
| `alert_severity` | `() → i32` | `0` = warning, `1` = critical.  Falls back to manifest severity if absent. |
| `alert_message_ptr` | `() → i32` | Pointer to UTF-8 alert message in plugin linear memory. |
| `alert_message_len` | `() → i32` | Byte length of alert message (max 4096 bytes). |

### Optional global

| Global | Type | Description |
|--------|------|-------------|
| `ebpf_guard_abi_version` | `i32` | Set to `1`.  Absence is accepted but produces a warning. |

### Event JSON schema

The host serializes each `types.Event` to JSON and writes it into the plugin's
linear memory before calling `evaluate`.  Only the sub-object for the active
event type is present.

```jsonc
{
  "type": 2,          // EventType: 1=syscall 2=network 3=file 4=tls 5=dns
                      //            6=privesc 7=net_close 8=kmod 9=cgroup_esc 10=gpu
  "pid":  1234,
  "ppid": 1,
  "tgid": 1234,
  "uid":  0,
  "comm": "nginx",
  "parent_comm": "containerd-shim",

  // Only one of the following sub-objects is present per event:
  "network":   { "saddr":"10.0.0.1","daddr":"1.2.3.4","sport":54321,"dport":443,"proto":6,"family":2 },
  "file":      { "filename":"/etc/shadow","flags":0,"mode":0,"op":0 },
  "dns":       { "qname":"example.com","qtype":1,"rcode":0,"direction":0 },
  "tls":       { "direction":0,"data_len":256 },
  "syscall":   { "nr":59,"ret":0 },
  "privesc":   { "old_caps":0,"new_caps":4096 },
  "net_close": { "saddr":"10.0.0.1","daddr":"1.2.3.4","sport":54321,"dport":443,"family":2,"duration_ms":120 },
  "kmod":      { "mod_name":"evil.ko","from_tmpfs":true },
  "cgroup_esc":{ "init_cgroup_id":1,"new_cgroup_id":2 },
  "gpu":       { "op":3,"dev_ptr":140234567890,"host_ptr":0,"size":1048576 }
}
```

---

## Writing a plugin in Go (TinyGo)

Use the SDK from `pkg/plugin-sdk/`.  It handles the ABI plumbing (malloc/free/
evaluate exports, alert state) so you only implement one function.

```go
package main

import sdk "github.com/zugolO/ebpf-guard/pkg/plugin-sdk"

func main() {}

func init() {
    sdk.Register(sdk.HandlerFunc(detect))
}

func detect(e *sdk.Event) *sdk.Alert {
    if e.Type == sdk.EventTCPConnect && e.Network != nil && e.Network.Dport == 4444 {
        return sdk.Alertf(sdk.SeverityCritical,
            "outbound connection to port 4444 from %s (pid %d)", e.Comm, e.PID)
    }
    return nil
}
```

Build:

```bash
tinygo build -o my-plugin.wasm -target wasi ./my-plugin/
```

See `pkg/plugin-sdk/examples/detect_privesc/` for a complete working example.

### Supported Go versions

TinyGo 0.33+ targeting `wasi`.  Standard `go build` (non-TinyGo) produces
binaries that import the `fmt` package and the Go runtime, resulting in
binaries > 3 MiB.  TinyGo produces binaries under 100 KiB with `-opt=z`.

---

## Writing a plugin in Rust

No SDK is needed for Rust — implement the ABI directly:

```rust
static mut ALERT_MSG: Vec<u8> = Vec::new();

#[no_mangle]
pub unsafe extern "C" fn malloc(size: u32) -> *mut u8 { /* ... */ }
#[no_mangle]
pub unsafe extern "C" fn free(_ptr: *mut u8) {}

#[no_mangle]
pub unsafe extern "C" fn evaluate(ptr: *const u8, len: u32) -> i32 {
    let data = std::slice::from_raw_parts(ptr, len as usize);
    // parse JSON, run detection, set ALERT_MSG ...
    0
}

#[no_mangle]
pub unsafe extern "C" fn alert_severity() -> i32 { 0 }
#[no_mangle]
pub unsafe extern "C" fn alert_message_ptr() -> *const u8 { ALERT_MSG.as_ptr() }
#[no_mangle]
pub unsafe extern "C" fn alert_message_len() -> u32 { ALERT_MSG.len() as u32 }
```

Build:

```bash
cargo build --target wasm32-wasi --release
```

See `pkg/plugin-sdk/examples/rust/` for a complete DNS DGA detector.

---

## Companion `.meta.yaml` manifest

Place a `<plugin_name>.meta.yaml` file alongside the `.wasm` file to supply
metadata.  If absent, the ID and name default to the filename stem.

```yaml
id: my_plugin_001           # stable identifier used in alert RuleID
name: "My detector"         # human-readable name used in alert RuleName
description: "Detects ..."  # used as fallback alert message when plugin returns no message
severity: warning           # warning | critical — fallback when alert_severity is absent
action: alert               # alert | block | kill | throttle | drop
tags: [custom, mitre:T1059]
```

---

## Config wiring

```yaml
wasm:
  enabled: true
  plugin_dir: rules/custom       # directory scanned for *.wasm at startup
  eval_timeout: 100ms            # per-invocation deadline; increase for complex plugins
  memory_limit_pages: 256        # 256 pages = 16 MiB per instance
```

Plugins are loaded once at startup.  Hot-reload of the rules file does **not**
reload WASM plugins; restart the agent to pick up new or updated `.wasm` files.

---

## Plugin lifecycle

```
Agent startup
  └─ NewEngine(ctx, plugin_dir)
       └─ For each *.wasm:
            ├─ rt.CompileModule()          ← compiled once, cached
            └─ loadMeta()

Per event (Engine.Evaluate):
  └─ For each Plugin:
       ├─ SerializeEvent → JSON bytes
       ├─ rt.InstantiateModule()           ← fresh instance per call
       ├─ malloc(len)
       ├─ Write JSON to linear memory
       ├─ evaluate(ptr, len) → 0 or 1
       ├─ free(ptr)
       ├─ [on match] alert_severity(), alert_message_ptr(), alert_message_len()
       └─ mod.Close()                      ← instance destroyed
```

Each evaluate call instantiates a **fresh module instance**.  This guarantees
full isolation across events and concurrent goroutines — no state from event N
bleeds into event N+1.

---

## Resource limits and performance budget

| Limit | Default | Config key |
|-------|---------|------------|
| Linear memory per instance | 16 MiB (256 pages) | `wasm.memory_limit_pages` |
| Per-invocation timeout | 100 ms | `wasm.eval_timeout` |
| Max alert message length | 4096 bytes | (hard limit) |

**Measured overhead per call** (linux/amd64, Xeon 2.10 GHz, Go 1.25, wazero v1.8.2):

```
BenchmarkWASMPluginEval-4          ~53 µs/op    111 KiB/op    95 allocs
BenchmarkWASMPluginEvalParallel-4  ~49 µs/op    111 KiB/op    95 allocs
```

The 111 KiB/op is dominated by wazero allocating one 64 KiB linear-memory page
per fresh module instance — an inherent cost of the full-isolation model.

Design implications:
- Keep detection logic O(1); avoid allocations proportional to input size.
- Plugins running > 1 ms of CPU per event will approach the 100 ms timeout at
  burst rates.  Use `wasm.eval_timeout` to relax or tighten the budget.
- With 10 loaded plugins and a 50k event/s throughput, plugin evaluation
  consumes ≈ 26 CPU cores at baseline.  Profile before enabling many plugins
  in high-throughput environments.

---

## Failure isolation semantics

- A plugin that **panics** or **traps** (WASM trap = divide-by-zero, OOB
  memory access, etc.) is logged as an error and skipped.  The event continues
  through the rest of the pipeline.
- A plugin that **exceeds its timeout** is logged as a timeout and skipped.
  The plugin remains loaded for subsequent events.
- A plugin that **writes outside its linear memory** cannot affect the host
  process — the WASM sandbox enforces memory boundaries.
- A plugin that **returns a match on every event** can flood alert storage.
  Use the rate-limiting settings in `rules.rate_limit_alerts` to cap output.

---

## Validating a plugin before deployment

```bash
# ABI check + dry-run against synthetic events
ebpf-guard plugins validate rules/custom/my-plugin.wasm

# Validate all plugins in a directory
ebpf-guard plugins validate rules/custom/

# ABI check only (skip dry-run)
ebpf-guard plugins validate rules/custom/ --no-dry-run
```

Example output:

```
[PASS] rules/custom/detect_privesc.wasm
      id=detect_privesc_001  name="CAP_SYS_ADMIN acquisition detector"  severity=critical  action=alert
      WARNING: missing ebpf_guard_abi_version global (ABI v1 assumed)
      dry-run: 1 alert(s) fired
        - [critical] process test (pid 5) gained CAP_SYS_ADMIN

All 1 plugin(s) passed ABI validation.
```

---

## Running in CI

Add the following step to validate all plugins on every pull request:

```yaml
# .github/workflows/ci.yml
- name: Validate WASM plugins
  run: |
    go build -o build/ebpf-guard ./cmd/ebpf-guard/
    ./build/ebpf-guard plugins validate rules/custom/ || exit 1
```

To also run the conformance test suite (uses the pre-built testdata plugins):

```bash
go test -v ./internal/wasm/...
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `missing required export: malloc` | Plugin not compiled with the WASM ABI | Use `tinygo build -target wasi` or implement `malloc`/`evaluate` manually |
| `compile: ...` error | Binary is not valid WASM | Check the build toolchain output |
| Plugin timeout in logs | Detection logic is too slow | Profile the plugin; simplify or increase `wasm.eval_timeout` |
| No alerts despite expected match | `evaluate` returns 0 | Add logging to debug; use `--dry-run` with `plugins validate` |
| Plugin loaded but no alerts ever | Wrong event type checked | Verify the `type` field in the JSON matches your condition |
