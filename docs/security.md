# Security Model — ebpf-guard

This document describes the input validation model, config file permission
requirements, and enforcement safety guarantees introduced in Sprint 30.0.

---

## Input Validation

### BPF Event Fields (Enforcer)

Before any enforcement action (kill, block, throttle, LSM block) the enforcer
validates the fields that originate from the BPF ring buffer:

| Field | Valid range | Error |
|-------|-------------|-------|
| `PID` | 1 – 4 194 304 | `ErrInvalidEvent` — action is rejected and logged |
| `UID` | 0 – 65 535 | `ErrInvalidEvent` — action is rejected and logged |

PID 0 is the kernel idle task and can never be a valid enforcement target.
The upper bound (4 194 304) is the Linux `/proc/sys/kernel/pid_max` ceiling.

#### `comm` Field Sanitization

The `comm` field (process name from BPF) is attacker-influenced: a malicious
process can set its name to arbitrary bytes including non-printable characters
and invalid UTF-8 sequences. Before writing `comm` to any log output the
enforcer runs it through `sanitizeComm`, which:

1. Decodes the string rune by rune using `utf8.DecodeRuneInString`.
2. Replaces any invalid UTF-8 byte with `\xNN` (hex escape).
3. Replaces any control character (U+0000–U+001F, U+007F) with `\xNN`.

This prevents log-injection and terminal escape attacks.

---

### Webhook Headers

Custom HTTP headers configured under `notifications.webhook.headers` are
validated at startup against RFC 7230 §3.2.6 *token* syntax:

```
tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" /
        "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
token = 1*tchar
```

Header **values** are additionally checked for CR (`\r`) and LF (`\n`)
characters, which would allow HTTP response-splitting / header-injection
attacks. If any header fails validation the notifier is disabled at startup
and an error is logged — no requests are sent.

---

### Mining Pool CIDR Blocklist

CIDR ranges loaded from the mining-pool blocklist file are validated on load
and hot-reload. Any range that overlaps a private / loopback address space is
silently skipped:

| Rejected range | Reason |
|----------------|--------|
| `127.0.0.0/8` | IPv4 loopback |
| `::1/128` | IPv6 loopback |
| `10.0.0.0/8` | RFC 1918 private |
| `172.16.0.0/12` | RFC 1918 private |
| `192.168.0.0/16` | RFC 1918 private |
| `fc00::/7` | IPv6 unique-local |

Blocking these ranges would drop legitimate internal Kubernetes/cluster
traffic and is almost certainly a misconfiguration. Operators who genuinely
need to block a specific internal host should use a host-based firewall rule
outside ebpf-guard.

---

## Config File Permissions

At startup, `config.NewManager` checks the config file before reading it:

1. **World-writable check** — if the file mode has the `o+w` bit set (octal
   `0o002`) the agent refuses to start with a fatal error:

   ```
   config: /etc/ebpf-guard/config.yaml is world-writable (mode 0646) —
   refusing to start; fix with: chmod o-w /etc/ebpf-guard/config.yaml
   ```

This prevents an unprivileged local user from injecting malicious rule paths,
webhook URLs, or disabling security features by editing the config file.

The check can be bypassed in integration tests via
`config.NewManagerSkipPermCheck(path)` or the `--skip-config-permission-check`
flag (if wired by the caller).

---

## Global Alert Rate Limit

A token-bucket rate limiter (`golang.org/x/time/rate`) caps the total number
of alerts emitted per second across **all rules**:

| Config key | Default | Description |
|------------|---------|-------------|
| `correlator.max_alerts_per_second` | `10000` | Maximum alerts/sec (0 = unlimited) |

Alerts that exceed the bucket are dropped and counted in the Prometheus
counter:

```
ebpf_guard_alerts_dropped_total{reason="global_rate_limit"}
```

This prevents a single noisy rule (or an attacker generating synthetic events)
from flooding downstream consumers (Alertmanager, Slack, OpenSearch) and
exhausting memory in the alert store.

The global limit is applied **after** per-rule rate limiting
(`rules.max_alerts_per_window`) so both guards are active simultaneously.

---

## Enforcement Safety Guarantees

| Property | Implementation |
|----------|----------------|
| PID/UID validation before kill/block | `validateEvent()` in enforcer — returns `ErrInvalidEvent` on out-of-range values |
| Comm sanitization before all log writes | `sanitizeComm()` — UTF-8 decode + escape of non-printable bytes |
| Config integrity at startup | `CheckConfigPermissions()` — rejects world-writable config files |
| Header injection prevention | `validateHeaders()` — RFC 7230 token check + CR/LF rejection |
| Internal traffic protection | RFC-1918 CIDR skip in mining-pool loader |
| Alert flood protection | Token-bucket global rate limiter with Prometheus counter |
