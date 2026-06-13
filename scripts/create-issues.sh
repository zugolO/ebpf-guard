#!/usr/bin/env bash
# scripts/create-issues.sh
# Creates all audit-found issues in zugolO/ebpf-guard via gh CLI.
# Usage: GITHUB_TOKEN=ghp_xxx bash scripts/create-issues.sh
#        (or just run after `gh auth login`)
set -euo pipefail

REPO="zugolO/ebpf-guard"

gh() { command gh "$@" --repo "$REPO"; }

echo "Creating issues in $REPO …"
echo

# ─── LABEL SETUP ──────────────────────────────────────────────────────────────
for spec in \
  "security/critical:d73a4a" \
  "security/high:e11d48" \
  "security/medium:f97316" \
  "security/low:facc15" \
  "hardening:8b5cf6" \
  "test-flake:06b6d4" \
  "docs:6366f1" \
  "feature:22c55e" \
  "benchmark:0ea5e9"
do
  name="${spec%%:*}"
  color="${spec##*:}"
  command gh label create "$name" --color "$color" --repo "$REPO" 2>/dev/null || true
done

# ─── HELPER ───────────────────────────────────────────────────────────────────
issue() {
  local title="$1" labels="$2" body="$3"
  command gh issue create \
    --repo  "$REPO"   \
    --title "$title"  \
    --label "$labels" \
    --body  "$body"
}

# ══════════════════════════════════════════════════════════════════════════════
# HIGH SECURITY
# ══════════════════════════════════════════════════════════════════════════════

issue \
  "security: predictable fallback auth token (fail-open on urandom error)" \
  "security/high" \
'## Summary
`generateToken()` in `cmd/ebpf-guard/main.go:1311` returns the hardcoded constant
`"insecure-fallback-change-me"` when `/dev/urandom` cannot be opened or read.
The startup log still prints *"generated admin token (not shown for security)"*,
so the operator has no indication that the admin and viewer tokens are publicly
known — granting anyone full API access and the ability to hot-reload BPF rules.

This is most likely to trigger inside a seccomp-restricted container that
blocks `open("/dev/urandom")`, or on an extremely early boot before devtmpfs is
mounted.

## Affected file
`cmd/ebpf-guard/main.go:1311–1322`

## Exploit scenario
1. Deploy in a seccomp profile that denies `openat` on `/dev/random`/`/dev/urandom`.
2. Agent starts, logs "token generated (not shown for security)".
3. Attacker queries `GET /alerts?token=insecure-fallback-change-me` — full access.

## Fix
Replace the `/dev/urandom`-open approach with `crypto/rand.Read` (already a
transitive dependency) and **fail closed** — refuse to start if entropy is
unavailable rather than returning a known constant.

```go
func generateToken() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", fmt.Errorf("cannot generate auth token: %w", err)
    }
    return hex.EncodeToString(b), nil
}
```

Also log the generated token **once** at startup (redacted after first use) so
operators can retrieve it from the pod logs.'

issue \
  "security: syslog record forgery via unescaped newline in alert.Message" \
  "security/high" \
'## Summary
`formatRFC5424` in `internal/exporter/syslog_cef.go:265` appends `alert.Message`
directly into the RFC 5424 line via `fmt.Fprintln`.  `alert.Message` is derived
from attacker-influenced data (DNS query names, file paths, `comm`).

An embedded `\n` or `\r\n` in a process name or DNS label terminates the current
syslog record and injects a fully attacker-crafted second record into the SIEM,
potentially spoofing a high-severity alert or poisoning log correlation.

`escapeSD` (lines 270–275) escapes `\`, `"`, `]` but does **not** strip newlines
or other C0 control characters.

## Affected files
- `internal/exporter/syslog_cef.go:265` (MSG field)
- `internal/exporter/syslog_cef.go:270–275` (`escapeSD` — missing `\n`/`\r`)

## Fix
Strip `\n`, `\r`, and other control characters (`\x00`–`\x1f`) from the entire
formatted line **before** writing, or sanitize `alert.Message`/`alert.Comm` at
alert creation time.'

issue \
  "security: WASM plugin eval timeout not enforced — detection pipeline DoS" \
  "security/high" \
'## Summary
The wazero runtime in `internal/wasm/engine.go:59–60` is created without
`WithCloseOnContextDone(true)`.  As a result wazero ignores the
`context.WithTimeout` deadline set per invocation, and a WASM plugin containing
an infinite loop (or very long computation) **blocks the event-pipeline goroutine
indefinitely**, causing a detection outage.

## Affected file
`internal/wasm/engine.go:59–60`

```go
rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().
    WithMemoryLimitPages(256)) // timeout is NOT enforced
```

## Fix
Add one option:
```go
rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().
    WithMemoryLimitPages(256).
    WithCloseOnContextDone(true))
```

This causes wazero to poll the context deadline and interrupt execution when it
expires.'

issue \
  "security: OTLP exporter ignores tls_enabled — sends credentials in cleartext" \
  "security/high" \
'## Summary
`internal/exporter/otlp.go:28,114–122,152–154`: when `tls_enabled: true` but the
configured endpoint uses the `http://` scheme (the documented default
`http://otel-collector:4318`), the scheme is never rewritten or validated.
Alerts **and** the `Headers` map (which commonly holds bearer tokens or API keys)
are transmitted in cleartext.

## Fix
At client construction time, reject or rewrite endpoints:
```go
if cfg.TLSEnabled && !strings.HasPrefix(cfg.Endpoint, "https://") {
    return nil, fmt.Errorf("otlp: tls_enabled requires an https:// endpoint, got %q", cfg.Endpoint)
}
```'

issue \
  "security: Kafka SASL PLAIN credentials sent in cleartext when TLS disabled" \
  "security/high" \
'## Summary
`internal/exporter/kafka.go:111–116` allows `sasl_enabled: true` together with
`tls_enabled: false`.  SASL PLAIN transmits the broker username and password in
base64 (effectively cleartext) over an unencrypted connection.

## Fix
Refuse to start when SASL PLAIN is requested without TLS:
```go
if cfg.SASLEnabled && cfg.SASLMechanism == "PLAIN" && !cfg.TLSEnabled {
    return nil, errors.New("kafka: SASL PLAIN requires tls_enabled: true")
}
```'

# ══════════════════════════════════════════════════════════════════════════════
# MEDIUM SECURITY
# ══════════════════════════════════════════════════════════════════════════════

issue \
  "security: webhook JSON injection via unescaped alert.Comm / RuleName" \
  "security/medium" \
'## Summary
The default webhook template in `internal/exporter/webhook.go:80–81` renders
`{{.Comm}}` and `{{.RuleName}}` without the `| json` escape function, while
`{{.Message}}` correctly uses it.

`alert.Comm` is raw BPF data set via `prctl(PR_SET_NAME)` — any process can set
its name to a string containing `"` or `\` to break out of the JSON object or
inject arbitrary fields into the outbound webhook payload.

## Fix
Add `| json` (or equivalent sanitization) to all unescaped template fields:
```
"comm": {{.Comm | json}},
"rule": {{.RuleName | json}},
```'

issue \
  "security: syslog structured-data injection via comm containing newline (escapeSD)" \
  "security/medium" \
'## Summary
`escapeSD` in `internal/exporter/syslog_cef.go:270–275` escapes `\`, `"`, and
`]` per RFC 5424 but does **not** strip `\n` or `\r`.  A process with a newline
in its name (`prctl(PR_SET_NAME, "foo\nbar")`) splits the SD element and can
inject an additional syslog record.

Related to the MSG-field finding but independent — both need fixing.

## Fix
Add `\n` and `\r` (and other C0 controls) to the escape set in `escapeSD`.'

issue \
  "security: notifier secrets (Telegram token, Discord/Teams webhook URL) leak via error log" \
  "security/medium" \
'## Summary
When an HTTP transport error occurs, Go wraps the error in `*url.Error` which
includes the full request URL — containing the secret token/webhook path.

Affected files:
- `internal/exporter/telegram.go:94–96` — bot token embedded in URL path
- `internal/exporter/discord.go:83–86` — webhook URL secret in path
- `internal/exporter/teams.go:84–87` — webhook URL secret in path

The wrapped error is logged at WARN/ERROR level, exposing secrets in pod logs
and any log aggregation system.

## Fix
Redact the URL when wrapping transport errors:
```go
if urlErr := (*url.Error)(nil); errors.As(err, &urlErr) {
    urlErr.URL = "[redacted]"
}
```'

issue \
  "security: WASM host panic via unchecked result slice indexing in plugin.go" \
  "security/medium" \
'## Summary
`internal/wasm/plugin.go:128–132` and `138–149` index `allocResults[0]` and
`evalResults[0]` without first checking `len(results) > 0`.

A plugin that exports `malloc` or `evaluate` with a void (zero-return) signature
— which passes the `ValidatePlugin` export-presence check — will panic the
entire agent process with an index-out-of-range.

## Fix
```go
if len(allocResults) == 0 {
    return 0, fmt.Errorf("malloc returned no results")
}
```
Also add export-signature validation to `ValidatePlugin` (check number and type
of return values, not just presence of the export).'

# ══════════════════════════════════════════════════════════════════════════════
# LOW SECURITY
# ══════════════════════════════════════════════════════════════════════════════

issue \
  "security: gossip endpoints unauthenticated when Secret is empty" \
  "security/low" \
'## Summary
`internal/gossip/http.go:120–122`: `authCheck` returns `true` (allow) when
`Secret == ""`.  If gossip is enabled without configuring a secret, any peer can
submit arbitrary IOCs — which can lower anomaly thresholds or drive alert
amplification.

## Fix
Fail closed: refuse to start gossip when `Secret` is empty, or disable the
gossip HTTP endpoints when no secret is configured.'

issue \
  "security: CA certificate read failure is non-fatal (fail-open TLS pinning)" \
  "security/low" \
'## Summary
`internal/exporter/otlp.go:95–101` and `internal/exporter/kafka.go:91–97`:
when a configured `ca_cert` file cannot be read, the error is only logged and
the client falls back to system roots, silently defeating certificate pinning.

## Fix
Treat an unloadable `ca_cert` as a fatal startup error:
```go
if err != nil {
    return nil, fmt.Errorf("cannot load ca_cert %q: %w", cfg.CACert, err)
}
```'

issue \
  "security: CEF syslog header fields not protected against newline injection" \
  "security/low" \
'## Summary
`escapeCEFHeader` in `internal/exporter/syslog_cef.go:331–335` escapes `|` and
`\` (per CEF spec) but not `\n`/`\r`.  Rule names and IDs can be imported via
the Falco migrator from untrusted rule files, so a crafted rule name with an
embedded newline can split the CEF record.

Note: the CEF *extension* escape (`escapeCEF`) and the HTTP export path
(`api.go:613`) already handle newlines correctly — only the header path is
affected.'

issue \
  "security: MISP/OpenCTI TLS verify flag inverted — direct struct init skips safe default" \
  "security/low" \
'## Summary
`internal/exporter/misp.go:57` and `internal/exporter/opencti.go:27` use a
`VerifyTLS bool` field where `false` (the zero value) means *skip verification*.
Viper-loaded configs are safe because `config.go:1589,1597` sets the default to
`true`.  However, any code that constructs the struct directly (tests, future
callers) silently disables TLS verification and leaks API keys.

## Fix
Invert to `InsecureSkipVerify bool` (zero value = verify), matching the
`crypto/tls.Config` convention and eliminating the fail-open zero-value risk.'

issue \
  "security: Discord notification allows markdown spoofing via unescaped Comm/Message" \
  "security/low" \
'## Summary
`internal/exporter/discord.go:130–164` renders `alert.Comm`, `alert.Message`,
and `alert.RuleName` inside Discord embed fields without markdown escaping.
A process can use Discord markdown syntax (e.g., `[malicious link](https://evil.example)`)
to render masked hyperlinks in security notifications.

JSON structure is safe (fields go through `json.Marshal`); the risk is purely
cosmetic spoofing of the notification text.

## Fix
Escape Discord markdown special characters (`*`, `_`, `~`, `` ` ``, `[`, `]`)
in user-influenced fields before embedding.'

# ══════════════════════════════════════════════════════════════════════════════
# HARDENING OPPORTUNITIES
# ══════════════════════════════════════════════════════════════════════════════

issue \
  "hardening: extend SSRF protection to all notifiers (Slack, Teams, Discord, webhook)" \
  "hardening" \
'## Context
The `strict_ssrf` option added in commit `af5c1b4` only covers the Alertmanager
client (`internal/exporter/alertmanager.go`).  The generic webhook, Slack, Teams,
Discord, Telegram, and OTLP exporters perform no SSRF validation.

In a Kubernetes environment, an attacker who can influence the config (or inject
a rule with a custom webhook action) can reach the instance metadata endpoint
(`169.254.169.254`), internal services, or cloud provider APIs.

## Request
Centralise webhook URL validation in a shared `validateURL(url, strict bool)`
helper and apply it consistently to all outbound HTTP clients at construction time.'

issue \
  "hardening: auto-generated auth token never surfaced to operator" \
  "hardening" \
'## Context
`main.go:514–521` logs `"admin token: [not shown for security]"`.  When the
token is auto-generated (no `auth.token` in config), the operator has no way to
retrieve it without restarting the agent — breaking `ebpf-guard alerts`,
`ebpf-guard status`, and any external scraper.

## Request
- On first start, print the generated token **once** at INFO level with a clear
  warning that it will not be shown again.
- Alternatively, write it to a well-known file (e.g. `/run/ebpf-guard/token`)
  with mode `0600`, similar to how k3s handles its kubeconfig.'

issue \
  "hardening: Swagger UI loaded from unpkg.com CDN — pin SRI hashes or vendor assets" \
  "hardening" \
'## Context
`internal/exporter/api.go:709–713` serves the Swagger UI by loading assets from
`https://unpkg.com/swagger-ui-dist/`.  A CDN compromise or BGP hijack allows
injecting arbitrary JavaScript into the API documentation page, potentially
stealing the bearer token from the browser.

## Request
Either:
- Vendor the swagger-ui-dist assets into the binary (embed via `//go:embed`), or
- Add Subresource Integrity (SRI) `integrity=` attributes pinned to a specific
  version hash.'

issue \
  "hardening: warn when config file is world- or group-readable at startup" \
  "hardening" \
'## Context
The config file can contain OpenSearch passwords, webhook URLs, and API tokens
(even with env-var overrides, operators often leave credentials in YAML for
convenience).  There is no startup check for permissive file modes.

## Request
At load time, `stat()` the config file and warn (or optionally fail) if the mode
includes group-read (`0040`) or world-read (`0004`):
```go
if info.Mode()&0044 != 0 {
    slog.Warn("config file is readable by group/world — consider chmod 0600", "path", path)
}
```'

issue \
  "hardening: set Content-Security-Policy and restrict CORS on /api/openapi.yaml" \
  "hardening" \
'## Context
`internal/exporter/api.go:731` sets `Access-Control-Allow-Origin: *` on the
OpenAPI spec endpoint.  Combined with the lack of a `Content-Security-Policy`
header on the Swagger UI page, this allows any origin to read the full API spec
and use the interactive UI to make authenticated requests if the user has a valid
token in the browser.

## Request
- Restrict `Access-Control-Allow-Origin` to a configurable allowlist (default:
  same origin).
- Add a `Content-Security-Policy` header to the Swagger UI route limiting
  `script-src` and `connect-src`.'

# ══════════════════════════════════════════════════════════════════════════════
# TEST / DOCS
# ══════════════════════════════════════════════════════════════════════════════

issue \
  "test: TestManager_Watch_MultipleChanges is flaky — fsnotify reads partial config write" \
  "test-flake" \
'## Symptom
`go test ./internal/config/` occasionally fails with:
```
expected: ":8080"
actual  : ":9090"
Test: TestManager_Watch_MultipleChanges
```
The warning `config: hot-reload rejected, keeping previous config error="...strconv.ParseBool: invalid syntax"` appears in the same run, indicating fsnotify fires while the test is mid-write.

The hot-reload logic is correct (it keeps the previous config on parse error).
The flakiness is in the test, not the production code.

## Fix
Write the updated config atomically using a temp-file + rename pattern in the
test helper, so fsnotify only fires after the full write is complete:
```go
tmp := path + ".tmp"
os.WriteFile(tmp, data, 0644)
os.Rename(tmp, path)
```'

issue \
  "docs: benchmark-competitor-analysis.md claims RuleEval_Callback=50ns/0alloc but measured 110ns/1alloc" \
  "docs" \
'## Discrepancy
`docs/benchmark-competitor-analysis.md` (section 2.1, "Rule eval (callback/EvaluateInto)") states:
> ebpf-guard: **50.0 ns, 0B**

Live benchmark result (`go test -bench=BenchmarkRuleEval_EbpfGuard_Callback ./bench/`):
```
BenchmarkRuleEval_EbpfGuard_Callback-4   10649504   110.2 ns/op   8 B/op   1 allocs/op
```

The doc was written on a faster machine or with an older implementation.

## Request
Re-run `make bench` on the reference machine and update the table with current
numbers.  Also update the "gap vs Tracee" commentary (currently says 3.8×, actual
is 8.2× at 110 ns vs 13 ns).'

# ══════════════════════════════════════════════════════════════════════════════
# FEATURES / ROADMAP
# ══════════════════════════════════════════════════════════════════════════════

issue \
  "feat: pidfd-based kill to fully eliminate PID-reuse race in enforcer" \
  "feature" \
'## Context
The PID-reuse fix in `af5c1b4` (read `/proc/<pid>/comm` and abort on mismatch)
reduces the race window to one kernel round-trip but does not eliminate it.
`pidfd_open(2)` + `pidfd_send_signal(2)` (Linux 5.1+) provide an atomic handle
to a specific process incarnation, making it impossible to SIGKILL the wrong
process even if the PID is recycled between validation and signal delivery.

## Request
Add `pidfd`-based kill as the primary path on kernels ≥ 5.1 (detect via
`unix.PidfdOpen`), with the current `/proc/comm` recheck as fallback.'

issue \
  "feat: rule import pipeline for Sigma and Elastic ECS rule formats" \
  "feature" \
'## Context
The Falco rule importer (`internal/migration/`) closes the compatibility gap with
one ecosystem.  Sigma rules (https://github.com/SigmaHQ/sigma) have become the
industry-standard portable detection format with 3000+ community rules covering
Windows, Linux, and cloud.  Elastic ECS rules (used in Elastic SIEM) cover
another large corpus.

## Request
Extend the migration package with:
1. `sigma2ebpfguard` converter — map Sigma `detection.selection` fields to
   ebpf-guard `condition` operators; map Sigma logsources to ebpf-guard
   `event_type`s.
2. `ecs2ebpfguard` converter for Elastic ECS process/network/file fields.
3. A `--validate` dry-run mode that reports which rules could not be converted
   and why.'

issue \
  "feat: cloud audit-log connectors (AWS CloudTrail, GCP Audit Logs, Azure Monitor)" \
  "feature" \
'## Context
Falco has native CloudTrail, GCP, and Azure plugins (https://github.com/falcosecurity/plugins).
ebpf-guard currently only observes kernel-level events; cloud control-plane
events (IAM role assumption, service-account key creation, node-pool escapes) are
invisible.

## Request
Add read-only cloud-audit collectors as an optional component:
- `--collector=cloudtrail` — poll/stream CloudTrail via SQS
- `--collector=gcp-audit` — stream GCP Audit Logs via Pub/Sub
- `--collector=azure-monitor` — stream Azure Monitor via Event Hub

Cloud events would go through the same YAML rule engine and OPA pipeline,
enabling cross-domain correlation (kernel + cloud control-plane in one alert).'

issue \
  "feat: per-rule event sampling configuration for high-load scenarios" \
  "feature" \
'## Context
Under sustained high load, all rules are evaluated at full rate regardless of
their severity or frequency.  Falco supports priority-based event sampling
(`-o syscall_event_drops.rate`) to shed load gracefully.

## Request
Add a `sample_rate` field to the rule DSL (0.0–1.0, default 1.0 = always evaluate):
```yaml
rules:
  - id: rule_high_volume
    event_type: syscall
    sample_rate: 0.1   # evaluate 10% of matching events
    severity: info
```
The existing `ShouldSample` / `DeterministicSample` infrastructure
(`internal/correlator/`) can be extended to support this.'

issue \
  "feat: syscall allowlist mode (seccomp-style — alert on unexpected syscalls)" \
  "feature" \
'## Context
ebpf-guard currently operates in deny-list mode: rules describe *bad* behaviour
and fire on match.  A complementary allowlist mode would build a per-workload
baseline of expected syscalls (leveraging the existing EWMA profiler) and alert
when an unexpected syscall appears — similar to seccomp-bpf but runtime-learned
rather than statically defined.

This enables detection of novel attacks not covered by any existing rule,
complementing the EWMA anomaly score with a discrete "syscall not in learned set"
signal.

## Request
Add an `allowlist_mode: true` profiler option that:
1. During the learning period, records every unique syscall per workload identity.
2. After learning, emits a `severity: warning` alert for any syscall outside the
   learned set for that workload.'

issue \
  "feat: real end-to-end benchmark vs Falco 0.38 / Tetragon 1.1 on shared hardware" \
  "benchmark" \
'## Context
Current performance claims in `docs/benchmark-competitor-analysis.md` are based
on in-process algorithm reproductions (`bench/vs_*_test.go`) — not actual
side-by-side process measurements.  The existing `bench/comparative/run.sh` and
Vagrantfile infrastructure is ready but has never produced published results.

## Request
Run `bench/comparative/run.sh` on a dedicated bare-metal or large VM (≥8 cores,
≥16 GB), publish the raw CSV output in `bench/comparative/results/`, and update
the doc with:
- Actual CPU overhead % at 1k/10k/100k events/sec workload intensities
- Actual RSS for each agent under load
- Drop rates at peak throughput
- Methodology section making clear which numbers are algorithm-only vs
  end-to-end process measurements

This is the single change that would most strengthen credibility with security
engineers evaluating the tool.'

echo
echo "✓ All issues created in $REPO"
