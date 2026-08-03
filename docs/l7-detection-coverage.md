# L7 (Application-Layer) Detection Coverage Boundary

ebpf-guard is a kernel-visibility tool: it sees syscalls, network connections,
file access, and (optionally) plaintext passed to OpenSSL. It does **not**
parse HTTP requests, understand SQL, or track application-level login state.
This document defines that boundary precisely, so alert absence during an
attack can be correctly read as "outside this tool's visibility" rather than
"detection failure."

## Why this matters

During the 2026-08-03 attack run against a Juice Shop target (SQLi via
sqlmap, brute-force login, SSRF, LDAP/CSRF), the SQLi and brute-force attack
scripts produced **zero new alerts**. This was not a bug: those attacks are
pure L7 traffic against a Node.js/Express process, and left no trace at the
syscall, file, or network level that any existing rule could key on.

## What ebpf-guard can see

| Layer | Source | Example signal |
|---|---|---|
| Syscall | `bpf/syscall.bpf.c` tracepoints | `execve`, `ptrace`, capability changes |
| Network (metadata only) | `bpf/network.bpf.c` kprobe on `tcp_connect` | src/dst IP:port, connection duration |
| File | `bpf/fileaccess.bpf.c` | open/read/write on paths like `/etc/passwd` |
| DNS | `bpf/dns.bpf.c` socket filter | query name, entropy, DGA scoring |
| TLS plaintext | `bpf/tls_uprobe.bpf.c` uprobes on `SSL_write`/`SSL_read` | HTTP payload **only if the process links OpenSSL/BoringSSL directly** |

## What it cannot see: the SQLi/brute-force gap

Juice Shop is a Node.js application. Node's built-in `https`/`tls` modules use
their own TLS implementation, not a linkable `libssl.so` call from the
Node process itself in the common deployment (see the support matrix in
[tls-inspection.md](tls-inspection.md#library-support) — Go, Java JSSE,
Node.js built-in, and Rustls are all **not supported** by the uprobe
approach). Consequences:

- **SQL injection payloads** (`' OR 1=1--`, UNION-based extraction) travel
  inside an HTTP request body/query string that ebpf-guard never parses.
  Unless the injected query actually reaches a shell (`sigma_*` LOLBin rules)
  or touches a sensitive file, there is no signal.
- **Brute-force login attempts** are individual HTTP POSTs to `/rest/user/login`.
  Each one is a normal TCP connection on port 3000 with an ordinary duration —
  indistinguishable from legitimate traffic at the network-metadata level.
  A failed-login response is HTTP body content, invisible without payload
  inspection.
- **LDAP injection / CSRF** are likewise request-body/header-level attacks.

### What *would* close this gap

1. **TLS-uprobe extension**: attach uprobes to Node's actual TLS/crypto
   native bindings (or require deployments to front Node with an
   OpenSSL-linked reverse proxy so `tls-patterns.yaml` rules apply there).
2. **Correlation with application logs**: ship the app's own access/auth logs
   to ebpf-guard (or a log pipeline it can query) so a `failed login` string
   in app logs can be correlated with the process/PID that emitted it.
3. **Behavioral signal from network metadata alone** (implemented — see below):
   without payload content, high-frequency *connection* patterns are still a
   legitimate kernel-visible proxy for brute-force/credential-stuffing
   activity.

## Behavioral signal: `net_high_frequency_connections`

Rule: [`rules/network-anomaly.yaml`](../rules/network-anomaly.yaml) (`net_high_frequency_connections`).

Tracked by `ConnFrequencyTracker`
([internal/correlator/conn_frequency.go](../internal/correlator/conn_frequency.go)):
a sliding 60-second window count of TCP connection attempts per
`(pid, destination port)`, exposed to the rule engine as the computed field
`conn_rate_1m` on `network` (`EventTCPConnect`) events. When a single process
opens more than 30 connections to the same port within a minute, the rule
fires a `warning` alert tagged `mitre:T1110` (Brute Force).

This does **not** know whether any individual login attempt succeeded or
failed — it only knows connection cadence. It will fire on legitimate
high-throughput clients too (health checks, load-test tools); tune the
threshold or add a `comm` exception for known-good callers via the rule's
`exceptions` block if that produces false positives in your environment.

### Verifying it fires

The bruteforce attack script
([deploy/docker-test-setup/attacks/bruteforce-attacks.sh](../deploy/docker-test-setup/attacks/bruteforce-attacks.sh))
sends batches of rapid login POSTs (e.g. ATTACK 6, ~500 requests). Each POST
opens a new TCP connection to the same destination port from the same
process; that traffic alone is sufficient to cross the 30-conn/60s threshold
and produce a `net_high_frequency_connections` alert even though the request
bodies themselves are never inspected.

## Summary

| Attack class | Kernel-visible today | Rule/mechanism |
|---|---|---|
| Reverse shell after SQLi | Yes | `sigma_*`, `lolbin_*`, `c2_*` rules on the spawned shell |
| File read via LFI/path traversal | Yes | `fim_*`, `webshell_sensitive_file_read` |
| Raw SQL injection payload | No | Would require L7 payload parsing |
| Single failed login | No | Would require L7 payload parsing or app-log correlation |
| High-frequency login attempts (volume) | Yes (behavioral) | `net_high_frequency_connections` |
| SSRF to cloud metadata endpoint | Yes | `appexploit_ssrf_gcp_metadata`, `cloud_ext_aws_imds_v1_access`, etc. |
