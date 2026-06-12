# Security Policy

## Supported Versions

The following versions of ebpf-guard are currently supported with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take the security of ebpf-guard seriously. If you believe you have found a security vulnerability, please **do not** report it through a public GitHub issue.

### Preferred: GitHub Private Vulnerability Reporting

Use [GitHub's private vulnerability reporting](https://github.com/zugolO/ebpf-guard/security/advisories/new) to submit a report confidentially. This is the recommended channel because it keeps details private until a fix is available and allows coordinated disclosure directly in the repository.

### Alternative: Email

Send an email to **security@ebpf-guard.io** with:

- A description of the vulnerability
- Steps to reproduce the issue
- Possible impact of the vulnerability
- Any suggested fixes or mitigations

You should receive a response within **48 hours**. If you do not, please follow up to ensure we received your original message.

## Responsible Disclosure Process

1. **Initial Report**: Submit via GitHub private advisory or email
2. **Acknowledgment**: Within 48 hours of receipt
3. **Investigation**: Our security team will investigate and validate the reported vulnerability
4. **Fix Development**: We will develop and test a fix
5. **Coordination**: We will agree on a disclosure timeline and credit with the reporter
6. **Disclosure**: Once the fix is released, the advisory is published

## Patch SLA

| Severity | Patch Target |
|---|---|
| Critical | 14 days from confirmed report |
| High | 30 days |
| Medium | 90 days |
| Low | Next scheduled release |

## Disclosure Timeline

We follow a 90-day disclosure timeline by default:

- **Day 0**: Vulnerability report received
- **Day 7**: Initial assessment completed
- **Day 30**: Fix developed and tested
- **Day 90**: Public disclosure (or sooner if fix is released)

This timeline may be adjusted based on the severity of the vulnerability and coordination with downstream users.

## Security Features

### Authentication & Authorization

- Bearer token authentication for all HTTP endpoints (`/metrics`, `/alerts`, `/rules`, `/debug/pprof`)
- mTLS support for Alertmanager webhook (client certificate + CA bundle; TLS 1.2 minimum)
- RBAC ClusterRole with read-only pod/namespace access; `networkpolicies` write only when enforcement enabled
- Bearer token auto-generated from 32 cryptographically random bytes at startup if not configured

### Data Integrity

- SHA-256 fingerprint on every alert payload (tamper detection + deduplication)
- SQLite AES-256 encryption for alert persistence (opt-in via `store.sqlite.encryption`)
- Webhook header validation (RFC 7230 token syntax + CR/LF injection prevention)
- Mining pool CIDR blocklist skips RFC-1918 ranges to prevent accidental cluster traffic blocking

### Runtime Hardening

- AppArmor enforce-mode profile ships in `deploy/security/apparmor-profile`
- Custom seccomp profile in `deploy/security/seccomp-profile.json` (~60 allowed syscalls)
- Minimum capabilities: `CAP_BPF` + `CAP_SYS_ADMIN` + `CAP_IPC_LOCK` + `CAP_PERFMON`
- `privileged: false` supported — use explicit capability list in `values-secure.yaml`
- Config file world-writable check at startup (agent refuses to start if `o+w` bit set)
- Enforcement safety: PID range [1–4194304] and UID range [0–65535] validated before kill/block
- `comm` field sanitized (invalid UTF-8 + control chars hex-escaped) before any log write
- Global alert rate limiter (token bucket) prevents flood attacks on downstream consumers

### Observability & Integrity

- Startup integrity scan: LD_PRELOAD check, cron dir scan, root shell config check, anonymous executable memory scan
- BPF program liveness check + auto-reattach via watchdog
- `EbpfGuardDown` Prometheus alert fires if heartbeat stalls for >2 minutes
- BPF map fullness exported as `ebpf_guard_bpf_map_full_total{map_name}` (no silent data loss)
- Audit log for all rule changes and config hot-reloads (JSONL on host filesystem)

### Supply Chain Security

- Container images signed with cosign keyless signing (Sigstore Fulcio CA, no stored private keys)
- Release binaries signed with `cosign sign-blob` + `.cosign.bundle` attached to GitHub release
- SLSA L3 provenance generated via `slsa-github-generator` and attached to every tagged release
- SPDX and CycloneDX SBOMs generated and signed for each binary and the container image
- SBOM vulnerability scanning with Grype on every release; CodeQL + govulncheck + Trivy on every PR

## Security Hardening

Use the bundled hardened values file for a production-ready deployment:

```bash
helm install ebpf-guard ./deploy/helm/ebpf-guard \
  -f deploy/helm/ebpf-guard/values-secure.yaml \
  --namespace ebpf-guard \
  --create-namespace
```

Key settings applied by `values-secure.yaml`:

```yaml
securityContext:
  privileged: false
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: [ALL]
    add: [SYS_ADMIN, BPF, PERFMON, IPC_LOCK, NET_ADMIN]

podSecurityContext:
  runAsNonRoot: true
  seccompProfile:
    type: RuntimeDefault
```

See [docs/security.md](docs/security.md) for the full operator security guide,
including AppArmor setup, NetworkPolicy, RBAC, and supply-chain verification.

### Alertmanager mTLS

```yaml
alerting:
  enabled: true
  webhook_url: "https://alertmanager:9093/api/v1/alerts"
  mtls:
    enabled: true
    cert_file: "/etc/ebpf-guard/certs/client.crt"
    key_file: "/etc/ebpf-guard/certs/client.key"
    ca_file: "/etc/ebpf-guard/certs/ca.crt"
```

### Metrics Endpoint Authentication

```yaml
server:
  auth:
    enabled: true
    bearer_token: "${METRICS_BEARER_TOKEN}"
```

## Security Checklist

Before deploying ebpf-guard in production (see [docs/security.md](docs/security.md) for full details):

**Authentication**
- [ ] Bearer token auth enabled and token injected from a Kubernetes Secret
- [ ] mTLS configured for Alertmanager webhook

**Container hardening**
- [ ] AppArmor enforce-mode profile loaded on all nodes
- [ ] Seccomp profile applied (`RuntimeDefault` or custom)
- [ ] `capabilities.drop: [ALL]` with explicit `add` list (no `privileged: true`)
- [ ] `readOnlyRootFilesystem: true`

**Network**
- [ ] NetworkPolicy applied (restrict ingress to Prometheus; egress to Alertmanager + K8s API)
- [ ] Alertmanager webhook URL uses HTTPS

**Config & secrets**
- [ ] Config file permissions: `0640`, owned by root
- [ ] All tokens, API keys, DB keys in Kubernetes Secrets (not ConfigMaps)
- [ ] SQLite encryption enabled if storing alerts

**Observability**
- [ ] ServiceMonitor and PrometheusRule enabled
- [ ] `EbpfGuardDown`, `EbpfGuardMemoryPressure`, `EbpfGuardCollectorDown` alerts routed to on-call
- [ ] Audit log enabled and ingested by SIEM

**Supply chain**
- [ ] Image pulled by digest or specific tag (not `:latest`)
- [ ] Container image signature verified with `cosign verify`
- [ ] SLSA L3 provenance verified with `slsa-verifier` for release binaries

## Threat Model & Known Risks

ebpf-guard runs as a privileged DaemonSet with `CAP_BPF`, `CAP_SYS_ADMIN`, and `CAP_NET_ADMIN`. A vulnerability in the agent itself could give an attacker cluster-wide kernel access. The following areas have been reviewed:

| Area | Risk | Mitigation |
|---|---|---|
| HTTP API auth | Bearer token timing | `crypto/subtle.ConstantTimeCompare` used on all token comparisons |
| Rule YAML — regex | Pattern length | Regex patterns are capped at 1 KiB; Go uses RE2 (linear-time, no ReDoS) |
| Gossip protocol secret | Timing attack | `crypto/subtle.ConstantTimeCompare` used on all secret comparisons |
| Alertmanager webhook | SSRF | URL scheme validated; loopback and link-local addresses rejected |
| SQLite store | SQL injection | All queries use parameterized placeholders; no dynamic SQL concatenation |
| Alertmanager mTLS | Cert validation | Full x509 chain validation; TLS 1.2 minimum |
| WASM plugin engine | Sandbox escape | wazero used (pure-Go, no CGo); filesystem and network access disabled |
| OPA/Rego eval | Policy bypass | Input structs are typed Go values, not raw JSON; no user-controllable schema |

An external third-party security audit is planned for the v1.0 milestone. See [Pre-Audit Checklist](#pre-audit-checklist-v10) below for current status.

## Pre-Audit Checklist (v1.0)

ebpf-guard runs as a privileged DaemonSet with `CAP_BPF + CAP_SYS_ADMIN + CAP_NET_ADMIN`. Before commissioning an external audit the following internal gates must pass.

### Internal Preparation

- [ ] `govulncheck ./...` exits clean (zero findings)
- [ ] `trivy fs --severity HIGH,CRITICAL .` exits clean (zero findings)
- [ ] Threat model document prepared and reviewed
- [ ] Audit scope document defined

### Audit Scope

The external audit must cover at minimum:

**Attack Surface**
- HTTP API authentication bypass (bearer token, RBAC)
- mTLS Alertmanager client certificate validation
- WASM plugin sandbox escape (wazero capabilities)
- OPA/Rego input injection
- Gossip protocol message forgery

**Privilege Escalation Paths**
- BPF map poisoning from userspace
- Ring buffer overflow handling
- nftables netlink privilege escalation
- XDP program injection

**Dependency Audit**
- `github.com/open-policy-agent/opa` — supply chain
- `github.com/tetratelabs/wazero` — sandbox completeness
- `github.com/google/nftables` — netlink attack surface
- `github.com/cilium/ebpf` — BPF verifier bypass risks

**Cryptographic Review**
- Alert fingerprinting (SHA-256 collision resistance for dedup)
- Token generation entropy (32-byte random — verify source)
- TLS configuration completeness

### Acceptance Criteria

- [ ] Audit engagement confirmed (firm + timeline)
- [ ] Internal preparation checklist above completed
- [ ] Audit report published (or summary with finding counts)
- [ ] All Critical/High findings resolved before v1.0 tag
- [ ] `SECURITY.md` updated with audit completion date and auditor

### Recommended Auditors

Trail of Bits, NCC Group, Cure53, or a CNCF-affiliated security firm.

## Automated Security Scanning

The following automated security checks run on every pull request and push to `main`:

- **CodeQL** — GitHub static analysis (Go, security-extended query suite)
- **gosec** — Go security linter (SARIF results uploaded to GitHub Security tab)
- **govulncheck** — Go vulnerability database checker (blocks on known CVEs)
- **Trivy** — filesystem dependency scanner (SARIF results uploaded)
- **Grype** — SBOM-based vulnerability scan (runs on release)

## Security Contacts

- **Security Team**: security@ebpf-guard.io
- **GPG Key**: [Download Public Key](https://ebpf-guard.io/security.gpg)
- **GitHub Private Advisory**: [Report a vulnerability](https://github.com/zugolO/ebpf-guard/security/advisories/new)

## Acknowledgments

We thank the following security researchers for their contributions:

*This section will be updated with acknowledgments for responsible disclosures.*
