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

### Authentication

- Bearer token authentication for `/metrics` and pprof endpoints
- mTLS support for Alertmanager webhook

### Authorization

- RBAC integration for Kubernetes environments
- Pod Security Standards compliance

### Data Protection

- Alert fingerprinting (SHA-256) for tamper detection
- Encrypted storage for sensitive configuration

### Runtime Security

- AppArmor profile (enforce mode)
- Seccomp profile enabled by default
- Minimal container privileges

## Security Hardening

### Kubernetes Deployment

```yaml
# Enable security features in values.yaml
securityContext:
  privileged: false
  capabilities:
    drop:
      - ALL
    add:
      - SYS_ADMIN
      - SYS_RESOURCE
      - IPC_LOCK
      - BPF
      - PERFMON

podSecurityContext:
  runAsNonRoot: true
  runAsUser: 65534
  seccompProfile:
    type: RuntimeDefault
```

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

Before deploying ebpf-guard in production:

- [ ] Enable AppArmor in enforce mode
- [ ] Enable seccomp profile
- [ ] Configure mTLS for Alertmanager
- [ ] Enable Bearer token auth for metrics
- [ ] Use Kubernetes Secrets for sensitive data
- [ ] Run as non-root user
- [ ] Drop unnecessary capabilities
- [ ] Enable audit logging
- [ ] Configure network policies
- [ ] Set resource limits

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

An external third-party security audit is planned for the v1.0 milestone.

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
