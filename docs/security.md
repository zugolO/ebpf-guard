# Security Guide — ebpf-guard

This document is the operator-facing security reference for ebpf-guard.
It covers: the threat model, all security features with enable/disable
instructions, default vs. hardened configuration, a pre-deployment checklist,
and supply-chain verification (cosign / SLSA).

---

## Table of Contents

1. [Threat Model](#threat-model)
2. [Capabilities & Privileges](#capabilities--privileges)
3. [Authentication & Authorization](#authentication--authorization)
4. [mTLS to Alertmanager](#mtls-to-alertmanager)
5. [Network Policies](#network-policies)
6. [AppArmor Profile](#apparmor-profile)
7. [Seccomp Profile](#seccomp-profile)
8. [RBAC](#rbac)
9. [Input Validation & Sanitization](#input-validation--sanitization)
10. [Alert Integrity](#alert-integrity)
11. [Config File Permissions](#config-file-permissions)
12. [Global Alert Rate Limit](#global-alert-rate-limit)
13. [Enforcement Safety Guarantees](#enforcement-safety-guarantees)
14. [Startup Integrity Scan](#startup-integrity-scan)
15. [Automated Security Scanning](#automated-security-scanning)
16. [Supply Chain Security — cosign & SLSA](#supply-chain-security--cosign--slsa)
17. [Hardened Deployment Example](#hardened-deployment-example)
18. [Security Checklist](#security-checklist)

---

## Threat Model

ebpf-guard runs as a privileged DaemonSet with `CAP_BPF`, `CAP_SYS_ADMIN`,
and `CAP_NET_ADMIN`. A compromise of the agent itself could grant an attacker
cluster-wide kernel visibility. The mitigations below are designed to reduce
the blast radius if any component is exploited.

| Attack surface | Risk | Mitigation |
|---|---|---|
| HTTP API auth | Bearer token timing | `crypto/subtle.ConstantTimeCompare` on every comparison |
| Rule YAML — regex | ReDoS | Patterns capped at 1 KiB; Go uses RE2 (linear time, no backtracking) |
| Gossip secret | Timing attack | `crypto/subtle.ConstantTimeCompare` on all secret comparisons |
| Alertmanager webhook | SSRF | URL scheme validated; loopback and link-local addresses rejected |
| SQLite store | SQL injection | All queries use parameterized placeholders; no dynamic SQL concatenation |
| Alertmanager mTLS | Cert validation | Full x509 chain validation; TLS 1.2 minimum |
| WASM plugin engine | Sandbox escape | wazero (pure-Go, no CGo); filesystem and network access disabled |
| OPA/Rego evaluation | Policy bypass | Input structs are typed Go values, not raw JSON |
| Config file | Privilege escalation | World-writable check at startup — agent refuses to start |
| Webhook headers | Header injection | RFC 7230 token validation + CR/LF rejection |
| Mining pool blocklist | Internal traffic blocking | RFC-1918 CIDR ranges skipped on load |
| BPF ring buffer | Overflow / data corruption | Bounded ring buffer; per-map full counters exported as metrics |

An external third-party security audit is planned for the v1.0 milestone. See
[SECURITY.md](../SECURITY.md) for the pre-audit checklist and recommended
auditors.

---

## Capabilities & Privileges

ebpf-guard requires elevated kernel capabilities to attach BPF programs.
The minimum set needed for full functionality is:

| Capability | Required for |
|---|---|
| `CAP_BPF` | Loading and attaching BPF programs (kernel 5.8+) |
| `CAP_SYS_ADMIN` | BPF on kernels < 5.8; BTF access; cgroup operations |
| `CAP_NET_ADMIN` | nftables network blocking enforcement |
| `CAP_SYS_PTRACE` | TLS uprobe inspection (opt-in — disable with `collectors.tls.enabled: false`) |
| `CAP_PERFMON` | BPF perf event access (kernel 5.8+; replaces part of `CAP_SYS_ADMIN`) |
| `CAP_IPC_LOCK` | Locking BPF map memory |

To disable optional capabilities:

```yaml
# values.yaml — drop CAP_NET_ADMIN if nftables enforcement is not needed
securityContext:
  capabilities:
    drop: [ALL]
    add: [SYS_ADMIN, BPF, PERFMON, IPC_LOCK]

config:
  enforcer:
    block_backend: lsm   # Use LSM instead of nftables (no CAP_NET_ADMIN needed)
```

```yaml
# Disable TLS inspection to drop CAP_SYS_PTRACE
config:
  collectors:
    tls:
      enabled: false
```

---

## Authentication & Authorization

All HTTP endpoints (`/metrics`, `/alerts`, `/rules`, `/debug/pprof`) require
a Bearer token. The token is auto-generated at startup (32 cryptographically
random bytes) if not explicitly configured.

### Configure a custom token

```yaml
# config.yaml
server:
  auth:
    enabled: true
    bearer_token: "${EBPF_GUARD_TOKEN}"  # inject from Kubernetes Secret
```

```bash
# Create the secret
kubectl create secret generic ebpf-guard-token \
  --namespace ebpf-guard \
  --from-literal=token=$(openssl rand -hex 32)
```

```yaml
# values.yaml — mount secret as env var
extraEnv:
  - name: EBPF_GUARD_TOKEN
    valueFrom:
      secretKeyRef:
        name: ebpf-guard-token
        key: token
```

### Disable auth (not recommended)

Auth can be disabled for testing only:

```yaml
config:
  server:
    auth:
      enabled: false
```

---

## mTLS to Alertmanager

Mutual TLS secures the Alertmanager webhook connection against MITM attacks.

### Enable mTLS

```yaml
# config.yaml
alerting:
  enabled: true
  webhook_url: "https://alertmanager.monitoring:9093/api/v1/alerts"
  mtls:
    enabled: true
    cert_file: "/etc/ebpf-guard/certs/client.crt"
    key_file:  "/etc/ebpf-guard/certs/client.key"
    ca_file:   "/etc/ebpf-guard/certs/ca.crt"
```

```yaml
# values.yaml — mount certs from a Kubernetes Secret
extraVolumeMounts:
  - name: alertmanager-certs
    mountPath: /etc/ebpf-guard/certs
    readOnly: true

extraVolumes:
  - name: alertmanager-certs
    secret:
      secretName: ebpf-guard-alertmanager-certs
```

TLS minimum version is 1.2. The agent performs full x509 chain validation
against the supplied CA — `insecure_skip_verify` is not exposed.

---

## Network Policies

Restrict egress to only the necessary endpoints.

```yaml
# deploy/security/networkpolicy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ebpf-guard
  namespace: ebpf-guard
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: ebpf-guard
  policyTypes:
    - Ingress
    - Egress
  ingress:
    # Prometheus scraping
    - ports:
        - port: 9090
          protocol: TCP
  egress:
    # Alertmanager
    - ports:
        - port: 9093
          protocol: TCP
    # Kubernetes API server (K8s enricher)
    - ports:
        - port: 443
          protocol: TCP
    # DNS resolution
    - ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
```

---

## AppArmor Profile

An enforce-mode AppArmor profile ships in `deploy/security/apparmor-profile`.
Apply it on each node before deploying the DaemonSet.

```bash
# Load profile on a node
sudo apparmor_parser -r -W deploy/security/apparmor-profile

# Verify it is loaded
sudo aa-status | grep ebpf-guard
```

```yaml
# values.yaml — annotate pod to enforce the profile
podAnnotations:
  container.apparmor.security.beta.kubernetes.io/ebpf-guard: localhost/ebpf-guard
```

The profile allows:
- Reading `/sys/kernel/btf/vmlinux` and `/sys/fs/bpf/**`
- Writing to `/var/lib/ebpf-guard/` and `/var/log/ebpf-guard/`
- TCP bind on the metrics port
- Signal delivery for enforcement kill actions

The profile denies:
- Writing to `/etc/**`, `/usr/**`, `/bin/**`, `/sbin/**`
- Network raw socket creation (not needed for BPF socket filters)
- `ptrace` on processes outside its own namespace (except when TLS inspection is enabled)

---

## Seccomp Profile

A custom seccomp profile in `deploy/security/seccomp-profile.json` restricts
the agent to the ~60 syscalls it actually uses.

```yaml
# values.yaml
podSecurityContext:
  seccompProfile:
    type: Localhost
    localhostProfile: profiles/ebpf-guard-seccomp.json
```

For a less restrictive but still safe option, use the runtime default:

```yaml
podSecurityContext:
  seccompProfile:
    type: RuntimeDefault
```

Key syscalls allowed: `bpf`, `perf_event_open`, `read`, `write`, `mmap`,
`socket`, `connect`, `bind`, `epoll_*`, `futex`, `clone`, `kill`, `signal`.

---

## RBAC

The Helm chart creates a minimal `ClusterRole`. Review it before deploying
in a multi-tenant cluster.

```yaml
# Default ClusterRole — read-only access
rules:
  - apiGroups: [""]
    resources: ["pods", "nodes", "namespaces"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["create"]
```

The `networkpolicy` enforcement add-on requires additional permissions:

```yaml
# Added when enforcement.networkpolicy.enabled=true
  - apiGroups: ["networking.k8s.io"]
    resources: ["networkpolicies"]
    verbs: ["get", "list", "watch", "create", "update", "delete"]
```

To restrict to a single namespace (not recommended for a DaemonSet):

```yaml
# values.yaml
rbac:
  clusterScoped: false   # use Role + RoleBinding instead of ClusterRole
```

---

## Input Validation & Sanitization

### BPF Event Fields (Enforcer)

Before any enforcement action (kill, block, throttle, LSM block) the enforcer
validates the fields that originate from the BPF ring buffer:

| Field | Valid range | Error |
|---|---|---|
| `PID` | 1 – 4 194 304 | `ErrInvalidEvent` — action rejected and logged |
| `UID` | 0 – 65 535 | `ErrInvalidEvent` — action rejected and logged |

PID 0 is the kernel idle task and can never be a valid enforcement target.

### `comm` Field Sanitization

The `comm` field (process name from BPF) is attacker-influenced. Before writing
to any log output the enforcer runs it through `sanitizeComm`, which:

1. Decodes the string rune by rune using `utf8.DecodeRuneInString`.
2. Replaces any invalid UTF-8 byte with `\xNN` (hex escape).
3. Replaces any control character (U+0000–U+001F, U+007F) with `\xNN`.

This prevents log-injection and terminal escape attacks.

### Webhook Headers

Custom HTTP headers configured under `notifications.webhook.headers` are
validated at startup against RFC 7230 §3.2.6 *token* syntax. Header values
are checked for CR (`\r`) and LF (`\n`) to prevent HTTP response-splitting.
If any header fails validation the notifier is disabled at startup.

### Mining Pool CIDR Blocklist

CIDR ranges are validated on load and hot-reload. Any range overlapping
RFC-1918 or loopback address space is silently skipped to prevent accidentally
blocking legitimate cluster traffic.

---

## Alert Integrity

Every alert carries a SHA-256 fingerprint computed over the event fields. The
fingerprint is used for deduplication (cooldown maps) and tamper detection —
any modification of the alert payload will invalidate the fingerprint.

The fingerprint is included in all export formats (Prometheus labels,
Alertmanager annotations, OpenSearch documents, Falco JSON output).

---

## Config File Permissions

At startup, `config.NewManager` checks the config file before reading it.
If the file mode has the `o+w` bit set (world-writable), the agent refuses
to start:

```
config: /etc/ebpf-guard/config.yaml is world-writable (mode 0646) —
refusing to start; fix with: chmod o-w /etc/ebpf-guard/config.yaml
```

Recommended permissions: `0640`, owned by `root:ebpf-guard`.

---

## Global Alert Rate Limit

A token-bucket rate limiter caps total alerts across all rules:

| Config key | Default | Description |
|---|---|---|
| `correlator.max_alerts_per_second` | `10000` | Maximum alerts/sec (0 = unlimited) |

Alerts that exceed the bucket are dropped and counted:

```
ebpf_guard_alerts_dropped_total{reason="global_rate_limit"}
```

The global limit is applied **after** per-rule rate limiting so both guards
are active simultaneously.

---

## Enforcement Safety Guarantees

| Property | Implementation |
|---|---|
| PID/UID validation before kill/block | `validateEvent()` in enforcer — returns `ErrInvalidEvent` |
| Comm sanitization before all log writes | `sanitizeComm()` — UTF-8 decode + hex-escape of non-printable bytes |
| Config integrity at startup | `CheckConfigPermissions()` — rejects world-writable config files |
| Header injection prevention | `validateHeaders()` — RFC 7230 token check + CR/LF rejection |
| Internal traffic protection | RFC-1918 CIDR skip in mining-pool loader |
| Alert flood protection | Token-bucket global rate limiter with Prometheus counter |
| Dry-run mode | `enforcer.dry_run: true` — logs enforcement decisions without executing them |

---

## Startup Integrity Scan

At startup ebpf-guard scans for signs of pre-existing compromise:

| Check | What it detects |
|---|---|
| `/etc/ld.so.preload` | LD_PRELOAD rootkit injection |
| Cron directories | Cron-based persistence (`/etc/cron*`, `/var/spool/cron`) |
| Root shell configs | Shell RC file backdoors (`~root/.bashrc`, `~root/.profile`) |
| Anonymous executable memory | Process memory regions marked `rwxp` with no backing file |

Findings are logged at `WARN` and incremented in
`ebpf_guard_integrity_findings_total{check}`.

To disable the scan (not recommended):

```yaml
config:
  integrity:
    enabled: false
```

---

## Automated Security Scanning

The following checks run on every PR and push to `main`:

| Tool | What it checks | Blocks PR |
|---|---|---|
| **CodeQL** | Static analysis — Go security-extended | Yes (Critical/High) |
| **gosec** | Go security patterns (SARIF → GitHub Security tab) | No (informational) |
| **govulncheck** | Known CVEs in Go dependencies | Yes |
| **Trivy** | Filesystem + container dependency scan (SARIF) | No (informational) |
| **Grype** | SBOM-based vulnerability scan | No (runs on release) |

---

## Supply Chain Security — cosign & SLSA

Every tagged release is signed and has SLSA L3 provenance.

### Container image verification

```bash
cosign verify ghcr.io/zugolO/ebpf-guard:v0.1.0 \
  --certificate-identity-regexp="https://github.com/zugolO/ebpf-guard/" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```

### Binary verification

```bash
# Download binary and cosign bundle
curl -LO https://github.com/zugolO/ebpf-guard/releases/download/v0.1.0/ebpf-guard-linux-amd64
curl -LO https://github.com/zugolO/ebpf-guard/releases/download/v0.1.0/ebpf-guard-linux-amd64.cosign.bundle

cosign verify-blob \
  --bundle ebpf-guard-linux-amd64.cosign.bundle \
  --certificate-identity-regexp="https://github.com/zugolO/ebpf-guard/" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ebpf-guard-linux-amd64
```

### SLSA L3 provenance verification

```bash
# Install slsa-verifier: https://github.com/slsa-framework/slsa-verifier/releases
curl -LO https://github.com/slsa-framework/slsa-verifier/releases/latest/download/slsa-verifier-linux-amd64
chmod +x slsa-verifier-linux-amd64

# Download provenance
curl -LO https://github.com/zugolO/ebpf-guard/releases/download/v0.1.0/ebpf-guard.intoto.jsonl

./slsa-verifier-linux-amd64 verify-artifact ebpf-guard-linux-amd64 \
  --provenance-path ebpf-guard.intoto.jsonl \
  --source-uri github.com/zugolO/ebpf-guard \
  --source-tag v0.1.0
```

### SBOM verification

```bash
curl -LO https://github.com/zugolO/ebpf-guard/releases/download/v0.1.0/ebpf-guard-linux-amd64.spdx.json
curl -LO https://github.com/zugolO/ebpf-guard/releases/download/v0.1.0/ebpf-guard-linux-amd64.spdx.json.cosign.bundle

cosign verify-blob \
  --bundle ebpf-guard-linux-amd64.spdx.json.cosign.bundle \
  --certificate-identity-regexp="https://github.com/zugolO/ebpf-guard/" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  ebpf-guard-linux-amd64.spdx.json
```

All signatures use keyless signing via Sigstore's public Fulcio CA. No
long-lived private keys are stored in the repository or CI secrets.

---

## Hardened Deployment Example

The Helm chart ships a ready-to-use hardened values file:

```bash
helm install ebpf-guard ./deploy/helm/ebpf-guard \
  -f deploy/helm/ebpf-guard/values-secure.yaml \
  --namespace ebpf-guard \
  --create-namespace
```

Key differences from default values:

| Setting | Default | Hardened |
|---|---|---|
| `image.pullPolicy` | `IfNotPresent` | `Always` |
| `resources.limits.memory` | `256Mi` | `512Mi` |
| `priorityClassName` | `""` | `system-node-critical` |
| `podSecurityContext.seccompProfile` | `{}` | `RuntimeDefault` |
| `securityContext.capabilities.drop` | `[]` | `[ALL]` |
| `config.profiler.learning_period` | `3600` | `7200` |
| `config.alerting.enabled` | `false` | `true` |
| `config.store.backend` | `memory` | `sqlite` |
| `config.collectors.tls.enabled` | `false` | `true` |
| `serviceMonitor.enabled` | `false` | `true` |
| `prometheusRule.enabled` | `false` | `true` |
| `vpa.enabled` | `false` | `true` |

---

## Security Checklist

Use this checklist before deploying ebpf-guard to a production cluster.

### Cluster prerequisites
- [ ] Kubernetes 1.25+ with Linux nodes only (`nodeSelector: kubernetes.io/os: linux`)
- [ ] Kernel 5.15+ with `CONFIG_DEBUG_INFO_BTF=y` on all nodes
- [ ] Pod Security Standards: `privileged` namespace label (required for `CAP_BPF`)

### Authentication
- [ ] Bearer token auth enabled (`server.auth.enabled: true`)
- [ ] Token injected from a Kubernetes Secret (not hardcoded in values)
- [ ] mTLS configured for Alertmanager if Alertmanager is used

### Network
- [ ] NetworkPolicy applied (restricts ingress to Prometheus, egress to Alertmanager + K8s API)
- [ ] Alertmanager webhook URL uses HTTPS (not plain HTTP)
- [ ] `insecure_skip_verify` not set (it is not exposed — this is a reminder to verify CA config)

### Container hardening
- [ ] AppArmor profile loaded on all nodes and annotation applied
- [ ] Seccomp profile (`RuntimeDefault` or custom) applied
- [ ] `capabilities.drop: [ALL]` with explicit `add` list
- [ ] `readOnlyRootFilesystem: true` (requires `extraVolumeMounts` for writable paths)
- [ ] `runAsNonRoot: true` + `runAsUser: 65534` (note: BPF still works with non-root + capabilities)

### Capability minimization
- [ ] `CAP_SYS_PTRACE` removed if TLS inspection disabled (`collectors.tls.enabled: false`)
- [ ] `CAP_NET_ADMIN` removed if nftables enforcement not used (`enforcer.block_backend: lsm`)

### Config & secrets
- [ ] Config file permissions: `0640` owned by `root`
- [ ] Sensitive config values (tokens, DB keys, webhook URLs) in Kubernetes Secrets, not ConfigMaps
- [ ] SQLite encryption enabled if storing alerts (`store.sqlite.encryption.enabled: true`)

### Observability
- [ ] `serviceMonitor.enabled: true` — metrics scraped by Prometheus
- [ ] `prometheusRule.enabled: true` — `EbpfGuardDown` alert wired to on-call
- [ ] `EbpfGuardMemoryPressure` and `EbpfGuardCollectorDown` alerts reviewed and routed

### Supply chain
- [ ] Image pulled from `ghcr.io/zugolO/ebpf-guard:<tag>` (not `:latest`)
- [ ] Container image signature verified with `cosign verify`
- [ ] Binary signature verified with `cosign verify-blob` (if deploying binary directly)
- [ ] SLSA L3 provenance verified with `slsa-verifier` for any release binary

### Operational
- [ ] `profilerStatePersistence.enabled: true` on stable clusters (avoids re-learning on restart)
- [ ] `auditLog.enabled: true` — rule-change audit trail ingested by SIEM
- [ ] Resource limits set (default: `500m` CPU / `256Mi` memory; hardened: `1000m` / `512Mi`)
- [ ] `vpa.enabled: true` on autoscaled clusters
- [ ] Dry-run mode (`enforcer.dry_run: true`) used to evaluate new enforcement rules before enabling
