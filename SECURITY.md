# Security Policy

## Supported Versions

The following versions of ebpf-guard are currently supported with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take the security of ebpf-guard seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### Please do not report security vulnerabilities through public GitHub issues.

Instead, please send an email to security@ebpf-guard.io with:

- A description of the vulnerability
- Steps to reproduce the issue
- Possible impact of the vulnerability
- Any suggested fixes or mitigations

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

## Responsible Disclosure Process

1. **Initial Report**: Submit your vulnerability report via email to security@ebpf-guard.io
2. **Acknowledgment**: We will acknowledge receipt of your vulnerability report within 48 hours
3. **Investigation**: Our security team will investigate and validate the reported vulnerability
4. **Fix Development**: We will work on developing a fix for the validated vulnerability
5. **Coordination**: We will coordinate with you on the disclosure timeline and credit
6. **Disclosure**: Once the fix is released, we will publicly disclose the vulnerability with appropriate credit

## Disclosure Timeline

We follow a 90-day disclosure timeline:

- **Day 0**: Vulnerability report received
- **Day 7**: Initial assessment completed
- **Day 30**: Fix developed and tested
- **Day 90**: Public disclosure (or sooner if fix is released)

This timeline may be adjusted based on the severity of the vulnerability and other factors.

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

## Security Contacts

- **Security Team**: security@ebpf-guard.io
- **GPG Key**: [Download Public Key](https://ebpf-guard.io/security.gpg)

## Acknowledgments

We thank the following security researchers for their contributions:

*This section will be updated with acknowledgments for responsible disclosures.*
