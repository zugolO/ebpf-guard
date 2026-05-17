# CNCF Due Diligence Document

This document serves as the foundation for the CNCF Sandbox application for ebpf-guard.

## Table of Contents

- [Project Description](#project-description)
- [Alignment with CNCF Mission](#alignment-with-cncf-mission)
- [Comparison with Existing Projects](#comparison-with-existing-projects)
- [Technical Architecture](#technical-architecture)
- [Security Self-Assessment](#security-self-assessment)
- [Production Users](#production-users)
- [Roadmap](#roadmap)
- [Community and Governance](#community-and-governance)
- [Licensing and IP](#licensing-and-ip)

---

## Project Description

**ebpf-guard** is a lightweight, eBPF-based runtime security and observability agent for Linux and Kubernetes environments. It correlates syscall, network, and file-access kernel events into behavioral process profiles, detects anomalies, and exports security alerts and Prometheus metrics.

### Key Features

- **eBPF-powered**: Uses eBPF for kernel tracing without kernel modules
- **Behavioral profiling**: Learns normal process behavior and detects deviations
- **Multi-event correlation**: Correlates syscalls, network, file access, and TLS traffic
- **Cloud-native**: Native Kubernetes integration with pod metadata enrichment
- **Lightweight**: Designed for minimal overhead (<5% CPU, <100MB RAM at 10k events/sec)
- **Vendor-neutral**: No dependency on specific CNI, service mesh, or cloud provider

### Target Users

- Platform engineers running Kubernetes on Linux
- Security teams needing runtime threat detection
- DevOps teams requiring observability without heavy agents

---

## Alignment with CNCF Mission

The CNCF mission is to "make cloud native computing ubiquitous." ebpf-guard aligns with this mission in several ways:

### 1. Cloud Native Security

Runtime security is a critical component of cloud native infrastructure. ebpf-guard provides:
- Kubernetes-native deployment (DaemonSet)
- Prometheus metrics export
- Integration with Alertmanager, Slack, Teams
- Helm chart for easy installation

### 2. Observability

ebpf-guard contributes to the observability ecosystem:
- eBPF-based event collection (no instrumentation required)
- Behavioral profiling for anomaly detection
- Integration with Prometheus/Grafana stack

### 3. Vendor Neutrality

Unlike competing solutions tied to specific vendors:
- No Cilium dependency (unlike Tetragon)
- No kernel module (unlike Falco's kernel module option)
- Works with any Kubernetes distribution
- Works with any CNI

### 4. Open Standards

- Uses standard eBPF (CO-RE, BTF)
- Exports standard Prometheus metrics
- Alertmanager webhook format
- SPDX/CycloneDX SBOMs

---

## Comparison with Existing Projects

### Falco

| Aspect | Falco | ebpf-guard |
|--------|-------|------------|
| Kernel access | Kernel module or eBPF | eBPF only |
| Runtime | Userspace daemon in C++ | Go |
| Rules | YAML with Lua conditions | YAML with Go conditions |
| Overhead | Higher (kernel module) | Lower (eBPF only) |
| Dependencies | Kernel headers | CO-RE (no headers) |
| Kubernetes | Via sidecar | Native integration |

**Key differentiator**: ebpf-guard is simpler to deploy (no kernel headers, no module compilation) and lighter at runtime.

### Tetragon

| Aspect | Tetragon | ebpf-guard |
|--------|----------|------------|
| CNI dependency | Cilium required | None |
| Focus | Network security | Process behavior |
| Runtime | Cilium ecosystem | Standalone |
| Overhead | Low (Cilium datapath) | Low (dedicated eBPF) |

**Key differentiator**: ebpf-guard works without Cilium, making it suitable for environments using other CNIs (Calico, Flannel, etc.).

### KubeArmor

| Aspect | KubeArmor | ebpf-guard |
|--------|-----------|------------|
| Approach | Policy-based enforcement | Behavioral anomaly detection |
| Use case | Compliance, hardening | Threat detection |
| Learning | Static policies | Dynamic baseline learning |

**Key differentiator**: ebpf-guard focuses on detecting unknown threats through behavioral analysis, while KubeArmor enforces known-good policies.

### Tracee

| Aspect | Tracee | ebpf-guard |
|--------|--------|------------|
| Focus | Forensics, event streaming | Real-time alerting |
| Output | Events to various sinks | Alerts + metrics |
| Profiling | Signature-based | Behavioral baseline |

**Key differentiator**: ebpf-guard includes built-in behavioral profiling and anomaly detection, not just event collection.

---

## Technical Architecture

### High-Level Design

```
┌─────────────────────────────────────────────────────────────┐
│                        User Space                           │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ Syscall  │  │ Network  │  │ File     │  │ TLS      │   │
│  │ Collector│  │ Collector│  │ Collector│  │ Collector│   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘   │
│       └─────────────┴─────────────┴─────────────┘         │
│                         │                                   │
│                   ┌─────┴─────┐                            │
│                   │ Correlator│                            │
│                   │  Engine   │                            │
│                   └─────┬─────┘                            │
│                         │                                   │
│       ┌─────────────────┼─────────────────┐                │
│       │                 │                 │                │
│  ┌────┴────┐      ┌────┴────┐      ┌────┴────┐           │
│  │ Profiler│      │  Rule   │      │ K8s     │           │
│  │ (EWMA)  │      │ Engine  │      │ Enricher│           │
│  └────┬────┘      └────┬────┘      └─────────┘           │
│       │                │                                    │
│       └────────────────┼────────────────┐                  │
│                        │                │                  │
│                   ┌────┴────┐     ┌────┴────┐             │
│                   │ Alert   │     │Metrics  │             │
│                   │ Manager │     │Exporter │             │
│                   └────┬────┘     └─────────┘             │
│                        │                                    │
└────────────────────────┼────────────────────────────────────┘
                         │
┌────────────────────────┼────────────────────────────────────┐
│                        │         Kernel Space               │
│  ┌──────────┐  ┌───────┴────┐  ┌──────────┐  ┌──────────┐ │
│  │ Syscall  │  │ Network    │  │ File     │  │ TLS      │ │
│  │ kprobes  │  │ kprobes    │  │ kprobes  │  │ uprobes  │ │
│  │ tracepoints│  │ tracepoints│  │ tracepoints│  │          │ │
│  └──────────┘  └────────────┘  └──────────┘  └──────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Key Components

1. **Collectors**: eBPF programs for syscall, network, file, and TLS events
2. **Correlator**: Event correlation engine with rule matching
3. **Profiler**: Behavioral profiling using EWMA and sequence analysis
4. **Enricher**: Kubernetes metadata enrichment
5. **Exporters**: Prometheus metrics and alert notifications

### Performance Characteristics

- **Throughput**: 10,000+ events/second per node
- **Memory**: <100MB RSS at sustained load
- **CPU**: <5% overhead on 4-core node
- **Latency**: p99 <10µs per event processing

---

## Security Self-Assessment

### Threat Model

#### Assets

1. **eBPF programs**: Kernel code that processes events
2. **Event data**: Process behavior data collected from kernel
3. **Configuration**: Rules, alerts, credentials
4. **Alert data**: Security alerts sent to external systems

#### Threats

| Threat | Risk | Mitigation |
|--------|------|------------|
| eBPF program tampering | High | Signed container images, readonly rootfs |
| Privilege escalation via eBPF | High | Run with minimal capabilities (CAP_BPF, CAP_PERFMON) |
| Event data exfiltration | Medium | Network policies, mTLS for Alertmanager |
| Credential exposure | High | Kubernetes Secrets, no env vars for secrets |
| DoS via event flooding | Medium | BPF-side sampling, rate limiting |

### Security Features

- **Container security**: Distroless base image, readonly rootfs
- **Runtime security**: AppArmor enforce mode, seccomp profile
- **Authentication**: Bearer token auth for metrics endpoint
- **Transport**: mTLS for Alertmanager webhook
- **Supply chain**: Signed container images (cosign), SBOMs

### Known Limitations

1. **eBPF verification**: Complex eBPF programs may fail verifier on older kernels
2. **TLS inspection**: Requires CAP_SYS_PTRACE, limited to OpenSSL
3. **Go TLS**: Not supported (static linking)
4. **Kernel version**: Requires 5.15+ for full feature set

### Vulnerability Reporting

See [SECURITY.md](../SECURITY.md) for our security policy and vulnerability disclosure process.

---

## Production Users

*This section will be populated as the project gains production users.*

### Current Status

ebpf-guard is currently in active development and seeking early adopters.

### Interested Parties

- Organizations evaluating runtime security tools
- Kubernetes platform teams

### Case Studies

*Pending first production deployments.*

---

## Roadmap

### Completed (2024)

- [x] Core eBPF collectors (syscall, network, file)
- [x] Behavioral profiling with EWMA
- [x] Kubernetes integration
- [x] Prometheus metrics export
- [x] Alertmanager integration
- [x] Slack/Teams/webhook notifications
- [x] TLS inspection via uprobes
- [x] Process lineage tracking
- [x] Syscall sequence anomaly detection

### Near-term (2025 Q1-Q2)

- [ ] Grafana dashboard
- [ ] OWASP web attack rules
- [ ] Container escape detection rules
- [ ] CLI tool completion
- [ ] OpenSearch backend stabilization
- [ ] Performance benchmark suite

### Mid-term (2025 Q3-Q4)

- [ ] Windows eBPF support (when available)
- [ ] Additional TLS libraries (BoringSSL, Rustls)
- [ ] Machine learning-based anomaly detection
- [ ] Falco rule converter
- [ ] Web UI for alert management

### Long-term

- [ ] CNCF Graduation
- [ ] Multi-cluster federation
- [ ] Integration with security orchestration platforms

---

## Community and Governance

### Current State

- **Contributors**: Seeking initial contributors
- **Maintainers**: TBD (see [MAINTAINERS.md](../MAINTAINERS.md))
- **Governance**: [GOVERNANCE.md](../GOVERNANCE.md)
- **Code of Conduct**: [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md)

### Communication

- GitHub Issues: Bug reports and feature requests
- GitHub Discussions: General questions and design discussions
- Security: security@ebpf-guard.io

### Meetings

Currently asynchronous via GitHub. Regular community meetings may be established as the community grows.

---

## Licensing and IP

### License

Apache License 2.0 (see [LICENSE](../LICENSE))

### Copyright

Copyright (c) The ebpf-guard Authors

### Third-Party Dependencies

All dependencies are Apache 2.0, MIT, or BSD licensed. See `go.mod` and SBOMs for full list.

### CLA / DCO

We use [Developer Certificate of Origin (DCO)](https://developercertificate.org/) via `git commit -s`. No CLA required.

---

## Appendix: CNCF Sandbox Requirements Checklist

- [x] **Open source**: Apache 2.0 license
- [x] **GitHub repo**: https://github.com/ebpf-guard/ebpf-guard
- [x] **Documentation**: README, docs/, CONTRIBUTING.md
- [x] **Governance**: GOVERNANCE.md, MAINTAINERS.md, CODE_OF_CONDUCT.md
- [x] **Security**: SECURITY.md, vulnerability disclosure process
- [x] **CI/CD**: GitHub Actions for build, test, release
- [x] **Signed releases**: Cosign-signed container images
- [x] **SBOM**: SPDX and CycloneDX generation

---

## Contact

For questions about this document or the CNCF application:

- Open an issue: https://github.com/ebpf-guard/ebpf-guard/issues
- Email: cncf@ebpf-guard.io
