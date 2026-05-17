# DNS Monitoring

ebpf-guard provides comprehensive DNS monitoring capabilities via eBPF tracepoints, enabling detection of DNS-based threats including DGA (Domain Generation Algorithm) malware, DNS tunneling, and suspicious query patterns.

## Overview

DNS monitoring intercepts DNS queries and responses at the kernel level using eBPF tracepoints on `sendmsg`/`sendto` syscalls. This approach provides:

- **Zero overhead for non-DNS traffic**: Early filtering in BPF drops all non-DNS packets
- **Low latency**: Direct kernel-space packet inspection
- **No DNS resolver modification required**: Works with any DNS resolver (systemd-resolved, dnsmasq, etc.)

## Architecture

```
┌─────────────────┐
│  Application    │
│  (curl, wget)   │
└────────┬────────┘
         │ DNS query
         ▼
┌─────────────────┐
│  Kernel Space   │
│  ┌───────────┐  │
│  │ BPF Hook  │  │◄── eBPF tracepoint on sendmsg/sendto
│  │  (dns.   │  │     Early filter: UDP dport == 53
│  │   bpf.c) │  │
│  └─────┬─────┘  │
│        │        │
│  ┌─────▼─────┐  │
│  │ Ring Buf  │  │
│  └─────┬─────┘  │
└────────┼────────┘
         │
         ▼
┌─────────────────┐
│  Userspace      │
│  DNSCollector   │
│  ┌───────────┐  │
│  │ Entropy   │  │◄── DGA detection via Shannon entropy
│  │ Analysis  │  │
│  └─────┬─────┘  │
│        │        │
│  ┌─────▼─────┐  │
│  │ Rule      │  │◄── DNS threat rules (dns-threats.yaml)
│  │ Engine    │  │
│  └─────┬─────┘  │
│        │        │
│  ┌─────▼─────┐  │
│  │ Alert     │  │
│  │ Manager   │  │
│  └───────────┘  │
└─────────────────┘
```

## Configuration

DNS monitoring is enabled by default. Configure via `config.yaml`:

```yaml
collectors:
  dns:
    enabled: true                    # Enable DNS monitoring
    dga_threshold: 3.5              # Shannon entropy threshold (bits/char)
    tunneling_min_length: 50        # Min domain length for tunneling detection
    high_frequency_threshold: 100   # Max queries/minute before alerting
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `true` | Enable/disable DNS monitoring |
| `dga_threshold` | `3.5` | Entropy threshold for DGA detection. Higher values = more strict |
| `tunneling_min_length` | `50` | Domains longer than this are flagged as potential tunneling |
| `high_frequency_threshold` | `100` | Max DNS queries per minute per process |

## Detection Capabilities

### 1. DGA (Domain Generation Algorithm) Detection

DGA malware generates pseudo-random domain names for C2 communication. These domains have high Shannon entropy:

```
Legitimate:  google.com          → entropy: 2.25 bits/char
DGA:         qxj4v9k2mnbp.com    → entropy: 3.75 bits/char
```

**Rule**: `dns_dga_high_entropy`

**Alert Trigger**: Domain entropy > 3.5 bits/character

### 2. DNS Tunneling Detection

Data exfiltration via DNS encodes data in subdomain labels:

```
Normal:      api.example.com
Tunneling:   SGVsbG8gV29ybGQgaGVsbG8gd29ybGQ.example.com (50+ chars)
```

**Rule**: `dns_tunneling_long_domain`

**Alert Trigger**: Domain length > 50 characters

### 3. Suspicious TLD Detection

Queries to known malicious TLDs:

| TLD | Risk |
|-----|------|
| `.onion` | Tor hidden services (often misconfigured) |
| `.bit` | Namecoin/Emercoin (malware C2) |
| `.bazar` | Emercoin (malware C2) |
| `.coin` | Emercoin (malware C2) |

**Rules**: `dns_suspicious_tld_onion`, `dns_suspicious_tld_emercoin`

### 4. High-Frequency DNS Detection

C2 beaconing often involves rapid DNS queries:

**Rule**: `dns_high_frequency`

**Alert Trigger**: > 100 unique domains queried per minute by a single process

### 5. TXT Record Abuse

TXT queries from non-mail processes may indicate DNS tunneling:

**Rule**: `dns_txt_suspicious`

**Filters**: Excludes mail processes (postfix, sendmail, exim, dovecot)

## Metrics

DNS monitoring exports the following Prometheus metrics:

```
# Total DNS queries by QTYPE and RCODE
ebpf_guard_dns_queries_total{qtype="A", rcode="NOERROR"}

# Dropped DNS events (ring buffer overflow)
ebpf_guard_dns_events_dropped_total

# DNS threat alerts by rule
ebpf_guard_alerts_total{rule_id="dns_dga_high_entropy", severity="critical"}
```

## Alert Examples

### DGA Detection Alert

```json
{
  "labels": {
    "alertname": "EbpfGuardAlert",
    "rule_id": "dns_dga_high_entropy",
    "severity": "critical",
    "pod": "web-app-abc123",
    "namespace": "production"
  },
  "annotations": {
    "summary": "DGA Domain Detected",
    "description": "Process curl (PID 1234) queried high-entropy domain qxj4v9k2mnbp.example.com (entropy: 3.75)"
  }
}
```

### DNS Tunneling Alert

```json
{
  "labels": {
    "alertname": "EbpfGuardAlert",
    "rule_id": "dns_tunneling_long_domain",
    "severity": "critical"
  },
  "annotations": {
    "summary": "DNS Tunneling Detected",
    "description": "Process python3 (PID 5678) queried 72-character domain (possible data exfiltration)"
  }
}
```

## Testing

### Manual Testing

```bash
# Test DGA detection
dig qxj4v9k2mnbp.example.com

# Test DNS tunneling detection
dig $(python3 -c "print('A'*60)").example.com

# Test suspicious TLD
dig test.onion

# Test TXT query (if not mail process)
dig TXT example.com
```

### Verify Metrics

```bash
# Check DNS query metrics
curl -s http://localhost:9090/metrics | grep ebpf_guard_dns_queries_total

# Check for dropped events
curl -s http://localhost:9090/metrics | grep ebpf_guard_dns_events_dropped_total
```

## Performance

DNS monitoring is designed for minimal overhead:

| Metric | Target | Typical |
|--------|--------|---------|
| CPU overhead | < 2% | ~0.5% |
| Memory | < 10MB | ~5MB |
| Latency per query | < 1µs | ~0.3µs |

### Optimization Strategies

1. **Early filtering in BPF**: Only UDP port 53 traffic is processed
2. **Ring buffer batching**: Events are batched for efficient userspace delivery
3. **Lazy entropy calculation**: Only computed when needed for rule evaluation

## Limitations

1. **IPv4 only**: Currently supports IPv4 DNS queries only
2. **UDP only**: TCP DNS (large responses) not yet supported
3. **No DNSSEC validation**: Only monitors queries, doesn't validate responses
4. **Encrypted DNS**: Cannot inspect DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT)

## Troubleshooting

### No DNS events appearing

```bash
# Check if collector is enabled
ebpf-guard status | grep dns

# Verify BPF programs are loaded
bpftool prog list | grep dns

# Check kernel capabilities
sysctl net.core.bpf_jit_enable
```

### High CPU usage

1. Check for DNS amplification attacks
2. Verify `dga_threshold` is not too low
3. Consider increasing `high_frequency_threshold`

### False positives

1. Adjust `dga_threshold` based on your environment
2. Add legitimate domains to allowlist
3. Tune `tunneling_min_length` for your DNS structure

## References

- [Shannon Entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory))
- [DGA Detection Techniques](https://www.splunk.com/en_us/blog/security/deep-learning-domain-generation-algorithms-dga-detection.html)
- [DNS Tunneling Detection](https://www.akamai.com/blog/security/dns-tunneling-detection)
