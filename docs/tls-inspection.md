# TLS Inspection

This document describes the TLS inspection feature of ebpf-guard, which captures plaintext TLS traffic before encryption and after decryption using eBPF uprobes.

## Overview

TLS inspection allows ebpf-guard to see the actual content of HTTPS and other TLS-encrypted connections by attaching uprobes to the OpenSSL library (`libssl.so`). This enables detection of threats that would otherwise be hidden inside encrypted traffic.

### How It Works

1. **Uprobe Attachment**: The TLS collector attaches uprobes to `SSL_write` and `SSL_read` functions in processes using `libssl.so`
2. **Data Capture**: Before encryption (outbound) and after decryption (inbound), the plaintext data is copied to a kernel ring buffer
3. **Pattern Analysis**: The correlator applies detection rules to the captured plaintext
4. **Alert Generation**: Suspicious patterns trigger security alerts

```
Application → SSL_write → [UPROBE: capture plaintext] → Encryption → Network
Network → Decryption → [UPROBE: capture plaintext] → SSL_read → Application
```

## Capabilities

### What Can Be Detected

- **Credential Exposure**: HTTP Basic Auth headers, API keys, tokens
- **Data Exfiltration**: Sensitive file contents (`/etc/passwd`, SSH keys)
- **Command & Control**: Reverse shell patterns, suspicious User-Agents
- **SQL Injection**: SQL error messages and query results in responses
- **Lateral Movement**: Internal API calls from unexpected processes

### Detection Rules

TLS-specific rules are defined in `rules/tls-patterns.yaml`:

| Rule ID | Description | Severity |
|---------|-------------|----------|
| `tls_http_basic_auth` | HTTP Basic Auth header detected | warning |
| `tls_suspicious_user_agent` | curl/wget User-Agent from production process | warning |
| `tls_data_exfil_patterns` | Sensitive data patterns (passwd, SSH keys) | critical |
| `tls_sql_patterns` | SQL queries or error messages | warning |
| `tls_api_key_exposure` | API key/token patterns | warning |
| `tls_reverse_shell_indicator` | Reverse shell command patterns | critical |

## Configuration

Enable TLS inspection in `config.yaml`:

```yaml
collectors:
  tls:
    enabled: true              # Default: false
    scan_interval: 30s         # How often to scan for new libssl processes
    max_data_size: 256         # Bytes to capture per TLS record (max 4096)
```

### Required Capabilities

TLS inspection requires additional capabilities:

```yaml
# Kubernetes securityContext
securityContext:
  capabilities:
    add:
      - CAP_SYS_PTRACE    # Required for uprobe attachment
      - CAP_BPF           # Required for loading eBPF programs
      - CAP_PERFMON       # Required for BPF_PROG_TYPE_KPROBE
```

### Helm Values

```yaml
# values.yaml
tlsInspection:
  enabled: false
  scanInterval: 30s
  
# Enable in values-secure.yaml for high-security environments
tlsInspection:
  enabled: true
```

## Limitations

### Library Support

| Library | Support Status | Notes |
|---------|---------------|-------|
| OpenSSL / libssl.so | ✅ Supported | Primary target |
| BoringSSL | ⚠️ Partial | May work with compatible ABI |
| Go crypto/tls | ❌ Not Supported | Uses native Go implementation |
| Java JSSE | ❌ Not Supported | Use OpenSSL via JNI for coverage |
| Node.js built-in | ❌ Not Supported | Unless compiled with OpenSSL |
| Rustls | ❌ Not Supported | Pure Rust implementation |

### Data Capture Limits

- **Size**: Only first 256 bytes (configurable) of each `SSL_write`/`SSL_read` call
- **Fragmentation**: Data spanning multiple SSL calls may be captured separately
- **Buffering**: Large writes may be split by the application before reaching SSL layer

### Performance Impact

| Metric | Impact |
|--------|--------|
| Latency | ~1-2µs per SSL_write/SSL_read |
| CPU | ~5% increase at 10k TLS ops/sec |
| Memory | 256KB ring buffer + per-process tracking |

## Privacy Considerations

⚠️ **Important**: TLS inspection captures plaintext data that may contain:
- User credentials and session tokens
- Personal identifiable information (PII)
- Financial data
- Proprietary business information

### Recommended Practices

1. **Enable only when necessary**: Default is disabled
2. **Limit data retention**: Configure short retention for TLS events
3. **Access control**: Restrict access to TLS inspection alerts
4. **Compliance review**: Ensure compliance with organizational policies
5. **Audit logging**: Log all access to captured TLS data

### Data Retention

```yaml
store:
  backend: sqlite
  sqlite:
    path: /var/lib/ebpf-guard/events.db
  
# Configure cleanup job for TLS events (short retention)
# TLS events contain sensitive data and should be purged frequently
```

## Troubleshooting

### TLS Events Not Generated

1. **Check if enabled**:
   ```bash
   curl -H "Authorization: Bearer $TOKEN" http://localhost:9090/api/v1/status | jq '.collectors.tls'
   ```

2. **Verify CAP_SYS_PTRACE**:
   ```bash
   kubectl exec -it <pod> -- cat /proc/self/status | grep Cap
   ```

3. **Check for libssl**:
   ```bash
   # Find processes using libssl
   kubectl exec -it <pod> -- grep libssl /proc/*/maps 2>/dev/null
   ```

4. **Review logs**:
   ```bash
   kubectl logs <pod> | grep -i tls
   ```

### High Memory Usage

If TLS inspection causes memory pressure:

1. Reduce `max_data_size` to 128 or 64 bytes
2. Increase `scan_interval` to 60s or 120s
3. Enable BPF-side sampling (if implemented)

### False Positives

To reduce false positives from TLS rules:

1. Tune rule thresholds in `rules/tls-patterns.yaml`
2. Add process name exclusions for known-good applications
3. Use context-aware rules combining TLS + process lineage

## Metrics

TLS inspection exposes the following Prometheus metrics:

```
# TLS events captured
ebpf_guard_events_total{type="tls", direction="write|read"}

# TLS events dropped (ring buffer full)
ebpf_guard_events_dropped_total{collector="tls", reason="channel_full|parse_error"}

# Processes with uprobes attached
ebpf_guard_tls_attached_processes

# TLS alerts by rule
ebpf_guard_alerts_total{rule_id=~"tls_.*"}
```

## Testing

### Generate Test Traffic

```bash
# Basic HTTPS request (should trigger tls_suspicious_user_agent)
curl -v https://httpbin.org/get

# Request with Basic Auth (should trigger tls_http_basic_auth)
curl -u user:pass https://httpbin.org/basic-auth/user/pass

# Request returning sensitive data patterns
# (configure httpbin locally to return /etc/passwd content)
```

### Verify Capture

```bash
# Check TLS events in store
ebpf-guard alerts list --type tls --since 1m

# Check metrics
curl -s http://localhost:9090/metrics | grep tls
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      User Space                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ TLSCollector │  │  Correlator  │  │    Store     │      │
│  │              │  │              │  │              │      │
│  │ • Discovery  │  │ • Pattern    │  │ • Persist    │      │
│  │ • Attach     │──│   matching   │──│   alerts     │      │
│  │ • Read loop  │  │ • Alert gen  │  │              │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│         │                                                  │
│         │ ring buffer                                      │
└─────────┼──────────────────────────────────────────────────┘
          │
┌─────────┼──────────────────────────────────────────────────┐
│         │              Kernel Space                         │
│  ┌──────┴──────┐                                          │
│  │  BPF Maps   │                                          │
│  │ • tls_events│  Ring buffer for TLS events               │
│  │ • ssl_ctx   │  Context storage for SSL_read             │
│  └─────────────┘                                          │
│         ▲                                                 │
│         │ uprobe/uretprobe                                │
│  ┌──────┴──────┐                                          │
│  │  BPF Progs  │                                          │
│  │•SSL_write   │  Capture outbound plaintext               │
│  │•SSL_read    │  Capture inbound plaintext                │
│  └─────────────┘                                          │
│         ▲                                                 │
└─────────┼──────────────────────────────────────────────────┘
          │
    ┌─────┴─────┐
    │  libssl   │  OpenSSL library in target process
    │  ┌─────┐  │
    │  │SSL_*│  │
    └──┴─────┴──┘
```

## Future Enhancements

- [ ] Go crypto/tls support via different mechanism
- [ ] HTTP/2 frame parsing for gRPC inspection
- [ ] JA3 fingerprinting for TLS client identification
- [ ] Certificate transparency logging
- [ ] mTLS client certificate capture

## References

- [OpenSSL SSL_write documentation](https://www.openssl.org/docs/man3.0/man3/SSL_write.html)
- [eBPF uprobe documentation](https://www.kernel.org/doc/html/latest/bpf/prog_type_kprobe.html)
- [Cilium eBPF library](https://github.com/cilium/ebpf)
