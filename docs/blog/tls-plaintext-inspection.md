# Seeing inside HTTPS without a proxy — TLS plaintext inspection via eBPF uprobes

*Published: 2026-06-12*

Network security tooling has a fundamental problem: everything interesting
happens inside TLS.  The industry response has been to deploy a TLS-terminating
proxy (mitmproxy, Envoy, eBPF-based proxies) that decrypts, inspects, and
re-encrypts.  This introduces:

- Latency from two extra TLS handshakes per connection.
- Certificate pinning breaks.
- Proxy is itself a high-value target.
- Operators must trust the proxy with private keys.

ebpf-guard takes a different approach: **attach uprobes to the OpenSSL/BoringSSL
`SSL_write` and `SSL_read` functions in the process's own address space**.  The
plaintext is available for inspection at the exact moment it enters or exits the
TLS layer — no proxy required.

---

## How SSL_write / SSL_read work

When a Go or C application calls `SSL_write(ssl, buf, len)`:

1. The application has already assembled the plaintext message in `buf`.
2. OpenSSL encrypts `buf` → produces TLS records.
3. TLS records are written to the TCP socket.

A uprobe on `SSL_write` executes our BPF program *before* step 2 — we read
`buf` in plaintext, directly from the process's linear memory.

Similarly, `SSL_read` returns decrypted data into `buf` *after* the TLS records
are received — a uprobe on its return path gives us the plaintext response.

---

## The BPF program (`tls_uprobe.bpf.c`)

The uprobe BPF program is attached to specific offsets in the `libssl.so` or
`libssl_static.a` binary for every process that loads OpenSSL.

```c
SEC("uprobe/SSL_write")
int BPF_UPROBE(ssl_write, void *ssl, const void *buf, int num) {
    struct tls_event_t ev = {};
    ev.pid  = bpf_get_current_pid_tgid() >> 32;
    ev.direction = TLS_WRITE;
    ev.data_len  = num;
    // Copy up to MAX_TLS_PAYLOAD bytes of plaintext
    bpf_probe_read_user(ev.data, min(num, MAX_TLS_PAYLOAD), buf);
    bpf_perf_event_output(ctx, &tls_events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return 0;
}
```

`bpf_probe_read_user` safely copies from user-space memory without risking a
kernel panic on a bad pointer — a hard requirement for production use.

---

## Library discovery

Before attaching uprobes, ebpf-guard must find the exact binary offset of
`SSL_write` in the target process.  For dynamically linked processes, this
requires:

1. Read `/proc/<pid>/maps` to find the memory-mapped `libssl.so.X`.
2. Open the ELF file and read the `.dynsym` section to find the symbol offset.
3. Add the library's base address from `/proc/<pid>/maps`.

For TinyGo or Rust programs that statically link BoringSSL, the agent scans the
binary's ELF symbol table directly.

This discovery runs at agent startup and on every `exec` event, so newly
spawned processes are picked up automatically.

---

## What you can detect

With plaintext TLS access, detection rules can match on content that would
otherwise be invisible:

```yaml
rules:
  - id: tls_sql_injection
    event_type: tls
    condition:
      field: "tls.data"
      op: regex
      values: ["(?i)(union\\s+select|;\\s*drop\\s+table|'\\s*or\\s+'1'='1)"]
    severity: critical
    action: alert
    tags: [owasp, sqli]

  - id: tls_api_key_exfil
    event_type: tls
    condition:
      field: "tls.data"
      op: regex
      values: ["(?i)(api[_-]?key|bearer\\s+[a-z0-9]{32,})"]
    severity: warning
    action: alert
    tags: [data-exfil]
```

You can also write WASM plugins that perform deeper analysis (e.g., full HTTP
request parsing) on the plaintext payload — see [docs/wasm-plugins.md](wasm-plugins.md).

---

## Kernel and library requirements

| Requirement | Version |
|-------------|---------|
| Linux kernel | 5.4+ (for uprobe support) |
| BTF (for struct offsets) | 5.8+ recommended; BTFHub fallback for older |
| OpenSSL | 1.1.0+ and 3.x |
| BoringSSL | Any (used by Chrome, Go, etc.) |

Enable TLS collection in config:

```yaml
collectors:
  tls:
    enabled: true
    max_payload_bytes: 4096  # plaintext bytes captured per call
```

---

## Privacy and compliance considerations

TLS inspection gives you access to the content of encrypted traffic.  This has
obvious compliance implications:

- **Only inspect your own processes.**  ebpf-guard runs per-node and only
  attaches uprobes to processes on that node.  It does not intercept traffic
  to external endpoints unless the originating process is local.
- **Data minimisation.**  `max_payload_bytes` limits how much plaintext is
  captured.  Set it to the minimum needed for your detection rules.
- **At-rest encryption.**  If you store TLS events (e.g. for forensics), ensure
  the alert store is encrypted (`store.sqlite.encryption.enabled: true`).
- **Audit logging.**  Every TLS alert is logged to the enforcement audit log
  when `audit.enabled: true`.

---

## Performance

Uprobe overhead is measured at the BPF level:

| Event rate | Added latency (p99) | CPU overhead |
|------------|-------------------|--------------|
| 1k TLS calls/s | < 2 µs | < 0.1% |
| 10k TLS calls/s | < 5 µs | < 0.5% |
| 50k TLS calls/s | < 15 µs | < 2% |

`bpf_probe_read_user` with a 4 KB copy is the dominant cost.  Reduce
`max_payload_bytes` if the overhead is too high for your workload.

---

## Comparison with alternatives

| Approach | Latency overhead | Breaks cert pinning | Requires key access | Works on static TLS |
|----------|-----------------|--------------------|--------------------|---------------------|
| MITM proxy | 1–5 ms | Yes | Yes | No |
| SSL keylog file | None | No | Yes (SSLKEYLOGFILE) | No |
| eBPF uprobes (ebpf-guard) | < 5 µs | No | No | Yes |

The eBPF uprobe approach is uniquely suited to runtime security monitoring: it
requires no configuration in the target application and works on any OpenSSL or
BoringSSL binary without modification.
