# Integrations

## Distributed Tracing / Trace Correlation

ebpf-guard propagates APM trace context into every alert it fires, so you can jump
directly from a security alert to the originating request in your APM tool
(Jaeger, Tempo, Datadog APM, Honeycomb, etc.).

### How it works

When an alert is generated, the engine tries to attach a `trace_context` object
using the following sources **in priority order**:

| Priority | Source | Description |
|----------|--------|-------------|
| 1 | `tls_header` | W3C `traceparent` header extracted from HTTP/gRPC plaintext captured by the TLS uprobe |
| 2 | `environ` | Trace env vars read from `/proc/<PID>/environ` of the triggering process |

The `trace_context.source` field tells you which path was used.

### Alert schema

```json
{
  "id": "...",
  "rule_id": "...",
  "pid": 1234,
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "span_id": "00f067aa0ba902b7",
  "trace_context": {
    "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
    "span_id":  "00f067aa0ba902b7",
    "trace_flags": "01",
    "trace_state": "vendor=value",
    "source": "tls_header"
  }
}
```

`trace_id` and `span_id` at the top level are kept for backward compatibility.
`trace_context` is the authoritative structured field going forward.

### Supported trace ID formats

#### W3C traceparent (OpenTelemetry, highest priority)

Set the `TRACEPARENT` environment variable in your workload:

```
TRACEPARENT=00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
TRACESTATE=vendor=value   # optional
```

Format: `<version>-<32-hex traceID>-<16-hex spanID>-<2-hex flags>`

This is also extracted automatically from HTTP/gRPC request headers by the TLS
uprobe — no env var needed for web servers.

#### Datadog

Set `DD_TRACE_ID` and `DD_SPAN_ID` (decimal uint64 values injected by the
Datadog tracer automatically):

```
DD_TRACE_ID=5546684440795525430
DD_SPAN_ID=2882413980551432843
```

ebpf-guard converts these to zero-padded lowercase hex for W3C compatibility.

#### Jaeger / Uber

Set `UBER_TRACE_ID` or `JAEGER_TRACE_ID`:

```
UBER_TRACE_ID=4bf92f3577b34da6:00f067aa0ba902b7:0:1
```

Format: `<traceID>:<spanID>:<parentSpanID>:<flags>`

64-bit trace IDs are zero-padded to 128-bit (32 hex chars) automatically.

### Linking alerts to APM traces

Most APM backends let you search by trace ID. Example deep-link patterns:

| Backend | URL pattern |
|---------|-------------|
| Jaeger UI | `http://jaeger:16686/trace/<trace_id>` |
| Grafana Tempo | `http://grafana/explore?...traceId=<trace_id>` |
| Datadog APM | `https://app.datadoghq.com/apm/trace/<decimal_trace_id>` |

You can build these links in Alertmanager receiver templates using the
`trace_id` label that ebpf-guard adds to every Alertmanager payload.

### Prometheus / Alertmanager labels

When `trace_context` is present, the following labels are added to the
Alertmanager payload:

| Label | Value |
|-------|-------|
| `trace_id` | 32-hex trace identifier |
| `span_id` | 16-hex span identifier |
| `trace_source` | `tls_header` or `environ` |

### Grafana dashboard

The bundled Grafana dashboard (shipped in the Helm chart) includes a
**Trace Correlation** panel showing alert counts grouped by `trace_source`
over time, and a link column that generates Jaeger deep-links from the
`trace_id` label.
