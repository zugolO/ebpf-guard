package correlator

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// traceContextTTL bounds how long a /proc/<pid>/environ lookup result is reused.
// A process's environment is immutable after exec, so the only staleness risk is
// PID reuse; a short TTL caps that window while still eliminating the repeated
// /proc read on every alert for the same PID.
const traceContextTTL = 30 * time.Second

// traceContextCache memoises extractTraceContext results per PID, including
// negative results. Most kernel events carry no trace context, so without the
// negative cache every alert would re-read /proc/<pid>/environ and rebuild a map
// only to find nothing. The cache turns that into one read per PID per TTL.
type traceContextCache struct {
	mu      sync.RWMutex
	entries map[uint32]traceCacheEntry
}

type traceCacheEntry struct {
	tc      *types.TraceContext // nil = looked up, found nothing (negative cache)
	expires time.Time
}

func newTraceContextCache() *traceContextCache {
	return &traceContextCache{entries: make(map[uint32]traceCacheEntry)}
}

// lookup returns the trace context for pid, reading /proc only on a cache miss
// or after the cached entry has expired. A fresh copy is returned on every call
// so callers may mutate the result (e.g. set Source) without corrupting the
// cached entry shared by other alerts.
func (c *traceContextCache) lookup(pid uint32, now time.Time) *types.TraceContext {
	c.mu.RLock()
	e, ok := c.entries[pid]
	c.mu.RUnlock()
	if ok && now.Before(e.expires) {
		return cloneTraceContext(e.tc)
	}

	tc := extractTraceContext(pid)

	c.mu.Lock()
	c.entries[pid] = traceCacheEntry{tc: tc, expires: now.Add(traceContextTTL)}
	c.mu.Unlock()
	return cloneTraceContext(tc)
}

// cloneTraceContext returns a shallow copy of tc, or nil when tc is nil.
func cloneTraceContext(tc *types.TraceContext) *types.TraceContext {
	if tc == nil {
		return nil
	}
	cp := *tc
	return &cp
}

// cleanup evicts entries that expired at or before now. Called from the engine's
// periodic cleanup goroutine so the map does not grow unbounded with dead PIDs.
func (c *traceContextCache) cleanup(now time.Time) {
	c.mu.Lock()
	for pid, e := range c.entries {
		if !now.Before(e.expires) {
			delete(c.entries, pid)
		}
	}
	c.mu.Unlock()
}

// extractTraceContext reads /proc/<pid>/environ and extracts distributed-trace
// identifiers using the following conventions (in priority order):
//
//  1. W3C traceparent  — TRACEPARENT env var ("00-<traceID>-<spanID>-<flags>")
//  2. OpenTelemetry    — OTEL_TRACE_ID + OTEL_SPAN_ID (non-standard but common)
//  3. Datadog          — DD_TRACE_ID + DD_SPAN_ID (decimal IDs, zero-padded to hex)
//  4. Jaeger           — UBER_TRACE_ID or JAEGER_TRACE_ID ("<traceID>:<spanID>:…")
//
// Returns nil when no trace context is found or /proc/<pid>/environ cannot be
// read (process gone, permission denied, etc.). The Source field is set to
// "environ" on all returned values.
func extractTraceContext(pid uint32) *types.TraceContext {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return nil
	}

	env := parseEnviron(data)

	// 1. W3C traceparent
	if tp, ok := env["TRACEPARENT"]; ok {
		if tc := parseTraceparent(tp); tc != nil {
			tc.Source = "environ"
			if ts, ok := env["TRACESTATE"]; ok {
				tc.TraceState = ts
			}
			return tc
		}
	}

	// 2. OpenTelemetry SDK env vars (non-standard propagation)
	if traceID, ok := env["OTEL_TRACE_ID"]; ok && traceID != "" {
		tc := &types.TraceContext{
			TraceID: traceID,
			SpanID:  env["OTEL_SPAN_ID"],
			Source:  "environ",
		}
		return tc
	}

	// 3. Datadog — DD_TRACE_ID and DD_SPAN_ID are decimal uint64 values.
	if ddTrace, ok := env["DD_TRACE_ID"]; ok && ddTrace != "" {
		tc := &types.TraceContext{
			TraceID: datadogDecimalToHex(ddTrace),
			SpanID:  datadogDecimalToHex(env["DD_SPAN_ID"]),
			Source:  "environ",
		}
		if tc.TraceID != "" {
			return tc
		}
	}

	// 4. Jaeger / Uber trace context: "<traceID>:<spanID>:<parentSpanID>:<flags>"
	for _, key := range []string{"UBER_TRACE_ID", "JAEGER_TRACE_ID"} {
		if val, ok := env[key]; ok && val != "" {
			if tc := parseJaegerTraceID(val); tc != nil {
				tc.Source = "environ"
				return tc
			}
		}
	}

	return nil
}

// parseEnviron splits a NUL-delimited /proc/PID/environ blob into a key=value map.
func parseEnviron(data []byte) map[string]string {
	env := make(map[string]string)
	for _, entry := range strings.Split(string(data), "\x00") {
		if idx := strings.IndexByte(entry, '='); idx > 0 {
			env[entry[:idx]] = entry[idx+1:]
		}
	}
	return env
}

// parseTraceparent parses the W3C Trace Context traceparent header value.
// Format: "00-<32-hex traceID>-<16-hex spanID>-<2-hex flags>"
func parseTraceparent(tp string) *types.TraceContext {
	parts := strings.SplitN(tp, "-", 4)
	if len(parts) < 4 {
		return nil
	}
	version, traceID, spanID, flags := parts[0], parts[1], parts[2], parts[3]
	if version == "ff" {
		return nil // reserved, invalid per spec
	}
	if len(traceID) != 32 || len(spanID) != 16 || len(flags) != 2 {
		return nil
	}
	return &types.TraceContext{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: flags,
	}
}

// parseJaegerTraceID parses the Jaeger/Uber trace ID format.
// Format: "<traceID>:<spanID>:<parentSpanID>:<flags>"
// traceID may be 32 hex chars (128-bit) or 16 hex chars (64-bit, zero-padded).
func parseJaegerTraceID(val string) *types.TraceContext {
	parts := strings.SplitN(val, ":", 4)
	if len(parts) < 2 {
		return nil
	}
	traceID := parts[0]
	spanID := parts[1]
	if traceID == "" || traceID == "0" {
		return nil
	}
	// Pad 64-bit trace IDs to 32 hex chars for W3C compatibility.
	if len(traceID) <= 16 {
		traceID = fmt.Sprintf("%032s", traceID)
	}
	if len(spanID) <= 16 {
		spanID = fmt.Sprintf("%016s", spanID)
	}
	return &types.TraceContext{
		TraceID: traceID,
		SpanID:  spanID,
	}
}

// datadogDecimalToHex converts a Datadog decimal uint64 trace/span ID string to
// a zero-padded lowercase hex string suitable for W3C trace IDs (32 chars for
// trace ID, 16 chars for span ID). Returns empty string on parse failure.
func datadogDecimalToHex(decimal string) string {
	if decimal == "" {
		return ""
	}
	var v uint64
	if _, err := fmt.Sscanf(decimal, "%d", &v); err != nil {
		return ""
	}
	// Datadog IDs are 64-bit; zero-pad to 32 hex chars to match W3C traceID width.
	return fmt.Sprintf("%032x", v)
}
