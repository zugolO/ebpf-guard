// Package collector provides eBPF-based event collection from the kernel.
package collector

import (
	"regexp"
	"strings"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// W3C Trace Context header names (case-insensitive in HTTP/1.1).
const (
	headerTraceparent = "traceparent"
	headerTracestate  = "tracestate"
)

// traceparentRE matches the W3C traceparent header value in an HTTP payload.
//
// Format: version(2)-traceId(32)-parentId(16)-flags(2)
// Example: traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
//
// The regex is intentionally tolerant of surrounding whitespace and CRLF line endings.
var traceparentRE = regexp.MustCompile(
	`(?i)traceparent\s*:\s*([\da-f]{2})-([\da-f]{32})-([\da-f]{16})-([\da-f]{2})`,
)

// tracestateRE matches the W3C tracestate header value in an HTTP payload.
// Captures everything up to the next CRLF or LF.
var tracestateRE = regexp.MustCompile(`(?i)tracestate\s*:\s*([^\r\n]+)`)

// ExtractTraceContext scans an HTTP plaintext payload (captured via TLS uprobe) for
// W3C Trace Context headers. Returns a populated TraceContext if a valid traceparent
// header is found, or nil if the payload contains no trace context.
//
// This function is called on every TLS plaintext event when the OTel tracing feature
// is enabled, so it is written to minimise allocations on the hot path.
func ExtractTraceContext(data []byte) *types.TraceContext {
	if len(data) == 0 {
		return nil
	}

	// Fast path: skip payloads that clearly don't contain HTTP headers.
	// HTTP/1.x requests start with a method verb; HTTP/2 starts with the PRI preface.
	// We check for the literal string "traceparent" before running the regex to avoid
	// unnecessary regex engine overhead on binary or non-HTTP payloads.
	payload := string(data)
	if !strings.Contains(strings.ToLower(payload), headerTraceparent) {
		return nil
	}

	m := traceparentRE.FindStringSubmatch(payload)
	if m == nil {
		return nil
	}

	tc := &types.TraceContext{
		// m[1] = version (ignored — only "00" defined today)
		TraceID:    m[2],
		SpanID:     m[3],
		TraceFlags: m[4],
	}

	// Extract optional tracestate (vendor-specific propagation data).
	if sm := tracestateRE.FindStringSubmatch(payload); sm != nil {
		tc.TraceState = strings.TrimSpace(sm[1])
	}

	return tc
}
