// Package exporter provides Prometheus metrics and Alertmanager alerting.
package exporter

import (
	"context"
	"encoding/hex"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// SpanLinker creates OTel child spans linked to remote APM trace context extracted
// from application HTTP/gRPC traffic via the TLS uprobe.
//
// When an eBPF security alert is triggered for a request that carried a W3C Trace
// Context (traceparent header), SpanLinker emits an OTel span as a logical child of
// the application's APM span. This produces a unified timeline in Jaeger/Tempo where
// security events appear alongside the originating business transaction.
//
// Usage:
//
//	sl := exporter.NewSpanLinker("ebpf-guard")
//	ctx, end := sl.LinkAlert(ctx, alert)
//	defer end()
type SpanLinker struct {
	tracer trace.Tracer
}

// NewSpanLinker creates a SpanLinker using the global OTel tracer provider.
// serviceName is used as the instrumentation scope (e.g. "ebpf-guard").
func NewSpanLinker(serviceName string) *SpanLinker {
	return &SpanLinker{
		tracer: otel.Tracer("github.com/zugolO/ebpf-guard/security/" + serviceName),
	}
}

// LinkAlert creates an OTel span for the security alert and links it to the remote
// APM span stored in alert.TraceID / alert.SpanID (W3C Trace Context).
//
// If the alert carries no trace context, a standalone span is emitted instead so
// the caller always gets a valid, closeable span. The returned `end` func MUST be
// called when the alert has been fully processed (typically via defer).
func (sl *SpanLinker) LinkAlert(ctx context.Context, alert types.Alert) (context.Context, func()) {
	opts := []trace.SpanStartOption{
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(securityAttributes(alert)...),
	}

	// If the alert carries APM trace context, inject it as the remote parent so the
	// new span becomes a child of the application span in the distributed trace.
	if alert.TraceID != "" {
		if remoteCtx, err := buildSpanContext(alert.TraceID, alert.SpanID); err == nil {
			ctx = trace.ContextWithRemoteSpanContext(ctx, remoteCtx)
		}
	}

	ctx, span := sl.tracer.Start(ctx, "security.alert", opts...)
	return ctx, func() { span.End() }
}

// securityAttributes returns OTel attributes that describe a security alert.
func securityAttributes(alert types.Alert) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("security.rule_id", alert.RuleID),
		attribute.String("security.severity", string(alert.Severity)),
		attribute.String("security.comm", alert.Comm),
		attribute.Int("security.pid", int(alert.PID)),
		attribute.String("security.message", alert.Message),
	}
	if alert.Enrichment.Namespace != "" {
		attrs = append(attrs,
			attribute.String("k8s.namespace", alert.Enrichment.Namespace),
			attribute.String("k8s.pod_name", alert.Enrichment.PodName),
		)
	}
	return attrs
}

// buildSpanContext constructs an OTel SpanContext from W3C Trace Context hex strings.
// traceID must be 32 hex chars; spanID must be 16 hex chars (or empty).
func buildSpanContext(traceID, spanID string) (trace.SpanContext, error) {
	if len(traceID) != 32 {
		return trace.SpanContext{}, fmt.Errorf("trace_id must be 32 hex chars, got %d", len(traceID))
	}

	traceIDBytes, err := hex.DecodeString(traceID)
	if err != nil {
		return trace.SpanContext{}, fmt.Errorf("decode trace_id: %w", err)
	}

	var tid [16]byte
	copy(tid[:], traceIDBytes)

	var sid [8]byte
	if spanID != "" {
		if len(spanID) != 16 {
			return trace.SpanContext{}, fmt.Errorf("span_id must be 16 hex chars, got %d", len(spanID))
		}
		spanIDBytes, err := hex.DecodeString(spanID)
		if err != nil {
			return trace.SpanContext{}, fmt.Errorf("decode span_id: %w", err)
		}
		copy(sid[:], spanIDBytes)
	}

	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID(tid),
		SpanID:     trace.SpanID(sid),
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})

	if !sc.IsValid() {
		return trace.SpanContext{}, fmt.Errorf("invalid span context: trace_id=%q span_id=%q", traceID, spanID)
	}

	return sc, nil
}
