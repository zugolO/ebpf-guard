package exporter

import (
	"context"
	"testing"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSpanLinker_LinkAlert(t *testing.T) {
	sl := NewSpanLinker("test")
	require.NotNil(t, sl)

	// Alert with valid W3C trace context → linked child span.
	linked := types.Alert{
		RuleID:   "rule-1",
		Severity: types.SeverityCritical,
		Comm:     "proc",
		PID:      42,
		Message:  "boom",
		TraceID:  "0123456789abcdef0123456789abcdef",
		SpanID:   "0123456789abcdef",
		Enrichment: types.EnrichmentInfo{Namespace: "ns", PodName: "pod"},
	}
	ctx, end := sl.LinkAlert(context.Background(), linked)
	require.NotNil(t, ctx)
	require.NotNil(t, end)
	end()

	// Alert without trace context → standalone span, still closeable.
	_, end2 := sl.LinkAlert(context.Background(), types.Alert{RuleID: "r2"})
	end2()
}

func TestBuildSpanContext(t *testing.T) {
	// Valid trace + span IDs.
	sc, err := buildSpanContext("0123456789abcdef0123456789abcdef", "0123456789abcdef")
	require.NoError(t, err)
	assert.True(t, sc.IsValid())

	// Valid trace ID, empty span ID is allowed (zero span).
	_, err = buildSpanContext("0123456789abcdef0123456789abcdef", "")
	// Empty span id yields an all-zero span which is invalid → error expected.
	assert.Error(t, err)

	// Wrong trace ID length.
	_, err = buildSpanContext("tooshort", "0123456789abcdef")
	assert.Error(t, err)

	// Non-hex trace ID of correct length.
	_, err = buildSpanContext("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "0123456789abcdef")
	assert.Error(t, err)

	// Wrong span ID length.
	_, err = buildSpanContext("0123456789abcdef0123456789abcdef", "abc")
	assert.Error(t, err)

	// Non-hex span ID.
	_, err = buildSpanContext("0123456789abcdef0123456789abcdef", "zzzzzzzzzzzzzzzz")
	assert.Error(t, err)
}
