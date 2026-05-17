package exporter

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestLogCounterHandler_CountsByLevel(t *testing.T) {
	// Create a handler that writes to io.Discard
	discardHandler := slog.NewJSONHandler(io.Discard, nil)
	handler := NewLogCounterHandler(discardHandler)

	ctx := context.Background()

	// Reset counter before test
	LogLinesTotal.Reset()

	// Log at different levels
	_ = handler.Handle(ctx, slog.Record{Level: slog.LevelDebug, Message: "debug msg"})
	_ = handler.Handle(ctx, slog.Record{Level: slog.LevelInfo, Message: "info msg"})
	_ = handler.Handle(ctx, slog.Record{Level: slog.LevelInfo, Message: "info msg 2"})
	_ = handler.Handle(ctx, slog.Record{Level: slog.LevelWarn, Message: "warn msg"})
	_ = handler.Handle(ctx, slog.Record{Level: slog.LevelError, Message: "error msg"})

	// Verify counts
	debugCount := testutil.ToFloat64(LogLinesTotal.WithLabelValues("DEBUG"))
	infoCount := testutil.ToFloat64(LogLinesTotal.WithLabelValues("INFO"))
	warnCount := testutil.ToFloat64(LogLinesTotal.WithLabelValues("WARN"))
	errorCount := testutil.ToFloat64(LogLinesTotal.WithLabelValues("ERROR"))

	assert.Equal(t, float64(1), debugCount, "expected 1 DEBUG log")
	assert.Equal(t, float64(2), infoCount, "expected 2 INFO logs")
	assert.Equal(t, float64(1), warnCount, "expected 1 WARN log")
	assert.Equal(t, float64(1), errorCount, "expected 1 ERROR log")
}

func TestLogCounterHandler_WithAttrs(t *testing.T) {
	discardHandler := slog.NewJSONHandler(io.Discard, nil)
	handler := NewLogCounterHandler(discardHandler)

	// Wrap with attrs
	newHandler := handler.WithAttrs([]slog.Attr{slog.String("key", "value")})
	assert.NotNil(t, newHandler)

	// Should still be a LogCounterHandler
	_, ok := newHandler.(*LogCounterHandler)
	assert.True(t, ok, "expected LogCounterHandler type")
}

func TestLogCounterHandler_WithGroup(t *testing.T) {
	discardHandler := slog.NewJSONHandler(io.Discard, nil)
	handler := NewLogCounterHandler(discardHandler)

	// Wrap with group
	newHandler := handler.WithGroup("group")
	assert.NotNil(t, newHandler)

	// Should still be a LogCounterHandler
	_, ok := newHandler.(*LogCounterHandler)
	assert.True(t, ok, "expected LogCounterHandler type")
}

func TestLogCounterHandler_Enabled(t *testing.T) {
	// Create handler with info level
	discardHandler := slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo})
	handler := NewLogCounterHandler(discardHandler)

	ctx := context.Background()

	// Debug should be disabled
	assert.False(t, handler.Enabled(ctx, slog.LevelDebug))
	// Info and above should be enabled
	assert.True(t, handler.Enabled(ctx, slog.LevelInfo))
	assert.True(t, handler.Enabled(ctx, slog.LevelWarn))
	assert.True(t, handler.Enabled(ctx, slog.LevelError))
}
