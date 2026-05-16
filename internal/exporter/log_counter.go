// Package exporter provides Prometheus metrics and Alertmanager alerting.
package exporter

import (
	"context"
	"log/slog"
)

// LogCounterHandler is a slog.Handler wrapper that counts log lines by level.
type LogCounterHandler struct {
	handler slog.Handler
}

// NewLogCounterHandler creates a new handler that counts log lines.
func NewLogCounterHandler(handler slog.Handler) *LogCounterHandler {
	return &LogCounterHandler{handler: handler}
}

// Enabled reports whether the handler handles records at the given level.
func (h *LogCounterHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level)
}

// Handle counts the log line and passes it to the wrapped handler.
func (h *LogCounterHandler) Handle(ctx context.Context, r slog.Record) error {
	// Count the log line by level
	levelStr := r.Level.String()
	RecordLogLine(levelStr)

	return h.handler.Handle(ctx, r)
}

// WithAttrs returns a new handler with the given attributes.
func (h *LogCounterHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &LogCounterHandler{handler: h.handler.WithAttrs(attrs)}
}

// WithGroup returns a new handler with the given group.
func (h *LogCounterHandler) WithGroup(name string) slog.Handler {
	return &LogCounterHandler{handler: h.handler.WithGroup(name)}
}
