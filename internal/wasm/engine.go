package wasm

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/tetratelabs/wazero"
	"github.com/zugolO/ebpf-guard/internal/util"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

var (
	pluginsLoaded = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ebpf_guard_wasm_plugins_loaded",
		Help: "Number of WASM detection plugins currently loaded.",
	})
	pluginEvals = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ebpf_guard_wasm_plugin_evaluations_total",
		Help: "Total WASM plugin evaluation calls.",
	}, []string{"plugin_id", "result"})
	pluginLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ebpf_guard_wasm_plugin_latency_seconds",
		Help:    "WASM plugin evaluation latency.",
		Buckets: prometheus.ExponentialBuckets(0.0001, 2, 12),
	}, []string{"plugin_id"})
)

// defaultPluginEvalTimeout is the fallback per-invocation deadline when none is configured.
const defaultPluginEvalTimeout = 100 * time.Millisecond

// Engine manages WASM detection plugins loaded from a directory.
// All plugins run in the same wazero Runtime (shared compilation cache)
// but each evaluation gets a fresh module instance for full isolation.
type Engine struct {
	mu      sync.RWMutex
	plugins []*Plugin
	rt      wazero.Runtime
	dir     string
	logger  *slog.Logger
	timeout time.Duration // per-invocation deadline; 0 uses defaultPluginEvalTimeout
}

// NewEngine creates a WASM engine and loads all .wasm files found in dir.
// If the directory does not exist, the engine starts with zero plugins.
// timeout sets the per-invocation deadline; pass 0 to use the default (100ms).
func NewEngine(ctx context.Context, dir string, logger *slog.Logger, timeout time.Duration) (*Engine, error) {
	if timeout <= 0 {
		timeout = defaultPluginEvalTimeout
	}

	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().
		WithMemoryLimitPages(256).          // 256 pages = 16 MB per instance
		WithCloseOnContextDone(true))       // honor caller context deadlines

	e := &Engine{
		rt:      rt,
		dir:     dir,
		logger:  logger.With("component", "wasm_engine"),
		timeout: timeout,
	}

	if err := e.loadDir(ctx, dir); err != nil {
		rt.Close(ctx) //nolint:errcheck
		return nil, err
	}

	return e, nil
}

// loadDir scans dir for .wasm files and loads each one.
// Missing directories are silently skipped (engine starts with 0 plugins).
func (e *Engine) loadDir(ctx context.Context, dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		e.logger.Info("WASM plugin directory not found, starting with no plugins",
			slog.String("dir", dir))
		return nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read plugin dir %q: %w", dir, err)
	}

	var loaded int
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".wasm") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		plugin, err := loadPlugin(ctx, e.rt, path, e.logger)
		if err != nil {
			e.logger.Warn("failed to load WASM plugin",
				slog.String("path", path),
				slog.Any("error", err))
			continue
		}
		e.plugins = append(e.plugins, plugin)
		loaded++
		e.logger.Info("loaded WASM plugin",
			slog.String("id", plugin.ID()),
			slog.String("name", plugin.meta.Name),
			slog.String("path", path))
	}

	pluginsLoaded.Set(float64(loaded))
	e.logger.Info("WASM plugin engine ready", slog.Int("plugins", loaded))
	return nil
}

// Evaluate runs all loaded plugins against the event and returns any matching alerts.
// If serialization fails or a plugin errors, the event is logged and skipped so
// a buggy plugin cannot halt the entire event pipeline.
func (e *Engine) Evaluate(ctx context.Context, event types.Event) []types.Alert {
	e.mu.RLock()
	plugins := e.plugins
	e.mu.RUnlock()

	if len(plugins) == 0 {
		return nil
	}

	eventJSON, err := SerializeEvent(event)
	if err != nil {
		e.logger.Warn("WASM engine: failed to serialize event",
			slog.Int("type", int(event.Type)),
			slog.Any("error", err))
		return nil
	}

	var alerts []types.Alert
	for _, plugin := range plugins {
		alert, matched := e.evalPlugin(ctx, plugin, event, eventJSON)
		if matched {
			alerts = append(alerts, alert)
		}
	}
	return alerts
}

// evalPlugin runs a single plugin and builds the resulting alert on a match.
func (e *Engine) evalPlugin(ctx context.Context, p *Plugin, event types.Event, eventJSON []byte) (types.Alert, bool) {
	pluginCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	start := time.Now()
	result, err := p.Evaluate(pluginCtx, eventJSON)
	elapsed := time.Since(start)

	pluginLatency.WithLabelValues(p.ID()).Observe(elapsed.Seconds())

	if err != nil {
		if pluginCtx.Err() != nil {
			// Timeout: the plugin exceeded the configured deadline. Log with enough
			// detail for operators to identify and optimise or remove the offending plugin.
			e.logger.Warn("WASM plugin timed out",
				slog.String("plugin", p.ID()),
				slog.Duration("limit", e.timeout),
				slog.Duration("elapsed", elapsed))
			pluginEvals.WithLabelValues(p.ID(), "timeout").Inc()
		} else {
			e.logger.Warn("WASM plugin evaluation error",
				slog.String("plugin", p.ID()),
				slog.Any("error", err))
			pluginEvals.WithLabelValues(p.ID(), "error").Inc()
		}
		return types.Alert{}, false
	}

	if !result.Matched {
		pluginEvals.WithLabelValues(p.ID(), "no_match").Inc()
		return types.Alert{}, false
	}

	pluginEvals.WithLabelValues(p.ID(), "match").Inc()

	meta := p.Meta()
	alert := types.Alert{
		Timestamp: time.Now(),
		RuleID:    meta.ID,
		RuleName:  meta.Name,
		Severity:  result.Severity,
		Message:   result.Message,
		PID:       event.PID,
		Comm:      util.BytesToString(event.Comm[:]),
		Event:     event,
		Action:    meta.Action,
	}

	if len(meta.Tags) > 0 {
		if alert.Details == nil {
			alert.Details = make(map[string]interface{})
		}
		alert.Details["wasm_plugin_tags"] = meta.Tags
		alert.Details["wasm_plugin_id"] = meta.ID
	}

	if event.TraceContext != nil {
		alert.TraceID = event.TraceContext.TraceID
		alert.SpanID = event.TraceContext.SpanID
	}
	if event.Enrichment != nil {
		alert.Enrichment = *event.Enrichment
	}

	return alert, true
}

// PluginCount returns the number of currently loaded plugins.
func (e *Engine) PluginCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.plugins)
}

// PluginIDs returns the IDs of all loaded plugins.
func (e *Engine) PluginIDs() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	ids := make([]string, len(e.plugins))
	for i, p := range e.plugins {
		ids[i] = p.ID()
	}
	return ids
}

// Close releases the wazero runtime and all compiled modules.
func (e *Engine) Close(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, p := range e.plugins {
		if err := p.Close(ctx); err != nil {
			e.logger.Warn("error closing plugin", slog.String("id", p.ID()), slog.Any("error", err))
		}
	}
	e.plugins = nil
	pluginsLoaded.Set(0)
	return e.rt.Close(ctx)
}
