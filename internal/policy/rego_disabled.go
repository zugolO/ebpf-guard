//go:build !rego

// Package policy provides a stub Rego engine when the rego build tag is not set.
package policy

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// PolicyDecision represents the result of evaluating an alert against Rego policies.
type PolicyDecision struct {
	RuleID         string
	Severity       types.Severity
	Message        string
	Action         string
	MitreTechnique string
	Matched        bool
}

// RegoEngine is a stub that never evaluates; Rego/OPA support is not compiled in.
type RegoEngine struct {
	enabled     atomic.Bool
	evalTotal     atomic.Uint64
	reloadCounter atomic.Uint64
}

// DurationObserver is a callback that receives Evaluate latency measurements.
type DurationObserver func(time.Duration)

// RegoEngineConfig holds configuration for the Rego engine.
type RegoEngineConfig struct {
	Enabled  bool
	RulesDir string
}

// DefaultRegoEngineConfig returns a default configuration.
func DefaultRegoEngineConfig() RegoEngineConfig {
	return RegoEngineConfig{
		Enabled:  true,
		RulesDir: "rules/rego",
	}
}

// NewRegoEngine creates a stub Rego engine that does nothing.
// Rego policy evaluation requires building with -tags rego.
func NewRegoEngine(config RegoEngineConfig) (*RegoEngine, error) {
	engine := &RegoEngine{}
	engine.enabled.Store(config.Enabled)
	return engine, nil
}

// Evaluate is a no-op in the stub; it always returns nil decisions.
func (re *RegoEngine) Evaluate(_ context.Context, _ types.Alert) ([]PolicyDecision, error) {
	return nil, nil
}

// Reload is a no-op in the stub.
func (re *RegoEngine) Reload() error { return nil }

// ReloadWithContext is a no-op in the stub.
func (re *RegoEngine) ReloadWithContext(_ context.Context) error { return nil }

// SetDurationObserver is a no-op in the stub.
func (re *RegoEngine) SetDurationObserver(_ DurationObserver) {}

// SetEnabled enables or disables the Rego engine.
func (re *RegoEngine) SetEnabled(enabled bool) {
	re.enabled.Store(enabled)
}

// IsEnabled returns whether the Rego engine is enabled.
func (re *RegoEngine) IsEnabled() bool {
	return re.enabled.Load()
}

// GetStats returns engine statistics (all zeros in the stub).
func (re *RegoEngine) GetStats() RegoEngineStats {
	return RegoEngineStats{
		EvalTotal:     re.evalTotal.Load(),
		ReloadCounter: re.reloadCounter.Load(),
	}
}

// RegoEngineStats holds Rego engine statistics.
type RegoEngineStats struct {
	EvalTotal     uint64
	EvalErrors    uint64
	ReloadCounter uint64
	PolicyCount   int
}
