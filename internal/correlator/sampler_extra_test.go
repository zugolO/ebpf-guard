package correlator

import (
	"context"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdaptiveSampler_Lifecycle(t *testing.T) {
	rules := []Rule{
		{ID: "warn", Name: "w", Severity: types.SeverityWarning},
		{ID: "crit", Name: "c", Severity: types.SeverityCritical},
	}
	rs := NewRuleSampler(rules)

	cfg := DefaultAdaptiveSamplingConfig()
	cfg.Enabled = true
	cfg.TriggerCPUPercent = 0.0 // any CPU usage activates downsampling
	cfg.CheckInterval = 10 * time.Millisecond

	a := NewAdaptiveSampler(cfg, rules, rs)
	require.NotNil(t, a)
	assert.False(t, a.Active())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.Start(ctx)

	// With a 0% trigger the monitor should engage adaptive sampling promptly.
	require.Eventually(t, a.Active, time.Second, 5*time.Millisecond)

	a.Stop()
}

func TestNewAdaptiveSampler_Defaults(t *testing.T) {
	rs := NewRuleSampler(nil)
	// Zero-value config gets sensible defaults applied in the constructor.
	a := NewAdaptiveSampler(AdaptiveSamplingConfig{}, nil, rs)
	assert.False(t, a.Active())
}
