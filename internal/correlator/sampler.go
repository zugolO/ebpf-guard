// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// SamplingMode defines the per-rule sampling strategy.
type SamplingMode string

const (
	// SamplingModeRandom uses a uniform random draw per event.
	SamplingModeRandom SamplingMode = "random"
	// SamplingModeHashPID uses FNV(PID || timestamp>>30) for deterministic per-PID sampling.
	// The same PID is consistently sampled or skipped within ~1-second windows,
	// preventing alert storms from a single hot process.
	SamplingModeHashPID SamplingMode = "hash_pid"
)

// RuleSampling is the per-rule sampling block parsed from YAML.
//
//	sampling:
//	  rate: 0.1        # evaluate 10% of matching events
//	  mode: hash_pid   # "random" (default) or "hash_pid"
type RuleSampling struct {
	// Rate is the fraction of events to evaluate [0.0, 1.0].
	// Absent or 0 is treated as 1.0 (evaluate all events).
	Rate float64 `yaml:"rate"`
	// Mode is "random" (default) or "hash_pid".
	Mode SamplingMode `yaml:"mode"`
}

// ruleEntry holds the effective sampling configuration for one rule.
type ruleEntry struct {
	baseRate     float64      // configured rate from rule YAML
	adaptiveRate float64      // override set by AdaptiveSampler; 0 = no override
	mode         SamplingMode // sampling mode
}

// effective returns the rate that should be used for sampling decisions.
// It applies the adaptive override when it is stricter than the base rate.
func (e *ruleEntry) effective() float64 {
	if e.adaptiveRate > 0 && e.adaptiveRate < e.baseRate {
		return e.adaptiveRate
	}
	return e.baseRate
}

// RuleSampler manages per-rule sampling rates and evaluates sampling decisions.
// Rules with rate ≥ 1.0 are not stored; ShouldEvaluate returns true immediately.
// Thread-safe.
type RuleSampler struct {
	mu         sync.RWMutex
	entries    map[string]*ruleEntry // only rules with rate < 1.0 are stored
	entryCount atomic.Int32          // len(entries); read lock-free by matchesTyped
}

// NewRuleSampler creates a RuleSampler from the loaded rule set.
// Only rules with SampleRate in (0.0, 1.0) are tracked; all others cost zero overhead.
// SampleRate == 0 (Go zero value for rules not processed by validateRule) is treated
// the same as 1.0 — "evaluate all events".
func NewRuleSampler(rules []Rule) *RuleSampler {
	s := &RuleSampler{
		entries: make(map[string]*ruleEntry),
	}
	for _, r := range rules {
		// 0.0 is the Go zero value; treat it as "no sampling configured".
		// validateRule normalises 0 → 1.0, but tests may construct Rules directly.
		if r.SampleRate <= 0 || r.SampleRate >= 1.0 {
			continue
		}
		mode := SamplingModeRandom
		if r.SampleDeterministic {
			mode = SamplingModeHashPID
		}
		s.entries[r.ID] = &ruleEntry{
			baseRate: r.SampleRate,
			mode:     mode,
		}
	}
	s.entryCount.Store(int32(len(s.entries)))
	return s
}

// CheckSampling is a single-lock replacement for the HasSampling + Mode + ShouldEvaluate
// triple call that matchesTyped previously made. Returns active=false for rules not in
// entries (no sampling configured). When active=true, skip=true means the event should
// be dropped by the sampling gate; skip=false means it was sampled and should be evaluated.
// rateStr is the effective sample rate formatted as a string (e.g. "0.10") for metric labels.
func (s *RuleSampler) CheckSampling(ruleID string, pid uint32, ts uint64) (active, skip bool, mode, rateStr string) {
	s.mu.RLock()
	e, ok := s.entries[ruleID]
	if !ok {
		s.mu.RUnlock()
		return false, false, "", ""
	}
	rate := e.effective()
	det := e.mode == SamplingModeHashPID
	modeStr := string(e.mode)
	s.mu.RUnlock()

	if rate <= 0 || rate >= 1.0 {
		return false, false, "", ""
	}
	if shouldSample(pid, ts, rate, det) {
		return true, false, modeStr, fmtRate(rate) // sampled — evaluate the event
	}
	return true, true, modeStr, fmtRate(rate) // not sampled — drop the event
}

// ShouldEvaluate returns true if the event should be evaluated against the rule.
// For rules with effective rate ≥ 1.0 this is always true with zero map-lookup overhead.
// For rules with effective rate ≥ 1.0 this is always true with zero map-lookup overhead.
func (s *RuleSampler) ShouldEvaluate(ruleID string, pid uint32, ts uint64) bool {
	s.mu.RLock()
	e, ok := s.entries[ruleID]
	if !ok {
		s.mu.RUnlock()
		return true
	}
	rate := e.effective()
	det := e.mode == SamplingModeHashPID
	s.mu.RUnlock()

	if rate >= 1.0 {
		return true
	}
	return shouldSample(pid, ts, rate, det)
}

// HasSampling returns true if any sampling (static or adaptive) is active for the rule.
// Returns false when rate == 0 (treat as "evaluate all") or rate ≥ 1.0.
func (s *RuleSampler) HasSampling(ruleID string) bool {
	s.mu.RLock()
	e, ok := s.entries[ruleID]
	if !ok {
		s.mu.RUnlock()
		return false
	}
	rate := e.effective()
	s.mu.RUnlock()
	return rate > 0 && rate < 1.0
}

// Mode returns the sampling mode for a rule (defaults to SamplingModeRandom).
func (s *RuleSampler) Mode(ruleID string) SamplingMode {
	s.mu.RLock()
	e, ok := s.entries[ruleID]
	s.mu.RUnlock()
	if !ok || e.mode == "" {
		return SamplingModeRandom
	}
	return e.mode
}

// setAdaptiveRate overrides the effective rate for a rule from the adaptive sampler.
// Passing rate=0 clears the override (restores the base configured rate).
// Only rules already tracked (base rate < 1.0) or newly added via the override path are affected.
func (s *RuleSampler) setAdaptiveRate(ruleID string, rate float64) {
	s.mu.Lock()
	prev := len(s.entries)
	if e, ok := s.entries[ruleID]; ok {
		e.adaptiveRate = rate
	} else if rate > 0 && rate < 1.0 {
		// Rule had rate=1.0 at load time but adaptive sampler is reducing it.
		s.entries[ruleID] = &ruleEntry{
			baseRate:     1.0,
			adaptiveRate: rate,
			mode:         SamplingModeRandom,
		}
	}
	curr := len(s.entries)
	s.mu.Unlock()
	if curr != prev {
		s.entryCount.Store(int32(curr))
	}
}

// clearAdaptiveRate removes the adaptive override for a rule, restoring base rate behaviour.
// If the base rate was 1.0, the entry is deleted entirely.
func (s *RuleSampler) clearAdaptiveRate(ruleID string) {
	s.mu.Lock()
	prev := len(s.entries)
	if e, ok := s.entries[ruleID]; ok {
		e.adaptiveRate = 0
		if e.baseRate >= 1.0 {
			delete(s.entries, ruleID)
		}
	}
	curr := len(s.entries)
	s.mu.Unlock()
	if curr != prev {
		s.entryCount.Store(int32(curr))
	}
}

// fmtRate formats a float64 sample rate as a string suitable for Prometheus metric labels.
// Formats with up to 4 decimal places, trimming trailing zeros (e.g. 0.1 → "0.1", 1.0 → "1").
func fmtRate(rate float64) string {
	return strconv.FormatFloat(rate, 'f', -1, 64)
}

// AdaptiveSamplingConfig configures CPU-load-triggered adaptive sampling.
type AdaptiveSamplingConfig struct {
	// Enabled activates adaptive sampling. Default: false.
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
	// TriggerCPUPercent is the CPU utilization threshold [0, 100] that activates sampling.
	TriggerCPUPercent float64 `mapstructure:"trigger_cpu_percent" yaml:"trigger_cpu_percent"`
	// WarningSampleRate is applied to warning-severity rules when active (0–1).
	WarningSampleRate float64 `mapstructure:"warning_sample_rate" yaml:"warning_sample_rate"`
	// CriticalSampleRate is always forced to 1.0 — critical rules are never downsampled.
	CriticalSampleRate float64 `mapstructure:"critical_sample_rate" yaml:"critical_sample_rate"`
	// CheckInterval controls how often CPU utilization is sampled. Default: 5s.
	CheckInterval time.Duration `mapstructure:"check_interval" yaml:"check_interval"`
}

// DefaultAdaptiveSamplingConfig returns safe production defaults.
func DefaultAdaptiveSamplingConfig() AdaptiveSamplingConfig {
	return AdaptiveSamplingConfig{
		Enabled:            false,
		TriggerCPUPercent:  80.0,
		WarningSampleRate:  0.25,
		CriticalSampleRate: 1.0,
		CheckInterval:      5 * time.Second,
	}
}

// AdaptiveSampler monitors CPU utilization and adjusts effective sample rates on the
// attached RuleSampler. When CPU exceeds TriggerCPUPercent, warning-severity rules are
// downsampled to WarningSampleRate. Critical rules are never affected.
type AdaptiveSampler struct {
	cfg     AdaptiveSamplingConfig
	rules   []Rule // kept for severity lookup
	sampler *RuleSampler
	active  atomic.Bool
	stop    chan struct{}
	stopped chan struct{}
}

// NewAdaptiveSampler creates an AdaptiveSampler attached to the given RuleSampler.
// Call Start to begin background CPU monitoring.
func NewAdaptiveSampler(cfg AdaptiveSamplingConfig, rules []Rule, sampler *RuleSampler) *AdaptiveSampler {
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = 5 * time.Second
	}
	if cfg.CriticalSampleRate <= 0 {
		cfg.CriticalSampleRate = 1.0
	}
	if cfg.WarningSampleRate <= 0 {
		cfg.WarningSampleRate = 0.25
	}
	return &AdaptiveSampler{
		cfg:     cfg,
		rules:   rules,
		sampler: sampler,
		stop:    make(chan struct{}),
		stopped: make(chan struct{}),
	}
}

// Active returns true when adaptive sampling is currently engaged.
func (a *AdaptiveSampler) Active() bool { return a.active.Load() }

// Start launches the background CPU-monitoring goroutine.
// The goroutine exits when ctx is cancelled or Stop is called.
func (a *AdaptiveSampler) Start(ctx context.Context) {
	go a.run(ctx)
}

// Stop signals the monitoring goroutine to exit and waits for it to finish.
func (a *AdaptiveSampler) Stop() {
	close(a.stop)
	<-a.stopped
}

func (a *AdaptiveSampler) run(ctx context.Context) {
	defer close(a.stopped)
	tick := time.NewTicker(a.cfg.CheckInterval)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			a.check()
		case <-ctx.Done():
			return
		case <-a.stop:
			return
		}
	}
}

func (a *AdaptiveSampler) check() {
	// cpu.Percent with interval=0 returns the usage since the last call.
	pcts, err := cpu.Percent(0, false)
	if err != nil || len(pcts) == 0 {
		return
	}
	activate := pcts[0] >= a.cfg.TriggerCPUPercent
	if activate == a.active.Load() {
		return // no state change
	}
	a.active.Store(activate)
	for _, rule := range a.rules {
		// Critical rules are never downsampled.
		if rule.Severity == types.SeverityCritical {
			continue
		}
		if activate {
			a.sampler.setAdaptiveRate(rule.ID, a.cfg.WarningSampleRate)
		} else {
			a.sampler.clearAdaptiveRate(rule.ID)
		}
	}
}
