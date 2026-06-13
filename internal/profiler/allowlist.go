package profiler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// AllowlistMode controls the operating mode of the syscall allowlist profiler.
type AllowlistMode string

const (
	AllowlistModeLearning   AllowlistMode = "learning"
	AllowlistModeEnforcing  AllowlistMode = "enforcing"
)

// AllowlistAction is the action taken on a violation.
type AllowlistAction string

const (
	AllowlistActionAlert AllowlistAction = "alert"
	AllowlistActionBlock AllowlistAction = "block"
	AllowlistActionKill  AllowlistAction = "kill"
	// AllowlistActionAudit logs violations without generating alerts.
	// Useful for initial tuning before switching to enforcing mode.
	AllowlistActionAudit AllowlistAction = "audit"
)

// SyscallAllowlistConfig holds configuration for the syscall allowlist profiler.
type SyscallAllowlistConfig struct {
	// Enabled activates allowlist mode.
	Enabled bool `mapstructure:"enabled"`
	// Mode sets the initial operating mode ("learning" or "enforcing").
	// After LearningPeriod the profiler auto-switches to enforcing regardless.
	Mode string `mapstructure:"mode"`
	// EnforcingAction is the action triggered for unknown syscalls: "alert", "block", "kill", or "audit".
	EnforcingAction string `mapstructure:"enforcing_action"`
	// PerWorkload separates allowlists per (comm, namespace, app_label) tuple.
	// When false a single global allowlist is maintained.
	PerWorkload bool `mapstructure:"per_workload"`
	// LearningPeriod is the duration in seconds to record syscalls before enforcing.
	LearningPeriod int `mapstructure:"learning_period"`
	// MinSamples is the minimum number of unique syscall numbers the profiler
	// must observe before a profile is considered complete.
	MinSamples int `mapstructure:"min_samples"`
	// SparseThreshold is the minimum unique-syscall count required before a
	// profile is considered non-sparse. Profiles with fewer unique syscalls at
	// the end of the learning period generate a "sparse_profile" alert.
	SparseThreshold int `mapstructure:"sparse_threshold"`
	// GlobalAllow is a list of syscall numbers always permitted (never alerted).
	GlobalAllow []int `mapstructure:"global_allow"`
	// GlobalDeny is a list of syscall numbers always alerted regardless of learned profile.
	GlobalDeny []int `mapstructure:"global_deny"`
	// PersistPath is the file path for JSON state persistence across restarts.
	// Empty string disables persistence.
	PersistPath string `mapstructure:"persist_path"`
}

// DefaultSyscallAllowlistConfig returns safe defaults.
func DefaultSyscallAllowlistConfig() SyscallAllowlistConfig {
	return SyscallAllowlistConfig{
		Enabled:         false,
		Mode:            string(AllowlistModeLearning),
		EnforcingAction: string(AllowlistActionAlert),
		PerWorkload:     true,
		LearningPeriod:  3600,
		MinSamples:      100,
		SparseThreshold: 10,
	}
}

// WorkloadSyscallProfile holds the syscall allowlist learned for one workload.
type WorkloadSyscallProfile struct {
	// AllowedSyscalls is the set of unique syscall numbers observed during learning.
	AllowedSyscalls map[uint32]struct{} `json:"-"`
	// AllowedList is the JSON-serialisable form of AllowedSyscalls.
	AllowedList []uint32 `json:"allowed_syscalls"`
	// ImageRef identifies the container image (comm for non-K8s workloads).
	ImageRef  string    `json:"image_ref"`
	Namespace string    `json:"namespace"`
	AppLabel  string    `json:"app_label"`
	// LearnedAt is the time the learning phase completed.
	LearnedAt time.Time `json:"learned_at"`
	// SampleCount is the total number of syscall events seen during learning.
	SampleCount int `json:"sample_count"`
	// Enforcing is true once the learning period has expired.
	Enforcing bool `json:"enforcing"`
	// StartedAt records when this profile began learning.
	StartedAt time.Time `json:"started_at"`
}

func newWorkloadSyscallProfile(key WorkloadKey, now time.Time) *WorkloadSyscallProfile {
	return &WorkloadSyscallProfile{
		AllowedSyscalls: make(map[uint32]struct{}),
		ImageRef:        key.Comm,
		Namespace:       key.Namespace,
		AppLabel:        key.AppLabel,
		StartedAt:       now,
	}
}

// toJSON prepares the profile for serialisation.
func (p *WorkloadSyscallProfile) toJSON() {
	p.AllowedList = make([]uint32, 0, len(p.AllowedSyscalls))
	for nr := range p.AllowedSyscalls {
		p.AllowedList = append(p.AllowedList, nr)
	}
}

// fromJSON rebuilds AllowedSyscalls from the deserialised AllowedList.
func (p *WorkloadSyscallProfile) fromJSON() {
	p.AllowedSyscalls = make(map[uint32]struct{}, len(p.AllowedList))
	for _, nr := range p.AllowedList {
		p.AllowedSyscalls[nr] = struct{}{}
	}
}

// AllowlistViolation is returned by Check when an unknown syscall is detected.
type AllowlistViolation struct {
	WorkloadKey WorkloadKey
	SyscallNr   uint32
	// Source is "global_deny" when the syscall is in the explicit deny list,
	// "unknown" when it was never seen during learning.
	Source string
	Action AllowlistAction
}

// persistedState is the top-level JSON structure written to PersistPath.
type persistedState struct {
	Version  int                              `json:"version"`
	SavedAt  time.Time                        `json:"saved_at"`
	Profiles map[string]*WorkloadSyscallProfile `json:"profiles"`
}

// SyscallAllowlistProfiler records unique syscall sets per workload during a
// learning phase and then flags unknown syscalls during enforcing.
type SyscallAllowlistProfiler struct {
	config SyscallAllowlistConfig
	mu     sync.RWMutex
	// profiles is keyed by WorkloadKey.String().
	profiles    map[string]*WorkloadSyscallProfile
	globalAllow map[uint32]struct{}
	globalDeny  map[uint32]struct{}
	// violations is the Prometheus counter for allowlist violations.
	violations *prometheus.CounterVec
	// sparseProfiles counts profiles that finished learning with too few syscalls.
	sparseProfiles prometheus.Counter
	samplingRate   float64
	log            *slog.Logger
}

// NewSyscallAllowlistProfiler creates a new profiler with the given config.
func NewSyscallAllowlistProfiler(cfg SyscallAllowlistConfig, log *slog.Logger) *SyscallAllowlistProfiler {
	if log == nil {
		log = slog.Default()
	}
	p := &SyscallAllowlistProfiler{
		config:       cfg,
		profiles:     make(map[string]*WorkloadSyscallProfile),
		globalAllow:  toSet(cfg.GlobalAllow),
		globalDeny:   toSet(cfg.GlobalDeny),
		samplingRate: 1.0,
		log:          log,
		violations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpf_guard_allowlist_violations_total",
			Help: "Number of syscalls that violated the learned allowlist, by workload and syscall number.",
		}, []string{"workload", "syscall"}),
		sparseProfiles: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ebpf_guard_allowlist_sparse_profiles_total",
			Help: "Number of workload profiles that completed learning with fewer unique syscalls than the sparse threshold.",
		}),
	}
	return p
}

// NewSyscallAllowlistProfilerWithContext creates a profiler and starts a
// background goroutine that loads persisted state and periodically saves it.
func NewSyscallAllowlistProfilerWithContext(ctx context.Context, cfg SyscallAllowlistConfig, log *slog.Logger) *SyscallAllowlistProfiler {
	p := NewSyscallAllowlistProfiler(cfg, log)
	if cfg.PersistPath != "" {
		if err := p.loadState(cfg.PersistPath); err != nil {
			p.log.Warn("allowlist: failed to load persisted state, starting fresh", "err", err)
		}
	}
	go p.persistLoop(ctx)
	return p
}

// RegisterMetrics registers Prometheus metrics with reg.
func (p *SyscallAllowlistProfiler) RegisterMetrics(reg prometheus.Registerer) error {
	if err := reg.Register(p.violations); err != nil {
		return err
	}
	return reg.Register(p.sparseProfiles)
}

// Record observes a syscall event during the learning phase.
// It is safe to call concurrently.
func (p *SyscallAllowlistProfiler) Record(e types.Event) {
	if !p.config.Enabled || e.Type != types.EventSyscall || e.Syscall == nil {
		return
	}
	if p.samplingRate < 1.0 && rand.Float64() >= p.samplingRate {
		return
	}

	key := p.resolveKey(e)
	now := time.Now()

	p.mu.Lock()
	defer p.mu.Unlock()

	profile, ok := p.profiles[key.String()]
	if !ok {
		profile = newWorkloadSyscallProfile(key, now)
		p.profiles[key.String()] = profile
	}

	// Already enforcing — nothing to record.
	if profile.Enforcing {
		return
	}

	nr := uint32(e.Syscall.Nr)
	if _, skip := p.globalAllow[nr]; !skip {
		profile.AllowedSyscalls[nr] = struct{}{}
	}
	profile.SampleCount++

	// Check whether learning is complete.
	elapsed := now.Sub(profile.StartedAt)
	learningPeriod := time.Duration(p.config.LearningPeriod) * time.Second
	if elapsed >= learningPeriod && profile.SampleCount >= p.config.MinSamples {
		p.transitionToEnforcing(profile, now)
	}
}

// Check tests whether a syscall event violates the allowlist.
// Returns nil during the learning phase or when the syscall is permitted.
func (p *SyscallAllowlistProfiler) Check(e types.Event) *AllowlistViolation {
	if !p.config.Enabled || e.Type != types.EventSyscall || e.Syscall == nil {
		return nil
	}

	nr := uint32(e.Syscall.Nr)

	// Global allow always wins.
	if _, ok := p.globalAllow[nr]; ok {
		return nil
	}

	key := p.resolveKey(e)
	action := AllowlistAction(p.config.EnforcingAction)
	if action == "" {
		action = AllowlistActionAlert
	}

	// Global deny always fires regardless of learned profile.
	if _, ok := p.globalDeny[nr]; ok {
		p.recordViolationMetric(key, nr)
		return &AllowlistViolation{WorkloadKey: key, SyscallNr: nr, Source: "global_deny", Action: action}
	}

	p.mu.RLock()
	profile, ok := p.profiles[key.String()]
	p.mu.RUnlock()

	// Not enforcing yet — no violation.
	if !ok || !profile.Enforcing {
		return nil
	}

	if _, allowed := profile.AllowedSyscalls[nr]; allowed {
		return nil
	}

	p.recordViolationMetric(key, nr)
	return &AllowlistViolation{WorkloadKey: key, SyscallNr: nr, Source: "unknown", Action: action}
}

// SparseProfiles returns all profiles that finished learning with fewer
// unique syscalls than SparseThreshold, along with their workload key strings.
// Called after learning to generate "sparse profile" alerts.
func (p *SyscallAllowlistProfiler) SparseProfiles() []WorkloadSyscallProfile {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var result []WorkloadSyscallProfile
	for _, prof := range p.profiles {
		if prof.Enforcing && len(prof.AllowedSyscalls) < p.config.SparseThreshold {
			result = append(result, *prof)
		}
	}
	return result
}

// SetSamplingRate adjusts probabilistic sampling (0.0–1.0).
func (p *SyscallAllowlistProfiler) SetSamplingRate(rate float64) {
	if rate < 0 {
		rate = 0
	}
	if rate > 1 {
		rate = 1
	}
	p.mu.Lock()
	p.samplingRate = rate
	p.mu.Unlock()
}

// --- internal helpers ---

func (p *SyscallAllowlistProfiler) resolveKey(e types.Event) WorkloadKey {
	if p.config.PerWorkload {
		return WorkloadKeyFromEvent(e)
	}
	// Single global profile: use empty key.
	return WorkloadKey{}
}

func (p *SyscallAllowlistProfiler) transitionToEnforcing(profile *WorkloadSyscallProfile, now time.Time) {
	profile.Enforcing = true
	profile.LearnedAt = now
	if len(profile.AllowedSyscalls) < p.config.SparseThreshold {
		p.sparseProfiles.Add(1)
		p.log.Warn("allowlist: sparse profile completed learning",
			"workload", profile.ImageRef,
			"namespace", profile.Namespace,
			"unique_syscalls", len(profile.AllowedSyscalls),
			"threshold", p.config.SparseThreshold,
		)
	} else {
		p.log.Info("allowlist: profile switched to enforcing",
			"workload", profile.ImageRef,
			"namespace", profile.Namespace,
			"unique_syscalls", len(profile.AllowedSyscalls),
		)
	}
}

func (p *SyscallAllowlistProfiler) recordViolationMetric(key WorkloadKey, nr uint32) {
	workloadLabel := key.Comm
	if key.Namespace != "" {
		workloadLabel = key.Namespace + "/" + key.Comm
	}
	p.violations.WithLabelValues(workloadLabel, fmt.Sprintf("%d", nr)).Inc()
}

// persistLoop saves state to disk every 5 minutes when PersistPath is set.
func (p *SyscallAllowlistProfiler) persistLoop(ctx context.Context) {
	if p.config.PersistPath == "" {
		return
	}
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := p.SaveState(p.config.PersistPath); err != nil {
				p.log.Warn("allowlist: failed to persist state", "err", err)
			}
		case <-ctx.Done():
			// Final save on shutdown.
			if err := p.SaveState(p.config.PersistPath); err != nil {
				p.log.Warn("allowlist: failed to persist state on shutdown", "err", err)
			}
			return
		}
	}
}

// SaveState serialises all profiles to a JSON file at path.
func (p *SyscallAllowlistProfiler) SaveState(path string) error {
	p.mu.RLock()
	// Prepare serialisable copies.
	out := persistedState{
		Version:  1,
		SavedAt:  time.Now(),
		Profiles: make(map[string]*WorkloadSyscallProfile, len(p.profiles)),
	}
	for k, prof := range p.profiles {
		cp := *prof
		cp.toJSON()
		out.Profiles[k] = &cp
	}
	p.mu.RUnlock()

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("allowlist: marshal state: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return fmt.Errorf("allowlist: mkdir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("allowlist: write tmp: %w", err)
	}
	return os.Rename(tmp, path)
}

// loadState reads persisted profiles from path. Profiles already in enforcing
// mode are restored immediately; others resume the learning phase.
func (p *SyscallAllowlistProfiler) loadState(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("allowlist: read state: %w", err)
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("allowlist: unmarshal state: %w", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, prof := range state.Profiles {
		prof.fromJSON()
		p.profiles[k] = prof
	}
	p.log.Info("allowlist: loaded persisted state", "profiles", len(state.Profiles), "saved_at", state.SavedAt)
	return nil
}

// toSet converts a slice of int syscall numbers into a lookup map.
func toSet(nrs []int) map[uint32]struct{} {
	m := make(map[uint32]struct{}, len(nrs))
	for _, n := range nrs {
		if n >= 0 {
			m[uint32(n)] = struct{}{}
		}
	}
	return m
}
