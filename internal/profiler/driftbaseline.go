package profiler

import (
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/zugolO/ebpf-guard/internal/util"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// DriftBaselineConfig configures the drift/FIM observe-mode profiler.
//
// Rules tagged `class: drift` (container/library/config drift, FIM-style
// monitoring — as opposed to `class: threat`, a genuine attack signature)
// are noisy on a live system: legitimate systemd/ldconfig/package-manager
// activity matches the same conditions as real container escapes. Rather
// than alerting on every match, the profiler spends a learning window
// building a per-workload baseline of the (rule, target) signatures it
// observes, then only alerts on signatures that were NOT seen during
// learning — i.e. genuine deviation from this host's own normal behavior.
type DriftBaselineConfig struct {
	// Enabled activates drift-class alert suppression. When false, rules
	// with class: drift alert exactly as class: threat rules do (no change
	// in behavior from before this profiler existed).
	Enabled bool `mapstructure:"enabled"`
	// LearningPeriod is the duration to observe drift-class matches before a
	// workload's baseline is considered complete, in seconds.
	LearningPeriod int `mapstructure:"learning_period"`
	// MinSamples is the minimum number of drift-class matches that must be
	// observed for a workload before its baseline can complete, in addition
	// to LearningPeriod elapsing.
	MinSamples int `mapstructure:"min_samples"`
	// PerWorkload separates baselines per (comm, namespace, app_label) tuple.
	// When false a single global baseline is maintained across all workloads.
	PerWorkload bool `mapstructure:"per_workload"`
}

// DefaultDriftBaselineConfig returns safe defaults. Disabled by default so
// installing a `class: drift`-tagged rule set never changes alert volume
// until an operator opts in.
func DefaultDriftBaselineConfig() DriftBaselineConfig {
	return DriftBaselineConfig{
		Enabled:        false,
		LearningPeriod: 3600,
		MinSamples:     20,
		PerWorkload:    true,
	}
}

// driftWorkloadProfile holds the drift-signature baseline learned for one workload.
type driftWorkloadProfile struct {
	// signatures is the set of (rule_id, normalized target) pairs observed
	// during the learning window.
	signatures  map[string]struct{}
	startedAt   time.Time
	sampleCount int
	enforcing   bool
}

// DriftBaselineProfiler learns, per workload, which drift-class rule matches
// are normal for this host during a learning window, then flags only the
// signatures that were never observed during learning as anomalies.
type DriftBaselineProfiler struct {
	config DriftBaselineConfig
	mu     sync.RWMutex
	// profiles is keyed by WorkloadKey.String().
	profiles map[string]*driftWorkloadProfile

	suppressedTotal *prometheus.CounterVec
	anomaliesTotal  *prometheus.CounterVec
	learningGauge   prometheus.Gauge
	log             *slog.Logger
}

// NewDriftBaselineProfiler creates a new profiler with the given config.
func NewDriftBaselineProfiler(cfg DriftBaselineConfig, log *slog.Logger) *DriftBaselineProfiler {
	if log == nil {
		log = slog.Default()
	}
	return &DriftBaselineProfiler{
		config:   cfg,
		profiles: make(map[string]*driftWorkloadProfile),
		log:      log,
		suppressedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpf_guard_drift_baseline_suppressed_total",
			Help: "Drift-class rule matches suppressed because they were still learning or matched the workload's known baseline.",
		}, []string{"rule_id", "reason"}),
		anomaliesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpf_guard_drift_baseline_anomalies_total",
			Help: "Drift-class rule matches that deviated from the learned baseline and were allowed through as alerts.",
		}, []string{"rule_id"}),
		learningGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpf_guard_drift_baseline_learning_workloads",
			Help: "Number of workloads currently in the drift-baseline learning phase.",
		}),
	}
}

// RegisterMetrics registers Prometheus metrics with reg.
func (p *DriftBaselineProfiler) RegisterMetrics(reg prometheus.Registerer) error {
	for _, c := range []prometheus.Collector{p.suppressedTotal, p.anomaliesTotal, p.learningGauge} {
		if err := reg.Register(c); err != nil {
			return err
		}
	}
	return nil
}

// Observe records a drift-class rule match and reports whether it should be
// emitted as an alert. Returns true when the profiler is disabled (fail-open
// to unchanged behavior), when the workload's baseline learning has just
// completed and the signature is genuinely novel, or immediately whenever
// the given ruleID's signature was never observed during learning.
//
// Returns false while the workload is still learning, or when the signature
// matches a baseline entry learned for this workload — both are treated as
// "normal for this host" and suppressed rather than alerted.
func (p *DriftBaselineProfiler) Observe(ruleID string, e types.Event) bool {
	if !p.config.Enabled {
		return true
	}

	sig := ruleID + "|" + driftSignatureTarget(e)
	key := p.resolveKey(e)
	now := time.Now()

	p.mu.Lock()
	defer p.mu.Unlock()

	prof, ok := p.profiles[key.String()]
	if !ok {
		prof = &driftWorkloadProfile{
			signatures: make(map[string]struct{}),
			startedAt:  now,
		}
		p.profiles[key.String()] = prof
	}

	if !prof.enforcing {
		prof.signatures[sig] = struct{}{}
		prof.sampleCount++

		learningPeriod := time.Duration(p.config.LearningPeriod) * time.Second
		if now.Sub(prof.startedAt) >= learningPeriod && prof.sampleCount >= p.config.MinSamples {
			prof.enforcing = true
			p.log.Info("drift-baseline: workload baseline learned, switching to enforcing",
				"workload", key.Comm, "namespace", key.Namespace, "unique_signatures", len(prof.signatures))
		}

		p.suppressedTotal.WithLabelValues(ruleID, "learning").Inc()
		return false
	}

	if _, known := prof.signatures[sig]; known {
		p.suppressedTotal.WithLabelValues(ruleID, "baseline_known").Inc()
		return false
	}

	p.anomaliesTotal.WithLabelValues(ruleID).Inc()
	return true
}

// LearningWorkloads returns the number of workloads still in the learning
// phase. Exposed for the learning-progress gauge.
func (p *DriftBaselineProfiler) LearningWorkloads() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	n := 0
	for _, prof := range p.profiles {
		if !prof.enforcing {
			n++
		}
	}
	return n
}

// UpdateLearningGauge refreshes the learning-progress gauge. Intended to be
// called periodically (e.g. by the same background loop that persists other
// profiler state).
func (p *DriftBaselineProfiler) UpdateLearningGauge() {
	p.learningGauge.Set(float64(p.LearningWorkloads()))
}

func (p *DriftBaselineProfiler) resolveKey(e types.Event) WorkloadKey {
	if p.config.PerWorkload {
		return WorkloadKeyFromEvent(e)
	}
	return WorkloadKey{}
}

// driftSignatureTarget extracts a normalized, PID/inode-independent
// description of what a drift-class rule matched, so that repeated matches
// against the same class of target (e.g. any file under /etc, any
// connection to the same port) collapse into a single baseline signature.
//nolint:exhaustive // only file/network/syscall events are meaningful drift-class targets; other event types fall through to the zero-value signature.
func driftSignatureTarget(e types.Event) string {
	switch e.Type {
	case types.EventFileAccess:
		if e.File != nil {
			path := e.File.FDPath
			if path == "" {
				path = util.BytesToString(e.File.Filename[:])
			}
			return normalizeDriftPathPrefix(path)
		}
	case types.EventTCPConnect:
		if e.Network != nil {
			return strconv.Itoa(int(e.Network.Dport))
		}
	case types.EventSyscall:
		if e.Syscall != nil {
			return strconv.Itoa(int(e.Syscall.Nr))
		}
	}
	return ""
}

// driftPathPrefixMaxDepth bounds how many path segments contribute to the
// signature, matching the aggregator's path-prefix collapsing (issue #285)
// so drift-class targets are grouped as coarsely as duplicate alerts are.
const driftPathPrefixMaxDepth = 2

// normalizeDriftPathPrefix reduces a file path to a short, PID/inode-independent
// prefix (e.g. "/proc/12345/mem" -> "/proc/*") so numeric path components and
// deep subpaths under the same directory collapse to one baseline signature.
func normalizeDriftPathPrefix(path string) string {
	if path == "" {
		return ""
	}
	kept := make([]string, 0, driftPathPrefixMaxDepth)
	start := 0
	for i := 0; i <= len(path); i++ {
		if i == len(path) || path[i] == '/' {
			if i > start {
				seg := path[start:i]
				if isNumericSegment(seg) {
					seg = "*"
				}
				kept = append(kept, seg)
				if len(kept) >= driftPathPrefixMaxDepth {
					break
				}
			}
			start = i + 1
		}
	}
	out := "/"
	for i, s := range kept {
		if i > 0 {
			out += "/"
		}
		out += s
	}
	return out
}

// isNumericSegment reports whether s consists entirely of ASCII digits (non-empty).
func isNumericSegment(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
