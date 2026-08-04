// cpu.go — CPU pressure auto-tuning for ebpf-guard
//
// Monitors the agent's own CPU usage and adaptively sheds the least critical
// but noisiest event sources when CPU consistently exceeds a configured limit.
// It is the CPU-side analogue of MemoryPressureWatcher (memory.go): where the
// memory watcher disables profilers on low available RAM, this watcher cuts
// BPF-side sampling of noisy collectors (file first, then syscall/network) when
// the agent burns too much CPU, and restores them after the spike subsides.

package watchdog

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// CPU pressure levels. Higher levels shed progressively more collectors.
const (
	cpuLevelNormal   = 0 // all collectors at full sampling
	cpuLevelFileShed = 1 // file sampling reduced (noisiest source)
	cpuLevelAllShed  = 2 // file + syscall + network sampling reduced
)

// clockTicksPerSecond is the conventional USER_HZ on Linux. /proc/self/stat
// reports CPU time in clock ticks; without cgo we assume the near-universal
// value of 100. Overridable in tests via the injected cpuTimeFn.
const clockTicksPerSecond = 100.0

// shedSamplingRate is the reduced sampling rate applied to a collector when it
// is shed under CPU pressure (1 event in 10).
const shedSamplingRate = 0.1

// CPUPressureWatcher monitors the agent's own CPU usage and reduces BPF-side
// sampling of noisy collectors when CPU exceeds configured thresholds.
type CPUPressureWatcher struct {
	logger        *slog.Logger
	bpfController BPFSamplingController

	// Thresholds, expressed as a percentage of a single CPU core (0–100 ==
	// idle..one core fully busy; can exceed 100 if the agent burns more than
	// one core). This is an absolute budget, not normalized by core count, so
	// the same defaults behave the same way on a 1-core VPS and an 8-core
	// box: one busy thread trips the same threshold either way.
	fileShedThreshold float64 // L1: cut file sampling above this
	allShedThreshold  float64 // L2: also cut syscall/network above this
	recoveryThreshold float64 // hysteresis: recover one level when below this

	checkInterval time.Duration
	windowSize    int
	numCPU        int // informational only (logged at startup); not used to scale thresholds

	// minDwell is the minimum time a shed level must be held before the
	// watcher will step back down, even if the smoothed CPU% has already
	// dropped below recoveryThreshold. This prevents the state machine from
	// flapping when load arrives in bursts shorter than the smoothing
	// window: without a dwell floor, a lull between bursts recovers
	// sampling just before the next burst re-trips it, and the agent loses
	// visibility exactly when it matters most.
	minDwell time.Duration

	// Injectable for tests. cpuTimeFn returns cumulative process CPU seconds
	// (utime+stime); nowFn returns the current wall-clock time.
	cpuTimeFn func() (float64, error)
	nowFn     func() time.Time

	// State (guarded by mu).
	mu             sync.RWMutex
	state          int
	window         []float64 // sliding window of recent CPU% samples
	lastCPU        float64   // previous cumulative CPU seconds
	lastWall       time.Time // previous sample wall-clock time
	haveLast       bool
	enteredStateAt time.Time          // when the current state was entered
	normalRates    map[string]float64 // saved sampling rates before shedding

	// Transition-log deduplication: a burst of transitions in quick
	// succession — whether repeated same-kind shedding or flapping back and
	// forth between reduce and recover — collapses into a single summary
	// line with per-kind counts, instead of one WARN/INFO per transition.
	// See logTransition for the flush conditions.
	transitionRunActive bool      // a run is currently open
	transitionRunStart  time.Time // when the current run started
	lastTransitionAt    time.Time // wall time of the most recent transition
	reduceCount         int       // reduce transitions seen in the current run
	recoverCount        int       // recover transitions seen in the current run
	// pendingTransition* mirror the message/values of the first transition
	// in the current run, reused when flushing its summary.
	pendingTransitionKind      string
	pendingTransitionMsg       string
	pendingTransitionPct       float64
	pendingTransitionThreshold float64

	// degradedSince records when the watcher most recently entered a
	// degraded (shed) state; zero value means currently normal. Combined
	// with degradedSeconds this tracks the fraction of time spent shedding
	// (see P1-18a acceptance criterion / degradedFraction).
	degradedSince   time.Time
	degradedSeconds float64 // accumulated seconds spent in any shed state
	trackingSince   time.Time

	// Metrics.
	pressureLevel    prometheus.Gauge
	pressurePercent  prometheus.Gauge
	degradedFraction prometheus.Gauge
}

// CPUConfig holds configuration for CPU pressure handling.
type CPUConfig struct {
	Enabled       bool          `mapstructure:"enabled"`
	CheckInterval time.Duration `mapstructure:"check_interval"`
	// CPULimitPercent is the target CPU budget, expressed as a percentage of
	// a single core (100 == one full core, independent of how many cores the
	// host has). It seeds the level thresholds when those are left at zero.
	CPULimitPercent float64 `mapstructure:"cpu_limit_percent"`
	// FileShedThreshold (L1): CPU% (of one core) above which file sampling is
	// reduced.
	FileShedThreshold float64 `mapstructure:"file_shed_threshold"`
	// AllShedThreshold (L2): CPU% (of one core) above which syscall/network
	// are also reduced.
	AllShedThreshold float64 `mapstructure:"all_shed_threshold"`
	// RecoveryThreshold: CPU% (of one core) below which the watcher steps
	// back one level.
	RecoveryThreshold float64 `mapstructure:"recovery_threshold"`
	// WindowSize is the number of samples averaged into the sliding window.
	WindowSize int `mapstructure:"window_size"`
	// MinDwell is the minimum time a shed level is held before the watcher
	// will step back down, even once the smoothed CPU% is back under
	// RecoveryThreshold. Guards against bursty attack traffic flapping the
	// state machine faster than the smoothing window can absorb.
	MinDwell time.Duration `mapstructure:"min_dwell"`
}

// DefaultCPUConfig returns safe defaults: shed file collectors above 40% of
// one core, add syscall/network above 70%, recover below 20%, smoothed over
// 6 samples (30s at the default 5s check interval), and held for at least
// 3 minutes before recovering a level. These are absolute per-core
// percentages, so they behave identically on a 1-core VPS and an 8-core
// host.
//
// MinDwell of 3 minutes (not the previous 30s) breaks a feedback loop
// observed on idle hosts: shedding file sampling to 10% is itself what drops
// CPU from ~50% to ~1%, so a short dwell just recovers full sampling,
// re-trips the threshold, and repeats — 813 reduce/recover cycles in one
// 9-hour idle run, one every ~40s (see P1-18a / ISSUES-attack-run.md). The
// dwell floor must be well above the time it takes shed-then-recovered load
// to climb back to the trip threshold, not just above the check interval.
func DefaultCPUConfig() CPUConfig {
	return CPUConfig{
		Enabled:           true,
		CheckInterval:     5 * time.Second,
		CPULimitPercent:   40.0,
		FileShedThreshold: 40.0,
		AllShedThreshold:  70.0,
		RecoveryThreshold: 20.0,
		WindowSize:        6,
		MinDwell:          3 * time.Minute,
	}
}

// NewCPUPressureWatcher creates a CPU pressure watcher. The bpfController is the
// existing SamplingController used to reduce per-collector sampling; it may be
// nil (the watcher then only tracks state and exposes metrics).
func NewCPUPressureWatcher(config CPUConfig, logger *slog.Logger, bpfController BPFSamplingController) *CPUPressureWatcher {
	if logger == nil {
		logger = slog.Default()
	}
	if config.CheckInterval <= 0 {
		config.CheckInterval = 5 * time.Second
	}
	if config.WindowSize <= 0 {
		config.WindowSize = 6
	}
	if config.MinDwell <= 0 {
		config.MinDwell = 3 * time.Minute
	}
	// Seed thresholds from CPULimitPercent when not set explicitly.
	if config.CPULimitPercent <= 0 {
		config.CPULimitPercent = 40.0
	}
	if config.FileShedThreshold <= 0 {
		config.FileShedThreshold = config.CPULimitPercent
	}
	if config.AllShedThreshold <= 0 {
		config.AllShedThreshold = config.FileShedThreshold * 7.0 / 4.0
	}
	if config.RecoveryThreshold <= 0 {
		config.RecoveryThreshold = config.FileShedThreshold * 0.5
	}

	numCPU := runtime.NumCPU()
	if numCPU < 1 {
		numCPU = 1
	}

	w := &CPUPressureWatcher{
		logger:            logger,
		bpfController:     bpfController,
		fileShedThreshold: config.FileShedThreshold,
		allShedThreshold:  config.AllShedThreshold,
		recoveryThreshold: config.RecoveryThreshold,
		checkInterval:     config.CheckInterval,
		windowSize:        config.WindowSize,
		minDwell:          config.MinDwell,
		numCPU:            numCPU,
		cpuTimeFn:         readProcSelfCPUSeconds,
		nowFn:             time.Now,
		normalRates:       make(map[string]float64),
		pressureLevel: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpf_guard_cpu_pressure_level",
			Help: "CPU pressure level: 0=normal, 1=file_sampling_reduced, 2=all_noisy_sampling_reduced",
		}),
		pressurePercent: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpf_guard_cpu_pressure_percent",
			Help: "Smoothed agent CPU usage as a percentage of a single CPU core (0-100 == idle..one core fully busy; not normalized by core count).",
		}),
		degradedFraction: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpf_guard_cpu_degraded_fraction",
			Help: "Fraction (0-1) of tracked watcher lifetime spent with sampling reduced (any shed level above normal). Lets an operator tell how much visibility was actually lost, rather than inferring it from log-grepping reduce/recover pairs.",
		}),
	}
	w.pressureLevel.Set(cpuLevelNormal)
	return w
}

// RegisterMetrics registers Prometheus metrics.
func (w *CPUPressureWatcher) RegisterMetrics(reg prometheus.Registerer) error {
	for _, c := range []prometheus.Collector{w.pressureLevel, w.pressurePercent, w.degradedFraction} {
		if err := reg.Register(c); err != nil {
			return err
		}
	}
	return nil
}

// SetupCPUPressureWatcher constructs a CPU pressure watcher from cfg, registers
// its Prometheus metrics on reg, and starts it on ctx in a background
// goroutine. It returns nil when cfg.Enabled is false. A metric-registration
// error is logged rather than returned so a duplicate registration cannot abort
// agent startup. Wiring lives here (rather than in package main) so it is
// unit-testable without a live eBPF kernel.
func SetupCPUPressureWatcher(
	ctx context.Context,
	cfg CPUConfig,
	logger *slog.Logger,
	mux BPFSamplingController,
	reg prometheus.Registerer,
) *CPUPressureWatcher {
	if !cfg.Enabled {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	w := NewCPUPressureWatcher(cfg, logger, mux)
	if reg != nil {
		if err := w.RegisterMetrics(reg); err != nil {
			logger.Warn("cpu pressure: failed to register metrics", slog.Any("error", err))
		}
	}
	go w.Start(ctx)
	logger.Info("cpu pressure: adaptive load shedding enabled",
		slog.Int("num_cpu", w.numCPU),
		slog.Float64("file_shed_threshold_pct_of_one_core", w.fileShedThreshold),
		slog.Float64("all_shed_threshold_pct_of_one_core", w.allShedThreshold),
		slog.Float64("recovery_threshold_pct_of_one_core", w.recoveryThreshold),
		slog.Duration("min_dwell", w.minDwell))
	return w
}

// Start begins monitoring CPU pressure until the context is cancelled.
func (w *CPUPressureWatcher) Start(ctx context.Context) {
	ticker := time.NewTicker(w.checkInterval)
	defer ticker.Stop()

	// Prime the sampler so the first real tick has a delta to work with.
	w.checkCPU()

	for {
		select {
		case <-ctx.Done():
			// Flush any collapsed-repeats run still pending so its summary
			// isn't silently lost on shutdown.
			w.mu.Lock()
			w.flushTransitionRun()
			w.mu.Unlock()
			w.logger.Info("cpu pressure watcher stopped")
			return
		case <-ticker.C:
			w.checkCPU()
		}
	}
}

// checkCPU samples CPU usage, updates the sliding window, and drives the state
// machine. The first call only primes the baseline and returns.
func (w *CPUPressureWatcher) checkCPU() {
	cpuSeconds, err := w.cpuTimeFn()
	if err != nil {
		w.logger.Error("cpu pressure: failed to read CPU time", slog.Any("error", err))
		return
	}
	now := w.nowFn()

	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.haveLast {
		w.lastCPU = cpuSeconds
		w.lastWall = now
		w.haveLast = true
		w.enteredStateAt = now
		w.trackingSince = now
		return
	}

	wallDelta := now.Sub(w.lastWall).Seconds()
	cpuDelta := cpuSeconds - w.lastCPU
	w.lastCPU = cpuSeconds
	w.lastWall = now
	if wallDelta <= 0 {
		return
	}
	if cpuDelta < 0 {
		cpuDelta = 0
	}

	// Attribute the elapsed interval to whatever state was in effect for
	// (most of) it, before evaluate() may transition to a new one — the
	// degraded-time accounting is about how long sampling was actually
	// reduced, not about the state as of this instant.
	if w.state != cpuLevelNormal {
		w.degradedSeconds += wallDelta
	}
	w.updateDegradedFraction(now)

	// Percentage of a single CPU core: busy seconds over wall-clock seconds.
	// Deliberately NOT normalized by numCPU — an absolute per-core budget
	// means the same threshold means the same thing (e.g. "0.4 of a core")
	// on a 1-core VPS and an 8-core box, instead of scaling the trip point
	// with unrelated hardware capacity.
	pct := (cpuDelta / wallDelta) * 100.0
	avg := w.pushWindow(pct)
	w.pressurePercent.Set(avg)

	w.evaluate(avg, now)

	// A run that goes quiet (no further transition) would otherwise sit
	// unflushed until the next transition or shutdown — potentially
	// indefinitely on a host that settles down. Flush it once the gap has
	// elapsed so its summary still appears promptly instead of only in the
	// final shutdown flush.
	if w.transitionRunActive && now.Sub(w.lastTransitionAt) >= transitionLogGap {
		w.flushTransitionRun()
	}
}

// updateDegradedFraction recomputes and publishes the fraction of tracked
// lifetime spent in a degraded (shed) state. Must be called with mu held.
func (w *CPUPressureWatcher) updateDegradedFraction(now time.Time) {
	total := now.Sub(w.trackingSince).Seconds()
	if total <= 0 {
		w.degradedFraction.Set(0)
		return
	}
	w.degradedFraction.Set(w.degradedSeconds / total)
}

// pushWindow appends a sample to the sliding window and returns its mean.
func (w *CPUPressureWatcher) pushWindow(pct float64) float64 {
	w.window = append(w.window, pct)
	if len(w.window) > w.windowSize {
		w.window = w.window[len(w.window)-w.windowSize:]
	}
	var sum float64
	for _, v := range w.window {
		sum += v
	}
	return sum / float64(len(w.window))
}

// evaluate transitions between pressure levels based on the smoothed CPU%.
// Recovery uses the (lower) recoveryThreshold for hysteresis so the watcher
// does not flap around a single threshold, and additionally requires the
// current level to have been held for at least minDwell: attack traffic
// arrives in bursts shorter than the smoothing window, and without a dwell
// floor a lull between bursts recovers sampling just before the next burst
// re-trips it — the agent loses visibility exactly when it matters most.
// Escalation is never gated by dwell time so the watcher still reacts
// immediately to genuine, sustained pressure.
func (w *CPUPressureWatcher) evaluate(cpuPct float64, now time.Time) {
	dwelled := now.Sub(w.enteredStateAt) >= w.minDwell

	switch w.state {
	case cpuLevelNormal:
		if cpuPct >= w.allShedThreshold {
			w.logTransition("reduce", "cpu pressure: reducing file, syscall and network sampling", cpuPct, w.allShedThreshold, now)
			w.enterFileShedMode()
			w.enterAllShedMode()
			w.setState(cpuLevelAllShed, now)
		} else if cpuPct >= w.fileShedThreshold {
			w.logTransition("reduce", "cpu pressure: reducing file sampling", cpuPct, w.fileShedThreshold, now)
			w.enterFileShedMode()
			w.setState(cpuLevelFileShed, now)
		}

	case cpuLevelFileShed:
		if cpuPct >= w.allShedThreshold {
			w.logTransition("reduce", "cpu pressure: escalating — reducing syscall and network sampling", cpuPct, w.allShedThreshold, now)
			w.enterAllShedMode()
			w.setState(cpuLevelAllShed, now)
		} else if cpuPct < w.recoveryThreshold && dwelled {
			w.logTransition("recover", "cpu pressure: recovered — restoring file sampling", cpuPct, w.recoveryThreshold, now)
			w.recoverNormalMode()
			w.setState(cpuLevelNormal, now)
		}

	case cpuLevelAllShed:
		if cpuPct < w.recoveryThreshold && dwelled {
			w.logTransition("recover", "cpu pressure: recovered — restoring all sampling", cpuPct, w.recoveryThreshold, now)
			w.recoverNormalMode()
			w.setState(cpuLevelNormal, now)
		}
	}
}

// transitionLogGap is how long a gap since the last transition (of either
// kind) ends the current run and lets the next transition log immediately
// again (rather than being folded into a stale run from long ago).
const transitionLogGap = 5 * time.Minute

// logTransition records a state transition, logging the first transition of
// a new run immediately for operator visibility, and silently counting every
// subsequent transition within transitionLogGap — regardless of kind —
// instead of logging each one. This deliberately collapses flapping
// (alternating reduce/recover), not just repeated same-kind transitions:
// real-world flapping alternates by construction (shed lowers CPU, which
// triggers recovery, which raises CPU again), so a same-kind-only rule would
// never actually collapse it. The accumulated run is flushed as a single
// summary line with per-kind counts once it ends — see flushTransitionRun.
// Must be called with mu held.
//
// Before this, a flapping watcher (813 reduce/recover cycles across one
// 9-hour idle run, one every ~40s) produced 1626 nearly-identical log lines
// — 99% of the night's log — burying anything else an operator needed to
// see and devaluing WARN as a signal.
func (w *CPUPressureWatcher) logTransition(kind, msg string, cpuPct, threshold float64, now time.Time) {
	sameRun := w.transitionRunActive && now.Sub(w.lastTransitionAt) < transitionLogGap
	if sameRun {
		// Within an active run: count silently by kind, don't re-log.
		if kind == "reduce" {
			w.reduceCount++
		} else {
			w.recoverCount++
		}
		w.lastTransitionAt = now
		return
	}

	// A stale/absent run: flush whatever was pending first (in case it was
	// merely idle past the gap, not yet flushed), then start a new run with
	// this transition logged immediately.
	w.flushTransitionRun()

	w.transitionRunActive = true
	w.transitionRunStart = now
	w.lastTransitionAt = now
	if kind == "reduce" {
		w.reduceCount = 1
		w.recoverCount = 0
	} else {
		w.reduceCount = 0
		w.recoverCount = 1
	}
	w.pendingTransitionKind = kind
	w.pendingTransitionMsg = msg
	w.pendingTransitionPct = cpuPct
	w.pendingTransitionThreshold = threshold

	w.emitTransitionLog(kind, msg, cpuPct, threshold, 0, 0, 0)
}

// flushTransitionRun emits a summary line for an in-progress run when it
// contained more than the one transition already logged by logTransition,
// and clears run-tracking state. A no-op if there is no active run or it
// never grew beyond its first transition. Must be called with mu held.
func (w *CPUPressureWatcher) flushTransitionRun() {
	if !w.transitionRunActive {
		return
	}
	total := w.reduceCount + w.recoverCount
	if total > 1 {
		w.emitTransitionLog(w.pendingTransitionKind, w.pendingTransitionMsg+" (collapsed repeats)",
			w.pendingTransitionPct, w.pendingTransitionThreshold,
			w.reduceCount, w.recoverCount, w.lastTransitionAt.Sub(w.transitionRunStart))
	}
	w.transitionRunActive = false
	w.reduceCount = 0
	w.recoverCount = 0
}

// emitTransitionLog writes one log line for a transition or a collapsed-run
// summary. reduceCount and recoverCount are both 0 for a single, uncollapsed
// transition (no repeat/duration fields added); a collapsed-run summary
// passes the per-kind counts accumulated over the run.
func (w *CPUPressureWatcher) emitTransitionLog(kind, msg string, cpuPct, threshold float64, reduceCount, recoverCount int, runDuration time.Duration) {
	attrs := []any{
		slog.String("cpu_pct", fmt.Sprintf("%.1f%%", cpuPct)),
		slog.String("threshold", fmt.Sprintf("%.1f%%", threshold)),
	}
	if reduceCount+recoverCount > 0 {
		attrs = append(attrs,
			slog.Int("repeat_count", reduceCount+recoverCount),
			slog.Int("reduce_count", reduceCount),
			slog.Int("recover_count", recoverCount),
			slog.Duration("run_duration", runDuration))
	}
	if kind == "recover" {
		w.logger.Info(msg, attrs...)
	} else {
		w.logger.Warn(msg, attrs...)
	}
}

// setState updates the state, records when it was entered (for dwell-time
// gating), and syncs the exported level gauge.
func (w *CPUPressureWatcher) setState(s int, now time.Time) {
	w.state = s
	w.enteredStateAt = now
	w.pressureLevel.Set(float64(s))
}

// enterFileShedMode reduces file sampling (L1).
func (w *CPUPressureWatcher) enterFileShedMode() {
	w.shed("file")
}

// enterAllShedMode reduces syscall and network sampling (L2).
//
// Deliberately does not touch "lsm" or any exec/canary event type: those are
// the highest-value sources for detecting the exact class of attack (privesc,
// container escape) that also tends to spike CPU, so this watcher never
// trades them away regardless of pressure level. Even L2 costs CPU budget
// rather than detection coverage on the hooks that matter most.
func (w *CPUPressureWatcher) enterAllShedMode() {
	w.shed("syscall")
	w.shed("network")
}

// shed reduces the sampling rate of one collector, remembering nothing beyond
// the fact that it has been shed (recovery restores to full rate).
func (w *CPUPressureWatcher) shed(eventType string) {
	if w.bpfController == nil {
		return
	}
	if _, already := w.normalRates[eventType]; already {
		return
	}
	w.normalRates[eventType] = 1.0
	w.bpfController.SetSamplingRate(eventType, shedSamplingRate)
}

// recoverNormalMode restores every shed collector to full sampling.
func (w *CPUPressureWatcher) recoverNormalMode() {
	if w.bpfController != nil {
		for eventType, rate := range w.normalRates {
			w.bpfController.SetSamplingRate(eventType, rate)
		}
	}
	w.normalRates = make(map[string]float64)
}

// PressureLevel returns the current CPU pressure level (0=normal, 1=file shed,
// 2=all noisy collectors shed).
func (w *CPUPressureWatcher) PressureLevel() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.state
}

// IsThrottling reports whether any collector is currently shed for CPU pressure.
func (w *CPUPressureWatcher) IsThrottling() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.state > cpuLevelNormal
}

// PressurePercent returns the current smoothed CPU usage as a percentage of a
// single core (mirrors the ebpf_guard_cpu_pressure_percent gauge), for
// operator-facing surfaces that would rather read Go state directly than
// scrape /metrics (issue #309).
func (w *CPUPressureWatcher) PressurePercent() float64 {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if len(w.window) == 0 {
		return 0
	}
	var sum float64
	for _, v := range w.window {
		sum += v
	}
	return sum / float64(len(w.window))
}

// readProcSelfCPUSeconds returns this process's cumulative CPU time (utime +
// stime) in seconds, read from /proc/self/stat.
func readProcSelfCPUSeconds() (float64, error) {
	// /proc/self/stat is a single short line; read it whole rather than
	// streaming so there is no file handle to close on the read path.
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, fmt.Errorf("read /proc/self/stat: %w", err)
	}
	return parseProcStatCPUSeconds(string(data))
}

// parseProcStatCPUSeconds extracts utime+stime (in seconds) from the contents
// of a /proc/<pid>/stat line. Split out from the file read so the field-parsing
// logic can be unit-tested without a live /proc.
func parseProcStatCPUSeconds(line string) (float64, error) {
	// The comm field (2) is wrapped in parentheses and may itself contain
	// spaces or ')'. Fields after the last ')' are fixed-position, so split
	// there. utime is field 14 and stime field 15 (1-indexed); relative to
	// the slice that starts at field 3 (state) they are indices 11 and 12.
	rparen := strings.LastIndexByte(line, ')')
	if rparen < 0 || rparen+2 >= len(line) {
		return 0, fmt.Errorf("malformed /proc/self/stat")
	}
	rest := strings.Fields(line[rparen+2:])
	if len(rest) < 13 {
		return 0, fmt.Errorf("malformed /proc/self/stat: too few fields")
	}
	utime, err := strconv.ParseUint(rest[11], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse utime: %w", err)
	}
	stime, err := strconv.ParseUint(rest[12], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse stime: %w", err)
	}
	return float64(utime+stime) / clockTicksPerSecond, nil
}
