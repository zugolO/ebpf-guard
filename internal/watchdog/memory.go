// memory.go — Memory pressure auto-tuning for ebpf-guard
//
// Monitors system memory pressure and automatically downgrades profiling
// when available memory falls below thresholds. Part of Sprint 22.0.

package watchdog

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// ControllableProfiler is the interface for profilers that can be controlled
// based on memory pressure. Defined here to avoid circular imports.
type ControllableProfiler interface {
	Enable()
	Disable()
	IsEnabled() bool
	SetSamplingRate(rate float64)
	GetSamplingRate() float64
}

// BPFSamplingController controls BPF-side event sampling.
type BPFSamplingController interface {
	SetSamplingRate(eventType string, rate float64)
}

// pressureLevel enumerates the three memory-pressure states.
const (
	pressureLevelNormal           = 0 // all profiling active
	pressureLevelSequenceDisabled = 1 // sequence profiling off, EWMA still active
	pressureLevelAllDisabled      = 2 // all profiling off
)

// MemoryPressureWatcher monitors system memory and adjusts profiler behavior.
type MemoryPressureWatcher struct {
	logger            *slog.Logger
	sequenceProfilers []ControllableProfiler // disabled first (level 1)
	allProfilers      []ControllableProfiler // disabled when deeper pressure (level 2)
	bpfController     BPFSamplingController

	// Thresholds (all as available-memory percentage, 0–100)
	disableSequenceThreshold float64
	disableAllThreshold      float64
	recoveryThreshold        float64

	// State
	mu          sync.RWMutex
	state       int
	normalRates map[string]float64 // saved rates before downgrade

	// Metrics
	pressureGauge  *prometheus.GaugeVec
	pressureRatio  prometheus.Gauge
	pressureLevel  prometheus.Gauge
}

// MemoryConfig holds configuration for memory pressure handling.
type MemoryConfig struct {
	Enabled            bool          `mapstructure:"enabled"`
	CheckInterval      time.Duration `mapstructure:"check_interval"`
	LowMemoryThreshold float64       `mapstructure:"low_memory_threshold"` // Percentage (0-100), deprecated
	RecoveryThreshold  float64       `mapstructure:"recovery_threshold"`   // Percentage (0-100)
	// DisableSequenceThreshold: available % below which sequence profiling is disabled (level 1).
	DisableSequenceThreshold float64 `mapstructure:"disable_sequence_threshold"`
	// DisableAllThreshold: available % below which all profiling is disabled (level 2).
	DisableAllThreshold float64 `mapstructure:"disable_all_threshold"`
}

// DefaultMemoryConfig returns default memory pressure configuration.
func DefaultMemoryConfig() MemoryConfig {
	return MemoryConfig{
		Enabled:                  true,
		CheckInterval:            5 * time.Second,
		LowMemoryThreshold:       10.0,
		RecoveryThreshold:        20.0,
		DisableSequenceThreshold: 10.0,
		DisableAllThreshold:      5.0,
	}
}

// NewMemoryPressureWatcher creates a new memory pressure watcher.
//
// sequenceProfilers are disabled first when available memory drops below
// DisableSequenceThreshold (level 1). allProfilers are disabled when memory
// drops further below DisableAllThreshold (level 2). Pass the same list for
// both parameters to replicate the original single-threshold behaviour.
func NewMemoryPressureWatcher(
	config MemoryConfig,
	logger *slog.Logger,
	allProfilers []ControllableProfiler,
	bpfController BPFSamplingController,
) *MemoryPressureWatcher {
	return NewMemoryPressureWatcherWithSequence(config, logger, allProfilers, allProfilers, bpfController)
}

// NewMemoryPressureWatcherWithSequence creates a watcher with separate profiler
// lists for the two downgrade stages.
func NewMemoryPressureWatcherWithSequence(
	config MemoryConfig,
	logger *slog.Logger,
	sequenceProfilers []ControllableProfiler,
	allProfilers []ControllableProfiler,
	bpfController BPFSamplingController,
) *MemoryPressureWatcher {
	if config.CheckInterval <= 0 {
		config.CheckInterval = 5 * time.Second
	}
	// Back-compat: fall back to LowMemoryThreshold when new fields are zero.
	if config.DisableSequenceThreshold <= 0 {
		if config.LowMemoryThreshold > 0 {
			config.DisableSequenceThreshold = config.LowMemoryThreshold
		} else {
			config.DisableSequenceThreshold = 10.0
		}
	}
	if config.DisableAllThreshold <= 0 {
		config.DisableAllThreshold = config.DisableSequenceThreshold / 2
	}
	if config.RecoveryThreshold <= 0 {
		config.RecoveryThreshold = 20.0
	}

	w := &MemoryPressureWatcher{
		logger:                   logger,
		sequenceProfilers:        sequenceProfilers,
		allProfilers:             allProfilers,
		bpfController:            bpfController,
		disableSequenceThreshold: config.DisableSequenceThreshold,
		disableAllThreshold:      config.DisableAllThreshold,
		recoveryThreshold:        config.RecoveryThreshold,
		// kept for tests that still read the old field names via accessor
		normalRates: make(map[string]float64),
		pressureGauge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_guard_memory_pressure_mode",
			Help: "Current memory pressure mode (1 = low memory, 0 = normal)",
		}, []string{"mode"}),
		pressureRatio: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpf_guard_memory_pressure_ratio",
			Help: "Ratio of available memory to total memory (0.0–1.0). Lower is more constrained.",
		}),
		pressureLevel: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpf_guard_memory_pressure_level",
			Help: "Memory pressure level: 0=normal, 1=sequence_profiling_disabled, 2=all_profiling_disabled",
		}),
	}

	// Initialise mode gauge so it appears in /metrics from startup.
	w.pressureGauge.WithLabelValues("normal").Set(1)
	w.pressureGauge.WithLabelValues("low").Set(0)
	w.pressureLevel.Set(pressureLevelNormal)

	return w
}

// RegisterMetrics registers Prometheus metrics.
func (w *MemoryPressureWatcher) RegisterMetrics(reg prometheus.Registerer) error {
	for _, c := range []prometheus.Collector{w.pressureGauge, w.pressureRatio, w.pressureLevel} {
		if err := reg.Register(c); err != nil {
			return err
		}
	}
	return nil
}

// Start begins monitoring memory pressure.
func (w *MemoryPressureWatcher) Start(ctx context.Context) {
	if w.logger == nil {
		w.logger = slog.Default()
	}

	ticker := time.NewTicker(w.checkIntervalOrDefault())
	defer ticker.Stop()

	// Initial check
	w.checkMemory()

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("memory pressure watcher stopped")
			return
		case <-ticker.C:
			w.checkMemory()
		}
	}
}

func (w *MemoryPressureWatcher) checkIntervalOrDefault() time.Duration {
	// The check interval is held on the config but not stored on the struct
	// (the original code hard-coded 5s in Start). Keep 5s as the fallback.
	return 5 * time.Second
}

// checkMemory reads /proc/meminfo and transitions between pressure levels.
func (w *MemoryPressureWatcher) checkMemory() {
	memAvailable, memTotal, err := w.readMemInfo()
	if err != nil {
		w.logger.Error("failed to read memory info", "error", err)
		return
	}
	if memTotal == 0 {
		w.logger.Error("invalid total memory")
		return
	}

	availPct := (float64(memAvailable) / float64(memTotal)) * 100
	w.pressureRatio.Set(float64(memAvailable) / float64(memTotal))

	w.mu.Lock()
	defer w.mu.Unlock()

	switch w.state {
	case pressureLevelNormal:
		if availPct < w.disableAllThreshold {
			w.logger.Warn("memory pressure: all profiling disabled",
				slog.String("available_pct", fmt.Sprintf("%.1f%%", availPct)),
				slog.String("threshold", fmt.Sprintf("%.1f%%", w.disableAllThreshold)),
			)
			w.enterAllDisabledMode()
			w.setState(pressureLevelAllDisabled)
		} else if availPct < w.disableSequenceThreshold {
			w.logger.Warn("memory pressure: sequence profiling disabled",
				slog.String("available_pct", fmt.Sprintf("%.1f%%", availPct)),
				slog.String("threshold", fmt.Sprintf("%.1f%%", w.disableSequenceThreshold)),
			)
			w.enterSequenceDisabledMode()
			w.setState(pressureLevelSequenceDisabled)
		}

	case pressureLevelSequenceDisabled:
		if availPct < w.disableAllThreshold {
			w.logger.Warn("memory pressure: escalating — all profiling disabled",
				slog.String("available_pct", fmt.Sprintf("%.1f%%", availPct)),
				slog.String("threshold", fmt.Sprintf("%.1f%%", w.disableAllThreshold)),
			)
			w.enterAllDisabledMode()
			w.setState(pressureLevelAllDisabled)
		} else if availPct > w.recoveryThreshold {
			w.logger.Warn("memory pressure: recovered from sequence-disabled state",
				slog.String("available_pct", fmt.Sprintf("%.1f%%", availPct)),
				slog.String("threshold", fmt.Sprintf("%.1f%%", w.recoveryThreshold)),
			)
			w.recoverNormalMode()
			w.setState(pressureLevelNormal)
		}

	case pressureLevelAllDisabled:
		if availPct > w.recoveryThreshold {
			w.logger.Warn("memory pressure: recovered from all-disabled state",
				slog.String("available_pct", fmt.Sprintf("%.1f%%", availPct)),
				slog.String("threshold", fmt.Sprintf("%.1f%%", w.recoveryThreshold)),
			)
			w.recoverNormalMode()
			w.setState(pressureLevelNormal)
		}
	}
}

// setState updates the pressure state and syncs all exported metrics.
func (w *MemoryPressureWatcher) setState(s int) {
	w.state = s
	w.pressureLevel.Set(float64(s))
	if s == pressureLevelNormal {
		w.pressureGauge.WithLabelValues("low").Set(0)
		w.pressureGauge.WithLabelValues("normal").Set(1)
	} else {
		w.pressureGauge.WithLabelValues("low").Set(1)
		w.pressureGauge.WithLabelValues("normal").Set(0)
	}
}

// readMemInfo parses /proc/meminfo and returns available and total memory in KB.
func (w *MemoryPressureWatcher) readMemInfo() (available, total uint64, err error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, fmt.Errorf("open /proc/meminfo: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		key := strings.TrimSuffix(fields[0], ":")
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}

		switch key {
		case "MemTotal":
			total = value
		case "MemAvailable":
			available = value
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, 0, fmt.Errorf("scan /proc/meminfo: %w", err)
	}

	return available, total, nil
}

// enterSequenceDisabledMode disables only the sequence profilers (level 1).
func (w *MemoryPressureWatcher) enterSequenceDisabledMode() {
	for i, p := range w.sequenceProfilers {
		key := fmt.Sprintf("seq_%d", i)
		w.normalRates[key] = p.GetSamplingRate()
		p.Disable()
	}
}

// enterAllDisabledMode disables all profilers and reduces BPF sampling (level 2).
func (w *MemoryPressureWatcher) enterAllDisabledMode() {
	// Disable sequence profilers first (may already be disabled at level 1).
	for i, p := range w.sequenceProfilers {
		key := fmt.Sprintf("seq_%d", i)
		if _, saved := w.normalRates[key]; !saved {
			w.normalRates[key] = p.GetSamplingRate()
		}
		p.Disable()
	}
	// Disable all remaining profilers.
	for i, p := range w.allProfilers {
		key := fmt.Sprintf("profiler_%d", i)
		w.normalRates[key] = p.GetSamplingRate()
		p.SetSamplingRate(0.1)
		p.Disable()
	}
	if w.bpfController != nil {
		w.bpfController.SetSamplingRate("syscall", 0.1)
		w.bpfController.SetSamplingRate("network", 0.1)
		w.bpfController.SetSamplingRate("file", 0.1)
	}
}

// recoverNormalMode restores all profilers and BPF sampling to pre-pressure state.
func (w *MemoryPressureWatcher) recoverNormalMode() {
	for i, p := range w.allProfilers {
		key := fmt.Sprintf("profiler_%d", i)
		if rate, ok := w.normalRates[key]; ok {
			p.SetSamplingRate(rate)
		} else {
			p.SetSamplingRate(1.0)
		}
		p.Enable()
	}
	for i, p := range w.sequenceProfilers {
		key := fmt.Sprintf("seq_%d", i)
		if rate, ok := w.normalRates[key]; ok {
			p.SetSamplingRate(rate)
		}
		p.Enable()
	}
	if w.bpfController != nil {
		w.bpfController.SetSamplingRate("syscall", 1.0)
		w.bpfController.SetSamplingRate("network", 1.0)
		w.bpfController.SetSamplingRate("file", 1.0)
	}
	w.normalRates = make(map[string]float64)
}

// IsLowMemory returns true if any profiling has been disabled due to memory pressure.
func (w *MemoryPressureWatcher) IsLowMemory() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.state > pressureLevelNormal
}

// PressureLevel returns the current pressure level (0=normal, 1=sequence_disabled, 2=all_disabled).
func (w *MemoryPressureWatcher) PressureLevel() int {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.state
}

// exported for tests — field accessors
func (w *MemoryPressureWatcher) getLowMemoryThreshold() float64  { return w.disableSequenceThreshold }
func (w *MemoryPressureWatcher) getRecoveryThreshold() float64   { return w.recoveryThreshold }
