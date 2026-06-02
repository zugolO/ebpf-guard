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

// MemoryPressureWatcher monitors system memory and adjusts profiler behavior.
type MemoryPressureWatcher struct {
	logger        *slog.Logger
	profilers     []ControllableProfiler
	bpfController BPFSamplingController

	// Thresholds
	lowMemoryThreshold float64 // Memory available % to trigger low-memory mode
	recoveryThreshold  float64 // Memory available % to recover normal mode

	// State
	mu          sync.RWMutex
	isLowMemory bool
	normalRates map[string]float64 // Saved sampling rates before downgrade

	// Metrics
	pressureGauge *prometheus.GaugeVec
	pressureRatio prometheus.Gauge // ebpf_guard_memory_pressure_ratio
}

// MemoryConfig holds configuration for memory pressure handling.
type MemoryConfig struct {
	Enabled            bool          `mapstructure:"enabled"`
	CheckInterval      time.Duration `mapstructure:"check_interval"`
	LowMemoryThreshold float64       `mapstructure:"low_memory_threshold"` // Percentage (0-100)
	RecoveryThreshold  float64       `mapstructure:"recovery_threshold"`   // Percentage (0-100)
}

// DefaultMemoryConfig returns default memory pressure configuration.
func DefaultMemoryConfig() MemoryConfig {
	return MemoryConfig{
		Enabled:            true,
		CheckInterval:      5 * time.Second,
		LowMemoryThreshold: 10.0, // 10% available
		RecoveryThreshold:  20.0, // 20% available
	}
}

// NewMemoryPressureWatcher creates a new memory pressure watcher.
func NewMemoryPressureWatcher(
	config MemoryConfig,
	logger *slog.Logger,
	profilers []ControllableProfiler,
	bpfController BPFSamplingController,
) *MemoryPressureWatcher {
	if config.CheckInterval <= 0 {
		config.CheckInterval = 5 * time.Second
	}
	if config.LowMemoryThreshold <= 0 {
		config.LowMemoryThreshold = 10.0
	}
	if config.RecoveryThreshold <= 0 {
		config.RecoveryThreshold = 20.0
	}

	w := &MemoryPressureWatcher{
		logger:             logger,
		profilers:          profilers,
		bpfController:      bpfController,
		lowMemoryThreshold: config.LowMemoryThreshold,
		recoveryThreshold:  config.RecoveryThreshold,
		normalRates:        make(map[string]float64),
		pressureGauge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_guard_memory_pressure_mode",
			Help: "Current memory pressure mode (1 = low memory, 0 = normal)",
		}, []string{"mode"}),
		pressureRatio: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpf_guard_memory_pressure_ratio",
			Help: "Ratio of available memory to total memory (0.0–1.0). Lower is more constrained.",
		}),
	}

	// Initialize the mode gauge to the default (normal) state so the metric is
	// present in /metrics from startup rather than only after the first mode
	// transition. The watcher starts in normal mode.
	w.pressureGauge.WithLabelValues("normal").Set(1)
	w.pressureGauge.WithLabelValues("low").Set(0)

	return w
}

// RegisterMetrics registers Prometheus metrics.
func (w *MemoryPressureWatcher) RegisterMetrics(reg prometheus.Registerer) error {
	for _, c := range []prometheus.Collector{w.pressureGauge, w.pressureRatio} {
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

	ticker := time.NewTicker(5 * time.Second)
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

// checkMemory reads /proc/meminfo and determines if action is needed.
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

	availablePercent := (float64(memAvailable) / float64(memTotal)) * 100
	w.pressureRatio.Set(float64(memAvailable) / float64(memTotal))

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.isLowMemory {
		// Check if we can recover
		if availablePercent > w.recoveryThreshold {
			w.logger.Warn("memory pressure recovered",
				"available_percent", fmt.Sprintf("%.1f%%", availablePercent),
				"threshold", fmt.Sprintf("%.1f%%", w.recoveryThreshold),
			)
			w.recoverNormalMode()
			w.isLowMemory = false
			w.pressureGauge.WithLabelValues("low").Set(0)
			w.pressureGauge.WithLabelValues("normal").Set(1)
		}
	} else {
		// Check if we need to downgrade
		if availablePercent < w.lowMemoryThreshold {
			w.logger.Warn("memory pressure detected, downgrading profiling",
				"available_percent", fmt.Sprintf("%.1f%%", availablePercent),
				"threshold", fmt.Sprintf("%.1f%%", w.lowMemoryThreshold),
			)
			w.enterLowMemoryMode()
			w.isLowMemory = true
			w.pressureGauge.WithLabelValues("low").Set(1)
			w.pressureGauge.WithLabelValues("normal").Set(0)
		}
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

// enterLowMemoryMode disables sequence profiling and reduces BPF sampling.
func (w *MemoryPressureWatcher) enterLowMemoryMode() {
	// Save current rates and disable profilers
	for i, p := range w.profilers {
		key := fmt.Sprintf("profiler_%d", i)
		w.normalRates[key] = p.GetSamplingRate()
		p.SetSamplingRate(0.1) // Reduce to 10% sampling
		p.Disable()
	}

	// Reduce BPF sampling rates
	if w.bpfController != nil {
		w.bpfController.SetSamplingRate("syscall", 0.1)
		w.bpfController.SetSamplingRate("network", 0.1)
		w.bpfController.SetSamplingRate("file", 0.1)
	}
}

// recoverNormalMode restores normal profiling operation.
func (w *MemoryPressureWatcher) recoverNormalMode() {
	// Restore profiler rates and enable
	for i, p := range w.profilers {
		key := fmt.Sprintf("profiler_%d", i)
		if rate, ok := w.normalRates[key]; ok {
			p.SetSamplingRate(rate)
		} else {
			p.SetSamplingRate(1.0) // Default to 100%
		}
		p.Enable()
	}

	// Restore BPF sampling rates
	if w.bpfController != nil {
		w.bpfController.SetSamplingRate("syscall", 1.0)
		w.bpfController.SetSamplingRate("network", 1.0)
		w.bpfController.SetSamplingRate("file", 1.0)
	}

	// Clear saved rates
	w.normalRates = make(map[string]float64)
}

// IsLowMemory returns true if currently in low-memory mode.
func (w *MemoryPressureWatcher) IsLowMemory() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.isLowMemory
}
