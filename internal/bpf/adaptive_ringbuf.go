// Package bpf provides eBPF program loading and management.
package bpf

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// RingBufLoadConfig configures the ring-buffer-load-based adaptive sampler.
// Unlike the CPU-triggered sampler (AdaptiveSampler), this controller responds
// to ring buffer back-pressure: when the event-processing channel is filling
// up or BPF-side drop counters are rising, it automatically reduces sample
// rates for high-volume event types so the pipeline can keep up without silent
// detection gaps on security-critical event types.
type RingBufLoadConfig struct {
	// Enabled activates ring-buffer-load adaptive sampling. Default: false.
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`

	// CheckInterval controls how often channel depth and drop counters are
	// sampled. Default: 2s.
	CheckInterval time.Duration `mapstructure:"check_interval" yaml:"check_interval"`

	// DegradedThreshold is the event-channel fill ratio (0.0–1.0) above which
	// the controller moves to the Degraded state and starts reducing sample
	// rates for high-volume types. Default: 0.50.
	DegradedThreshold float64 `mapstructure:"degraded_threshold" yaml:"degraded_threshold"`

	// CriticalThreshold is the fill ratio above which the controller moves to
	// the Critical state and reduces rates further. Default: 0.80.
	CriticalThreshold float64 `mapstructure:"critical_threshold" yaml:"critical_threshold"`

	// RecoveryThreshold is the fill ratio below which the controller returns
	// to Normal. Hysteresis: RecoveryThreshold must be lower than
	// DegradedThreshold to prevent oscillation. Default: 0.30.
	RecoveryThreshold float64 `mapstructure:"recovery_threshold" yaml:"recovery_threshold"`

	// SyscallDegradedRate is the syscall sampling rate (0.0–1.0) applied in
	// Degraded state. Default: 0.25.
	SyscallDegradedRate float64 `mapstructure:"syscall_degraded_rate" yaml:"syscall_degraded_rate"`

	// SyscallCriticalRate is the syscall sampling rate applied in Critical
	// state. Default: 0.10.
	SyscallCriticalRate float64 `mapstructure:"syscall_critical_rate" yaml:"syscall_critical_rate"`

	// FileDegradedRate is the file-event sampling rate in Degraded state.
	// Default: 0.50.
	FileDegradedRate float64 `mapstructure:"file_degraded_rate" yaml:"file_degraded_rate"`

	// FileCriticalRate is the file-event sampling rate in Critical state.
	// Default: 0.25.
	FileCriticalRate float64 `mapstructure:"file_critical_rate" yaml:"file_critical_rate"`

	// NetworkCriticalRate is the network-event sampling rate in Critical
	// state. Network events are reduced last (they tend to be lower-volume
	// but higher security-value). Default: 0.50.
	NetworkCriticalRate float64 `mapstructure:"network_critical_rate" yaml:"network_critical_rate"`

	// MinSyscallRate is the absolute floor for syscall sampling — the
	// controller will never go below this regardless of load. Default: 0.05.
	MinSyscallRate float64 `mapstructure:"min_syscall_rate" yaml:"min_syscall_rate"`

	// MinFileRate is the absolute floor for file sampling. Default: 0.10.
	MinFileRate float64 `mapstructure:"min_file_rate" yaml:"min_file_rate"`

	// MinNetworkRate is the absolute floor for network sampling. Default: 0.25.
	// Network/LSM/privesc events are never sampled below this.
	MinNetworkRate float64 `mapstructure:"min_network_rate" yaml:"min_network_rate"`
}

// DefaultRingBufLoadConfig returns safe production defaults.
func DefaultRingBufLoadConfig() RingBufLoadConfig {
	return RingBufLoadConfig{
		Enabled:             false,
		CheckInterval:       2 * time.Second,
		DegradedThreshold:   0.50,
		CriticalThreshold:   0.80,
		RecoveryThreshold:   0.30,
		SyscallDegradedRate: 0.25,
		SyscallCriticalRate: 0.10,
		FileDegradedRate:    0.50,
		FileCriticalRate:    0.25,
		NetworkCriticalRate: 0.50,
		MinSyscallRate:      0.05,
		MinFileRate:         0.10,
		MinNetworkRate:      0.25,
	}
}

// loadLevel is the current adaptive-sampling state.
type loadLevel int

const (
	loadLevelNormal   loadLevel = 0
	loadLevelDegraded loadLevel = 1
	loadLevelCritical loadLevel = 2
)

// ChannelDepthProvider returns the current fill ratio [0.0, 1.0] of the
// event-processing channel. Implemented by the collector/correlator layer.
type ChannelDepthProvider interface {
	ChannelDepth() float64
}

// ChannelDepthFunc is a functional implementation of ChannelDepthProvider.
type ChannelDepthFunc func() float64

func (f ChannelDepthFunc) ChannelDepth() float64 { return f() }

// RingBufSamplingController is the subset of SamplingController needed by
// the adaptive load controller (avoids importing the full BPF controller in
// tests).
type RingBufSamplingController interface {
	SetSamplingRate(eventType string, rate float64) error
}

// RingBufLoadController monitors event-channel fill level and adjusts BPF
// sampling rates to prevent back-pressure from silently dropping events in
// the kernel ring buffer.
//
// Priority order for sampling reduction (highest to lowest volume):
//  1. syscall — reduced first; per-syscall filtering keeps critical ones visible
//  2. file    — reduced second
//  3. network — reduced last; lower volume, higher security value
//
// LSM, privesc, and kmod events are NOT controlled here — their BPF programs
// do not use the shared sampling map, so they always pass through.
type RingBufLoadController struct {
	cfg      RingBufLoadConfig
	ctrl     RingBufSamplingController
	depth    ChannelDepthProvider
	logger   *slog.Logger

	mu       sync.Mutex
	level    loadLevel
	rates    map[string]float64 // current effective rates per event type

	// Prometheus metrics
	samplingRateGauge *prometheus.GaugeVec  // ebpf_guard_bpf_sampling_rate
	channelDepthGauge prometheus.Gauge       // ebpf_guard_bpf_channel_depth_ratio
	levelGauge        prometheus.Gauge       // ebpf_guard_bpf_load_level
	downgrades        *prometheus.CounterVec // ebpf_guard_bpf_sampling_downgrades_total
}

// NewRingBufLoadController creates a new controller.
// ctrl may be nil (controller logs but does not update BPF maps — useful for tests).
// depth may be nil (controller uses 0.0 channel depth — for testing without a live channel).
func NewRingBufLoadController(
	cfg RingBufLoadConfig,
	ctrl RingBufSamplingController,
	depth ChannelDepthProvider,
	logger *slog.Logger,
) *RingBufLoadController {
	if logger == nil {
		logger = slog.Default()
	}
	cfg = applyRingBufLoadDefaults(cfg)

	c := &RingBufLoadController{
		cfg:    cfg,
		ctrl:   ctrl,
		depth:  depth,
		logger: logger,
		level:  loadLevelNormal,
		rates: map[string]float64{
			"syscall": 1.0,
			"file":    1.0,
			"network": 1.0,
		},
		samplingRateGauge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_guard_bpf_sampling_rate",
			Help: "Current effective BPF sampling rate per event type (1.0 = all events).",
		}, []string{"event_type"}),
		channelDepthGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpf_guard_bpf_channel_depth_ratio",
			Help: "Current event-processing channel fill ratio (0.0–1.0).",
		}),
		levelGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpf_guard_bpf_load_level",
			Help: "Current adaptive-sampling load level: 0=normal, 1=degraded, 2=critical.",
		}),
		downgrades: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpf_guard_bpf_sampling_downgrades_total",
			Help: "Total number of times sampling was downgraded for an event type.",
		}, []string{"event_type", "state"}),
	}
	// Initialise gauges at the normal state so they appear from startup.
	for _, et := range []string{"syscall", "file", "network"} {
		c.samplingRateGauge.WithLabelValues(et).Set(1.0)
	}
	c.levelGauge.Set(0)
	return c
}

// RegisterMetrics registers the controller's Prometheus collectors.
func (c *RingBufLoadController) RegisterMetrics(reg prometheus.Registerer) error {
	for _, col := range []prometheus.Collector{
		c.samplingRateGauge,
		c.channelDepthGauge,
		c.levelGauge,
		c.downgrades,
	} {
		if err := reg.Register(col); err != nil {
			return err
		}
	}
	return nil
}

// Start launches the background monitoring goroutine.
// Returns immediately; the goroutine exits when ctx is cancelled.
// stopped is closed once the goroutine has exited (nil is allowed).
func (c *RingBufLoadController) Start(ctx context.Context) {
	c.StartWithDone(ctx, nil)
}

// StartWithDone is like Start but closes the done channel after the goroutine exits.
// Useful in tests to avoid racing on shared state after context cancellation.
func (c *RingBufLoadController) StartWithDone(ctx context.Context, done chan struct{}) {
	if !c.cfg.Enabled {
		c.logger.Info("ring-buffer adaptive sampling disabled")
		if done != nil {
			close(done)
		}
		return
	}
	c.logger.Info("ring-buffer adaptive sampling started",
		slog.Float64("degraded_threshold", c.cfg.DegradedThreshold),
		slog.Float64("critical_threshold", c.cfg.CriticalThreshold),
		slog.Float64("recovery_threshold", c.cfg.RecoveryThreshold),
	)
	go func() {
		c.run(ctx)
		if done != nil {
			close(done)
		}
	}()
}

func (c *RingBufLoadController) run(ctx context.Context) {
	ticker := time.NewTicker(c.cfg.CheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			c.restore()
			return
		case <-ticker.C:
			c.check()
		}
	}
}

func (c *RingBufLoadController) check() {
	var fill float64
	if c.depth != nil {
		fill = c.depth.ChannelDepth()
	}
	c.channelDepthGauge.Set(fill)

	c.mu.Lock()
	defer c.mu.Unlock()

	switch c.level {
	case loadLevelNormal:
		if fill >= c.cfg.CriticalThreshold {
			c.enterLevel(loadLevelCritical, fill)
		} else if fill >= c.cfg.DegradedThreshold {
			c.enterLevel(loadLevelDegraded, fill)
		}
	case loadLevelDegraded:
		if fill >= c.cfg.CriticalThreshold {
			c.enterLevel(loadLevelCritical, fill)
		} else if fill < c.cfg.RecoveryThreshold {
			c.enterLevel(loadLevelNormal, fill)
		}
	case loadLevelCritical:
		if fill < c.cfg.RecoveryThreshold {
			c.enterLevel(loadLevelNormal, fill)
		}
	}
}

// enterLevel transitions to the given load level and applies BPF rate changes.
// Must be called with c.mu held.
func (c *RingBufLoadController) enterLevel(next loadLevel, fill float64) {
	prev := c.level
	c.level = next
	c.levelGauge.Set(float64(next))

	switch next {
	case loadLevelNormal:
		c.logger.Info("ring-buffer load: recovered to normal",
			slog.Float64("channel_depth", fill))
		c.applyRates(map[string]float64{
			"syscall": 1.0,
			"file":    1.0,
			"network": 1.0,
		})

	case loadLevelDegraded:
		c.logger.Warn("ring-buffer load: entering degraded state — reducing syscall/file sampling",
			slog.Float64("channel_depth", fill),
			slog.Float64("syscall_rate", c.cfg.SyscallDegradedRate),
			slog.Float64("file_rate", c.cfg.FileDegradedRate),
		)
		c.applyRates(map[string]float64{
			"syscall": clampRate(c.cfg.SyscallDegradedRate, c.cfg.MinSyscallRate),
			"file":    clampRate(c.cfg.FileDegradedRate, c.cfg.MinFileRate),
			"network": 1.0,
		})
		if prev < loadLevelDegraded {
			c.downgrades.WithLabelValues("syscall", "degraded").Inc()
			c.downgrades.WithLabelValues("file", "degraded").Inc()
		}

	case loadLevelCritical:
		c.logger.Warn("ring-buffer load: entering critical state — reducing all sampling",
			slog.Float64("channel_depth", fill),
			slog.Float64("syscall_rate", c.cfg.SyscallCriticalRate),
			slog.Float64("file_rate", c.cfg.FileCriticalRate),
			slog.Float64("network_rate", c.cfg.NetworkCriticalRate),
		)
		c.applyRates(map[string]float64{
			"syscall": clampRate(c.cfg.SyscallCriticalRate, c.cfg.MinSyscallRate),
			"file":    clampRate(c.cfg.FileCriticalRate, c.cfg.MinFileRate),
			"network": clampRate(c.cfg.NetworkCriticalRate, c.cfg.MinNetworkRate),
		})
		if prev < loadLevelCritical {
			c.downgrades.WithLabelValues("syscall", "critical").Inc()
			c.downgrades.WithLabelValues("file", "critical").Inc()
			c.downgrades.WithLabelValues("network", "critical").Inc()
		}
	}
}

// applyRates updates BPF maps and internal state. Must be called with c.mu held.
func (c *RingBufLoadController) applyRates(rates map[string]float64) {
	for et, rate := range rates {
		c.rates[et] = rate
		c.samplingRateGauge.WithLabelValues(et).Set(rate)
		if c.ctrl != nil {
			if err := c.ctrl.SetSamplingRate(et, rate); err != nil {
				c.logger.Error("failed to update BPF sampling rate",
					slog.String("event_type", et),
					slog.Float64("rate", rate),
					slog.Any("error", err),
				)
			}
		}
	}
}

// restore resets all BPF sampling rates to 1.0 on shutdown.
func (c *RingBufLoadController) restore() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.level == loadLevelNormal {
		return
	}
	c.logger.Info("ring-buffer adaptive sampling: restoring full rates on shutdown")
	c.applyRates(map[string]float64{
		"syscall": 1.0,
		"file":    1.0,
		"network": 1.0,
	})
	c.level = loadLevelNormal
	c.levelGauge.Set(0)
}

// CurrentRates returns a snapshot of the current effective sampling rates.
func (c *RingBufLoadController) CurrentRates() map[string]float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]float64, len(c.rates))
	for k, v := range c.rates {
		out[k] = v
	}
	return out
}

// EWMAScaleFactor returns the inverse sampling correction factor (1.0 / rate)
// for a given event type. Profilers should multiply EWMA update weights by
// this factor so down-sampled baselines converge to the same value as full
// sampling would produce.
//
// Example: when syscall sampling is at 25%, EWMAScaleFactor("syscall") == 4.0.
// Callers update EWMA with weight*4 so each sampled event accounts for the
// 4 events that were likely skipped.
func (c *RingBufLoadController) EWMAScaleFactor(eventType string) float64 {
	c.mu.Lock()
	rate, ok := c.rates[eventType]
	c.mu.Unlock()
	if !ok || rate <= 0 {
		return 1.0
	}
	if rate >= 1.0 {
		return 1.0
	}
	return 1.0 / rate
}

// Level returns the current load level (0=normal, 1=degraded, 2=critical).
func (c *RingBufLoadController) Level() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return int(c.level)
}

// clampRate ensures rate is within [min, 1.0].
func clampRate(rate, min float64) float64 {
	if min > 0 && rate < min {
		return min
	}
	if rate > 1.0 {
		return 1.0
	}
	if rate < 0 {
		return 0
	}
	return rate
}

// applyRingBufLoadDefaults fills in zero values with production defaults.
func applyRingBufLoadDefaults(cfg RingBufLoadConfig) RingBufLoadConfig {
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = 2 * time.Second
	}
	if cfg.DegradedThreshold <= 0 {
		cfg.DegradedThreshold = 0.50
	}
	if cfg.CriticalThreshold <= 0 {
		cfg.CriticalThreshold = 0.80
	}
	if cfg.RecoveryThreshold <= 0 {
		cfg.RecoveryThreshold = 0.30
	}
	if cfg.SyscallDegradedRate <= 0 {
		cfg.SyscallDegradedRate = 0.25
	}
	if cfg.SyscallCriticalRate <= 0 {
		cfg.SyscallCriticalRate = 0.10
	}
	if cfg.FileDegradedRate <= 0 {
		cfg.FileDegradedRate = 0.50
	}
	if cfg.FileCriticalRate <= 0 {
		cfg.FileCriticalRate = 0.25
	}
	if cfg.NetworkCriticalRate <= 0 {
		cfg.NetworkCriticalRate = 0.50
	}
	if cfg.MinSyscallRate <= 0 {
		cfg.MinSyscallRate = 0.05
	}
	if cfg.MinFileRate <= 0 {
		cfg.MinFileRate = 0.10
	}
	if cfg.MinNetworkRate <= 0 {
		cfg.MinNetworkRate = 0.25
	}
	return cfg
}
