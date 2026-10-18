// overload.go — proportional bulk-event shedding by queue pressure.
//
// Волна 8.8, Р3. Beyond its ceiling the agent used to collapse instead of
// holding a plateau (pod: 17 → 5 thousand events/s as the feed grew): the CPU
// went into reading rings and dropping after the work was done. This controller
// closes the loop on the thing that actually says "the pipeline cannot keep up"
// — the bulk queue / worker channel fill and the drop rate — and sheds bulk
// file events IN THE KERNEL by lowering the file sampling multiplier (the BPF
// side applies it to hot processes only, see file_shed_pass in
// bpf/fileaccess.bpf.c). The divisor N (1 event in N from hot pids) is adjusted
// multiplicatively: up while the queue is full or events are being dropped,
// down slowly after a calm period, off below 1.1. Protected classes (network,
// syscall, dns, …) are never touched here.
//
// The signal is the bulk LOSS share, not the queue fill. A single hot pid keeps
// its worker's channel full by construction (its events are serialised on one
// worker, and the worker also serves that pid's protected events first), so a
// full channel alone says "this worker is busy", not "the feed is too fast"; the
// first version raised N on it and oscillated far below capacity (host, 1 hot
// process, 30 000 ops/s: processed 0.81 of the ceiling). Loss between LossLow
// and LossHigh is tolerated: the Go-side drop of the dominant pid's surplus
// keeps the worker saturated, which is exactly the plateau.

package watchdog

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// OverloadConfig configures the controller.
type OverloadConfig struct {
	Enabled       bool          `mapstructure:"enabled"`
	CheckInterval time.Duration `mapstructure:"check_interval"`
	// FillHigh: queue fill ratio at or above which, together with loss at or
	// above LossLow, the feed is considered too fast (a full queue alone is not).
	FillHigh float64 `mapstructure:"fill_high"`
	// LossHigh: bulk loss fraction per tick at or above which (with at least
	// MinDrops drops) the feed is considered too fast.
	LossHigh float64 `mapstructure:"loss_high"`
	// LossLow: loss fraction at or below which the tick counts as calm.
	LossLow  float64 `mapstructure:"loss_low"`
	MinDrops int64   `mapstructure:"min_drops"`
	// MaxDivisor caps N. Default 64.
	MaxDivisor float64 `mapstructure:"max_divisor"`
	// CalmTicks is how many consecutive calm ticks lower N by one step.
	CalmTicks int `mapstructure:"calm_ticks"`
}

// DefaultOverloadConfig returns the production defaults.
func DefaultOverloadConfig() OverloadConfig {
	return OverloadConfig{
		Enabled:       true,
		CheckInterval: time.Second,
		FillHigh:      0.9,
		LossHigh:      0.05,
		LossLow:       0.01,
		MinDrops:      50,
		MaxDivisor:    64,
		CalmTicks:     5,
	}
}

// OverloadSignals are the controller's inputs, sampled once per tick.
type OverloadSignals struct {
	// BulkDropped / BulkAccepted are cumulative counters of the bulk class.
	BulkDropped  func() int64
	BulkAccepted func() int64
	// Fill returns the highest fill ratio (0..1) among the bulk queue and the
	// ingest workers' bulk channels.
	Fill func() float64
}

// OverloadShedder implements the loop. Safe for concurrent reads of Active/Divisor.
type OverloadShedder struct {
	cfg    OverloadConfig
	logger *slog.Logger
	ctrl   BPFSamplingController
	sig    OverloadSignals

	mu       sync.Mutex
	divisor  float64 // 1 == off
	calm     int
	holdTill time.Time
	lastDrop int64
	lastAcc  int64
	started  bool

	divisorGauge prometheus.Gauge
	activeGauge  prometheus.Gauge
	stepsTotal   *prometheus.CounterVec
}

// NewOverloadShedder builds the controller; ctrl is the named "overload" view
// of the sampling arbiter and may be nil (state and metrics only).
func NewOverloadShedder(cfg OverloadConfig, logger *slog.Logger, ctrl BPFSamplingController, sig OverloadSignals) *OverloadShedder {
	def := DefaultOverloadConfig()
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = def.CheckInterval
	}
	if cfg.FillHigh <= 0 {
		cfg.FillHigh = def.FillHigh
	}
	if cfg.LossLow <= 0 {
		cfg.LossLow = def.LossLow
	}
	if cfg.LossHigh <= 0 {
		cfg.LossHigh = def.LossHigh
	}
	if cfg.MinDrops <= 0 {
		cfg.MinDrops = def.MinDrops
	}
	if cfg.MaxDivisor < 2 {
		cfg.MaxDivisor = def.MaxDivisor
	}
	if cfg.CalmTicks <= 0 {
		cfg.CalmTicks = def.CalmTicks
	}
	if logger == nil {
		logger = slog.Default()
	}
	s := &OverloadShedder{
		cfg: cfg, logger: logger, ctrl: ctrl, sig: sig, divisor: 1,
		divisorGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpf_guard_overload_shed_divisor",
			Help: "Overload controller's file sampling divisor N (1 in N events from hot processes); 1 == shedding off.",
		}),
		activeGauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ebpf_guard_overload_shed_active",
			Help: "1 while the overload controller is shedding bulk file events in the kernel.",
		}),
		stepsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpf_guard_overload_shed_steps_total",
			Help: "Overload controller divisor changes by direction (up=shed more, down=shed less).",
		}, []string{"direction"}),
	}
	s.divisorGauge.Set(1)
	s.stepsTotal.WithLabelValues("up").Add(0)
	s.stepsTotal.WithLabelValues("down").Add(0)
	return s
}

// RegisterMetrics registers the controller's metrics.
func (s *OverloadShedder) RegisterMetrics(reg prometheus.Registerer) error {
	for _, c := range []prometheus.Collector{s.divisorGauge, s.activeGauge, s.stepsTotal} {
		if err := reg.Register(c); err != nil {
			return err
		}
	}
	return nil
}

// Active reports whether bulk shedding is currently on.
func (s *OverloadShedder) Active() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.divisor > 1
}

// Divisor returns the current N (1 == off).
func (s *OverloadShedder) Divisor() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.divisor
}

// Start runs the loop until ctx is cancelled.
func (s *OverloadShedder) Start(ctx context.Context) {
	t := time.NewTicker(s.cfg.CheckInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.mu.Lock()
			s.applyLocked(1)
			s.mu.Unlock()
			return
		case now := <-t.C:
			s.Step(now)
		}
	}
}

// Step evaluates one tick at time now.
func (s *OverloadShedder) Step(now time.Time) {
	var drop, acc int64
	if s.sig.BulkDropped != nil {
		drop = s.sig.BulkDropped()
	}
	if s.sig.BulkAccepted != nil {
		acc = s.sig.BulkAccepted()
	}
	fill := 0.0
	if s.sig.Fill != nil {
		fill = s.sig.Fill()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started {
		s.started, s.lastDrop, s.lastAcc = true, drop, acc
		return
	}
	dd, da := drop-s.lastDrop, acc-s.lastAcc
	s.lastDrop, s.lastAcc = drop, acc
	if dd < 0 {
		dd = 0
	}
	if da < 0 {
		da = 0
	}
	lossFrac := 0.0
	if dd+da > 0 {
		lossFrac = float64(dd) / float64(dd+da)
	}
	pressure := dd >= s.cfg.MinDrops && (lossFrac >= s.cfg.LossHigh || (fill >= s.cfg.FillHigh && lossFrac >= s.cfg.LossLow))
	calm := lossFrac <= s.cfg.LossLow

	switch {
	case pressure:
		s.calm = 0
		if now.Before(s.holdTill) {
			return // let the previous step take effect before the next one
		}
		next := s.divisor*1.5 + 0.5
		if next > s.cfg.MaxDivisor {
			next = s.cfg.MaxDivisor
		}
		if next != s.divisor {
			s.stepsTotal.WithLabelValues("up").Inc()
			s.logStepLocked("up", next, fill, lossFrac, dd)
			s.applyLocked(next)
			s.holdTill = now.Add(2 * s.cfg.CheckInterval)
		}
	case calm:
		if s.divisor <= 1 {
			return
		}
		s.calm++
		if s.calm < s.cfg.CalmTicks {
			return
		}
		s.calm = 0
		next := s.divisor / 1.25
		if next < 1.1 {
			next = 1
		}
		s.stepsTotal.WithLabelValues("down").Inc()
		s.logStepLocked("down", next, fill, lossFrac, dd)
		s.applyLocked(next)
	default:
		s.calm = 0
	}
}

func (s *OverloadShedder) logStepLocked(dir string, next, fill, lossFrac float64, dd int64) {
	// Start and end of shedding are INFO events; intermediate steps are debug.
	lvl := slog.LevelDebug
	if (dir == "up" && s.divisor <= 1) || (dir == "down" && next <= 1) {
		lvl = slog.LevelWarn
		if dir == "down" {
			lvl = slog.LevelInfo
		}
	}
	s.logger.Log(context.Background(), lvl, "overload: bulk file shedding "+dir,
		slog.Float64("divisor_from", s.divisor), slog.Float64("divisor_to", next),
		slog.Float64("queue_fill", fill), slog.Float64("loss_fraction_tick", lossFrac), slog.Int64("dropped_tick", dd))
}

func (s *OverloadShedder) applyLocked(n float64) {
	s.divisor = n
	s.divisorGauge.Set(n)
	if n > 1 {
		s.activeGauge.Set(1)
	} else {
		s.activeGauge.Set(0)
	}
	if s.ctrl != nil {
		s.ctrl.SetSamplingRate("file", 1/n)
	}
}
