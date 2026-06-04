// Package watchdog provides heartbeat and BPF liveness monitoring.
package watchdog

import (
	"log/slog"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
)

// BPFTelemetry is a prometheus.Collector that scrapes per-program BPF
// execution statistics (run time, invocation count) directly from the kernel.
//
// It requires /proc/sys/kernel/bpf_stats_enabled=1 (kernel 5.1+). The
// constructor attempts to enable stats automatically; if that fails (e.g.
// no CAP_SYS_ADMIN) it logs a warning and emits zeros instead of failing.
//
// Register with prometheus.DefaultRegisterer and call RegisterProvider for
// each BPFProgramProvider whose programs should be scraped.
type BPFTelemetry struct {
	mu        sync.RWMutex
	providers []BPFProgramProvider
	logger    *slog.Logger

	descRunTime     *prometheus.Desc
	descRunCount    *prometheus.Desc
	descAvgRunNs    *prometheus.Desc
	descStatsEnabled *prometheus.Desc
}

// NewBPFTelemetry creates a BPFTelemetry collector and attempts to enable
// kernel-level BPF program stats. Pass the result to prometheus.Register.
func NewBPFTelemetry(logger *slog.Logger) *BPFTelemetry {
	if logger == nil {
		logger = slog.Default()
	}
	if !bpfStatsEnabled() {
		if err := os.WriteFile("/proc/sys/kernel/bpf_stats_enabled", []byte("1"), 0644); err != nil {
			logger.Warn("bpf_telemetry: cannot enable kernel BPF stats; per-program CPU metrics will be zero",
				slog.String("hint", "requires CAP_SYS_ADMIN and kernel 5.1+"),
				slog.Any("error", err))
		} else {
			logger.Info("bpf_telemetry: kernel BPF program stats enabled")
		}
	}

	return &BPFTelemetry{
		logger: logger,
		descRunTime: prometheus.NewDesc(
			"ebpf_guard_bpf_prog_run_time_seconds_total",
			"Cumulative CPU time spent inside the BPF program (requires bpf_stats_enabled).",
			[]string{"program"}, nil,
		),
		descRunCount: prometheus.NewDesc(
			"ebpf_guard_bpf_prog_run_count_total",
			"Cumulative number of times the BPF program was invoked.",
			[]string{"program"}, nil,
		),
		descAvgRunNs: prometheus.NewDesc(
			"ebpf_guard_bpf_prog_avg_run_time_nanoseconds",
			"Rolling average per-invocation run time of the BPF program in nanoseconds.",
			[]string{"program"}, nil,
		),
		descStatsEnabled: prometheus.NewDesc(
			"ebpf_guard_bpf_stats_enabled",
			"1 if /proc/sys/kernel/bpf_stats_enabled is active, 0 otherwise.",
			nil, nil,
		),
	}
}

// RegisterProvider adds a BPFProgramProvider whose programs are scraped on
// every Prometheus collection cycle. Safe to call after registration.
func (t *BPFTelemetry) RegisterProvider(p BPFProgramProvider) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.providers = append(t.providers, p)
}

// Describe implements prometheus.Collector.
func (t *BPFTelemetry) Describe(ch chan<- *prometheus.Desc) {
	ch <- t.descRunTime
	ch <- t.descRunCount
	ch <- t.descAvgRunNs
	ch <- t.descStatsEnabled
}

// Collect implements prometheus.Collector.
// It iterates every registered provider, calls prog.Info() for each program,
// and emits run-time and run-count metrics.
func (t *BPFTelemetry) Collect(ch chan<- prometheus.Metric) {
	statsVal := 0.0
	if bpfStatsEnabled() {
		statsVal = 1.0
	}
	ch <- prometheus.MustNewConstMetric(t.descStatsEnabled, prometheus.GaugeValue, statsVal)

	t.mu.RLock()
	providers := make([]BPFProgramProvider, len(t.providers))
	copy(providers, t.providers)
	t.mu.RUnlock()

	// Deduplicate by program name so two providers exposing the same program
	// (e.g. syscall tracepoints registered twice) don't double-count.
	seen := make(map[string]struct{})
	for _, p := range providers {
		for name, prog := range p.GetPrograms() {
			if prog == nil {
				continue
			}
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}
			t.emitProgStats(ch, name, prog)
		}
	}
}

func (t *BPFTelemetry) emitProgStats(ch chan<- prometheus.Metric, name string, prog *ebpf.Program) {
	info, err := prog.Info()
	if err != nil {
		t.logger.Debug("bpf_telemetry: prog.Info failed",
			slog.String("program", name), slog.Any("error", err))
		return
	}

	runTime, hasRunTime := info.Runtime()
	runCount, hasRunCount := info.RunCount()

	if hasRunTime {
		ch <- prometheus.MustNewConstMetric(
			t.descRunTime, prometheus.CounterValue,
			runTime.Seconds(),
			name,
		)
	}
	if hasRunCount {
		ch <- prometheus.MustNewConstMetric(
			t.descRunCount, prometheus.CounterValue,
			float64(runCount),
			name,
		)
	}
	if hasRunTime && hasRunCount && runCount > 0 {
		avgNs := float64(runTime.Nanoseconds()) / float64(runCount)
		ch <- prometheus.MustNewConstMetric(
			t.descAvgRunNs, prometheus.GaugeValue,
			avgNs,
			name,
		)
	}
}

// bpfStatsEnabled reads /proc/sys/kernel/bpf_stats_enabled.
func bpfStatsEnabled() bool {
	data, err := os.ReadFile("/proc/sys/kernel/bpf_stats_enabled")
	return err == nil && len(data) > 0 && data[0] == '1'
}
