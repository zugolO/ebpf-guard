// Package collector provides eBPF-based event collection from the kernel.
package collector

import (
	"context"
	"log/slog"
	"math/rand"
	"sync/atomic"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Collector defines the interface for eBPF event collectors.
// Each collector attaches specific eBPF programs and streams events
// to the provided channel.
type Collector interface {
	// Start attaches eBPF programs and begins sending events.
	// Blocks until ctx is cancelled.
	Start(ctx context.Context, out chan<- types.Event) error
	// Name returns a short identifier (e.g. "syscall", "network").
	Name() string
	// Close releases all eBPF resources.
	Close() error
}

// BackpressureStrategy controls collector behaviour when the event channel is full.
type BackpressureStrategy string

const (
	// StrategyDrop silently drops the event and increments the drop counter (default).
	StrategyDrop BackpressureStrategy = "drop"
	// StrategyBlock blocks the collector goroutine until the channel drains.
	StrategyBlock BackpressureStrategy = "block"
	// StrategySample drops with 50% probability, preserving approximate event rate.
	StrategySample BackpressureStrategy = "sample"
)

// sendEvent sends an event to the output channel according to the configured
// backpressure strategy. It is called from each collector's readLoop.
func sendEvent(ctx context.Context, out chan<- types.Event, e types.Event, strategy BackpressureStrategy, dropped func()) {
	switch strategy {
	case StrategyBlock:
		select {
		case out <- e:
		case <-ctx.Done():
		}
	case StrategySample:
		if rand.Intn(2) == 0 { //nolint:gosec // fast non-crypto sampling
			select {
			case out <- e:
			default:
				dropped()
			}
		} else {
			dropped()
		}
	default: // StrategyDrop
		select {
		case out <- e:
		default:
			dropped()
		}
	}
}

// dropLogger throttles "event dropped" log lines to at most one per interval,
// aggregating the drop count so operators see "dropped N events in last 5s"
// instead of one log line per dropped event (which itself causes CPU overhead).
type dropLogger struct {
	interval    time.Duration
	lastLogTime atomic.Int64 // Unix nanoseconds of last log emission
	pending     atomic.Int64 // events dropped since last log
}

func newDropLogger(interval time.Duration) *dropLogger {
	return &dropLogger{interval: interval}
}

// record increments the pending drop counter. If the throttle interval has
// elapsed since the last emission, it logs the aggregated count and resets.
func (d *dropLogger) record(logger *slog.Logger, collectorName string) {
	d.pending.Add(1)

	now := time.Now().UnixNano()
	last := d.lastLogTime.Load()
	if now-last < d.interval.Nanoseconds() {
		return
	}
	// Try to become the goroutine that logs (CAS last → now).
	if !d.lastLogTime.CompareAndSwap(last, now) {
		return
	}
	count := d.pending.Swap(0)
	if count > 0 {
		logger.Warn("event channel full, dropping events",
			slog.String("collector", collectorName),
			slog.Int64("dropped_count", count),
			slog.String("window", d.interval.String()))
	}
}
