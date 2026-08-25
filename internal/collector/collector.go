// Package collector provides eBPF-based event collection from the kernel.
package collector

import (
	"context"
	"encoding/hex"
	"log/slog"
	"math/rand"
	"sync"
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

// runReadLoop starts fn (a collector's readLoop) in a goroutine and blocks
// until it returns.
//
// Each collector's Start used to do `go c.readLoop(ctx, out); <-ctx.Done();
// return nil` — returning as soon as ctx was cancelled, without waiting for
// readLoop to actually stop. readLoop can still be parked in a blocking ring
// buffer Read() at that point; it only unblocks once Close() runs, which
// happens later, after ctx is already done (cmd/ebpf-guard's gracefulShutdown
// closes collectors after the context is cancelled). The caller of Start
// (PriorityEventCollector) closes its hand-off channel as soon as Start
// returns, so a readLoop still in flight would send on a closed channel —
// exactly the "send on closed channel" panic on graceful shutdown (5.8d,
// finding №20). Start must not return until readLoop has actually stopped
// calling sendEvent on `out`.
func runReadLoop(fn func()) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	return done
}

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

// malformedLogger throttles hex-dump diagnostic warnings for one
// malformed-record reason (see exporter.EventsMalformed) to at most one line
// per interval, keeping the most recent offending sample. Wave 5.9.2c
// (finding #40): the counter alone says a reason fired; the sample is what
// lets a human confirm which hypothesis it actually is, without flooding the
// log at ring-buffer rate.
type malformedLogger struct {
	interval    time.Duration
	lastLogTime atomic.Int64
	pending     atomic.Int64

	mu         sync.Mutex
	lastSample []byte
	// lastExtra holds the structured fields (5.9.6g, №65) passed alongside
	// the last recorded sample — e.g. DNS's direction/payload_len. Kept
	// next to lastSample under the same lock so the fields logged when the
	// throttle window opens describe the SAME occurrence as sample_hex,
	// not a stale one from an earlier call that happened to lose the race.
	lastExtra []slog.Attr
}

func newMalformedLogger(interval time.Duration) *malformedLogger {
	return &malformedLogger{interval: interval}
}

// record notes one occurrence of reason, keeping up to the first 48 bytes of
// raw as the sample logged when the throttle window next opens. extra is an
// optional set of structured fields describing this specific occurrence
// (5.9.6g) — e.g. the DNS event's direction and payload_len, which the
// caller already parsed from the fixed header before the payload itself
// failed to decode, and which a hex dump alone forces a human to re-derive
// by hand. Existing callers (syscall.go) pass none and are unaffected.
//
// logger is expected to already carry a "collector" attribute (bound via
// .With, the same convention every collector's c.logger already follows)
// — record does not add its own, since doing so on top of an already-bound
// logger duplicated the "collector" key in the emitted JSON (finding #127).
func (m *malformedLogger) record(logger *slog.Logger, reason string, raw []byte, extra ...slog.Attr) {
	m.pending.Add(1)

	n := len(raw)
	if n > 48 {
		n = 48
	}
	m.mu.Lock()
	m.lastSample = append(m.lastSample[:0], raw[:n]...)
	m.lastExtra = append([]slog.Attr(nil), extra...)
	m.mu.Unlock()

	now := time.Now().UnixNano()
	last := m.lastLogTime.Load()
	if now-last < m.interval.Nanoseconds() {
		return
	}
	if !m.lastLogTime.CompareAndSwap(last, now) {
		return
	}
	count := m.pending.Swap(0)
	if count == 0 {
		return
	}
	m.mu.Lock()
	sample := hex.EncodeToString(m.lastSample)
	lastExtra := m.lastExtra
	m.mu.Unlock()
	args := []any{
		slog.String("reason", reason),
		slog.Int64("count", count),
		slog.String("window", m.interval.String()),
		slog.String("sample_hex", sample),
	}
	for _, a := range lastExtra {
		args = append(args, a)
	}
	logger.Warn("malformed event record", args...)
}
