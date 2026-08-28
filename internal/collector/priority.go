// Package collector provides eBPF-based event collection from the kernel.
package collector

import (
	"context"
	"log/slog"
	"time"

	"github.com/zugolO/ebpf-guard/internal/exporter"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Compile-time assertion: the wrapper is handed to the same start loop as any
// other collector, so it must satisfy the interface. Without this, a signature
// drift only shows up at the call site in cmd/ebpf-guard.
var _ Collector = (*PriorityEventCollector)(nil)

// PriorityEventCollector wraps a collector and routes events to priority-specific channels.
// High-priority events (network, dns) go to highPriorityCh, others to lowPriorityCh.
type PriorityEventCollector struct {
	collector       Collector
	highPriorityCh  chan<- types.Event
	lowPriorityCh   chan<- types.Event
	eventPriorityFn func(types.EventType) bool
	strategy        BackpressureStrategy
	droppedFn       func(collectorName string, isHighPriority bool)
	acceptedFn      func(collectorName string, isHighPriority bool)
	logger          *slog.Logger
	dropLogger      *dropLogger
}

// NewPriorityEventCollector creates a new priority-aware collector wrapper.
// droppedFn and acceptedFn are both optional; together they let the caller
// compute a loss fraction rather than only an absolute drop count.
func NewPriorityEventCollector(c Collector, highPriorityCh, lowPriorityCh chan<- types.Event, strategy BackpressureStrategy, droppedFn, acceptedFn func(collectorName string, isHighPriority bool), logger *slog.Logger) *PriorityEventCollector {
	if logger == nil {
		logger = slog.Default()
	}
	return &PriorityEventCollector{
		collector:       c,
		highPriorityCh:  highPriorityCh,
		lowPriorityCh:   lowPriorityCh,
		eventPriorityFn: defaultEventPriority,
		strategy:        strategy,
		droppedFn:       droppedFn,
		acceptedFn:      acceptedFn,
		logger:          logger,
		dropLogger:      newDropLogger(5 * time.Second),
	}
}

// defaultEventPriority determines event priority for queue routing.
//
// The split is by flood source, not by perceived importance. Run #4 measured
// file events at 99.4% of the stream (~5800/s on an idle host) while network
// carried the entire useful signal in 0.2% — a single shared queue let file
// starve everything else (52% network loss, 55% syscall loss). Only
// EventFileAccess is therefore demoted; everything else, syscall included,
// shares the protected queue so the P0-25 criterion (network/dns zero loss,
// syscall < 1%) is reachable.
func defaultEventPriority(eventType types.EventType) bool {
	return eventType != types.EventFileAccess
}

// Name returns the wrapped collector's name.
func (p *PriorityEventCollector) Name() string {
	return p.collector.Name()
}

// Start starts the wrapped collector and fans its events out to the priority
// channels. It satisfies collector.Collector: the `out` parameter is the queue
// the wrapper would have used had it not been splitting by priority, so it is
// accepted and ignored — callers pass the low-priority channel by convention.
//
// Start blocks until the wrapped collector returns, matching the interface
// contract that Start blocks until ctx is cancelled.
func (p *PriorityEventCollector) Start(ctx context.Context, _ chan<- types.Event) error {
	// Internal hand-off channel between the wrapped collector and the router.
	internalCh := make(chan types.Event, priorityRouterBuffer)

	routerDone := make(chan struct{})
	go func() {
		defer close(routerDone)
		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-internalCh:
				if !ok {
					return
				}
				p.routeEvent(ctx, event)
			}
		}
	}()

	err := p.collector.Start(ctx, internalCh)

	// The wrapped collector has returned, so no further sends can happen.
	// Close the hand-off channel and wait for the router to drain it, so
	// events already in flight are not silently discarded on shutdown.
	close(internalCh)
	<-routerDone
	return err
}

// priorityRouterBuffer sizes the hand-off channel between a wrapped collector
// and the priority router. It only has to absorb scheduling jitter — the real
// backpressure decision happens in routeEvent against the priority queues.
const priorityRouterBuffer = 1024

// Close closes the wrapped collector.
func (p *PriorityEventCollector) Close() error {
	return p.collector.Close()
}

// routeEvent sends an event to the appropriate priority channel.
//
// ctx must be the collector's context: with StrategyBlock, sendEvent parks on
// the target channel until it drains or ctx is cancelled, so passing a
// background context here would wedge the router for the process lifetime.
func (p *PriorityEventCollector) routeEvent(ctx context.Context, event types.Event) {
	isHighPriority := p.eventPriorityFn(event.Type)
	targetCh := p.lowPriorityCh
	if isHighPriority {
		targetCh = p.highPriorityCh
	}

	// Track drops for visibility degradation (P0-25). The high-priority flag is
	// what lets /health distinguish "we lost file noise" from "we lost the
	// security signal".
	dropped := false
	droppedFunc := func() {
		dropped = true
		p.dropLogger.record(p.logger.With(slog.String("collector", p.collector.Name())), "router_to_queue")
		if p.droppedFn != nil {
			p.droppedFn(p.collector.Name(), isHighPriority)
		}
		// plan.md 5.9.8b (№91): the router_to_queue hop is the third and last
		// place a canary event can go missing, and it is counted in the
		// general series (events_dropped_total{collector="fileaccess"}, via
		// droppedFn above) that the canary series has to stay comparable
		// with. Without this the canary sum would be short by exactly the
		// events lost here, and criterion 20 would read a real, explained
		// loss as an unexplained one — the inverse of the background bias
		// 5.9.8b exists to remove. Counted here rather than in main.go
		// because an event dropped at this hop never reaches processEvent.
		if event.Type == types.EventFileAccess && event.File != nil && exporter.IsCountingCanaryPath(event.File.FDPath) {
			exporter.RecordCountingCanary("dropped")
		}
	}

	sendEvent(ctx, targetCh, event, p.strategy, droppedFunc)

	// sendEvent reports failure but not success, so acceptance is inferred from
	// the drop callback not having fired. Safe here because routeEvent runs on
	// a single router goroutine per collector and `dropped` never escapes it.
	if !dropped && p.acceptedFn != nil {
		p.acceptedFn(p.collector.Name(), isHighPriority)
	}
}

// WithBackpressureStrategy sets the backpressure strategy (no-op for wrapper).
func (p *PriorityEventCollector) WithBackpressureStrategy(strategy BackpressureStrategy) Collector {
	p.strategy = strategy
	return p
}
