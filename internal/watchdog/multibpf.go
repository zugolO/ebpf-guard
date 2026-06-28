// multibpf.go — fan-out BPF sampling controller for ebpf-guard
//
// Each collector (syscall, network, fileaccess) owns an independent BPF
// sampling_config map and its own SamplingController. The pressure watchers,
// however, speak a single BPFSamplingController interface keyed by event type.
// MultiBPFController bridges the two: it routes a SetSamplingRate call for an
// event type to the controller registered for that collector.

package watchdog

import (
	"log/slog"
	"sync"
)

// BPFRateController is the per-collector control surface that MultiBPFController
// fans out to. The production *bpf.SamplingController satisfies it.
type BPFRateController interface {
	SetSamplingRate(eventType string, rate float64) error
}

// MultiBPFController fans watchdog SetSamplingRate calls out to per-collector
// BPF controllers keyed by event type ("syscall", "network", "file"). It
// implements BPFSamplingController and is safe for concurrent use.
//
// Controllers are registered lazily as their collectors come up, so a rate
// change for an event type with no registered controller is silently dropped.
type MultiBPFController struct {
	mu          sync.Mutex
	logger      *slog.Logger
	controllers map[string]BPFRateController
}

// NewMultiBPFController creates an empty multiplexer.
func NewMultiBPFController(logger *slog.Logger) *MultiBPFController {
	if logger == nil {
		logger = slog.Default()
	}
	return &MultiBPFController{
		logger:      logger,
		controllers: make(map[string]BPFRateController),
	}
}

// Register associates a controller with an event type. Called from collector
// status reporters as each collector comes up. A later registration for the
// same event type replaces the earlier one.
func (m *MultiBPFController) Register(eventType string, ctrl BPFRateController) {
	if ctrl == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.controllers[eventType] = ctrl
}

// SetSamplingRate implements BPFSamplingController. It routes the call to the
// controller registered for eventType, logging (but not surfacing) any error
// from the underlying map write — a failed rate adjustment must not crash the
// pressure watcher's control loop.
func (m *MultiBPFController) SetSamplingRate(eventType string, rate float64) {
	m.mu.Lock()
	ctrl := m.controllers[eventType]
	m.mu.Unlock()
	if ctrl == nil {
		return
	}
	if err := ctrl.SetSamplingRate(eventType, rate); err != nil {
		m.logger.Warn("multibpf: failed to adjust sampling rate",
			slog.String("event_type", eventType),
			slog.Float64("rate", rate),
			slog.Any("error", err))
	}
}
