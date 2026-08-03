// multibpf.go — fan-out + arbitrating BPF sampling controller for ebpf-guard
//
// Each collector (syscall, network, fileaccess) owns an independent BPF
// sampling_config map and its own SamplingController. The pressure watchers,
// however, speak a single BPFSamplingController interface keyed by event type.
// MultiBPFController bridges the two: it routes a SetSamplingRate call for an
// event type to the controller registered for that collector.
//
// It is also the single arbitration point between the several independent
// writers of the same sampling knob (issue #304). Without arbitration each
// writer overwrote the shared BPF map with an absolute rate, so:
//
//   - a CPU-pressure recovery restored a hardcoded 1.0, silently discarding the
//     operator's configured base rate (e.g. syscall 1-in-4) until restart, and
//   - the CPU watcher and the ring-buffer load controller fought: one
//     recovering to 1.0 would undo the other's active degradation.
//
// Instead of absolute rates, MultiBPFController tracks a configured *base* rate
// per event type plus a *multiplier* per (controller, event type). The
// effective rate written to the BPF map is base × min(multipliers): the
// tightest degradation any controller currently wants, layered on top of the
// operator's base. Recovering one controller sets its multiplier back to 1.0
// without touching another controller's, and never overwrites the base.

package watchdog

import (
	"log/slog"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// legacyControllerName is the multiplier bucket used by the bare
// SetSamplingRate entrypoint (BPFSamplingController), for callers that have not
// been given a named Controller view.
const legacyControllerName = "legacy"

// BPFRateController is the per-collector control surface that MultiBPFController
// fans out to. The production *bpf.SamplingController satisfies it.
type BPFRateController interface {
	SetSamplingRate(eventType string, rate float64) error
}

// MultiBPFController fans watchdog SetSamplingRate calls out to per-collector
// BPF controllers keyed by event type ("syscall", "network", "file"), while
// arbitrating between multiple independent rate writers. It implements
// BPFSamplingController and is safe for concurrent use.
//
// Controllers are registered lazily as their collectors come up, so a rate
// change for an event type with no registered controller is remembered and
// applied when that controller registers.
type MultiBPFController struct {
	mu          sync.Mutex
	logger      *slog.Logger
	controllers map[string]BPFRateController

	// base is the operator-configured base rate per event type (default 1.0).
	base map[string]float64
	// multipliers is controllerName -> eventType -> factor in [0,1]. The
	// effective rate is base × the minimum factor across all controllers.
	multipliers map[string]map[string]float64

	effectiveGauge *prometheus.GaugeVec
}

// NewMultiBPFController creates an empty multiplexer.
func NewMultiBPFController(logger *slog.Logger) *MultiBPFController {
	if logger == nil {
		logger = slog.Default()
	}
	return &MultiBPFController{
		logger:      logger,
		controllers: make(map[string]BPFRateController),
		base:        make(map[string]float64),
		multipliers: make(map[string]map[string]float64),
		effectiveGauge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ebpf_guard_effective_sampling_rate",
			Help: "Effective BPF sampling rate per event type after arbitration (base rate x minimum controller multiplier; 1.0 = all events).",
		}, []string{"event_type"}),
	}
}

// RegisterMetrics registers the controller's Prometheus collectors.
func (m *MultiBPFController) RegisterMetrics(reg prometheus.Registerer) error {
	return reg.Register(m.effectiveGauge)
}

// Register associates a controller with an event type. Called from collector
// status reporters as each collector comes up. A later registration for the
// same event type replaces the earlier one. If a degraded effective rate is
// already pending for this event type (a watcher shed it before the collector
// came up), it is applied immediately so the new controller does not start at
// full rate.
func (m *MultiBPFController) Register(eventType string, ctrl BPFRateController) {
	if ctrl == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.controllers[eventType] = ctrl
	// Only push if arbitration has already produced a degraded rate; at full
	// rate the collector's own startup config is authoritative and we avoid a
	// redundant map write.
	if m.effectiveLocked(eventType) < 1.0 {
		m.applyLocked(eventType)
	}
}

// SetBaseRate records the operator-configured base sampling rate for an event
// type (1.0 = all events). The effective rate is this base scaled by whatever
// degradation the pressure controllers currently request, so recovery restores
// exactly this value rather than a hardcoded 1.0.
func (m *MultiBPFController) SetBaseRate(eventType string, rate float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.base[eventType] = rate
	m.applyLocked(eventType)
}

// SetSamplingRate implements BPFSamplingController for callers holding the bare
// multiplexer (e.g. the memory-pressure watcher). The rate is treated as this
// caller's multiplier over the configured base, arbitrated against every other
// controller. Named controllers should use Controller instead so their
// degradations are attributed and coordinated independently.
func (m *MultiBPFController) SetSamplingRate(eventType string, rate float64) {
	m.setMultiplier(legacyControllerName, eventType, rate)
}

// Controller returns a named view onto the arbiter. Each named controller's
// SetSamplingRate calls record a multiplier under that name, so recovering one
// controller (setting its multiplier back to 1.0) never overwrites another
// controller's still-active degradation.
func (m *MultiBPFController) Controller(name string) BPFSamplingController {
	return &bpfControllerView{parent: m, name: name}
}

// setMultiplier records a per-controller multiplier and re-applies the
// arbitrated effective rate for the event type.
func (m *MultiBPFController) setMultiplier(name, eventType string, factor float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	byType := m.multipliers[name]
	if byType == nil {
		byType = make(map[string]float64)
		m.multipliers[name] = byType
	}
	byType[eventType] = factor
	m.applyLocked(eventType)
}

// effectiveLocked computes base × min(multipliers) for an event type, clamped
// to [0,1]. Must be called with m.mu held.
func (m *MultiBPFController) effectiveLocked(eventType string) float64 {
	base, ok := m.base[eventType]
	if !ok {
		base = 1.0
	}
	minMult := 1.0
	for _, byType := range m.multipliers {
		if f, ok := byType[eventType]; ok && f < minMult {
			minMult = f
		}
	}
	eff := base * minMult
	if eff < 0 {
		eff = 0
	}
	if eff > 1.0 {
		eff = 1.0
	}
	return eff
}

// applyLocked writes the current effective rate for an event type to the
// registered controller and updates the exported gauge. Must be called with
// m.mu held.
func (m *MultiBPFController) applyLocked(eventType string) {
	eff := m.effectiveLocked(eventType)
	m.effectiveGauge.WithLabelValues(eventType).Set(eff)
	ctrl := m.controllers[eventType]
	if ctrl == nil {
		return
	}
	if err := ctrl.SetSamplingRate(eventType, eff); err != nil {
		m.logger.Warn("multibpf: failed to adjust sampling rate",
			slog.String("event_type", eventType),
			slog.Float64("rate", eff),
			slog.Any("error", err))
	}
}

// EffectiveRates returns a snapshot of the current arbitrated effective rate
// per event type. Surfaced in metrics and /debug/state so an operator can see
// what is actually being sampled after all controllers have had their say.
func (m *MultiBPFController) EffectiveRates() map[string]float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	types := make(map[string]struct{})
	for et := range m.base {
		types[et] = struct{}{}
	}
	for _, byType := range m.multipliers {
		for et := range byType {
			types[et] = struct{}{}
		}
	}
	out := make(map[string]float64, len(types))
	for et := range types {
		out[et] = m.effectiveLocked(et)
	}
	return out
}

// bpfControllerView is a named handle onto MultiBPFController that records
// SetSamplingRate calls as its owner's multiplier. It implements
// BPFSamplingController.
type bpfControllerView struct {
	parent *MultiBPFController
	name   string
}

func (v *bpfControllerView) SetSamplingRate(eventType string, rate float64) {
	v.parent.setMultiplier(v.name, eventType, rate)
}
