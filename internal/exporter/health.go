// Package exporter surfaces agent-internal operational state — CPU pressure
// load-shedding, drift-baseline learning progress, per-collector sampling
// rates, and the resolved hardware profile — to GET /api/v1/status, so a
// VPS operator without a Prometheus/Grafana stack (issue #287's audience)
// can tell "no alerts because nothing happened" apart from "no alerts
// because the agent degraded visibility" (issue #309).
package exporter

// AgentHealth is the agent-health snapshot embedded in StatusAPIResponse.
// Populated via SetAgentHealthProvider; omitted from the response when no
// provider is configured (dry-run mode, or an older agent build).
type AgentHealth struct {
	// CPUPressureLevel mirrors ebpf_guard_cpu_pressure_level: 0=normal,
	// 1=file sampling reduced, 2=file+syscall+network reduced.
	CPUPressureLevel int `json:"cpu_pressure_level"`
	// CPUPressurePercent mirrors ebpf_guard_cpu_pressure_percent: smoothed
	// agent CPU usage as a percentage of a single core.
	CPUPressurePercent float64 `json:"cpu_pressure_percent"`
	// VisibilityReduced is true when CPUPressureLevel > 0 — i.e. some
	// collector is currently sampled below its configured rate, so an
	// absence of alerts may reflect reduced visibility rather than an
	// absence of activity.
	VisibilityReduced bool `json:"visibility_reduced"`
	// SamplingRates maps collector/event-type name (e.g. "file", "syscall",
	// "network") to its current effective sampling rate (1.0 == full rate).
	SamplingRates map[string]float64 `json:"sampling_rates,omitempty"`
	// DriftLearningWorkloads is the number of workloads still inside the
	// drift-baseline learning window (class: drift rules are suppressed for
	// these until their baseline is established).
	DriftLearningWorkloads int `json:"drift_learning_workloads"`
	// DriftStuckWorkloads is the number of workloads that have exceeded their
	// learning-period deadline without reaching MinSamples — a sign the
	// workload is too low-traffic to ever complete learning on its own.
	DriftStuckWorkloads int `json:"drift_stuck_workloads"`
	// DriftProfilesActive is the total number of workloads with an active
	// drift baseline (learning or learned).
	DriftProfilesActive int `json:"drift_profiles_active"`
	// HardwareProfile is the resolved lite/balanced/production tuning
	// profile name (see HardwareProfileState).
	HardwareProfile string `json:"hardware_profile,omitempty"`
}

// SetAgentHealthProvider wires the function that supplies the agent-health
// snapshot returned by GET /api/v1/status. Must be called before Start; nil
// (the default) omits the "health" field from the status response.
func (s *Server) SetAgentHealthProvider(fn func() AgentHealth) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agentHealthFn = fn
}

// getAgentHealth returns the current agent-health snapshot and whether a
// provider is configured.
func (s *Server) getAgentHealth() (AgentHealth, bool) {
	s.mu.RLock()
	fn := s.agentHealthFn
	s.mu.RUnlock()
	if fn == nil {
		return AgentHealth{}, false
	}
	return fn(), true
}
