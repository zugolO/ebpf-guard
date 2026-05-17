// controllable.go — ControllableProfiler interface for memory-aware profiling
//
// This interface allows profilers to be dynamically enabled/disabled
// and have their sampling rates adjusted based on system memory pressure.
// Part of Sprint 22.0: Memory Pressure Auto-Tuning.

package profiler

// ControllableProfiler defines the interface for profilers that can be
// dynamically controlled based on system resource pressure.
//
// Implementations must be safe for concurrent use.
type ControllableProfiler interface {
	// Enable activates the profiler. If already enabled, this is a no-op.
	Enable()

	// Disable deactivates the profiler. If already disabled, this is a no-op.
	Disable()

	// IsEnabled returns true if the profiler is currently active.
	IsEnabled() bool

	// SetSamplingRate adjusts the profiler's sampling rate.
	// rate must be in range [0.0, 1.0] where 1.0 means 100% sampling.
	// A rate of 0.0 effectively disables the profiler.
	SetSamplingRate(rate float64)

	// GetSamplingRate returns the current sampling rate.
	GetSamplingRate() float64
}

// Ensure SequenceProfiler implements ControllableProfiler
var _ ControllableProfiler = (*SequenceProfiler)(nil)

// Ensure AnomalyDetector implements ControllableProfiler
var _ ControllableProfiler = (*AnomalyDetector)(nil)
