// Package collector provides eBPF-based event collection from the kernel.
package collector

// StatusReporter is implemented by anything that can track collector up/down status.
// This interface decouples collectors from the exporter package, eliminating the
// collector→exporter import dependency.
type StatusReporter interface {
	// SetUp marks the named collector as up (true) or down (false).
	SetUp(name string, up bool)
}

// NoopStatusReporter discards all status updates. Useful in tests.
type NoopStatusReporter struct{}

func (NoopStatusReporter) SetUp(_ string, _ bool) {}
