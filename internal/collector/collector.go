// Package collector provides eBPF-based event collection from the kernel.
package collector

import (
	"context"

	"github.com/ebpf-guard/ebpf-guard/pkg/types"
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
