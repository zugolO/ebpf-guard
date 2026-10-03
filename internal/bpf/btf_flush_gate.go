package bpf

import (
	"sync"
	"sync/atomic"
)

// KernelBTFFlushGate observes the load outcome of the collectors that load BPF
// objects and flushes cilium/ebpf's process-global kernel BTF cache exactly
// once, after the LAST of them has reported. The full decision record — why the
// flush must wait for all loaders, and which post-startup loads are dormant —
// lives at the call site in cmd/ebpf-guard/main.go (wave-8.1 item 4).
//
// The ordering invariants are the point of this type:
//   - Arm is called once, with the number of collectors expected to report,
//     before any Start goroutine exists.
//   - Report de-duplicates by collector name, so a collector that publishes a
//     second time (e.g. a future up→down transition) cannot consume another
//     collector's slot and fire the flush early.
//   - The flush runs under sync.Once: concurrent last reports still flush once.
//
// Fail-safe direction: if a collector never reports, the countdown never
// reaches zero and the cache is simply retained — the gate never flushes early.
type KernelBTFFlushGate struct {
	pending atomic.Int64
	once    sync.Once

	mu       sync.Mutex
	reported map[string]bool

	// flush is the side effect run exactly once when the countdown reaches zero.
	// Defaults to FlushKernelBTF; tests replace it to observe the call.
	flush func()
}

// NewKernelBTFFlushGate returns a disarmed gate whose flush drops the cached
// kernel BTF spec. Arm it before collectors start reporting.
func NewKernelBTFFlushGate() *KernelBTFFlushGate {
	return &KernelBTFFlushGate{
		reported: make(map[string]bool, 16),
		flush:    FlushKernelBTF,
	}
}

// Arm sets the number of collectors expected to report a load outcome. Call it
// after every collector was appended and before any Start goroutine exists, so
// no report can be lost. Zero (dry-run/synthetic) leaves the gate disarmed.
func (g *KernelBTFFlushGate) Arm(n int) {
	g.pending.Store(int64(n))
}

// Pending reports how many armed collectors have not yet reported a load
// outcome. It stays > 0 forever if a collector stalls before reporting, which is
// the signal the caller uses to warn that the flush will never run.
func (g *KernelBTFFlushGate) Pending() int64 {
	return g.pending.Load()
}

// Report records one collector's load outcome. A repeated report for the same
// name is ignored. It returns true exactly on the call that drove the countdown
// to zero and ran the flush, so the caller can log the release; every other
// call — including concurrent duplicates of the last name — returns false.
func (g *KernelBTFFlushGate) Report(name string) bool {
	g.mu.Lock()
	alreadyReported := g.reported[name]
	g.reported[name] = true
	g.mu.Unlock()
	if alreadyReported {
		return false
	}
	if g.pending.Add(-1) != 0 {
		return false
	}

	flushed := false
	g.once.Do(func() {
		g.flush()
		flushed = true
	})
	return flushed
}
