package bpf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// ObserverFilterController manages the in-kernel measurement-harness exclusion
// (observer_root_pid, observer_tree_cache, observer_excluded_counters).
//
// This is the kernel-side replacement for the correlator filter added in 5.9a.
// That version walked the lineage tracker — and, on a cache miss, bootstrapped
// the ancestor chain from /proc — once per event, on the agent's hottest path,
// in order to decide that the event should be discarded. The BPF side now
// decides the same thing before bpf_ringbuf_reserve, so a harness event costs
// one LRU lookup instead of a ring-buffer crossing, a router hop, a shard
// insert and a /proc walk.
//
// The controller is deliberately its own type rather than a field on
// KernelFilterController for the same reason PathFilterController is: it is
// test-only (correlator.observer_exclude, set in config-test.yaml), it is the
// one filter whose root PID changes at runtime, and folding it into the
// general filter surface would make it look like something a production
// deployment is expected to configure.
type ObserverFilterController struct {
	rootMap  bpfMap
	countMap bpfMap
}

// NewObserverFilterController creates a controller backed by
// observer_root_pid. countersMap may be nil — ReadExcludedCount then returns 0
// instead of erroring, matching PathFilterController: the counter is
// diagnostic, and its absence must not stop the filter itself from working.
//
// Parameters are typed *ebpf.Map rather than the internal bpfMap interface so
// the nil checks below are meaningful — a nil *ebpf.Map stored in an interface
// field yields a non-nil interface holding a nil pointer, which would defeat
// "rootMap == nil" and turn a missing map into a nil-pointer dereference at
// the first Update.
func NewObserverFilterController(rootMap, countersMap *ebpf.Map) (*ObserverFilterController, error) {
	if rootMap == nil {
		return nil, fmt.Errorf("bpf: observer_root_pid is nil")
	}
	c := &ObserverFilterController{rootMap: rootMap}
	if countersMap != nil {
		c.countMap = countersMap
	}
	return c, nil
}

// SetRootPID publishes the measurement harness's root TGID to the kernel.
// Every task whose real_parent chain reaches this TGID has its events dropped
// before the ring buffer.
//
// Passing 0 is rejected rather than treated as "disable": the BPF side reads 0
// as "not configured", so accepting it here would report success while
// silently leaving the filter off — the same trap SetAgentPID guards against.
// Use ClearRootPID when disabling is what is actually wanted.
func (o *ObserverFilterController) SetRootPID(pid uint32) error {
	if pid == 0 {
		return fmt.Errorf("bpf: observer root pid 0 is invalid (0 means the filter is disabled)")
	}
	key := uint32(0)
	if err := o.rootMap.Update(key, pid, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("bpf: set observer root pid %d: %w", pid, err)
	}
	return nil
}

// ClearRootPID disables the filter by writing the "not configured" sentinel.
func (o *ObserverFilterController) ClearRootPID() error {
	key := uint32(0)
	if err := o.rootMap.Update(key, uint32(0), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("bpf: clear observer root pid: %w", err)
	}
	return nil
}

// RootPID returns the root TGID currently published to the kernel, or 0 when
// the filter is not configured or the map cannot be read.
func (o *ObserverFilterController) RootPID() uint32 {
	key := uint32(0)
	var pid uint32
	if err := o.rootMap.Lookup(key, &pid); err != nil {
		return 0
	}
	return pid
}

// ReadExcludedCount reads and sums the per-CPU counter from
// observer_excluded_counters. Returns 0, nil when no counters map was supplied.
//
// The value is cumulative since BPF load; callers publishing it as a
// Prometheus counter must report the delta since their last read, and must
// re-baseline rather than subtract if it goes backwards (a collector reload
// recreates the map and restarts the count from zero — subtracting there would
// add ~2^64 to the series in one tick).
func (o *ObserverFilterController) ReadExcludedCount() (uint64, error) {
	if o.countMap == nil {
		return 0, nil
	}
	key := uint32(0)
	var perCPU []uint64
	if err := o.countMap.Lookup(key, &perCPU); err != nil {
		return 0, fmt.Errorf("bpf: read observer_excluded_counters: %w", err)
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total, nil
}
