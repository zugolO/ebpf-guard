package bpf

// SumPerCPUUint64 reads and sums a single-slot (key 0) PERCPU_ARRAY uint64
// counter map — the shape ringbuf_full_counters, path_filter_drop_counters,
// observer_excluded_counters, and net_block_counters all share.
//
// m must be non-nil: unlike PathFilterController/ObserverFilterController,
// which own their counter map and can meaningfully check "was one supplied"
// in their constructor, this is a free function taking the bpfMap interface
// — a nil *ebpf.Map passed in as that interface would arrive here as a
// non-nil interface wrapping a nil pointer, which Lookup would then panic
// on. Callers check nil on the concrete *ebpf.Map before calling, the same
// way ringbufFullRegistry.register in cmd/ebpf-guard/main.go does.
func SumPerCPUUint64(m bpfMap) (uint64, error) {
	key := uint32(0)
	var perCPU []uint64
	if err := m.Lookup(key, &perCPU); err != nil {
		return 0, err
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total, nil
}
