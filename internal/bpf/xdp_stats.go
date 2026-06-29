package bpf

import "fmt"

// XDPPerCPUStats mirrors C struct xdp_stats in bpf/xdp_block.bpf.c.
// xdp_stats_map is BPF_MAP_TYPE_PERCPU_ARRAY, so a Lookup returns one
// XDPPerCPUStats value per logical CPU; ReadXDPStats sums them.
type XDPPerCPUStats struct {
	Dropped uint64
	Passed  uint64
}

// XDPAggregate is the sum of XDPPerCPUStats across all CPUs.
type XDPAggregate struct {
	Dropped uint64
	Passed  uint64
}

// ReadXDPStats reads xdp_stats_map (BPF_MAP_TYPE_PERCPU_ARRAY, key 0)
// and returns the total drop and pass counts summed across all CPU slots.
func ReadXDPStats(statsMap bpfMap) (XDPAggregate, error) {
	if statsMap == nil {
		return XDPAggregate{}, fmt.Errorf("bpf: xdp_stats_map is nil")
	}
	key := uint32(0)
	var perCPU []XDPPerCPUStats
	if err := statsMap.Lookup(key, &perCPU); err != nil {
		return XDPAggregate{}, fmt.Errorf("bpf: read xdp_stats_map: %w", err)
	}
	var agg XDPAggregate
	for _, v := range perCPU {
		agg.Dropped += v.Dropped
		agg.Passed += v.Passed
	}
	return agg, nil
}
