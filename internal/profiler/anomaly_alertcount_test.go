package profiler

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestRecordPublishedAnomaly_IncrementsAlertCount is the 1.75b acceptance test
// (plan.md волна 1.75b). /debug/state's anomalies_total is summed by
// CountAlertTotal → profile.AlertCount. Before 1.75b that field was only
// written during persistence restore, so /debug/state reported 0 while
// /metrics climbed (46 vs 0 in замер №1). RecordPublishedAnomaly is the live
// write that closes the gap; after N calls on the same workload,
// AlertTotal() must equal N exactly.
func TestRecordPublishedAnomaly_IncrementsAlertCount(t *testing.T) {
	ad := NewAnomalyDetector(0.7, time.Hour, 0.3)
	require.NotNil(t, ad)

	var comm [16]byte
	copy(comm[:], "sqlmap")
	event := types.Event{
		Type: types.EventSyscall,
		PID:  42,
		Comm: comm,
		Syscall: &types.SyscallEvent{
			Nr: 1,
		},
	}

	// Seed the workload profile by recording the event during learning so
	// GetByKey has something to find. Without this the increment is a no-op
	// (the detector never saw this comm) and the test would silently pass
	// without exercising the field write.
	ad.profileManager.RecordEvent(event)

	// Sanity: no anomalies recorded yet.
	require.Equal(t, uint64(0), ad.AlertTotal(), "fresh detector must report zero anomalies")

	const n = 5
	for i := 0; i < n; i++ {
		ad.RecordPublishedAnomaly(event)
	}

	assert.Equal(t, uint64(n), ad.AlertTotal(),
		"AlertTotal must equal the number of RecordPublishedAnomaly calls — "+
			"this is what makes /debug/state and /metrics converge by construction")
}

// TestRecordPublishedAnomaly_NilSafe guards the engine's hot path: the
// publish-time call site in engine.go would panic on a nil detector if not
// for the explicit nil check, and a profile-less event (never recorded) must
// be a no-op rather than panic — e.g. the first event for a brand-new comm.
func TestRecordPublishedAnomaly_NilSafe(t *testing.T) {
	var ad *AnomalyDetector
	// Must not panic on nil receiver.
	ad.RecordPublishedAnomaly(types.Event{})

	// Fresh detector with no profile for this event: also a no-op.
	live := NewAnomalyDetector(0.7, time.Hour, 0.3)
	live.RecordPublishedAnomaly(types.Event{Type: types.EventSyscall, PID: 999})
	assert.Equal(t, uint64(0), live.AlertTotal(),
		"event for a workload the detector never saw must not bump AlertCount")
}

// TestCountAlertTotal_AggregatesShards verifies the aggregator that
// ProfilerStats uses still walks every shard after RecordPublishedAnomaly
// writes — i.e. the increment is visible through the package-level read path,
// not just via the detector's own AlertTotal(). This guards against a future
// refactor that sums only one shard and silently drops the others.
func TestCountAlertTotal_AggregatesShards(t *testing.T) {
	ad := NewAnomalyDetector(0.7, time.Hour, 0.3)

	// Spread writes across several workload keys so they land in different
	// shards of the WorkloadProfileManager (16 shards, FNV-1a hash).
	comms := []string{"alpha", "beta", "gamma", "delta", "epsilon"}
	for _, name := range comms {
		var c [16]byte
		copy(c[:], name)
		evt := types.Event{
			Type:    types.EventSyscall,
			PID:     uint32(len(name)),
			Comm:    c,
			Syscall: &types.SyscallEvent{Nr: 1},
		}
		ad.profileManager.RecordEvent(evt)
		ad.RecordPublishedAnomaly(evt)
	}

	got := CountAlertTotal(ad.profileManager)
	assert.Equal(t, uint64(len(comms)), got,
		"CountAlertTotal must sum AlertCount across all shards, not just one — "+
			"this is the read path used by engine.ProfilerStats")
}
