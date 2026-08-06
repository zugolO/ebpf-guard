package profiler

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func commFixed(s string) [16]byte {
	var a [16]byte
	copy(a[:], s)
	return a
}

// TestLookupOwnPPID_CachesNegativeResult guards the hot-path cost of the P0-1
// /proc fallback added in wave 2.
//
// getParentInfo runs on every event, ahead of store()'s steady-state fast path.
// When BPF leaves PPID zero (the normal case for the four main collectors) the
// fallback reads /proc/<pid>/status. If that read fails — the process already
// exited, or /proc is unavailable — the result must still be cached, otherwise
// every subsequent event from that PID repeats the syscall. Forking attackers
// like sqlmap generate exactly this pattern at volume, so an uncached miss
// turns a ~75ns path into a multi-microsecond one for the duration of the run.
//
// A PID this high cannot exist on any Linux host (pid_max is 2^22 at most), so
// the /proc read is guaranteed to fail on every platform.
func TestLookupOwnPPID_CachesNegativeResult(t *testing.T) {
	lt := NewLineageTracker(DefaultLineageConfig(), nil)
	const deadPID uint32 = 4000000

	require.Zero(t, lt.lookupOwnPPID(deadPID),
		"a nonexistent PID must resolve to no parent")

	s := lt.shardFor(deadPID)
	s.mu.RLock()
	entry, ok := s.procCache[deadPID]
	s.mu.RUnlock()

	require.True(t, ok,
		"the failed lookup must leave a cache entry — without it every event "+
			"from this PID re-reads /proc on the per-event hot path")
	assert.True(t, entry.ppidMissing, "the entry must record the miss")
	assert.Zero(t, entry.ppid)

	// Second call must be served from cache, still reporting no parent.
	assert.Zero(t, lt.lookupOwnPPID(deadPID))
}

// TestStore_BPFPPIDClearsNegativeCache verifies the negative cache cannot
// outlive better information. If a /proc read failed for a PID and a later
// event arrives carrying a BPF-supplied PPID, the miss flag must be cleared so
// the tracker does not keep reporting "no parent" for a process whose parent
// is now known.
func TestStore_BPFPPIDClearsNegativeCache(t *testing.T) {
	lt := NewLineageTracker(DefaultLineageConfig(), nil)
	const pid uint32 = 4000001

	require.Zero(t, lt.lookupOwnPPID(pid), "prime the negative cache")

	// A later event carries BPF-supplied ancestry for the same PID.
	lt.Track(types.Event{
		PID:        pid,
		PPID:       424242,
		Comm:       commFixed("curl"),
		ParentComm: commFixed("bash"),
	})

	s := lt.shardFor(pid)
	s.mu.RLock()
	entry := s.procCache[pid]
	s.mu.RUnlock()

	require.NotNil(t, entry)
	assert.False(t, entry.ppidMissing,
		"a BPF-supplied PPID must clear the negative-cache flag")
	assert.Equal(t, uint32(424242), entry.ppid)
	assert.Equal(t, uint32(424242), lt.lookupOwnPPID(pid))
}

// BenchmarkTrack_PPIDZero_ProcMiss measures the per-event cost of the fallback
// when /proc cannot resolve the PID. With the negative cache this should be
// within the same order of magnitude as BenchmarkTrack_PPIDPresent; without it
// the failed readProcStatus dominates by ~100x.
func BenchmarkTrack_PPIDZero_ProcMiss(b *testing.B) {
	lt := NewLineageTracker(DefaultLineageConfig(), nil)
	e := types.Event{PID: 4000002, PPID: 0, Comm: commFixed("sqlmap")}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lt.Track(e)
	}
}

// BenchmarkTrack_PPIDPresent is the baseline: BPF supplied PPID, steady-state
// fast path in store().
func BenchmarkTrack_PPIDPresent(b *testing.B) {
	lt := NewLineageTracker(DefaultLineageConfig(), nil)
	e := types.Event{PID: 4000003, PPID: 1, Comm: commFixed("sqlmap"), ParentComm: commFixed("bash")}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lt.Track(e)
	}
}
