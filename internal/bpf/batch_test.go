package bpf

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// GetStats — sequential path
// ---------------------------------------------------------------------------

func TestGetStats_Sequential_ZeroCounters(t *testing.T) {
	cfgMap := newTestArrayMap(t, 16)
	sc, err := NewSamplingController(cfgMap)
	require.NoError(t, err)
	// hasBatch defaults to false — sequential path.

	countersMap := newTestArrayMap(t, 8)
	stats, err := sc.GetStats(countersMap)
	require.NoError(t, err)
	assert.Equal(t, SamplingStats{}, stats, "empty map should yield zero stats")
}

func TestGetStats_Sequential_NilMap(t *testing.T) {
	cfgMap := newTestArrayMap(t, 16)
	sc, err := NewSamplingController(cfgMap)
	require.NoError(t, err)

	_, err = sc.GetStats(nil)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// GetStats — batch path
// ---------------------------------------------------------------------------

func TestGetStats_Batch_ZeroCounters(t *testing.T) {
	cfgMap := newTestArrayMap(t, 16)
	sc, err := NewSamplingController(cfgMap)
	require.NoError(t, err)
	sc.SetBatchMode(true)

	countersMap := newTestArrayMap(t, 8)
	stats, err := sc.GetStats(countersMap)
	require.NoError(t, err)
	assert.Equal(t, SamplingStats{}, stats, "empty map should yield zero stats on batch path")
}

func TestGetStats_Batch_NilMap(t *testing.T) {
	cfgMap := newTestArrayMap(t, 16)
	sc, err := NewSamplingController(cfgMap)
	require.NoError(t, err)
	sc.SetBatchMode(true)

	_, err = sc.GetStats(nil)
	require.Error(t, err)
}

// TestGetStats_Batch_FallsBackOnError confirms that when the batch call returns
// an unexpected error, GetStats transparently retries with the per-element path.
func TestGetStats_Batch_FallsBackOnError(t *testing.T) {
	origBatch := getStatsBatchFn
	origSeq := getStatsSequentialFn
	t.Cleanup(func() {
		getStatsBatchFn = origBatch
		getStatsSequentialFn = origSeq
	})

	batchCalled := false
	seqCalled := false
	wantStats := SamplingStats{SyscallEvents: 42, NetworkEvents: 7}

	getStatsBatchFn = func(_ *ebpf.Map) (SamplingStats, error) {
		batchCalled = true
		return SamplingStats{}, errors.New("simulated batch error")
	}
	getStatsSequentialFn = func(_ *ebpf.Map) (SamplingStats, error) {
		seqCalled = true
		return wantStats, nil
	}

	cfgMap := newTestArrayMap(t, 16)
	sc, err := NewSamplingController(cfgMap)
	require.NoError(t, err)
	sc.SetBatchMode(true)

	countersMap := newTestArrayMap(t, 8)
	stats, err := sc.GetStats(countersMap)
	require.NoError(t, err)
	assert.Equal(t, wantStats, stats)
	assert.True(t, batchCalled, "batch path must have been attempted")
	assert.True(t, seqCalled, "sequential fallback must have been invoked")
}

// ---------------------------------------------------------------------------
// SetBatchMode toggling
// ---------------------------------------------------------------------------

func TestSamplingController_SetBatchMode(t *testing.T) {
	cfgMap := newTestArrayMap(t, 16)
	sc, err := NewSamplingController(cfgMap)
	require.NoError(t, err)
	assert.False(t, sc.hasBatch, "hasBatch must default to false")

	sc.SetBatchMode(true)
	assert.True(t, sc.hasBatch)

	sc.SetBatchMode(false)
	assert.False(t, sc.hasBatch)
}

// ---------------------------------------------------------------------------
// KernelFilterController.SetBatchMode
// ---------------------------------------------------------------------------

func TestKernelFilterController_SetBatchMode(t *testing.T) {
	kf := &KernelFilterController{}
	assert.False(t, kf.hasBatch)

	kf.SetBatchMode(true)
	assert.True(t, kf.hasBatch)

	kf.SetBatchMode(false)
	assert.False(t, kf.hasBatch)
}

// ---------------------------------------------------------------------------
// UpdateSyscallFilter — batch path (requires a real BPF map)
// ---------------------------------------------------------------------------

// newTestSyscallArrayMap creates a 512-entry uint8 array map for exercising
// UpdateSyscallFilter without a real BPF program loaded.
func newTestSyscallArrayMap(t *testing.T) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: 512,
	})
	if err != nil {
		t.Skipf("BPF map creation unavailable in this environment: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func TestUpdateSyscallFilter_BatchPath(t *testing.T) {
	syscallMap := newTestSyscallArrayMap(t)
	cfgMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Array, KeySize: 4, ValueSize: 1, MaxEntries: 1,
	})
	if err != nil {
		t.Skipf("BPF map creation unavailable: %v", err)
	}
	defer cfgMap.Close()
	commMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Hash, KeySize: 16, ValueSize: 1, MaxEntries: 64,
	})
	if err != nil {
		t.Skipf("BPF map creation unavailable: %v", err)
	}
	defer commMap.Close()

	kf, err := NewKernelFilterController(commMap, syscallMap, cfgMap)
	require.NoError(t, err)
	kf.SetBatchMode(true)

	nrs := []uint32{59, 322, 101} // execve, execveat, ptrace
	require.NoError(t, kf.UpdateSyscallFilter(nrs))

	// Verify the three allowed syscalls are set to 1, others to 0.
	for _, nr := range nrs {
		var val uint8
		require.NoError(t, syscallMap.Lookup(nr, &val), "lookup nr=%d", nr)
		assert.Equal(t, uint8(1), val, "nr=%d should be allowed", nr)
	}
	// Spot-check a slot that should be zeroed.
	var val uint8
	require.NoError(t, syscallMap.Lookup(uint32(0), &val))
	assert.Equal(t, uint8(0), val, "nr=0 should be cleared")
}

func TestUpdateSyscallFilter_SequentialPath(t *testing.T) {
	syscallMap := newTestSyscallArrayMap(t)
	cfgMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Array, KeySize: 4, ValueSize: 1, MaxEntries: 1,
	})
	if err != nil {
		t.Skipf("BPF map creation unavailable: %v", err)
	}
	defer cfgMap.Close()
	commMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Hash, KeySize: 16, ValueSize: 1, MaxEntries: 64,
	})
	if err != nil {
		t.Skipf("BPF map creation unavailable: %v", err)
	}
	defer commMap.Close()

	kf, err := NewKernelFilterController(commMap, syscallMap, cfgMap)
	require.NoError(t, err)
	// hasBatch defaults to false — sequential path.

	nrs := []uint32{59, 322}
	require.NoError(t, kf.UpdateSyscallFilter(nrs))

	for _, nr := range nrs {
		var val uint8
		require.NoError(t, syscallMap.Lookup(nr, &val))
		assert.Equal(t, uint8(1), val, "nr=%d should be allowed", nr)
	}
}

// TestUpdateSyscallFilter_BatchFallsBackOnError verifies that when the batch
// write fails (e.g. older kernel), UpdateSyscallFilter falls back to the
// sequential path and succeeds.  The batch function is stubbed via a package-
// level var so no real kernel or BPF map is needed.
func TestUpdateSyscallFilter_BatchFallsBackOnError(t *testing.T) {
	origBatch := updateSyscallFilterBatchFn
	t.Cleanup(func() { updateSyscallFilterBatchFn = origBatch })

	batchCalled := false
	updateSyscallFilterBatchFn = func(_ *KernelFilterController, _ map[uint32]bool) error {
		batchCalled = true
		return errors.New("simulated batch error")
	}

	syscallMap := newTestSyscallArrayMap(t)
	cfgMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Array, KeySize: 4, ValueSize: 1, MaxEntries: 1,
	})
	if err != nil {
		t.Skipf("BPF map creation unavailable: %v", err)
	}
	defer cfgMap.Close()
	commMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Hash, KeySize: 16, ValueSize: 1, MaxEntries: 64,
	})
	if err != nil {
		t.Skipf("BPF map creation unavailable: %v", err)
	}
	defer commMap.Close()

	kf, err := NewKernelFilterController(commMap, syscallMap, cfgMap)
	require.NoError(t, err)
	kf.SetBatchMode(true)

	nrs := []uint32{59, 322} // execve, execveat
	require.NoError(t, kf.UpdateSyscallFilter(nrs), "should succeed via sequential fallback")
	assert.True(t, batchCalled, "batch path must have been attempted")

	// Confirm sequential path wrote correct values.
	for _, nr := range nrs {
		var val uint8
		require.NoError(t, syscallMap.Lookup(nr, &val))
		assert.Equal(t, uint8(1), val, "nr=%d should be allowed", nr)
	}
}

// ---------------------------------------------------------------------------
// Benchmarks — batch vs sequential for GetStats
// ---------------------------------------------------------------------------

func BenchmarkGetStats_Sequential(b *testing.B) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 4,
	})
	if err != nil {
		b.Skipf("BPF map creation unavailable: %v", err)
	}
	defer m.Close()

	cfgMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Array, KeySize: 4, ValueSize: 16, MaxEntries: 1,
	})
	if err != nil {
		b.Skipf("BPF map creation unavailable: %v", err)
	}
	defer cfgMap.Close()

	sc, _ := NewSamplingController(cfgMap)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = sc.GetStats(m)
	}
}

func BenchmarkGetStats_Batch(b *testing.B) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 4,
	})
	if err != nil {
		b.Skipf("BPF map creation unavailable: %v", err)
	}
	defer m.Close()

	cfgMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Array, KeySize: 4, ValueSize: 16, MaxEntries: 1,
	})
	if err != nil {
		b.Skipf("BPF map creation unavailable: %v", err)
	}
	defer cfgMap.Close()

	sc, _ := NewSamplingController(cfgMap)
	sc.SetBatchMode(true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = sc.GetStats(m)
	}
}

// ---------------------------------------------------------------------------
// Benchmarks — batch vs sequential for UpdateSyscallFilter
// ---------------------------------------------------------------------------

func BenchmarkUpdateSyscallFilter_Sequential(b *testing.B) {
	syscallMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Array, KeySize: 4, ValueSize: 1, MaxEntries: 512,
	})
	if err != nil {
		b.Skipf("BPF map creation unavailable: %v", err)
	}
	defer syscallMap.Close()
	cfgMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Array, KeySize: 4, ValueSize: 1, MaxEntries: 1,
	})
	if err != nil {
		b.Skipf("BPF map creation unavailable: %v", err)
	}
	defer cfgMap.Close()
	commMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Hash, KeySize: 16, ValueSize: 1, MaxEntries: 64,
	})
	if err != nil {
		b.Skipf("BPF map creation unavailable: %v", err)
	}
	defer commMap.Close()

	kf, _ := NewKernelFilterController(commMap, syscallMap, cfgMap)
	nrs := make([]uint32, 14)
	for i, n := range DefaultMonitoredSyscalls() {
		nrs[i] = uint32(n)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = kf.UpdateSyscallFilter(nrs)
	}
}

func BenchmarkUpdateSyscallFilter_Batch(b *testing.B) {
	syscallMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Array, KeySize: 4, ValueSize: 1, MaxEntries: 512,
	})
	if err != nil {
		b.Skipf("BPF map creation unavailable: %v", err)
	}
	defer syscallMap.Close()
	cfgMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Array, KeySize: 4, ValueSize: 1, MaxEntries: 1,
	})
	if err != nil {
		b.Skipf("BPF map creation unavailable: %v", err)
	}
	defer cfgMap.Close()
	commMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Hash, KeySize: 16, ValueSize: 1, MaxEntries: 64,
	})
	if err != nil {
		b.Skipf("BPF map creation unavailable: %v", err)
	}
	defer commMap.Close()

	kf, _ := NewKernelFilterController(commMap, syscallMap, cfgMap)
	kf.SetBatchMode(true)
	nrs := make([]uint32, 14)
	for i, n := range DefaultMonitoredSyscalls() {
		nrs[i] = uint32(n)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = kf.UpdateSyscallFilter(nrs)
	}
}

