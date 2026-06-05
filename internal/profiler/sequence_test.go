package profiler

import (
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeSeqVec creates a seqVecSize FrequencyVector with the given (index, value) pairs.
// Pairs are specified as alternating int index and float32 value arguments.
func makeSeqVec(pairs ...float32) FrequencyVector {
	v := make(FrequencyVector, seqVecSize)
	for i := 0; i+1 < len(pairs); i += 2 {
		v[int(pairs[i])] = pairs[i+1]
	}
	return v
}

func TestSyscallWindow(t *testing.T) {
	tests := []struct {
		name     string
		capacity int
		pushes   []int
		// wantAt lists (index, value) pairs to check in the output vector.
		// Elements not listed are expected to be 0.
		wantAt []float32
		// wantZero is true when the entire vector should be zero.
		wantZero bool
	}{
		{
			name:     "empty window",
			capacity: 4,
			pushes:   []int{},
			wantZero: true,
		},
		{
			name:     "single syscall",
			capacity: 4,
			pushes:   []int{1},
			wantAt:   []float32{1, 1.0},
		},
		{
			name:     "multiple same syscall",
			capacity: 4,
			pushes:   []int{1, 1, 1},
			wantAt:   []float32{1, 1.0},
		},
		{
			name:     "mixed syscalls",
			capacity: 4,
			pushes:   []int{1, 2, 1, 2},
			wantAt:   []float32{1, 0.5, 2, 0.5},
		},
		{
			name:     "ring buffer wrap",
			capacity: 4,
			pushes:   []int{1, 2, 3, 4, 5, 6},
			wantAt:   []float32{3, 0.25, 4, 0.25, 5, 0.25, 6, 0.25},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newSyscallWindow(tt.capacity)
			for _, s := range tt.pushes {
				w.push(s)
			}
			dst := make(FrequencyVector, seqVecSize)
			w.toVector(dst)

			if tt.wantZero {
				for i, v := range dst {
					assert.Equal(t, float32(0), v, "index %d should be zero", i)
				}
				return
			}

			// Build expected vector and compare element-by-element.
			want := makeSeqVec(tt.wantAt...)
			for i := range want {
				assert.InDelta(t, want[i], dst[i], 0.001, "index %d", i)
			}
		})
	}
}

func TestCosineDistance(t *testing.T) {
	tests := []struct {
		name string
		a    FrequencyVector
		b    FrequencyVector
		want float64
	}{
		{
			name: "identical vectors",
			a:    makeSeqVec(1, 0.5, 2, 0.5),
			b:    makeSeqVec(1, 0.5, 2, 0.5),
			want: 0.0,
		},
		{
			name: "orthogonal vectors",
			a:    makeSeqVec(1, 1.0),
			b:    makeSeqVec(2, 1.0),
			want: 1.0,
		},
		{
			name: "empty first vector",
			a:    make(FrequencyVector, seqVecSize),
			b:    makeSeqVec(1, 1.0),
			want: 1.0,
		},
		{
			name: "empty second vector",
			a:    makeSeqVec(1, 1.0),
			b:    make(FrequencyVector, seqVecSize),
			want: 1.0,
		},
		{
			name: "partial overlap",
			a:    makeSeqVec(1, 0.7, 2, 0.3),
			b:    makeSeqVec(1, 0.3, 2, 0.7),
			// dot=0.42, |a|=|b|=sqrt(0.58); cos=0.42/0.58≈0.7241; distance≈0.2759
			want: 0.2759,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cosineDistance(tt.a, tt.b)
			if tt.want == 0.0 || tt.want == 1.0 {
				assert.InDelta(t, tt.want, got, 0.0001, "cosine distance mismatch")
			} else {
				assert.InDelta(t, tt.want, got, 0.01, "cosine distance mismatch")
			}
		})
	}
}

func TestCosineDistanceOrthogonal(t *testing.T) {
	// Test that orthogonal vectors have distance 1.0
	a := makeSeqVec(1, 1.0)
	b := makeSeqVec(2, 1.0)

	dist := cosineDistance(a, b)
	assert.InDelta(t, 1.0, dist, 0.0001, "orthogonal vectors should have distance 1.0")
}

func TestMergeVectors(t *testing.T) {
	base := makeSeqVec(1, 0.5, 2, 0.5)
	update := makeSeqVec(1, 0.3, 3, 0.7)

	mergeVectors(base, update, 0.2)

	// Expected: base * 0.8 + update * 0.2
	// 1: 0.5*0.8 + 0.3*0.2 = 0.4 + 0.06 = 0.46
	// 2: 0.5*0.8 + 0 = 0.4
	// 3: 0 + 0.7*0.2 = 0.14
	assert.InDelta(t, 0.46, base[1], 0.001)
	assert.InDelta(t, 0.4, base[2], 0.001)
	assert.InDelta(t, 0.14, base[3], 0.001)
}

func TestSequenceProfilerUpdate(t *testing.T) {
	config := SequenceConfig{
		Enabled:    true,
		WindowSize: 8,
		Threshold:  0.3,
	}

	profiler := NewSequenceProfiler(config, 5*time.Minute)

	// Create events with consistent syscall pattern.
	// Two different PIDs with the same comm share one workload baseline.
	makeEvent := func(pid uint32, syscallNr int) types.Event {
		return types.Event{
			Type: types.EventSyscall,
			PID:  pid,
			Comm: [16]byte{'b', 'a', 's', 'h'},
			Syscall: &types.SyscallEvent{
				Nr: int64(syscallNr),
			},
		}
	}

	pid := uint32(1234)

	// Learning phase - no anomalies
	for i := 0; i < 10; i++ {
		// Pattern: syscall 1, 2, 1, 2 (regular)
		e := makeEvent(pid, 1+(i%2))
		dist, isAnomaly := profiler.Update(e)

		if i < 8 {
			// Still collecting samples
			assert.False(t, isAnomaly, "should not detect anomaly during learning phase")
			assert.Equal(t, 0.0, dist, "distance should be 0 during learning")
		}
	}

	// Verify workload state exists keyed by comm (no K8s enrichment → namespace/app empty)
	key := WorkloadKey{Comm: "bash"}
	state, ok := profiler.GetStateByKey(key)
	require.True(t, ok, "state should exist for workload key")
	require.NotNil(t, state.baseline, "baseline should be established")

	// Continue with same pattern - should not trigger
	for i := 0; i < 5; i++ {
		e := makeEvent(pid, 1+(i%2))
		_, isAnomaly := profiler.Update(e)
		assert.False(t, isAnomaly, "should not detect anomaly with consistent pattern")
	}

	// Now inject anomalous pattern - all syscall 99
	for i := 0; i < 8; i++ {
		e := makeEvent(pid, 99)
		dist, isAnomaly := profiler.Update(e)

		if i == 7 {
			// After filling window with anomalous syscalls
			assert.True(t, dist > 0.0, "distance should be positive for anomalous pattern")
			if dist > config.Threshold {
				assert.True(t, isAnomaly, "should detect anomaly when distance exceeds threshold")
			}
		}
	}
}

func TestSequenceProfilerDisabled(t *testing.T) {
	config := SequenceConfig{
		Enabled:    false,
		WindowSize: 8,
		Threshold:  0.3,
	}

	profiler := NewSequenceProfiler(config, 5*time.Minute)

	e := types.Event{
		Type: types.EventSyscall,
		PID:  1234,
		Syscall: &types.SyscallEvent{
			Nr: 1,
		},
	}

	dist, isAnomaly := profiler.Update(e)
	assert.Equal(t, 0.0, dist, "distance should be 0 when disabled")
	assert.False(t, isAnomaly, "should not detect anomaly when disabled")
}

func TestSequenceProfilerNonSyscallEvent(t *testing.T) {
	config := SequenceConfig{
		Enabled:    true,
		WindowSize: 8,
		Threshold:  0.3,
	}

	profiler := NewSequenceProfiler(config, 5*time.Minute)

	// Network event should be ignored
	e := types.Event{
		Type: types.EventTCPConnect,
		PID:  1234,
		Network: &types.NetworkEvent{
			Dport: 80,
		},
	}

	dist, isAnomaly := profiler.Update(e)
	assert.Equal(t, 0.0, dist, "distance should be 0 for non-syscall events")
	assert.False(t, isAnomaly, "should not detect anomaly for non-syscall events")
}

func TestSequenceProfilerCleanup(t *testing.T) {
	config := SequenceConfig{
		Enabled:    true,
		WindowSize: 4,
		Threshold:  0.3,
	}

	ttl := 100 * time.Millisecond
	profiler := NewSequenceProfiler(config, ttl)

	// Add state using a named workload (comm "svc")
	e := types.Event{
		Type: types.EventSyscall,
		PID:  1234,
		Comm: [16]byte{'s', 'v', 'c'},
		Syscall: &types.SyscallEvent{
			Nr: 1,
		},
	}

	for i := 0; i < 5; i++ {
		profiler.Update(e)
	}

	key := WorkloadKey{Comm: "svc"}

	// Verify state exists
	_, ok := profiler.GetStateByKey(key)
	require.True(t, ok, "state should exist before cleanup")

	// Wait for TTL to expire
	time.Sleep(ttl + 50*time.Millisecond)

	// Run cleanup
	profiler.Cleanup(time.Now())

	// State should be removed
	_, ok = profiler.GetStateByKey(key)
	assert.False(t, ok, "state should be removed after cleanup")
}

func TestSequenceProfilerWorkloadIsolation(t *testing.T) {
	// Verifies that different workloads (different comms) maintain separate
	// baselines, while replicas of the same workload (same comm) share one.
	config := SequenceConfig{
		Enabled:    true,
		WindowSize: 4,
		Threshold:  0.3,
	}

	profiler := NewSequenceProfiler(config, 5*time.Minute)

	makeEvent := func(pid uint32, comm string, syscallNr int) types.Event {
		var c [16]byte
		copy(c[:], comm)
		return types.Event{
			Type: types.EventSyscall,
			PID:  pid,
			Comm: c,
			Syscall: &types.SyscallEvent{
				Nr: int64(syscallNr),
			},
		}
	}

	// Two different workloads with distinct syscall patterns.
	for i := 0; i < 6; i++ {
		profiler.Update(makeEvent(100, "nginx", 1)) // nginx workload: syscall 1
		profiler.Update(makeEvent(200, "redis", 2)) // redis workload: syscall 2
	}

	// Each workload has its own separate baseline.
	stateNginx, ok := profiler.GetStateByKey(WorkloadKey{Comm: "nginx"})
	require.True(t, ok)
	assert.InDelta(t, 1.0, stateNginx.baseline[1], 0.01)

	stateRedis, ok := profiler.GetStateByKey(WorkloadKey{Comm: "redis"})
	require.True(t, ok)
	assert.InDelta(t, 1.0, stateRedis.baseline[2], 0.01)

	// A second nginx replica (different PID, same comm) shares the same state.
	for i := 0; i < 6; i++ {
		profiler.Update(makeEvent(101, "nginx", 1)) // another nginx pod
	}
	stateNginx2, ok := profiler.GetStateByKey(WorkloadKey{Comm: "nginx"})
	require.True(t, ok)
	assert.Equal(t, stateNginx, stateNginx2, "nginx replicas must share one state")
}

func TestDefaultSequenceConfig(t *testing.T) {
	cfg := DefaultSequenceConfig()
	assert.True(t, cfg.Enabled)
	assert.Equal(t, 64, cfg.WindowSize)
	assert.Equal(t, 0.3, cfg.Threshold)
}

func TestNewSequenceProfilerDefaults(t *testing.T) {
	// Test that zero values get defaults
	config := SequenceConfig{
		Enabled:    true,
		WindowSize: 0, // should default to 64
		Threshold:  0, // should default to 0.3
	}

	profiler := NewSequenceProfiler(config, 5*time.Minute)
	assert.Equal(t, 64, profiler.config.WindowSize)
	assert.Equal(t, 0.3, profiler.config.Threshold)
}

// BenchmarkSequenceProfilerUpdate benchmarks the sequence profiler hot path.
func BenchmarkSequenceProfilerUpdate(b *testing.B) {
	config := SequenceConfig{
		Enabled:    true,
		WindowSize: 64,
		Threshold:  0.3,
	}

	profiler := NewSequenceProfiler(config, 5*time.Minute)

	e := types.Event{
		Type: types.EventSyscall,
		PID:  1234,
		Comm: [16]byte{'b', 'a', 's', 'h'},
		Syscall: &types.SyscallEvent{
			Nr: 1,
		},
	}

	// Pre-warm the profiler
	for i := 0; i < 100; i++ {
		profiler.Update(e)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		profiler.Update(e)
	}
}

// BenchmarkCosineDistance benchmarks the distance calculation.
func BenchmarkCosineDistance(b *testing.B) {
	a := makeSeqVec(1, 0.1, 2, 0.2, 3, 0.3, 4, 0.4)
	bvec := makeSeqVec(1, 0.4, 2, 0.3, 3, 0.2, 4, 0.1)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		cosineDistance(a, bvec)
	}
}
