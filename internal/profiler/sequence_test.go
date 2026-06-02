package profiler

import (
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSyscallWindow(t *testing.T) {
	tests := []struct {
		name     string
		capacity int
		pushes   []int
		wantVec  FrequencyVector
	}{
		{
			name:     "empty window",
			capacity: 4,
			pushes:   []int{},
			wantVec:  FrequencyVector{},
		},
		{
			name:     "single syscall",
			capacity: 4,
			pushes:   []int{1},
			wantVec:  FrequencyVector{1: 1.0},
		},
		{
			name:     "multiple same syscall",
			capacity: 4,
			pushes:   []int{1, 1, 1},
			wantVec:  FrequencyVector{1: 1.0},
		},
		{
			name:     "mixed syscalls",
			capacity: 4,
			pushes:   []int{1, 2, 1, 2},
			wantVec:  FrequencyVector{1: 0.5, 2: 0.5},
		},
		{
			name:     "ring buffer wrap",
			capacity: 4,
			pushes:   []int{1, 2, 3, 4, 5, 6},
			wantVec:  FrequencyVector{3: 0.25, 4: 0.25, 5: 0.25, 6: 0.25},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newSyscallWindow(tt.capacity)
			for _, s := range tt.pushes {
				w.push(s)
			}
			got := w.toVector()
			assert.Equal(t, tt.wantVec, got)
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
			a:    FrequencyVector{1: 0.5, 2: 0.5},
			b:    FrequencyVector{1: 0.5, 2: 0.5},
			want: 0.0,
		},
		{
			name: "orthogonal vectors",
			a:    FrequencyVector{1: 1.0},
			b:    FrequencyVector{2: 1.0},
			want: 1.0,
		},
		{
			name: "empty first vector",
			a:    FrequencyVector{},
			b:    FrequencyVector{1: 1.0},
			want: 1.0,
		},
		{
			name: "empty second vector",
			a:    FrequencyVector{1: 1.0},
			b:    FrequencyVector{},
			want: 1.0,
		},
		{
			name: "partial overlap",
			a:    FrequencyVector{1: 0.7, 2: 0.3},
			b:    FrequencyVector{1: 0.3, 2: 0.7},
			want: 0.4, // approximate
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
	a := FrequencyVector{1: 1.0, 2: 0.0}
	b := FrequencyVector{1: 0.0, 2: 1.0}

	dist := cosineDistance(a, b)
	assert.InDelta(t, 1.0, dist, 0.0001, "orthogonal vectors should have distance 1.0")
}

func TestMergeVectors(t *testing.T) {
	base := FrequencyVector{1: 0.5, 2: 0.5}
	update := FrequencyVector{1: 0.3, 3: 0.7}

	merged := mergeVectors(base, update, 0.2)

	// Expected: base * 0.8 + update * 0.2
	// 1: 0.5*0.8 + 0.3*0.2 = 0.4 + 0.06 = 0.46
	// 2: 0.5*0.8 + 0 = 0.4
	// 3: 0 + 0.7*0.2 = 0.14
	assert.InDelta(t, 0.46, merged[1], 0.0001)
	assert.InDelta(t, 0.4, merged[2], 0.0001)
	assert.InDelta(t, 0.14, merged[3], 0.0001)
}

func TestSequenceProfilerUpdate(t *testing.T) {
	config := SequenceConfig{
		Enabled:    true,
		WindowSize: 8,
		Threshold:  0.3,
	}

	profiler := NewSequenceProfiler(config, 5*time.Minute)

	// Create events with consistent syscall pattern
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

	// Verify state exists
	state, ok := profiler.GetState(pid)
	require.True(t, ok, "state should exist for PID")
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

	// Add state for a PID
	e := types.Event{
		Type: types.EventSyscall,
		PID:  1234,
		Syscall: &types.SyscallEvent{
			Nr: 1,
		},
	}

	for i := 0; i < 5; i++ {
		profiler.Update(e)
	}

	// Verify state exists
	_, ok := profiler.GetState(1234)
	require.True(t, ok, "state should exist before cleanup")

	// Wait for TTL to expire
	time.Sleep(ttl + 50*time.Millisecond)

	// Run cleanup
	profiler.Cleanup(time.Now())

	// State should be removed
	_, ok = profiler.GetState(1234)
	assert.False(t, ok, "state should be removed after cleanup")
}

func TestSequenceProfilerMultiplePIDs(t *testing.T) {
	config := SequenceConfig{
		Enabled:    true,
		WindowSize: 4,
		Threshold:  0.3,
	}

	profiler := NewSequenceProfiler(config, 5*time.Minute)

	makeEvent := func(pid uint32, syscallNr int) types.Event {
		return types.Event{
			Type: types.EventSyscall,
			PID:  pid,
			Comm: [16]byte{'a', 'p', 'p'},
			Syscall: &types.SyscallEvent{
				Nr: int64(syscallNr),
			},
		}
	}

	// Different patterns for different PIDs
	for i := 0; i < 6; i++ {
		profiler.Update(makeEvent(100, 1)) // PID 100: syscall 1
		profiler.Update(makeEvent(200, 2)) // PID 200: syscall 2
	}

	// Verify both states exist with different baselines
	state100, ok := profiler.GetState(100)
	require.True(t, ok)
	assert.InDelta(t, 1.0, state100.baseline[1], 0.01)

	state200, ok := profiler.GetState(200)
	require.True(t, ok)
	assert.InDelta(t, 1.0, state200.baseline[2], 0.01)
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

// BenchmarkProcessEvent benchmarks the sequence profiler hot path.
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
	a := FrequencyVector{1: 0.1, 2: 0.2, 3: 0.3, 4: 0.4}
	bvec := FrequencyVector{1: 0.4, 2: 0.3, 3: 0.2, 4: 0.1}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		cosineDistance(a, bvec)
	}
}
