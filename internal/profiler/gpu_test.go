package profiler

import (
	"context"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeGPUEvent constructs a synthetic EventGPU event for testing.
func makeGPUEvent(comm string, op types.GPUOpType, size uint64) types.Event {
	e := types.Event{
		Type: types.EventGPU,
		PID:  9999,
		GPU:  &types.GPUEvent{Op: op, Size: size},
	}
	copy(e.Comm[:], comm)
	return e
}

// completeLearningSendEvents feeds n events into ad and waits for the learning
// phase to complete (requires learningPeriod to have elapsed and minSamples hit).
func completeLearningSendEvents(ad *AnomalyDetector, e types.Event, n int, wait time.Duration) {
	for i := 0; i < n; i++ {
		ad.ProcessEvent(e, false)
	}
	time.Sleep(wait)
	for i := 0; i < n; i++ {
		ad.ProcessEvent(e, false)
	}
}

// ─── gpuSizeBucket ───────────────────────────────────────────────────────────

func TestGPUSizeBucket(t *testing.T) {
	tests := []struct {
		size uint64
		want uint8
	}{
		{0, 0},       // special case: zero
		{1, 0},       // 2^0 → floor(log2(1)) = 0
		{2, 1},       // 2^1 → bucket 1
		{1023, 9},    // 2^10 - 1 → bits.Len64 = 10 → bucket 9
		{1024, 10},   // 2^10 → bucket 10
		{1 << 20, 20}, // 1 MB
		{1 << 30, 30}, // 1 GB
		{1<<63 - 1, 62}, // max useful size
	}
	for _, tt := range tests {
		got := gpuSizeBucket(tt.size)
		assert.Equal(t, tt.want, got, "size=%d", tt.size)
	}
}

// ─── ProcessProfile GPU recording ────────────────────────────────────────────

func TestProcessProfile_RecordGPUEvent(t *testing.T) {
	p := NewProcessProfile(1234, "xmrig")
	weight := 0.3

	e := &types.GPUEvent{Op: types.GPUOpAlloc, Size: 1 << 30}
	p.RecordGPUEvent(e, weight)

	assert.Equal(t, uint64(1), p.GPUProfile.TotalOps)
	assert.NotNil(t, p.GPUProfile.OpCounts[types.GPUOpAlloc])
	assert.Equal(t, 1.0, p.GPUProfile.OpCounts[types.GPUOpAlloc].Value())

	bucket := gpuSizeBucket(1 << 30)
	assert.NotNil(t, p.GPUProfile.AllocSizeBuckets[bucket])
	assert.Equal(t, 1.0, p.GPUProfile.AllocSizeBuckets[bucket].Value())
}

func TestProcessProfile_RecordGPUEvent_ZeroSize(t *testing.T) {
	p := NewProcessProfile(1234, "nvidia-smi")
	e := &types.GPUEvent{Op: types.GPUOpKernelLaunch, Size: 0}
	p.RecordGPUEvent(e, 0.3)

	assert.Equal(t, uint64(1), p.GPUProfile.TotalOps)
	// Size == 0 → no size bucket recorded
	assert.Empty(t, p.GPUProfile.AllocSizeBuckets)
}

func TestProcessProfile_RecordGPUEvent_MultipleOps(t *testing.T) {
	p := NewProcessProfile(1234, "train")
	weight := 0.3

	ops := []types.GPUOpType{types.GPUOpAlloc, types.GPUOpMemcpyHtoD, types.GPUOpKernelLaunch, types.GPUOpMemcpyDtoH}
	for _, op := range ops {
		p.RecordGPUEvent(&types.GPUEvent{Op: op, Size: 1 << 20}, weight)
	}

	assert.Equal(t, uint64(4), p.GPUProfile.TotalOps)
	for _, op := range ops {
		assert.NotNil(t, p.GPUProfile.OpCounts[op], "op %d should be recorded", op)
	}
}

// ─── gpuOpName ───────────────────────────────────────────────────────────────

func TestGPUOpName(t *testing.T) {
	assert.Equal(t, "alloc", gpuOpName(types.GPUOpAlloc))
	assert.Equal(t, "free", gpuOpName(types.GPUOpFree))
	assert.Equal(t, "memcpy_htod", gpuOpName(types.GPUOpMemcpyHtoD))
	assert.Equal(t, "memcpy_dtoh", gpuOpName(types.GPUOpMemcpyDtoH))
	assert.Equal(t, "memcpy_dtod", gpuOpName(types.GPUOpMemcpyDtoD))
	assert.Equal(t, "kernel_launch", gpuOpName(types.GPUOpKernelLaunch))
	assert.Equal(t, "99", gpuOpName(types.GPUOpType(99))) // unknown → numeric
}

// ─── WorkloadProfileManager GPU recording ────────────────────────────────────

func TestWorkloadProfileManager_RecordGPUEvent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wpm := NewWorkloadProfileManager(ctx, 0.3, 24*time.Hour, 100)

	gpuEv := makeGPUEvent("xmrig", types.GPUOpKernelLaunch, 0)
	wpm.RecordEvent(gpuEv)

	key := WorkloadKeyFromEvent(gpuEv)
	p := wpm.GetByKey(key)
	require.NotNil(t, p, "profile must be created after RecordEvent")
	assert.Equal(t, uint64(1), p.GPUProfile.TotalOps)
	assert.NotNil(t, p.GPUProfile.OpCounts[types.GPUOpKernelLaunch])
}

func TestWorkloadProfileManager_RecordGPUEvent_EWMA(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wpm := NewWorkloadProfileManager(ctx, 0.5, 24*time.Hour, 100)

	// Record 5 alloc events; EWMA with weight 0.5 should converge toward 1.0.
	for i := 0; i < 5; i++ {
		wpm.RecordEvent(makeGPUEvent("train", types.GPUOpAlloc, 1<<20))
	}

	key := WorkloadKeyFromEvent(makeGPUEvent("train", types.GPUOpAlloc, 0))
	p := wpm.GetByKey(key)
	require.NotNil(t, p)

	opEWMA := p.GPUProfile.OpCounts[types.GPUOpAlloc]
	require.NotNil(t, opEWMA)
	assert.InDelta(t, 1.0, opEWMA.Value(), 0.1, "frequent alloc should have high EWMA")
}

// ─── AnomalyDetector GPU scoring ─────────────────────────────────────────────

func TestGPUAnomaly_CPUOnlyWorkload(t *testing.T) {
	// A workload that only does syscalls during learning should score max (1.0)
	// when the first GPU event arrives after the learning phase.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const learningPeriod = 10 * time.Millisecond
	const minSamples = 10
	ad := NewAnomalyDetectorWithSamples(ctx, 0.5, learningPeriod, 0.3, minSamples, 0)

	// Feed CPU-only events (syscalls) to build baseline.
	syscallEv := types.Event{
		Type:    types.EventSyscall,
		PID:     1234,
		Syscall: &types.SyscallEvent{Nr: 1},
	}
	copy(syscallEv.Comm[:], "python3")
	completeLearningSendEvents(ad, syscallEv, 50, learningPeriod*2)

	require.True(t, ad.IsLearningComplete(), "learning must be complete before GPU test")

	// Now send a GPU event — workload never used GPU, so anomaly score must be 1.0.
	gpuEv := makeGPUEvent("python3", types.GPUOpAlloc, 1<<30)
	result := ad.ProcessEvent(gpuEv, false)

	require.NotNil(t, result, "result must not be nil after learning completes")
	assert.Equal(t, 1.0, result.Score, "CPU-only workload must have max GPU anomaly score")
	assert.True(t, result.IsAnomaly, "score >= threshold must mark as anomaly")
	require.NotEmpty(t, result.Contributions)
	assert.Equal(t, "gpu", result.Contributions[0].Category)
	assert.Equal(t, "gpu_op", result.Contributions[0].Field)
	assert.Equal(t, "alloc", result.Contributions[0].Value)
	ReleaseResult(result)
}

func TestGPUAnomaly_KnownGPUWorkload(t *testing.T) {
	// A workload that consistently uses GPU alloc during learning should NOT
	// trigger an anomaly when the same operation arrives post-learning.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const learningPeriod = 10 * time.Millisecond
	const minSamples = 10
	ad := NewAnomalyDetectorWithSamples(ctx, 0.5, learningPeriod, 0.3, minSamples, 0)

	// Build a GPU-heavy baseline.
	gpuLearning := makeGPUEvent("train", types.GPUOpAlloc, 1<<20)
	completeLearningSendEvents(ad, gpuLearning, 50, learningPeriod*2)

	require.True(t, ad.IsLearningComplete())

	// A familiar GPU alloc of the same size should not be anomalous.
	result := ad.ProcessEvent(makeGPUEvent("train", types.GPUOpAlloc, 1<<20), false)
	if result != nil {
		assert.Less(t, result.Score, 0.5, "familiar GPU operation should score below threshold")
		ReleaseResult(result)
	}
}

func TestGPUAnomaly_NewOperationType(t *testing.T) {
	// A workload that only does alloc during learning should score anomalously
	// when a new op type (kernel_launch) appears after learning.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const learningPeriod = 10 * time.Millisecond
	const minSamples = 10
	ad := NewAnomalyDetectorWithSamples(ctx, 0.5, learningPeriod, 0.3, minSamples, 0)

	gpuAllocEv := makeGPUEvent("miner", types.GPUOpAlloc, 1<<20)
	completeLearningSendEvents(ad, gpuAllocEv, 50, learningPeriod*2)

	require.True(t, ad.IsLearningComplete())

	// New op type never seen during learning → anomalous.
	result := ad.ProcessEvent(makeGPUEvent("miner", types.GPUOpKernelLaunch, 1<<20), false)
	require.NotNil(t, result)
	assert.True(t, result.IsAnomaly, "unseen GPU op type should trigger anomaly")
	found := false
	for _, c := range result.Contributions {
		if c.Category == "gpu" && c.Field == "gpu_op" {
			found = true
			assert.Equal(t, "kernel_launch", c.Value)
		}
	}
	assert.True(t, found, "gpu_op contribution must be present")
	ReleaseResult(result)
}
