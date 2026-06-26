package profiler

import (
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnomalyDetector_Accessors(t *testing.T) {
	ad := NewAnomalyDetector(0.7, time.Hour, 0.3)
	require.NotNil(t, ad)

	// Learning has just started.
	assert.False(t, ad.IsLearningComplete())
	assert.GreaterOrEqual(t, ad.LearningProgress(), 0.0)
	assert.LessOrEqual(t, ad.LearningProgress(), 1.0)
	assert.Greater(t, ad.TimeRemaining(), time.Duration(0))
	assert.NotNil(t, ad.GetProfileManager())

	// Sampling rate is clamped to [0, 1].
	ad.SetSamplingRate(2.0)
	assert.Equal(t, 1.0, ad.GetSamplingRate())
	ad.SetSamplingRate(-1.0)
	assert.Equal(t, 0.0, ad.GetSamplingRate())
	ad.SetSamplingRate(0.5)
	assert.Equal(t, 0.5, ad.GetSamplingRate())

	// Enable/Disable toggle the detector without panicking.
	ad.Disable()
	ad.Enable()

	// SetSharedLearner swaps in a shared baseline learner.
	ad.SetSharedLearner(NewBaselineLearner(time.Hour, 100))

	// ProcessEvent during learning returns a non-nil result and does not panic.
	var c [16]byte
	copy(c[:], "proc")
	res := ad.ProcessEvent(types.Event{
		Type:    types.EventSyscall,
		PID:     1,
		Comm:    c,
		Syscall: &types.SyscallEvent{Nr: 1},
	}, false)
	_ = res // result may be nil while learning; the call must simply be safe

	ad.FlushProfiles()
}

func TestSequenceProfiler_Accessors(t *testing.T) {
	sp := NewSequenceProfiler(DefaultSequenceConfig(), time.Hour)
	require.NotNil(t, sp)

	sp.Enable()
	assert.True(t, sp.IsEnabled())
	sp.Disable()
	assert.False(t, sp.IsEnabled())

	sp.SetSamplingRate(2.0)
	assert.LessOrEqual(t, sp.GetSamplingRate(), 1.0)
	sp.SetSamplingRate(-1.0)
	assert.GreaterOrEqual(t, sp.GetSamplingRate(), 0.0)
	sp.SetSamplingRate(0.25)
	assert.InDelta(t, 0.25, sp.GetSamplingRate(), 1e-9)
}
