package profiler

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEWMA_Reset(t *testing.T) {
	e := NewEWMA(0.3)
	e.Update(10)
	e.Update(20)
	assert.Greater(t, e.Value(), 0.0)
	assert.Equal(t, uint64(2), e.Count())

	e.Reset()
	assert.Equal(t, 0.0, e.Value())
	assert.Equal(t, uint64(0), e.Count())
}

func TestBaselineLearner_Reset(t *testing.T) {
	bl := NewBaselineLearner(time.Hour, 10)
	require.False(t, bl.IsLearningComplete())
	bl.Reset()
	assert.Equal(t, uint64(0), bl.GetSampleCount())
	assert.False(t, bl.IsLearningComplete())
}

func TestProcessProfile_UpdateLastSeen(t *testing.T) {
	p := NewProcessProfile(1234, "nginx")
	before := p.LastSeenAt
	time.Sleep(time.Millisecond)
	p.UpdateLastSeen()
	assert.True(t, p.LastSeenAt.After(before) || !p.LastSeenAt.IsZero())
}

func TestProfileManager_Methods(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pm := NewProfileManagerWithContext(ctx, 0.3, time.Hour, 100)

	// Touch a couple of PIDs via GetOrCreate.
	pm.GetOrCreate(1, "a")
	pm.GetOrCreate(2, "b")

	seen := map[uint32]bool{}
	pm.ForEachPID(func(pid uint32) { seen[pid] = true })
	assert.True(t, seen[1] && seen[2])

	require.NoError(t, pm.RegisterMetrics(prometheus.NewRegistry()))

	pm.Flush()
}
