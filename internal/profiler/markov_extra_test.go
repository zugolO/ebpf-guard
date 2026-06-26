package profiler

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultMarkovConfig(t *testing.T) {
	cfg := DefaultMarkovConfig()
	assert.True(t, cfg.Enabled)
	assert.Equal(t, 64, cfg.MaxUniqueSyscalls)
	assert.InDelta(t, -3.0, cfg.FloorProbability, 1e-9)
	assert.InDelta(t, 0.35, cfg.Threshold, 1e-9)
}

func TestMarkovChain_ScoreWindowAndAccessors(t *testing.T) {
	mc := NewMarkovChain(DefaultMarkovConfig())

	// Before finalization, scoring returns the neutral default.
	assert.False(t, mc.IsFinalized())
	score, anom, thr := mc.ScoreWindow([]int64{1, 2, 3})
	assert.Equal(t, 0.0, score)
	assert.False(t, anom)
	assert.InDelta(t, 0.35, thr, 1e-9)

	// Learn a strong, repetitive pattern 1->2->3->1 ...
	seq := []int64{1, 2, 3}
	for r := 0; r < 200; r++ {
		for i := 1; i < len(seq); i++ {
			mc.RecordTransition(seq[i-1], seq[i])
		}
		mc.RecordTransition(seq[len(seq)-1], seq[0])
	}

	assert.Greater(t, mc.SampleCount(), uint64(0))
	assert.Equal(t, 3, mc.UniqueFromSyscallCount())

	mc.Finalize()
	assert.True(t, mc.IsFinalized())
	// Deterministic transitions have probability 1.0 → log10 = 0, so the
	// baseline average log-likelihood is <= 0 (0 here for a perfect pattern).
	assert.LessOrEqual(t, mc.BaselineAvgLL(), 0.0)

	// A window following the learned pattern should score low (not anomalous).
	normalScore, normalAnom, _ := mc.ScoreWindow([]int64{1, 2, 3, 1, 2})
	assert.False(t, normalAnom)
	assert.LessOrEqual(t, normalScore, 0.35)

	// A window of never-seen transitions should score higher.
	anomScore, _, _ := mc.ScoreWindow([]int64{100, 200, 300, 400})
	assert.GreaterOrEqual(t, anomScore, normalScore)

	// A window shorter than 2 returns the neutral score.
	s, a, _ := mc.ScoreWindow([]int64{5})
	assert.Equal(t, 0.0, s)
	assert.False(t, a)

	// RecordTransition after Finalize is a no-op.
	before := mc.SampleCount()
	mc.RecordTransition(1, 2)
	assert.Equal(t, before, mc.SampleCount())
}

func TestMarkovChain_RecordTransitionBounds(t *testing.T) {
	mc := NewMarkovChain(DefaultMarkovConfig())
	// Out-of-range syscalls are ignored.
	mc.RecordTransition(-1, 2)
	mc.RecordTransition(1, markovVecSize+5)
	require.Equal(t, uint64(0), mc.SampleCount())
}
