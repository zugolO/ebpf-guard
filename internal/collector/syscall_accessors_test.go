package collector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSyscallCollector_NilObjsAccessors covers the objs==nil branch of every
// accessor that guards on a loaded BPF object set. A freshly constructed
// collector has not loaded, so each of these must return its nil/zero value
// without panicking.
func TestSyscallCollector_NilObjsAccessors(t *testing.T) {
	c := newTestSyscallCollector(t)

	assert.Nil(t, c.GetPrograms(), "GetPrograms must be nil before load")
	assert.Nil(t, c.MapFullCountersMap(), "MapFullCountersMap must be nil before load")
	assert.Nil(t, c.SamplingConfigMap(), "SamplingConfigMap must be nil before load")

	comm, syscall, cfg := c.KernelFilterMaps()
	assert.Nil(t, comm)
	assert.Nil(t, syscall)
	assert.Nil(t, cfg)

	assert.NoError(t, c.LoadError(), "no load attempted yet")
	assert.Equal(t, uint64(0), c.LostEvents(), "no events lost before start")
}

// TestSyscallCollector_Builders verifies the fluent configuration setters return
// the same collector and apply their values.
func TestSyscallCollector_Builders(t *testing.T) {
	c := newTestSyscallCollector(t)

	assert.Same(t, c, c.WithStatusReporter(NoopStatusReporter{}))
	assert.Same(t, c, c.WithBackpressureStrategy(StrategyDrop))
	assert.Same(t, c, c.WithRingBufSize(8*1024*1024))
	assert.Equal(t, 8*1024*1024, c.ringBufSize)
}
