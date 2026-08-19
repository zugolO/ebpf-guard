package collector

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bpfpkg "github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/pkg/types"
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

	comm, syscall, cfg, agentPid := c.KernelFilterMaps()
	assert.Nil(t, comm)
	assert.Nil(t, syscall)
	assert.Nil(t, cfg)
	assert.Nil(t, agentPid)

	assert.NoError(t, c.LoadError(), "no load attempted yet")
	assert.Equal(t, uint64(0), c.LostEvents(), "no events lost before start")
}

// TestSyscallCollector_LoadedObjsAccessors covers the objs!=nil branch of the
// accessors. A zero-value SyscallObjects is non-nil but carries nil program/map
// handles, so each accessor takes its loaded path without needing a real kernel.
func TestSyscallCollector_LoadedObjsAccessors(t *testing.T) {
	c := newTestSyscallCollector(t)
	c.objs = &bpfpkg.SyscallObjects{}

	progs := c.GetPrograms()
	require.NotNil(t, progs, "GetPrograms must return the program map once loaded")
	assert.Contains(t, progs, "trace_sys_enter")

	// Maps come straight off the (empty) objs, so they are nil but the loaded
	// branch executes without panicking.
	assert.Nil(t, c.MapFullCountersMap())
	assert.Nil(t, c.SamplingConfigMap())
	comm, syscall, cfg, agentPid := c.KernelFilterMaps()
	assert.Nil(t, comm)
	assert.Nil(t, syscall)
	assert.Nil(t, cfg)
	assert.Nil(t, agentPid)

	// With objs set and no load error, the collector reports healthy.
	assert.True(t, c.IsHealthy())
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

// TestSyscallCollector_ParseEvent covers parseEvent's error path (raw too short
// for the syscall wire format) and its success path (a minimal valid sample is
// decoded into the supplied event).
func TestSyscallCollector_ParseEvent(t *testing.T) {
	c := newTestSyscallCollector(t)

	t.Run("too short returns error", func(t *testing.T) {
		var evt types.Event
		require.Error(t, c.parseEvent([]byte{1, 2, 3}, &evt))
	})

	t.Run("valid sample is decoded", func(t *testing.T) {
		// 104 bytes is the minimum syscall sample size; a zeroed buffer with the
		// event-type field set parses successfully.
		raw := make([]byte, 104)
		binary.LittleEndian.PutUint32(raw[0:], uint32(types.EventSyscall))
		var evt types.Event
		require.NoError(t, c.parseEvent(raw, &evt))
	})
}

// validSyscallSample builds a minimal 104-byte syscall wire-format record
// with Type set to bpf.EventTypeSyscall, nr set to nr, and comm left at its
// zero value (16 leading NULs, i.e. IsEmptyComm(comm) == true) unless comm is
// non-empty.
func validSyscallSample(nr int64, comm string) []byte {
	raw := make([]byte, 104)
	binary.LittleEndian.PutUint32(raw[0:], bpfpkg.EventTypeSyscall)
	copy(raw[24:40], comm) // offset 24 = comm field start (see ParseSyscallEventInto)
	binary.LittleEndian.PutUint64(raw[40:], uint64(nr))
	return raw
}

// TestSyscallCollector_ParseEvent_MalformedDiagnostics covers the three
// independent diagnostic checks parseEvent added for 5.9.2c (finding #40):
// type_mismatch always drops the record (the "недостающая валидация формата"
// barrier), nr_not_monitored and empty_comm are observation-only and let the
// record through.
func TestSyscallCollector_ParseEvent_MalformedDiagnostics(t *testing.T) {
	t.Run("type mismatch is dropped and reported once, not double-counted", func(t *testing.T) {
		c := newTestSyscallCollector(t)
		raw := validSyscallSample(1, "sh") // nr=1 (write) is irrelevant here
		binary.LittleEndian.PutUint32(raw[0:], 7 /* EVENT_TYPE_NET_CLOSE */)

		var evt types.Event
		err := c.parseEvent(raw, &evt)
		require.Error(t, err)
		assert.ErrorIs(t, err, errMalformedSyscallType)
	})

	t.Run("type match with nr outside allowlist is observed but not dropped", func(t *testing.T) {
		c := newTestSyscallCollector(t)
		c.WithMalformedDiagnostics([]int{59}, true) // execve only
		raw := validSyscallSample(41 /* socket, not in allowlist */, "sh")

		var evt types.Event
		require.NoError(t, c.parseEvent(raw, &evt))
		assert.Equal(t, int64(41), evt.Syscall.Nr)
	})

	t.Run("nr outside allowlist is not flagged when kernel_filter is disabled", func(t *testing.T) {
		c := newTestSyscallCollector(t)
		c.WithMalformedDiagnostics([]int{59}, false)
		raw := validSyscallSample(41, "sh")

		var evt types.Event
		require.NoError(t, c.parseEvent(raw, &evt))
	})

	t.Run("empty comm is observed but not dropped", func(t *testing.T) {
		c := newTestSyscallCollector(t)
		raw := validSyscallSample(59, "") // comm left zeroed

		var evt types.Event
		require.NoError(t, c.parseEvent(raw, &evt))
		assert.Equal(t, byte(0), evt.Comm[0])
	})

	t.Run("well-formed record trips none of the three counters", func(t *testing.T) {
		c := newTestSyscallCollector(t)
		c.WithMalformedDiagnostics([]int{59}, true)
		raw := validSyscallSample(59, "bash")

		var evt types.Event
		require.NoError(t, c.parseEvent(raw, &evt))
		assert.Equal(t, int64(59), evt.Syscall.Nr)
	})
}
