package bpf

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Item 10 wave 6.6: cgroup_id is the 8 bytes AFTER offset 332 of
// struct event. The offset is written as a literal here (not derived from
// EventCgroupIDOffset) so a moved field in bpf/common.h and a moved constant here
// cannot agree by construction.
func TestEventCgroupTail(t *testing.T) {
	const wantID = 0x1122334455667788

	build := func(n int) []byte {
		raw := make([]byte, n)
		binary.LittleEndian.PutUint32(raw[0:], 1)
		binary.LittleEndian.PutUint32(raw[12:], 4242) // pid
		copy(raw[28:], "bash")
		if n >= 332+8 {
			binary.LittleEndian.PutUint64(raw[332:], wantID)
		}
		return raw
	}

	require.Equal(t, 332, EventCgroupIDOffset)

	t.Run("new record carries cgroup id in all three event kinds", func(t *testing.T) {
		raw := build(332 + 8)
		var se SyscallEvent
		require.NoError(t, ParseSyscallEventInto(raw, &se))
		assert.Equal(t, uint64(wantID), se.CgroupID)
		assert.Equal(t, uint32(4242), se.PID, "existing offsets unchanged")
		assert.Equal(t, uint64(wantID), se.ToTypesEvent().CgroupID)

		var ne NetworkEvent
		require.NoError(t, ParseNetworkEventInto(raw, &ne))
		assert.Equal(t, uint64(wantID), ne.CgroupID)
		assert.Equal(t, uint64(wantID), ne.ToTypesEvent().CgroupID)

		var fe FileaccessEvent
		require.NoError(t, ParseFileaccessEventInto(raw, &fe))
		assert.Equal(t, uint64(wantID), fe.CgroupID)
		assert.Equal(t, uint64(wantID), fe.ToTypesEvent().CgroupID)
	})

	t.Run("old 332-byte record (sizeof(struct event) before item 10) still parses, cgroup id 0", func(t *testing.T) {
		raw := build(332)
		var se SyscallEvent
		require.NoError(t, ParseSyscallEventInto(raw, &se))
		assert.Zero(t, se.CgroupID)
		var fe FileaccessEvent
		require.NoError(t, ParseFileaccessEventInto(raw, &fe))
		assert.Zero(t, fe.CgroupID)
	})

	t.Run("reused out struct does not keep a stale id", func(t *testing.T) {
		var se SyscallEvent
		require.NoError(t, ParseSyscallEventInto(build(332+8), &se))
		require.NoError(t, ParseSyscallEventInto(build(332), &se))
		assert.Zero(t, se.CgroupID)
	})
}
