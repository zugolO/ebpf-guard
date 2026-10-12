package bpf

import (
	"encoding/binary"
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Волна 8.5, U1: unit_cgroup_id — 8 байт ПОСЛЕ cgroup_id (offset 340, sizeof(struct event) = 348).
// Смещение — литерал, а не EventUnitCgroupIDOffset: сдвиг поля в bpf/common.h и
// сдвиг константы здесь не могут согласоваться по построению.
func TestW85_U1_UnitCgroupTail(t *testing.T) {
	const wantUnit, wantCg = 0x0102030405060708, 0x1122334455667788
	build := func(n int) []byte {
		raw := make([]byte, n)
		binary.LittleEndian.PutUint32(raw[0:], 1)
		binary.LittleEndian.PutUint32(raw[12:], 4242)
		copy(raw[28:], "bash")
		if n >= 332+8 {
			binary.LittleEndian.PutUint64(raw[332:], wantCg)
		}
		if n >= 340+8 {
			binary.LittleEndian.PutUint64(raw[340:], wantUnit)
		}
		return raw
	}
	require.Equal(t, 340, EventUnitCgroupIDOffset)

	t.Run("новая запись: id юнита во всех трёх видах событий", func(t *testing.T) {
		raw := build(348)
		var se SyscallEvent
		require.NoError(t, ParseSyscallEventInto(raw, &se))
		assert.Equal(t, uint64(wantUnit), se.UnitCgroupID)
		assert.Equal(t, uint64(wantCg), se.CgroupID, "cgroup_id не сдвинулся")
		assert.Equal(t, uint64(wantUnit), se.ToTypesEvent().UnitCgroupID)
		var ne NetworkEvent
		require.NoError(t, ParseNetworkEventInto(raw, &ne))
		assert.Equal(t, uint64(wantUnit), ne.ToTypesEvent().UnitCgroupID)
		var fe FileaccessEvent
		require.NoError(t, ParseFileaccessEventInto(raw, &fe))
		assert.Equal(t, uint64(wantUnit), fe.ToTypesEvent().UnitCgroupID)
	})
	t.Run("старая 340-байтовая запись разбирается, id юнита 0", func(t *testing.T) {
		var se SyscallEvent
		require.NoError(t, ParseSyscallEventInto(build(340), &se))
		assert.Zero(t, se.UnitCgroupID)
		assert.Equal(t, uint64(wantCg), se.CgroupID)
	})
	t.Run("переиспользуемая структура не хранит чужой id", func(t *testing.T) {
		var se SyscallEvent
		require.NoError(t, ParseSyscallEventInto(build(348), &se))
		require.NoError(t, ParseSyscallEventInto(build(340), &se))
		assert.Zero(t, se.UnitCgroupID)
	})
}

// Литерал в C и константа в Go — одно число: сторож по исходнику заголовка
// (_Static_assert в common.h держит саму раскладку, этот тест — Go-сторону).
func TestW85_U1_OffsetMatchesCHeader(t *testing.T) {
	src, err := os.ReadFile("../../bpf/common.h")
	require.NoError(t, err)
	m := regexp.MustCompile(`#define EVENT_UNIT_CGROUP_ID_OFFSET (\d+)`).FindSubmatch(src)
	require.NotNil(t, m, "в bpf/common.h нет EVENT_UNIT_CGROUP_ID_OFFSET")
	n, err := strconv.Atoi(string(m[1]))
	require.NoError(t, err)
	assert.Equal(t, n, EventUnitCgroupIDOffset)
	assert.Contains(t, string(src), "sizeof(struct event) == EVENT_UNIT_CGROUP_ID_OFFSET + 8")
}
