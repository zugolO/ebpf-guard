package correlator

import (
	"sync"
	"testing"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEventBuffer_AddGet(t *testing.T) {
	eb := NewEventBuffer(3)

	// Empty PID returns nil.
	assert.Nil(t, eb.Get(99))

	eb.Add(1, types.Event{PID: 1, Timestamp: 10})
	eb.Add(1, types.Event{PID: 1, Timestamp: 20})

	got := eb.Get(1)
	require.Len(t, got, 2)
	assert.Equal(t, uint64(10), got[0].Timestamp)
	assert.Equal(t, uint64(20), got[1].Timestamp)
}

func TestEventBuffer_WrapAround(t *testing.T) {
	eb := NewEventBuffer(3)
	for i := 0; i < 5; i++ {
		eb.Add(7, types.Event{PID: 7, Timestamp: uint64(i)})
	}

	// Only the last 3 (2,3,4) survive, in chronological order.
	got := eb.Get(7)
	require.Len(t, got, 3)
	assert.Equal(t, uint64(2), got[0].Timestamp)
	assert.Equal(t, uint64(3), got[1].Timestamp)
	assert.Equal(t, uint64(4), got[2].Timestamp)
}

func TestEventBuffer_GetRecent(t *testing.T) {
	eb := NewEventBuffer(5)
	for i := 0; i < 4; i++ {
		eb.Add(3, types.Event{PID: 3, Timestamp: uint64(i)})
	}

	// n larger than available returns everything.
	assert.Len(t, eb.GetRecent(3, 10), 4)

	// n smaller returns the tail.
	last2 := eb.GetRecent(3, 2)
	require.Len(t, last2, 2)
	assert.Equal(t, uint64(2), last2[0].Timestamp)
	assert.Equal(t, uint64(3), last2[1].Timestamp)
}

func TestEventBuffer_RemoveClear(t *testing.T) {
	eb := NewEventBuffer(2)
	eb.Add(1, types.Event{PID: 1})
	eb.Add(2, types.Event{PID: 2})

	eb.Remove(1)
	assert.Nil(t, eb.Get(1))
	assert.NotNil(t, eb.Get(2))

	eb.Clear()
	assert.Empty(t, eb.PIDs())
}

func TestEventBuffer_PIDsAndForEach(t *testing.T) {
	eb := NewEventBuffer(2)
	eb.Add(10, types.Event{PID: 10})
	eb.Add(20, types.Event{PID: 20})

	assert.ElementsMatch(t, []uint32{10, 20}, eb.PIDs())

	seen := map[uint32]bool{}
	eb.ForEachPID(func(pid uint32) { seen[pid] = true })
	assert.True(t, seen[10] && seen[20])
}

func TestEventBuffer_ConcurrentAdd(t *testing.T) {
	eb := NewEventBuffer(8)
	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				eb.Add(uint32(w), types.Event{PID: uint32(w), Timestamp: uint64(i)})
			}
		}(w)
	}
	wg.Wait()
	assert.Len(t, eb.PIDs(), 16)
}
