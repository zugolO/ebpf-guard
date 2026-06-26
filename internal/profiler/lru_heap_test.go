package profiler

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLRUStringIndex(t *testing.T) {
	h := &lruStringHeap{}
	idx := make(lruStringIndex)

	idx.push(h, "a")
	idx.push(h, "b")
	idx.push(h, "c")
	require.Equal(t, 3, h.Len())

	// touch updates lastAccess and re-fixes heap order without changing length.
	idx.touch(h, "a")
	assert.Equal(t, 3, h.Len())

	// touch on a missing key is a no-op.
	idx.touch(h, "zzz")
	assert.Equal(t, 3, h.Len())

	// remove drops the entry from both heap and index.
	idx.remove(h, "b")
	assert.Equal(t, 2, h.Len())
	_, ok := idx["b"]
	assert.False(t, ok)

	// remove of a missing key is a no-op.
	idx.remove(h, "b")
	assert.Equal(t, 2, h.Len())
}

func TestLRUStringIndex_NilNoop(t *testing.T) {
	h := &lruStringHeap{}
	var idx lruStringIndex // nil
	// All operations are safe no-ops when the index is nil (LRU disabled).
	idx.push(h, "x")
	idx.touch(h, "x")
	idx.remove(h, "x")
	assert.Equal(t, 0, h.Len())
}

func TestLRUUint32Index(t *testing.T) {
	h := &lruUint32Heap{}
	idx := make(lruUint32Index)

	idx.push(h, 1)
	idx.push(h, 2)
	idx.push(h, 3)
	require.Equal(t, 3, h.Len())

	idx.touch(h, 2)
	idx.touch(h, 999) // missing — no-op
	assert.Equal(t, 3, h.Len())

	idx.remove(h, 1)
	assert.Equal(t, 2, h.Len())
	_, ok := idx[1]
	assert.False(t, ok)
}

func TestLRUWorkloadKeyIndex(t *testing.T) {
	h := &lruWorkloadKeyHeap{}
	idx := make(lruWorkloadKeyIndex)

	k1 := WorkloadKey{Comm: "a"}
	k2 := WorkloadKey{Comm: "b"}
	idx.push(h, k1)
	idx.push(h, k2)
	require.Equal(t, 2, h.Len())

	idx.touch(h, k1)
	idx.remove(h, k2)
	assert.Equal(t, 1, h.Len())
}
