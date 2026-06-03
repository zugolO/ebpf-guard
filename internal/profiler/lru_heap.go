package profiler

import (
	"container/heap"
	"time"
)

// lruEntry is an element in the LRU min-heap, ordered by lastAccess (oldest first).
// The index field is kept in sync with the heap position by Swap so that
// heap.Fix and heap.Remove are O(log n).
type lruEntry struct {
	key        string
	lastAccess time.Time
	index      int // position in lruStringHeap; -1 when not in heap
}

// lruStringHeap is a min-heap of *lruEntry keyed by string, ordered by lastAccess.
type lruStringHeap []*lruEntry

func (h lruStringHeap) Len() int           { return len(h) }
func (h lruStringHeap) Less(i, j int) bool { return h[i].lastAccess.Before(h[j].lastAccess) }
func (h lruStringHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}
func (h *lruStringHeap) Push(x any) {
	e := x.(*lruEntry)
	e.index = len(*h)
	*h = append(*h, e)
}
func (h *lruStringHeap) Pop() any {
	old := *h
	n := len(old)
	e := old[n-1]
	old[n-1] = nil
	e.index = -1
	*h = old[:n-1]
	return e
}

// lruUint32Entry is an element in the LRU min-heap keyed by uint32.
type lruUint32Entry struct {
	key        uint32
	lastAccess time.Time
	index      int // position in lruUint32Heap; -1 when not in heap
}

// lruUint32Heap is a min-heap of *lruUint32Entry, ordered by lastAccess (oldest first).
type lruUint32Heap []*lruUint32Entry

func (h lruUint32Heap) Len() int           { return len(h) }
func (h lruUint32Heap) Less(i, j int) bool { return h[i].lastAccess.Before(h[j].lastAccess) }
func (h lruUint32Heap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}
func (h *lruUint32Heap) Push(x any) {
	e := x.(*lruUint32Entry)
	e.index = len(*h)
	*h = append(*h, e)
}
func (h *lruUint32Heap) Pop() any {
	old := *h
	n := len(old)
	e := old[n-1]
	old[n-1] = nil
	e.index = -1
	*h = old[:n-1]
	return e
}

// lruStringIndex is the companion lookup map for lruStringHeap.
// Methods are no-ops when the index is nil (LRU disabled).
type lruStringIndex map[string]*lruEntry

func (idx lruStringIndex) push(h *lruStringHeap, key string) {
	if idx == nil {
		return
	}
	e := &lruEntry{key: key, lastAccess: time.Now()}
	heap.Push(h, e)
	idx[key] = e
}

func (idx lruStringIndex) touch(h *lruStringHeap, key string) {
	if idx == nil {
		return
	}
	if e, ok := idx[key]; ok {
		e.lastAccess = time.Now()
		heap.Fix(h, e.index)
	}
}

func (idx lruStringIndex) remove(h *lruStringHeap, key string) {
	if idx == nil {
		return
	}
	if e, ok := idx[key]; ok {
		heap.Remove(h, e.index)
		delete(idx, key)
	}
}

// lruUint32Index is the companion lookup map for lruUint32Heap.
// Methods are no-ops when the index is nil (LRU disabled).
type lruUint32Index map[uint32]*lruUint32Entry

func (idx lruUint32Index) push(h *lruUint32Heap, key uint32) {
	if idx == nil {
		return
	}
	e := &lruUint32Entry{key: key, lastAccess: time.Now()}
	heap.Push(h, e)
	idx[key] = e
}

func (idx lruUint32Index) touch(h *lruUint32Heap, key uint32) {
	if idx == nil {
		return
	}
	if e, ok := idx[key]; ok {
		e.lastAccess = time.Now()
		heap.Fix(h, e.index)
	}
}

func (idx lruUint32Index) remove(h *lruUint32Heap, key uint32) {
	if idx == nil {
		return
	}
	if e, ok := idx[key]; ok {
		heap.Remove(h, e.index)
		delete(idx, key)
	}
}
