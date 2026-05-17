// Package correlator provides event correlation and rule-based detection.
package correlator

import (
	"sync"

	"github.com/ebpf-guard/ebpf-guard/pkg/types"
)

// EventBuffer stores events per process for correlation analysis.
// It maintains a bounded queue of recent events for each PID.
type EventBuffer struct {
	mu      sync.RWMutex
	buffers map[uint32]*ringBuffer
	maxSize int
}

// ringBuffer is a circular buffer for events.
type ringBuffer struct {
	events []types.Event
	head   int
	size   int
}

// NewEventBuffer creates a new event buffer with the given max size per process.
func NewEventBuffer(maxSize int) *EventBuffer {
	return &EventBuffer{
		buffers: make(map[uint32]*ringBuffer),
		maxSize: maxSize,
	}
}

// Add adds an event to the buffer for the given PID.
func (eb *EventBuffer) Add(pid uint32, e types.Event) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	rb, exists := eb.buffers[pid]
	if !exists {
		rb = &ringBuffer{
			events: make([]types.Event, eb.maxSize),
		}
		eb.buffers[pid] = rb
	}

	// Add event to circular buffer
	rb.events[rb.head] = e
	rb.head = (rb.head + 1) % eb.maxSize
	if rb.size < eb.maxSize {
		rb.size++
	}
}

// Get returns all events for a given PID.
func (eb *EventBuffer) Get(pid uint32) []types.Event {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	rb, exists := eb.buffers[pid]
	if !exists || rb.size == 0 {
		return nil
	}

	// Copy events in chronological order
	result := make([]types.Event, rb.size)
	if rb.size < eb.maxSize {
		// Buffer not full yet, events are in [0, size)
		copy(result, rb.events[:rb.size])
	} else {
		// Buffer full, events wrap around
		// Copy from head to end, then from start to head
		copied := copy(result, rb.events[rb.head:])
		copy(result[copied:], rb.events[:rb.head])
	}

	return result
}

// GetRecent returns the last n events for a given PID.
func (eb *EventBuffer) GetRecent(pid uint32, n int) []types.Event {
	events := eb.Get(pid)
	if len(events) <= n {
		return events
	}
	return events[len(events)-n:]
}

// Remove deletes the buffer for a given PID.
func (eb *EventBuffer) Remove(pid uint32) {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	delete(eb.buffers, pid)
}

// Clear removes all buffers.
func (eb *EventBuffer) Clear() {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	eb.buffers = make(map[uint32]*ringBuffer)
}

// PIDs returns all PIDs with buffered events.
func (eb *EventBuffer) PIDs() []uint32 {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	pids := make([]uint32, 0, len(eb.buffers))
	for pid := range eb.buffers {
		pids = append(pids, pid)
	}
	return pids
}
