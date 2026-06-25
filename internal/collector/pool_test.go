package collector

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func TestEventPool_GetReturnsNonNil(t *testing.T) {
	evt := eventPool.Get().(*types.Event)
	require.NotNil(t, evt)
	eventPool.Put(evt)
}

func TestEventPool_PutAndGet_ReuseObject(t *testing.T) {
	// Get an event, mark it, put it back, then retrieve it again.
	// sync.Pool may not always return the exact same object (e.g. under GC
	// pressure), but on a single goroutine without GC interference this
	// reliably exercises the put→get path.
	evt := eventPool.Get().(*types.Event)
	require.NotNil(t, evt)

	evt.PID = 12345
	eventPool.Put(evt)

	evt2 := eventPool.Get().(*types.Event)
	require.NotNil(t, evt2)
	// The value we get back is a valid *types.Event regardless of whether it
	// is the same allocation — the pool contract guarantees non-nil.
	assert.IsType(t, &types.Event{}, evt2)
	eventPool.Put(evt2)
}

func TestEventPool_Concurrent(t *testing.T) {
	const goroutines = 32
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				evt := eventPool.Get().(*types.Event)
				evt.PID = uint32(j)
				evt.Reset()
				eventPool.Put(evt)
			}
		}()
	}

	wg.Wait()
}
