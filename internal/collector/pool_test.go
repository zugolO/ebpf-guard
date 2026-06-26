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
	// Get an event, mark it, reset it, put it back, then retrieve it again.
	evt := eventPool.Get().(*types.Event)
	require.NotNil(t, evt)

	// Reset nils pointer fields and clears ProcArgs so a pooled Event doesn't
	// retain inner structs. Scalar fields (PID, etc.) are intentionally NOT
	// cleared — they are overwritten on the next fill (see types.Event.Reset).
	evt.DNS = &types.DNSEvent{}
	evt.ProcArgs = "marked"
	evt.Reset()
	assert.Nil(t, evt.DNS, "Reset() must nil pointer fields")
	assert.Empty(t, evt.ProcArgs, "Reset() must clear ProcArgs")

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
