package collector

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestW9B_BulkShardsByPid: a bulk event lands in shard pid&mask (the shard of the
// ingest worker that owns the pid), and a full shard of one pid does not cost the
// events of a pid on another shard — the head of line of host×8 (волна 9, В8).
func TestW9B_BulkShardsByPid(t *testing.T) {
	hi := make(chan *types.Event, 16)
	shards := []chan *types.Event{make(chan *types.Event, 1), make(chan *types.Event, 1), make(chan *types.Event, 8), make(chan *types.Event, 8)}
	send := make([]chan<- *types.Event, len(shards))
	for i, c := range shards {
		send[i] = c
	}
	read := func(pid uint32) types.Event {
		return types.Event{Type: types.EventFileAccess, PID: pid, File: &types.FileEvent{Op: 1}} // read: no protected fallback
	}
	// pid 4 (shard 0) floods a shard of depth 1; pids 2 and 6 (shard 2) must all arrive.
	evs := []types.Event{read(4), read(4), read(4), read(2), read(4), read(6), read(4), read(2)}
	fc := newFakeCollector("fake", evs...)
	p := NewShardedPriorityEventCollector(fc, hi, send, StrategyDrop, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Start(ctx, nil) }()
	<-fc.sent
	require.Eventually(t, func() bool { return len(shards[2]) == 3 }, 2*time.Second, 5*time.Millisecond)
	require.Equal(t, 1, len(shards[0]), "flooded shard keeps its depth, the surplus is dropped")
	require.Zero(t, len(shards[1])+len(shards[3]))
	for len(shards[2]) > 0 {
		e := <-shards[2]
		require.Equal(t, uint32(2), e.PID&3)
	}
}

func TestW9B_ShardCountMustBePowerOfTwo(t *testing.T) {
	require.Panics(t, func() {
		NewShardedPriorityEventCollector(newFakeCollector("x"), make(chan *types.Event), make([]chan<- *types.Event, 3), StrategyDrop, nil, nil, nil)
	})
}
