package profiler

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func (lt *LineageTracker) ancestryLen() (n int) {
	for _, s := range lt.shards {
		s.mu.RLock()
		n += len(s.ancestry)
		s.mu.RUnlock()
	}
	return n
}

// Волна 8.2, доводка T1: ancestry родителя без собственных событий не имел
// lineage и не выселялся Cleanup'ом — потолком был pid_max.
func TestCleanup_EvictsAncestryWithoutLineage(t *testing.T) {
	cfg := DefaultLineageConfig()
	lt := NewLineageTracker(cfg, nil)

	// Родители 3_000_000+ не существуют → /proc пуст, lineage у них нет.
	for i := uint32(0); i < 10000; i++ {
		e := types.Event{PID: 100000 + i, PPID: 3000000 + i, ParentComm: commFixed("ghost")}
		e.Comm = commFixed("child")
		lt.Track(e)
	}
	require.Equal(t, 10000, lt.ancestryLen(), "по одной цепочке на живой pid")

	lt.Cleanup(time.Now().Add(time.Hour))
	require.Zero(t, lt.ancestryLen())
}

// Цепочка мёртвого родителя ({ppid,0,""}) не кэшируется под pid родителя.
func TestBuildAncestry_DoesNotCacheEmptyParentChain(t *testing.T) {
	lt := NewLineageTracker(DefaultLineageConfig(), nil)
	const ppid uint32 = 3999999
	e := types.Event{PID: 4242, PPID: ppid, ParentComm: commFixed("ghost")}
	e.Comm = commFixed("child")
	lt.Track(e)

	s := lt.shardFor(ppid)
	s.mu.RLock()
	_, cached := s.ancestry[ppid]
	s.mu.RUnlock()
	require.False(t, cached)
	require.NotEmpty(t, lt.GetProcessTree(4242), "цепочка самого pid при этом строится")
}

// Содержательная цепочка родителя (bootstrap из /proc) без lineage[ppid]
// выселяется по собственному TTL, а свежая — остаётся.
func TestCleanup_EvictsBootstrappedParentChainByOwnTTL(t *testing.T) {
	lt := NewLineageTracker(DefaultLineageConfig(), nil)
	now := time.Now()
	for i := uint32(1); i <= 1000; i++ {
		s := lt.shardFor(i)
		s.mu.Lock()
		s.ancestry[i] = []types.ProcessNode{{PID: i, PPID: 1, Comm: "parent"}}
		s.ancestryTS[i] = now
		s.mu.Unlock()
	}
	lt.Cleanup(now.Add(time.Minute))
	require.Equal(t, 1000, lt.ancestryLen(), "в пределах TTL не трогаем")
	lt.Cleanup(now.Add(time.Hour))
	require.Zero(t, lt.ancestryLen())
}
