package profiler

import (
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLineageTrackerDisabled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := LineageConfig{Enabled: false}

	tracker := NewLineageTracker(config, logger)

	e := types.Event{
		Type: types.EventSyscall,
		PID:  1234,
		PPID: 1,
		Comm: commBytes("bash"),
	}

	tracker.Track(e)
	assert.Equal(t, 0, tracker.Size(), "disabled tracker must not record anything")
}

func TestLineageTrackerStoresLineage(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := DefaultLineageConfig()

	tracker := NewLineageTracker(config, logger)

	e := types.Event{
		Type:       types.EventSyscall,
		PID:        5678,
		PPID:       1234,
		Comm:       commBytes("bash"),
		ParentComm: commBytes("nginx"),
	}

	tracker.Track(e)

	// Verify lineage was stored
	info, ok := tracker.GetLineage(5678)
	require.True(t, ok, "lineage should be stored")
	assert.Equal(t, uint32(1234), info.PPID)
	assert.Equal(t, "nginx", info.ParentComm)
}

func TestLineageTrackerCleanup(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := LineageConfig{
		Enabled:  true,
		TTL:      100 * time.Millisecond,
	}

	tracker := NewLineageTracker(config, logger)

	e := types.Event{
		Type: types.EventSyscall,
		PID:  5678,
		PPID: 1234,
		Comm: commBytes("bash"),
	}

	tracker.Track(e)

	// Verify entry exists
	assert.Equal(t, 1, tracker.Size())

	// Wait for TTL
	time.Sleep(150 * time.Millisecond)

	// Run cleanup
	tracker.Cleanup(time.Now())

	// Verify entry was removed
	assert.Equal(t, 0, tracker.Size())

	_, ok := tracker.GetLineage(5678)
	assert.False(t, ok, "lineage should be removed after cleanup")
}

func TestCleanComm(t *testing.T) {
	tests := []struct {
		input [16]byte
		want  string
	}{
		{[16]byte{'b', 'a', 's', 'h', 0, 0, 0, 0}, "bash"},
		{[16]byte{'n', 'g', 'i', 'n', 'x', 0, 0, 0}, "nginx"},
		{[16]byte{'p', 'y', 't', 'h', 'o', 'n', '3', 0}, "python3"},
		{[16]byte{'a', 'p', 'a', 'c', 'h', 'e', '2', 0}, "apache2"},
		{[16]byte{'n', 'o', 'n', 'u', 'l', 'l', 's', 't', 'r', 'i', 'n', 'g'}, "nonullstring"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := cleanComm(tt.input[:])
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNewLineageTrackerDefaults(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := LineageConfig{
		Enabled:  true,
		TTL:      0, // should default to 5m
	}

	tracker := NewLineageTracker(config, logger)
	assert.Equal(t, 5*time.Minute, tracker.config.TTL)
}

func TestLineageTrackerMultipleEvents(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := DefaultLineageConfig()

	tracker := NewLineageTracker(config, logger)

	// Add multiple events for different PIDs
	events := []types.Event{
		{Type: types.EventSyscall, PID: 100, PPID: 1, Comm: commBytes("nginx")},
		{Type: types.EventSyscall, PID: 200, PPID: 1, Comm: commBytes("bash")},
		{Type: types.EventSyscall, PID: 300, PPID: 1, Comm: commBytes("python3")},
	}

	for _, e := range events {
		tracker.Track(e)
	}

	assert.Equal(t, 3, tracker.Size())

	// Verify each entry
	for _, e := range events {
		info, ok := tracker.GetLineage(e.PID)
		require.True(t, ok, "PID %d should exist", e.PID)
		assert.Equal(t, uint32(1), info.PPID)
	}
}

// commBytes converts a string to [16]byte for testing.
func commBytes(s string) [16]byte {
	var b [16]byte
	copy(b[:], s)
	return b
}

func TestLineageTrackerGetProcessTree_SingleEvent(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	tracker := NewLineageTracker(DefaultLineageConfig(), logger)

	e := types.Event{
		Type:       types.EventSyscall,
		PID:        5678,
		PPID:       1234,
		Comm:       commBytes("bash"),
		ParentComm: commBytes("nginx"),
	}
	tracker.Track(e)

	tree := tracker.GetProcessTree(5678)
	require.NotNil(t, tree)
	// Last node must be bash itself.
	last := tree[len(tree)-1]
	assert.Equal(t, uint32(5678), last.PID)
	assert.Equal(t, "bash", last.Comm)
	assert.Equal(t, uint32(1234), last.PPID)
}

func TestLineageTrackerGetProcessTree_Chain(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	tracker := NewLineageTracker(DefaultLineageConfig(), logger)

	// Simulate: nginx (100) → bash (200) → curl (300)
	tracker.Track(types.Event{
		Type:       types.EventSyscall,
		PID:        200,
		PPID:       100,
		Comm:       commBytes("bash"),
		ParentComm: commBytes("nginx"),
	})
	tracker.Track(types.Event{
		Type:       types.EventSyscall,
		PID:        300,
		PPID:       200,
		Comm:       commBytes("curl"),
		ParentComm: commBytes("bash"),
	})

	tree := tracker.GetProcessTree(300)
	require.NotNil(t, tree, "process tree should be built for curl")

	// The chain must end with curl.
	last := tree[len(tree)-1]
	assert.Equal(t, uint32(300), last.PID)
	assert.Equal(t, "curl", last.Comm)

	// The second-to-last must be bash.
	require.GreaterOrEqual(t, len(tree), 2)
	prev := tree[len(tree)-2]
	assert.Equal(t, uint32(200), prev.PID)
	assert.Equal(t, "bash", prev.Comm)
}

func TestLineageTrackerGetProcessTree_MaxDepth(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := DefaultLineageConfig()
	cfg.MaxDepth = 3
	tracker := NewLineageTracker(cfg, logger)

	// Build a 5-deep chain: pid 1→2→3→4→5
	for i := uint32(2); i <= 5; i++ {
		p := commBytes(fmt.Sprintf("proc%d", i-1))
		c := commBytes(fmt.Sprintf("proc%d", i))
		tracker.Track(types.Event{
			Type:       types.EventSyscall,
			PID:        i,
			PPID:       i - 1,
			Comm:       c,
			ParentComm: p,
		})
	}

	tree := tracker.GetProcessTree(5)
	require.NotNil(t, tree)
	assert.LessOrEqual(t, len(tree), 3, "tree should be capped at MaxDepth")
	// Must still end at pid 5.
	assert.Equal(t, uint32(5), tree[len(tree)-1].PID)
}

func TestLineageTrackerGetProcessTree_Unknown(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	tracker := NewLineageTracker(DefaultLineageConfig(), logger)

	tree := tracker.GetProcessTree(99999)
	assert.Nil(t, tree, "unknown PID should return nil")
}

// BenchmarkLineageTrackerUpdate benchmarks the lineage tracker hot path.
func BenchmarkLineageTrackerUpdate(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	config := DefaultLineageConfig()
	tracker := NewLineageTracker(config, logger)

	e := types.Event{
		Type: types.EventSyscall,
		PID:  1234,
		PPID: 1,
		Comm: commBytes("bash"),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		tracker.Track(e)
		e.PID++ // Vary PID to avoid map collision
	}
}

// BenchmarkLineageTrackerUpdateSteadyState benchmarks the common case of a
// long-lived process emitting repeated events with the same PID/PPID/comm.
// This should hit the store() fast path: no allocation, single shard lock.
func BenchmarkLineageTrackerUpdateSteadyState(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	config := DefaultLineageConfig()
	tracker := NewLineageTracker(config, logger)

	e := types.Event{
		Type:       types.EventSyscall,
		PID:        1234,
		PPID:       1,
		Comm:       commBytes("bash"),
		ParentComm: commBytes("init"),
	}

	tracker.Track(e) // warm up: first call always builds ancestry

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		tracker.Track(e)
	}
}

// Д4 (волна 8.6, №558): зашитых паттернов цепочек нет — ни в конфиге по умолчанию,
// ни в трекере; детект цепочек живёт правилами.
func TestDefaultLineageConfig(t *testing.T) {
	cfg := DefaultLineageConfig()
	assert.True(t, cfg.Enabled)
	assert.Equal(t, 5*time.Minute, cfg.TTL)
	assert.Equal(t, 8, cfg.MaxDepth)
}
