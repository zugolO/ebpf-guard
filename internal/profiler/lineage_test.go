package profiler

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultLineageConfig(t *testing.T) {
	cfg := DefaultLineageConfig()
	assert.True(t, cfg.Enabled)
	assert.Equal(t, 5*time.Minute, cfg.TTL)
	assert.Len(t, cfg.Patterns, 3)

	// Check default patterns
	var foundWebShell, foundShellNetwork bool
	for _, p := range cfg.Patterns {
		switch p.Name {
		case "web_shell_spawn":
			foundWebShell = true
			assert.Equal(t, "critical", p.Severity)
		case "shell_network_tool":
			foundShellNetwork = true
			assert.Equal(t, "critical", p.Severity)
		}
	}
	assert.True(t, foundWebShell, "web_shell_spawn pattern should exist")
	assert.True(t, foundShellNetwork, "shell_network_tool pattern should exist")
}

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

	match := tracker.Update(e)
	assert.Nil(t, match, "should not return match when disabled")
}

func TestLineageTrackerWebShellPattern(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := DefaultLineageConfig()

	tracker := NewLineageTracker(config, logger)

	// Simulate nginx spawning bash
	e := types.Event{
		Type:       types.EventSyscall,
		PID:        5678,
		PPID:       1234,
		Comm:       commBytes("bash"),
		ParentComm: commBytes("nginx"),
	}

	var capturedMatch *LineageMatch
	tracker.SetMatchHandler(func(m LineageMatch) {
		capturedMatch = &m
	})

	match := tracker.Update(e)

	require.NotNil(t, match, "should detect web_shell_spawn pattern")
	assert.Equal(t, "web_shell_spawn", match.Pattern.Name)
	assert.Equal(t, "nginx", match.ParentComm)
	assert.Equal(t, "bash", match.Comm)
	assert.Equal(t, uint32(5678), match.PID)
	assert.Equal(t, uint32(1234), match.PPID)
	assert.Equal(t, "critical", match.Pattern.Severity)

	// Verify callback was called
	require.NotNil(t, capturedMatch)
	assert.Equal(t, match.Pattern.Name, capturedMatch.Pattern.Name)
}

func TestLineageTrackerShellNetworkPattern(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := DefaultLineageConfig()

	tracker := NewLineageTracker(config, logger)

	// Simulate bash spawning curl
	e := types.Event{
		Type:       types.EventSyscall,
		PID:        5678,
		PPID:       1234,
		Comm:       commBytes("curl"),
		ParentComm: commBytes("bash"),
	}

	match := tracker.Update(e)

	require.NotNil(t, match, "should detect shell_network_tool pattern")
	assert.Equal(t, "shell_network_tool", match.Pattern.Name)
	assert.Equal(t, "critical", match.Pattern.Severity)
}

func TestLineageTrackerNoMatch(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := DefaultLineageConfig()

	tracker := NewLineageTracker(config, logger)

	// Normal pattern: bash spawning ls (not suspicious)
	e := types.Event{
		Type:       types.EventSyscall,
		PID:        5678,
		PPID:       1234,
		Comm:       commBytes("ls"),
		ParentComm: commBytes("bash"),
	}

	match := tracker.Update(e)
	assert.Nil(t, match, "should not match normal parent-child relationship")
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

	tracker.Update(e)

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
		Patterns: []LineagePattern{},
	}

	tracker := NewLineageTracker(config, logger)

	e := types.Event{
		Type: types.EventSyscall,
		PID:  5678,
		PPID: 1234,
		Comm: commBytes("bash"),
	}

	tracker.Update(e)

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

func TestMatchesAny(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		patterns []string
		want     bool
	}{
		{"exact match", "bash", []string{"sh", "bash", "zsh"}, true},
		{"no match", "bash", []string{"sh", "zsh"}, false},
		{"exact nginx", "nginx", []string{"nginx", "apache2"}, true},
		{"hyphen variant nginx-worker", "nginx-worker", []string{"nginx"}, true},
		{"digit variant python3", "python3", []string{"python"}, true},
		{"digit-dot variant python3.11", "python3.11", []string{"python"}, true},
		// underscore suffix must NOT match — prevents node_exporter matching node
		{"underscore suffix node_exporter", "node_exporter", []string{"node"}, false},
		// letter suffix must NOT match — node and nodejs are separate entries in patterns
		{"letter suffix nodejs", "nodejs", []string{"node"}, false},
		{"empty string", "", []string{"bash"}, false},
		{"empty patterns", "bash", []string{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesAny(tt.s, tt.patterns)
			assert.Equal(t, tt.want, got)
		})
	}
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

func TestLineagePatternConditionParsed(t *testing.T) {
	// Patterns with a Condition field must be parsed (not silently dropped by
	// the YAML decoder) and must still fire — condition is not yet evaluated.
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := LineageConfig{
		Enabled: true,
		TTL:     5 * time.Minute,
		Patterns: []LineagePattern{
			{
				Name:        "test_conditional",
				Description: "fires unconditionally despite condition field",
				ParentComms: []string{"sshd"},
				ChildComms:  []string{"bash"},
				Severity:    "info",
				Condition:   "verify_source_ip",
			},
		},
	}

	tracker := NewLineageTracker(config, logger)

	e := types.Event{
		Type:       types.EventSyscall,
		PID:        1000,
		PPID:       999,
		Comm:       commBytes("bash"),
		ParentComm: commBytes("sshd"),
	}

	match := tracker.Update(e)
	// Pattern should still fire — Condition is parsed but not evaluated.
	require.NotNil(t, match, "pattern with condition field must still fire unconditionally")
	assert.Equal(t, "test_conditional", match.Pattern.Name)
	assert.Equal(t, "verify_source_ip", match.Pattern.Condition)
}

func TestNewLineageTrackerDefaults(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	config := LineageConfig{
		Enabled:  true,
		TTL:      0, // should default to 5m
		Patterns: []LineagePattern{},
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
		tracker.Update(e)
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
		tracker.Update(e)
		e.PID++ // Vary PID to avoid map collision
	}
}
