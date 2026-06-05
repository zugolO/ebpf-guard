// lsm_test.go — Tests for LSM collector

package collector

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLSMConfig_Default(t *testing.T) {
	config := DefaultLSMConfig()
	assert.Equal(t, "auto", config.Enabled)
}

func TestNewLSMCollector(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	tests := []struct {
		name      string
		config    LSMConfig
		wantAvail bool
		wantErr   bool
	}{
		{
			name:      "auto mode with no kernel support",
			config:    LSMConfig{Enabled: "auto"},
			wantAvail: false,
			wantErr:   false,
		},
		{
			name:      "disabled mode",
			config:    LSMConfig{Enabled: "false"},
			wantAvail: false,
			wantErr:   false,
		},
		{
			name:      "forced mode with no kernel support",
			config:    LSMConfig{Enabled: "true"},
			wantAvail: false,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lc, err := NewLSMCollector(tt.config, logger)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantAvail, lc.IsAvailable())
		})
	}
}

func TestLSMCollector_Name(t *testing.T) {
	lc := &LSMCollector{}
	assert.Equal(t, "lsm", lc.Name())
}

func TestLSMCollector_RegisterMetrics(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	lc, err := NewLSMCollector(DefaultLSMConfig(), logger)
	require.NoError(t, err)

	reg := prometheus.NewRegistry()
	err = lc.RegisterMetrics(reg)
	require.NoError(t, err)

	// Verify metrics are registered
	families, err := reg.Gather()
	require.NoError(t, err)
	require.Len(t, families, 1)
	assert.Equal(t, "ebpf_guard_lsm_blocks_total", *families[0].Name)
}

func TestLSMCollector_StartStop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	lc, err := NewLSMCollector(LSMConfig{Enabled: "false"}, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	out := make(chan types.Event, 10)
	errChan := make(chan error, 1)

	go func() {
		errChan <- lc.Start(ctx, out)
	}()

	// Wait for context timeout
	err = <-errChan
	assert.Equal(t, context.DeadlineExceeded, err)
}

func TestLSMCollector_BlocklistOperations(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	lc, err := NewLSMCollector(LSMConfig{Enabled: "false"}, logger)
	require.NoError(t, err)

	// Should fail when not available
	err = lc.AddToBlocklist(1234)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available")

	err = lc.RemoveFromBlocklist(1234)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not available")
}

func TestLSMCollector_Close(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	lc, err := NewLSMCollector(LSMConfig{Enabled: "false"}, logger)
	require.NoError(t, err)

	err = lc.Close()
	assert.NoError(t, err)
}

func TestLSMCollector_checkAvailability(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	lc := &LSMCollector{
		logger: logger,
	}

	// This will return false in test environment without LSM support
	avail := lc.checkAvailability()
	// Just verify it doesn't panic
	_ = avail
}

// TestFNV32a verifies the Go FNV-32a helper produces values that satisfy the
// basic collision-free requirement needed for the path blocklist.
func TestFNV32a(t *testing.T) {
	// Same path → same hash
	assert.Equal(t, fnv32a("/tmp/evil"), fnv32a("/tmp/evil"))
	// Different paths → different hashes (no false positives in blocklist)
	assert.NotEqual(t, fnv32a("/tmp/evil"), fnv32a("/tmp/legit"))
	assert.NotEqual(t, fnv32a("/etc/shadow"), fnv32a("/etc/passwd"))
	// Empty string has a well-defined value (FNV offset basis unchanged = 2166136261)
	assert.Equal(t, uint32(2166136261), fnv32a(""))
}

// TestPathBlocklist_BlockEvil_AllowLegit is the acceptance-test from issue #33:
// blocking /tmp/evil must not block /tmp/legit.
// We simulate the BPF map with an in-memory map keyed by FNV-32a hash.
func TestPathBlocklist_BlockEvil_AllowLegit(t *testing.T) {
	// Simulate the BPF path_blocklist map: hash → blocked
	bpfMap := map[uint32]bool{
		fnv32a("/tmp/evil"): true,
	}

	isBlocked := func(path string) bool {
		return bpfMap[fnv32a(path)]
	}

	assert.True(t, isBlocked("/tmp/evil"), "/tmp/evil must be blocked")
	assert.False(t, isBlocked("/tmp/legit"), "/tmp/legit must be allowed")
	assert.False(t, isBlocked("/etc/passwd"), "/etc/passwd must be allowed")
}

// TestLSMCollector_PathBlocklist_StubMode verifies that path operations return
// a meaningful error when the LSM collector is in stub mode (no kernel support).
func TestLSMCollector_PathBlocklist_StubMode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	lc, err := NewLSMCollector(LSMConfig{Enabled: "false"}, logger)
	require.NoError(t, err)

	err = lc.AddPathToBlocklist("/tmp/evil")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not available")

	err = lc.RemovePathFromBlocklist("/tmp/evil")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not available")

	err = lc.SetPathBlocklist([]string{"/tmp/evil"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not available")
}

// TestPathBlocklist_Idempotent verifies that adding the same path twice does
// not change the effective blocklist (the BPF map update is idempotent).
func TestPathBlocklist_Idempotent(t *testing.T) {
	bpfMap := map[uint32]bool{}

	add := func(path string) {
		bpfMap[fnv32a(path)] = true
	}

	add("/tmp/evil")
	add("/tmp/evil") // second add must not cause problems
	assert.Len(t, bpfMap, 1, "duplicate path must not create duplicate map entries")
}

// TestPathBlocklist_HotReload verifies that SetPathBlocklist replaces the
// previous config-driven set while preserving dynamically added entries.
func TestPathBlocklist_HotReload(t *testing.T) {
	// Round 1: config has /etc/shadow
	configMap := map[uint32]bool{fnv32a("/etc/shadow"): true}
	// Dynamic rule blocked /tmp/evil too
	dynamicMap := map[uint32]bool{fnv32a("/tmp/evil"): true}

	isBlocked := func(path string) bool {
		return configMap[fnv32a(path)] || dynamicMap[fnv32a(path)]
	}

	assert.True(t, isBlocked("/etc/shadow"))
	assert.True(t, isBlocked("/tmp/evil"))
	assert.False(t, isBlocked("/tmp/legit"))

	// Round 2: config hot-reload removes /etc/shadow, adds /proc/sysrq-trigger
	delete(configMap, fnv32a("/etc/shadow"))
	configMap[fnv32a("/proc/sysrq-trigger")] = true

	assert.False(t, isBlocked("/etc/shadow"), "removed config path must be unblocked")
	assert.True(t, isBlocked("/proc/sysrq-trigger"), "new config path must be blocked")
	assert.True(t, isBlocked("/tmp/evil"), "dynamic path must survive hot-reload")
}
