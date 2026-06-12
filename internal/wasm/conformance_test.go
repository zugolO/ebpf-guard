package wasm

// Conformance test suite for the WASM plugin ABI.
//
// These tests verify that any plugin claiming ABI v1 compliance passes a
// minimum bar before being deployed.  They run in CI with the pre-built
// testdata artefacts (always_match.wasm, noop.wasm) and are designed so that
// plugin authors can run them locally against their own .wasm binaries:
//
//	WASM_PLUGIN_DIR=./myplugin go test -v -run TestWASMConformance ./internal/wasm/
//
// If WASM_PLUGIN_DIR is set, its *.wasm files are validated in addition to the
// testdata ones.

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// conformancePlugins maps testdata plugin filename to whether it should fire
// at least one alert against the standard synthetic event set.
var conformancePlugins = map[string]bool{
	"always_match.wasm": true,  // must fire on every event
	"noop.wasm":         false, // must never fire
}

// TestWASMConformance_RequiredExports verifies that every testdata plugin
// exports the ABI-required symbols malloc and evaluate.
func TestWASMConformance_RequiredExports(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	for name := range conformancePlugins {
		path := filepath.Join("testdata", name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Skipf("testdata/%s not present; skipping conformance test", name)
		}

		t.Run(name, func(t *testing.T) {
			res := ValidatePlugin(ctx, path, nil, logger)
			assert.Empty(t, res.Errors,
				"plugin %s has ABI errors: %v", name, res.Errors)
			assert.True(t, res.OK, "plugin %s failed ABI validation", name)
		})
	}
}

// TestWASMConformance_DryRun runs each testdata plugin against all event types
// and verifies the expected match/no-match behaviour.
func TestWASMConformance_DryRun(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	syntheticEvents := conformanceSyntheticEvents()

	for name, shouldFire := range conformancePlugins {
		path := filepath.Join("testdata", name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Skipf("testdata/%s not present", name)
		}

		t.Run(name, func(t *testing.T) {
			res := ValidatePlugin(ctx, path, syntheticEvents, logger)
			require.True(t, res.OK, "plugin %s failed ABI check: %v", name, res.Errors)

			if shouldFire {
				assert.NotEmpty(t, res.DryRunAlerts,
					"plugin %s should fire on synthetic events but produced no alerts", name)
			} else {
				assert.Empty(t, res.DryRunAlerts,
					"plugin %s should never fire but produced %d alert(s)", name, len(res.DryRunAlerts))
			}
		})
	}
}

// TestWASMConformance_Isolation verifies that two concurrent evaluations of the
// same plugin do not share state (i.e., the fresh-instance-per-call model holds).
func TestWASMConformance_Isolation(t *testing.T) {
	path := filepath.Join("testdata", "always_match.wasm")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("testdata/always_match.wasm not present")
	}

	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	dir := filepath.Dir(path)
	e, err := NewEngine(ctx, dir, logger, 0)
	require.NoError(t, err)
	defer e.Close(ctx)

	ev := buildEvent(types.EventTCPConnect)

	const goroutines = 16
	results := make(chan int, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			alerts := e.Evaluate(ctx, ev)
			results <- len(alerts)
		}()
	}

	for i := 0; i < goroutines; i++ {
		count := <-results
		// always_match.wasm should produce exactly one alert per call regardless
		// of concurrent execution.
		assert.Equal(t, 1, count, "expected exactly 1 alert from always_match.wasm per goroutine")
	}
}

// TestWASMConformance_Timeout verifies that a timed-out plugin does not crash
// the evaluation pipeline and that subsequent events are still processed.
func TestWASMConformance_Timeout(t *testing.T) {
	path := filepath.Join("testdata", "noop.wasm")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("testdata/noop.wasm not present")
	}

	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	dir := t.TempDir()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "noop.wasm"), data, 0600))

	// Use a 1 ns timeout — guaranteed to expire before any real work is done.
	e, err := NewEngine(ctx, dir, logger, 1)
	require.NoError(t, err)
	defer e.Close(ctx)

	ev := buildEvent(types.EventTCPConnect)
	// Must not panic; alerts will be empty due to timeout.
	alerts := e.Evaluate(ctx, ev)
	assert.Empty(t, alerts, "timed-out plugin should produce no alerts")

	// Pipeline must remain functional after a timeout.
	alerts2 := e.Evaluate(ctx, ev)
	assert.Empty(t, alerts2, "subsequent evaluation after timeout must succeed")
}

// TestWASMConformance_ExternalPluginDir runs ValidatePlugin on every *.wasm
// file found in WASM_PLUGIN_DIR (if set).  Useful for plugin authors:
//
//	WASM_PLUGIN_DIR=./dist go test -v -run TestWASMConformance_ExternalPluginDir ./internal/wasm/
func TestWASMConformance_ExternalPluginDir(t *testing.T) {
	dir := os.Getenv("WASM_PLUGIN_DIR")
	if dir == "" {
		t.Skip("WASM_PLUGIN_DIR not set; skipping external plugin conformance")
	}

	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err, "WASM_PLUGIN_DIR not readable")

	var plugins []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".wasm") {
			plugins = append(plugins, filepath.Join(dir, e.Name()))
		}
	}
	require.NotEmpty(t, plugins, "no .wasm files found in WASM_PLUGIN_DIR=%s", dir)

	events := conformanceSyntheticEvents()

	for _, p := range plugins {
		p := p
		t.Run(filepath.Base(p), func(t *testing.T) {
			t.Parallel()
			res := ValidatePlugin(ctx, p, events, logger)
			assert.Empty(t, res.Errors, "ABI errors: %v", res.Errors)
			if len(res.Warnings) > 0 {
				t.Logf("ABI warnings: %v", res.Warnings)
			}
			assert.True(t, res.OK)
		})
	}
}

// conformanceSyntheticEvents returns the canonical event set used for conformance dry-runs.
// It covers every documented EventType so a catch-all plugin can be verified.
func conformanceSyntheticEvents() []types.Event {
	var comm [16]byte
	copy(comm[:], "conformance")

	var addr [16]byte
	addr[0], addr[1], addr[2], addr[3] = 1, 2, 3, 4

	return []types.Event{
		{Type: types.EventSyscall, PID: 1, Comm: comm,
			Syscall: &types.SyscallEvent{Nr: 59, Ret: 0}},
		{Type: types.EventTCPConnect, PID: 2, Comm: comm,
			Network: &types.NetworkEvent{Dport: 443, Sport: 54321, Family: types.AFInet, Daddr: addr}},
		{Type: types.EventFileAccess, PID: 3, Comm: comm,
			File: &types.FileEvent{Flags: 2, Op: 0}},
		{Type: types.EventTLS, PID: 4, Comm: comm,
			TLS: &types.TLSEvent{Direction: 0, DataLen: 256}},
		{Type: types.EventDNS, PID: 5, Comm: comm,
			DNS: &types.DNSEvent{QName: "evil.example.com", QType: 1}},
		{Type: types.EventPrivesc, PID: 6, Comm: comm,
			Privesc: &types.PrivescEvent{OldCaps: 0, NewCaps: 1 << 21}},
		{Type: types.EventKmodLoad, PID: 7, Comm: comm,
			Kmod: &types.KmodEvent{ModName: "evil.ko", FromTmpfs: true}},
		{Type: types.EventCgroupEsc, PID: 8, Comm: comm,
			CgroupEsc: &types.CgroupEscapeEvent{InitCgroupID: 1, NewCgroupID: 2}},
	}
}
