package wasm

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/wazero"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// testLogger returns a logger that discards output, for noise-free tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// loadFixturePlugin loads a plugin directly from testdata/name, skipping the
// test if the fixture isn't present (mirrors the skip pattern used elsewhere
// in this package for optional wasm artefacts).
func loadFixturePlugin(t *testing.T, ctx context.Context, rt wazero.Runtime, name string) *Plugin {
	t.Helper()
	path := filepath.Join("testdata", name)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skipf("testdata/%s not present", name)
	}
	p, err := loadPlugin(ctx, rt, path, testLogger())
	require.NoError(t, err, "loadPlugin(%s)", name)
	return p
}

// ─────────────────────────────────────────────────────────────────────────────
// Plugin.Evaluate — malformed/hostile plugin ABI edge cases
//
// These fixtures are minimal, hand-assembled WASM binaries (see
// scripts/gen notes in the PR description) that deliberately violate the
// plugin ABI in specific ways a buggy or malicious plugin author might.
// Engine.Evaluate's contract is that no single plugin can crash the
// pipeline; these tests hold that contract to real WASM execution instead
// of mocks.
// ─────────────────────────────────────────────────────────────────────────────

func TestPluginEvaluate_NoMemory(t *testing.T) {
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	defer rt.Close(ctx)

	p := loadFixturePlugin(t, ctx, rt, "no_memory.wasm")
	defer p.Close(ctx)

	// Must return a clean error, not panic, even though malloc/evaluate are
	// exported — the module simply declares no memory at all.
	_, err := p.Evaluate(ctx, []byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no exported memory")
}

func TestPluginEvaluate_MallocReturnsInvalidPointer(t *testing.T) {
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	defer rt.Close(ctx)

	p := loadFixturePlugin(t, ctx, rt, "malloc_bad_ptr.wasm")
	defer p.Close(ctx)

	_, err := p.Evaluate(ctx, []byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write to linear memory failed")
}

func TestPluginEvaluate_MissingRequiredExports(t *testing.T) {
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	defer rt.Close(ctx)

	p := loadFixturePlugin(t, ctx, rt, "missing_exports.wasm")
	defer p.Close(ctx)

	_, err := p.Evaluate(ctx, []byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing required exports")
}

func TestPluginEvaluate_EvaluateTraps(t *testing.T) {
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	defer rt.Close(ctx)

	p := loadFixturePlugin(t, ctx, rt, "evaluate_traps.wasm")
	defer p.Close(ctx)

	_, err := p.Evaluate(ctx, []byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "evaluate")
}

func TestPluginEvaluate_EvaluateReturnsNoResults(t *testing.T) {
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	defer rt.Close(ctx)

	p := loadFixturePlugin(t, ctx, rt, "evaluate_no_result.wasm")
	defer p.Close(ctx)

	_, err := p.Evaluate(ctx, []byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no results")
}

// TestEngineEvaluate_HostilePluginsDoNotCrashPipeline exercises the full
// Engine.Evaluate path (not just Plugin.Evaluate) against every malformed
// fixture, confirming the documented "a buggy plugin cannot halt the
// pipeline" guarantee end to end.
func TestEngineEvaluate_HostilePluginsDoNotCrashPipeline(t *testing.T) {
	fixtures := []string{
		"no_memory.wasm",
		"malloc_bad_ptr.wasm",
		"missing_exports.wasm",
		"evaluate_traps.wasm",
		"evaluate_no_result.wasm",
	}

	ctx := context.Background()
	dir := t.TempDir()
	for _, f := range fixtures {
		src := filepath.Join("testdata", f)
		if _, err := os.Stat(src); os.IsNotExist(err) {
			t.Skipf("testdata/%s not present", f)
		}
		data, err := os.ReadFile(src)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, f), data, 0o644))
	}

	e, err := NewEngine(ctx, dir, testLogger(), 0)
	require.NoError(t, err)
	defer e.Close(ctx)

	assert.Equal(t, len(fixtures), e.PluginCount(), "all malformed-but-compilable plugins should still load")

	ev := buildEvent(types.EventTCPConnect)
	require.NotPanics(t, func() {
		alerts := e.Evaluate(ctx, ev)
		assert.Empty(t, alerts, "malformed plugins must never produce a match")
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// loadMeta — edge cases
// ─────────────────────────────────────────────────────────────────────────────

func TestLoadMeta_UnreadableManifest(t *testing.T) {
	dir := t.TempDir()
	wasmPath := filepath.Join(dir, "plugin.wasm")
	metaPath := filepath.Join(dir, "plugin.meta.yaml")
	// A directory in place of the manifest file triggers a non-ENOENT read error.
	require.NoError(t, os.Mkdir(metaPath, 0o755))

	_, err := loadMeta(wasmPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read")
}

func TestLoadMeta_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	wasmPath := filepath.Join(dir, "plugin.wasm")
	metaPath := filepath.Join(dir, "plugin.meta.yaml")
	require.NoError(t, os.WriteFile(metaPath, []byte("id: [not valid yaml"), 0o644))

	_, err := loadMeta(wasmPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse")
}

func TestLoadMeta_EmptyFieldsFallBackToDefaults(t *testing.T) {
	dir := t.TempDir()
	wasmPath := filepath.Join(dir, "my_plugin.wasm")
	metaPath := filepath.Join(dir, "my_plugin.meta.yaml")
	// Explicit but empty id/severity/action must fall back to filename/defaults.
	require.NoError(t, os.WriteFile(metaPath, []byte("id: \"\"\nseverity: \"\"\naction: \"\"\nname: Custom\n"), 0o644))

	meta, err := loadMeta(wasmPath)
	require.NoError(t, err)
	assert.Equal(t, "my_plugin", meta.ID)
	assert.Equal(t, types.SeverityWarning, meta.Severity)
	assert.Equal(t, "alert", meta.Action)
	assert.Equal(t, "Custom", meta.Name)
}

// ─────────────────────────────────────────────────────────────────────────────
// loadPlugin — error branches
// ─────────────────────────────────────────────────────────────────────────────

func TestLoadPlugin_MissingFile(t *testing.T) {
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	defer rt.Close(ctx)

	_, err := loadPlugin(ctx, rt, filepath.Join(t.TempDir(), "nope.wasm"), testLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read wasm")
}

func TestLoadPlugin_InvalidWasmBytes(t *testing.T) {
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	defer rt.Close(ctx)

	dir := t.TempDir()
	path := filepath.Join(dir, "garbage.wasm")
	require.NoError(t, os.WriteFile(path, []byte("not a wasm module"), 0o644))

	_, err := loadPlugin(ctx, rt, path, testLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "compile wasm")
}

func TestLoadPlugin_InvalidManifestPropagates(t *testing.T) {
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	defer rt.Close(ctx)

	src := filepath.Join("testdata", "noop.wasm")
	if _, err := os.Stat(src); os.IsNotExist(err) {
		t.Skip("testdata/noop.wasm not present")
	}
	data, err := os.ReadFile(src)
	require.NoError(t, err)

	dir := t.TempDir()
	wasmPath := filepath.Join(dir, "noop.wasm")
	require.NoError(t, os.WriteFile(wasmPath, data, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "noop.meta.yaml"), []byte("id: [bad"), 0o644))

	_, err = loadPlugin(ctx, rt, wasmPath, testLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load meta")
}
