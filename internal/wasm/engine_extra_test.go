package wasm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// loadDir / NewEngine — directory scanning edge cases
// ─────────────────────────────────────────────────────────────────────────────

func TestNewEngine_ReadDirFails(t *testing.T) {
	ctx := context.Background()
	// A regular file in place of a directory: os.Stat succeeds (not
	// IsNotExist) but os.ReadDir fails with "not a directory".
	file := filepath.Join(t.TempDir(), "not-a-dir")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o644))

	_, err := NewEngine(ctx, file, testLogger(), 0)
	require.Error(t, err)
}

func TestLoadDir_SkipsSubdirsAndNonWasmFiles(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "subdir"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "subdir", "nested.wasm"), []byte("ignored"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte("not a plugin"), 0o644))

	e, err := NewEngine(ctx, dir, testLogger(), 0)
	require.NoError(t, err)
	defer e.Close(ctx)

	assert.Equal(t, 0, e.PluginCount(), "subdirectories and non-.wasm files must be skipped")
}

func TestLoadDir_CorruptWasmFileSkippedWithWarning(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "corrupt.wasm"), []byte("not a real wasm module"), 0o644))

	e, err := NewEngine(ctx, dir, testLogger(), 0)
	require.NoError(t, err, "a corrupt plugin must be skipped, not fail engine startup")
	defer e.Close(ctx)

	assert.Equal(t, 0, e.PluginCount())
}

func TestLoadDir_MixOfGoodAndCorruptPlugins(t *testing.T) {
	good := filepath.Join("testdata", "always_match.wasm")
	if _, err := os.Stat(good); os.IsNotExist(err) {
		t.Skip("testdata/always_match.wasm not present")
	}

	ctx := context.Background()
	dir := t.TempDir()
	data, err := os.ReadFile(good)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "always_match.wasm"), data, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "corrupt.wasm"), []byte("garbage"), 0o644))

	e, err := NewEngine(ctx, dir, testLogger(), 0)
	require.NoError(t, err)
	defer e.Close(ctx)

	assert.Equal(t, 1, e.PluginCount(), "only the valid plugin should load")
}

// ─────────────────────────────────────────────────────────────────────────────
// PluginIDs
// ─────────────────────────────────────────────────────────────────────────────

func TestEngine_PluginIDs(t *testing.T) {
	path := filepath.Join("testdata", "always_match.wasm")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("testdata/always_match.wasm not present")
	}

	ctx := context.Background()
	e, err := NewEngine(ctx, filepath.Dir(path), testLogger(), 0)
	require.NoError(t, err)
	defer e.Close(ctx)

	ids := e.PluginIDs()
	assert.Contains(t, ids, "always_match")
}

// ─────────────────────────────────────────────────────────────────────────────
// evalPlugin — alert enrichment (tags, trace context, k8s enrichment)
// ─────────────────────────────────────────────────────────────────────────────

func TestEngineEvaluate_AlertCarriesTagsTraceAndEnrichment(t *testing.T) {
	src := filepath.Join("testdata", "always_match.wasm")
	if _, err := os.Stat(src); os.IsNotExist(err) {
		t.Skip("testdata/always_match.wasm not present")
	}

	ctx := context.Background()
	dir := t.TempDir()
	data, err := os.ReadFile(src)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "always_match.wasm"), data, 0o644))

	manifest := "id: tagged_detector\nname: Tagged Detector\nseverity: critical\naction: alert\ntags: [owasp, custom]\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "always_match.meta.yaml"), []byte(manifest), 0o644))

	e, err := NewEngine(ctx, dir, testLogger(), 0)
	require.NoError(t, err)
	defer e.Close(ctx)

	ev := buildEvent(types.EventTCPConnect)
	ev.TraceContext = &types.TraceContext{TraceID: "abc123", SpanID: "def456"}
	ev.Enrichment = &types.EnrichmentInfo{ContainerID: "c1", Namespace: "default", PodName: "mypod"}

	alerts := e.Evaluate(ctx, ev)
	require.Len(t, alerts, 1)
	a := alerts[0]
	assert.Equal(t, "abc123", a.TraceID)
	assert.Equal(t, "def456", a.SpanID)
	assert.Equal(t, "c1", a.Enrichment.ContainerID)
	require.NotNil(t, a.Details)
	assert.Equal(t, []string{"owasp", "custom"}, a.Details["wasm_plugin_tags"])
	assert.Equal(t, "tagged_detector", a.Details["wasm_plugin_id"])
}
