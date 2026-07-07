package wasm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/wazero/api"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// ValidatePlugin — error and warning branches
// ─────────────────────────────────────────────────────────────────────────────

func TestValidatePlugin_FileNotFound(t *testing.T) {
	res := ValidatePlugin(context.Background(), filepath.Join(t.TempDir(), "nope.wasm"), nil, testLogger())
	assert.False(t, res.OK)
	require.NotEmpty(t, res.Errors)
	assert.Contains(t, res.Errors[0], "read file")
}

func TestValidatePlugin_InvalidWasmBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.wasm")
	require.NoError(t, os.WriteFile(path, []byte("garbage"), 0o644))

	res := ValidatePlugin(context.Background(), path, nil, testLogger())
	assert.False(t, res.OK)
	require.NotEmpty(t, res.Errors)
	assert.Contains(t, res.Errors[0], "compile")
}

func TestValidatePlugin_MissingRequiredExports(t *testing.T) {
	path := filepath.Join("testdata", "invalid", "missing_exports.wasm")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("testdata/invalid/missing_exports.wasm not present")
	}

	res := ValidatePlugin(context.Background(), path, nil, testLogger())
	assert.False(t, res.OK)
	assert.Contains(t, res.Errors, "missing required export: malloc")
	assert.Contains(t, res.Errors, "missing required export: evaluate")
}

func TestValidatePlugin_CorruptMetaProducesWarning(t *testing.T) {
	src := filepath.Join("testdata", "always_match.wasm")
	if _, err := os.Stat(src); os.IsNotExist(err) {
		t.Skip("testdata/always_match.wasm not present")
	}
	dir := t.TempDir()
	data, err := os.ReadFile(src)
	require.NoError(t, err)
	wasmPath := filepath.Join(dir, "always_match.wasm")
	require.NoError(t, os.WriteFile(wasmPath, data, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "always_match.meta.yaml"), []byte("id: [bad"), 0o644))

	res := ValidatePlugin(context.Background(), wasmPath, nil, testLogger())
	assert.NotEmpty(t, res.Warnings)
}

func TestValidatePlugin_DryRunWithSyntheticEvents(t *testing.T) {
	path := filepath.Join("testdata", "always_match.wasm")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("testdata/always_match.wasm not present")
	}

	events := []types.Event{buildEvent(types.EventTCPConnect)}
	res := ValidatePlugin(context.Background(), path, events, testLogger())
	require.True(t, res.OK)
	assert.NotEmpty(t, res.DryRunAlerts)
}

// ─────────────────────────────────────────────────────────────────────────────
// FormatValidationResult
// ─────────────────────────────────────────────────────────────────────────────

func TestFormatValidationResult_Pass(t *testing.T) {
	res := ValidationResult{
		Path: "plugin.wasm",
		Meta: PluginMeta{ID: "p1", Name: "Plugin One", Severity: types.SeverityWarning, Action: "alert"},
		OK:   true,
	}
	out := FormatValidationResult(res)
	assert.Contains(t, out, "[PASS] plugin.wasm")
	assert.Contains(t, out, "id=p1")
	assert.Contains(t, out, "no alerts fired against synthetic events")
}

func TestFormatValidationResult_FailWithErrorsAndWarnings(t *testing.T) {
	res := ValidationResult{
		Path:     "bad.wasm",
		OK:       false,
		Errors:   []string{"missing required export: malloc"},
		Warnings: []string{"missing recommended export: free"},
	}
	out := FormatValidationResult(res)
	assert.Contains(t, out, "[FAIL] bad.wasm")
	assert.Contains(t, out, "ERROR:   missing required export: malloc")
	assert.Contains(t, out, "WARNING: missing recommended export: free")
}

func TestFormatValidationResult_WithDryRunAlerts(t *testing.T) {
	res := ValidationResult{
		Path: "plugin.wasm",
		OK:   true,
		DryRunAlerts: []types.Alert{
			{Severity: types.SeverityCritical, Message: "matched something bad"},
		},
	}
	out := FormatValidationResult(res)
	assert.Contains(t, out, "dry-run: 1 alert(s) fired")
	assert.Contains(t, out, "matched something bad")
}

// ─────────────────────────────────────────────────────────────────────────────
// checkFuncSignature / valueTypesEqual — pure logic, no runtime needed
// ─────────────────────────────────────────────────────────────────────────────

func TestValueTypesEqual(t *testing.T) {
	assert.True(t, valueTypesEqual(nil, nil))
	assert.True(t, valueTypesEqual([]api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}))
	assert.False(t, valueTypesEqual([]api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI64}))
	assert.False(t, valueTypesEqual([]api.ValueType{api.ValueTypeI32}, nil))
	assert.False(t, valueTypesEqual([]api.ValueType{api.ValueTypeI32, api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}))
}

func TestCheckFuncSignature_MismatchRecordsErrors(t *testing.T) {
	// Real function definitions come from a compiled module; reuse the
	// evaluate export from evaluate_no_result.wasm, which deliberately
	// returns no results (mismatching the required (i32,i32)->i32 shape).
	path := filepath.Join("testdata", "invalid", "evaluate_no_result.wasm")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("testdata/invalid/evaluate_no_result.wasm not present")
	}

	res := ValidatePlugin(context.Background(), path, nil, testLogger())
	assert.Contains(t, res.Errors, "evaluate: wrong results: want [127], got []")
}
