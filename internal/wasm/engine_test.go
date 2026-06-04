package wasm

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// buildEvent builds a synthetic types.Event for testing.
func buildEvent(t types.EventType) types.Event {
	var comm [16]byte
	copy(comm[:], "nginx")
	return types.Event{
		Type:  t,
		PID:   1234,
		PPID:  1,
		UID:   0,
		Comm:  comm,
		TGID:  1234,
	}
}

func TestSerializeEvent_Network(t *testing.T) {
	ev := buildEvent(types.EventTCPConnect)
	ev.Network = &types.NetworkEvent{
		Dport:  443,
		Sport:  54321,
		Family: types.AFInet,
	}
	ev.Network.Daddr[0] = 1
	ev.Network.Daddr[1] = 2
	ev.Network.Daddr[2] = 3
	ev.Network.Daddr[3] = 4

	data, err := SerializeEvent(ev)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"dport":443`)
	assert.Contains(t, string(data), `"daddr":"1.2.3.4"`)
	assert.Contains(t, string(data), `"comm":"nginx"`)
	assert.Contains(t, string(data), `"type":2`)
}

func TestSerializeEvent_DNS(t *testing.T) {
	ev := buildEvent(types.EventDNS)
	ev.DNS = &types.DNSEvent{
		QName: "evil.example.com",
		QType: 1,
	}

	data, err := SerializeEvent(ev)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"qname":"evil.example.com"`)
	assert.Contains(t, string(data), `"type":5`)
}

func TestSerializeEvent_File(t *testing.T) {
	ev := buildEvent(types.EventFileAccess)
	ev.File = &types.FileEvent{Flags: 2, Op: 1}
	copy(ev.File.Filename[:], "/etc/shadow")

	data, err := SerializeEvent(ev)
	require.NoError(t, err)
	assert.Contains(t, string(data), "/etc/shadow")
	assert.Contains(t, string(data), `"op":1`)
}

func TestLoadMeta_Defaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "my_detector.wasm")

	// No manifest file — should return defaults derived from filename
	meta, err := loadMeta(path)
	require.NoError(t, err)
	assert.Equal(t, "my_detector", meta.ID)
	assert.Equal(t, "my_detector", meta.Name)
	assert.Equal(t, types.SeverityWarning, meta.Severity)
	assert.Equal(t, "alert", meta.Action)
}

func TestLoadMeta_WithManifest(t *testing.T) {
	dir := t.TempDir()
	wasmPath := filepath.Join(dir, "sqli_detector.wasm")
	metaPath := filepath.Join(dir, "sqli_detector.meta.yaml")

	manifest := `
id: custom_sqli_001
name: "SQL Injection Detector"
description: "Detects SQL injection patterns in TLS plaintext"
severity: critical
action: alert
tags: [owasp, sqli, custom]
`
	require.NoError(t, os.WriteFile(metaPath, []byte(manifest), 0600))

	meta, err := loadMeta(wasmPath)
	require.NoError(t, err)
	assert.Equal(t, "custom_sqli_001", meta.ID)
	assert.Equal(t, "SQL Injection Detector", meta.Name)
	assert.Equal(t, types.SeverityCritical, meta.Severity)
	assert.Equal(t, []string{"owasp", "sqli", "custom"}, meta.Tags)
}

func TestNewEngine_EmptyDir(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	e, err := NewEngine(ctx, dir, logger, 0)
	require.NoError(t, err)
	defer e.Close(ctx)

	assert.Equal(t, 0, e.PluginCount())
	assert.Empty(t, e.PluginIDs())
}

func TestNewEngine_MissingDir(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Non-existent directory should NOT return an error — just 0 plugins
	e, err := NewEngine(ctx, "/nonexistent/plugin/path", logger, 0)
	require.NoError(t, err)
	defer e.Close(ctx)

	assert.Equal(t, 0, e.PluginCount())
}

func TestEngine_Evaluate_NoPlugins(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	e, err := NewEngine(ctx, dir, logger, 0)
	require.NoError(t, err)
	defer e.Close(ctx)

	ev := buildEvent(types.EventTCPConnect)
	alerts := e.Evaluate(ctx, ev)
	assert.Empty(t, alerts)
}

func TestNewEngine_CustomTimeout(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	e, err := NewEngine(ctx, dir, logger, 250*time.Millisecond)
	require.NoError(t, err)
	defer e.Close(ctx)

	assert.Equal(t, 250*time.Millisecond, e.timeout)
}

func TestEngine_Evaluate_WithRealWasmPlugin(t *testing.T) {
	// This test loads a real compiled WASM module from testdata/.
	// If the testdata file is absent (CI without wasm compiler), skip gracefully.
	wasmPath := filepath.Join("testdata", "always_match.wasm")
	if _, err := os.Stat(wasmPath); os.IsNotExist(err) {
		t.Skip("testdata/always_match.wasm not present; skipping real WASM test")
	}

	ctx := context.Background()
	dir := filepath.Dir(wasmPath)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	e, err := NewEngine(ctx, dir, logger, 0)
	require.NoError(t, err)
	defer e.Close(ctx)

	ev := buildEvent(types.EventTCPConnect)
	alerts := e.Evaluate(ctx, ev)
	require.Len(t, alerts, 1)
	assert.Equal(t, "always_match", alerts[0].RuleID)
}

func TestFormatIP_IPv4(t *testing.T) {
	var addr [16]byte
	addr[0], addr[1], addr[2], addr[3] = 192, 168, 1, 100
	assert.Equal(t, "192.168.1.100", formatIP(addr, types.AFInet))
}

func TestFormatIP_IPv6(t *testing.T) {
	var addr [16]byte
	// ::1 (loopback)
	addr[15] = 1
	result := formatIP(addr, types.AFInet6)
	assert.Contains(t, result, ":")
	assert.Contains(t, result, "0001")
}
