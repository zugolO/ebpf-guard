package exporter

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnixSocketNotifier_Disabled(t *testing.T) {
	n := NewUnixSocketNotifier(UnixSocketConfig{Enabled: false}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	assert.Equal(t, "unix_socket", n.Name())
	assert.False(t, n.Enabled())
	// Send is a no-op when disabled.
	require.NoError(t, n.Send(context.Background(), types.Alert{ID: "x"}))
	require.NoError(t, n.Close())
}

func TestUnixSocketNotifier_StreamsAlert(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "a.sock")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	n := NewUnixSocketNotifier(UnixSocketConfig{Enabled: true, Path: sockPath}, logger)
	require.True(t, n.Enabled())
	defer n.Close()

	// Connect a client and wait for acceptLoop to register it.
	conn, err := net.Dial("unix", sockPath)
	require.NoError(t, err)
	defer conn.Close()

	require.Eventually(t, func() bool {
		n.mu.RLock()
		defer n.mu.RUnlock()
		return len(n.conns) == 1
	}, time.Second, 5*time.Millisecond)

	// Broadcast an alert and read it back as a JSON line.
	want := types.Alert{ID: "alert-1", RuleID: "rule-007", Severity: types.SeverityCritical}
	require.NoError(t, n.Send(context.Background(), want))

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(time.Second)))
	line, err := bufio.NewReader(conn).ReadString('\n')
	require.NoError(t, err)

	var got types.Alert
	require.NoError(t, json.Unmarshal([]byte(line), &got))
	assert.Equal(t, "alert-1", got.ID)
	assert.Equal(t, "rule-007", got.RuleID)

	require.NoError(t, n.Close())
	assert.False(t, n.Enabled())
}

func TestUnixSocketNotifier_ListenError(t *testing.T) {
	// A path inside a non-existent directory cannot be bound; the notifier
	// must downgrade to disabled rather than panic.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	n := NewUnixSocketNotifier(UnixSocketConfig{Enabled: true, Path: "/nonexistent-dir/a.sock"}, logger)
	assert.False(t, n.Enabled())
}
