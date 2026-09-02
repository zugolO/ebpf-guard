package exporter

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// syncBuffer is a goroutine-safe io.Writer used to capture log output that the
// acceptLoop goroutine may write concurrently with the test reading it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// tempSockPath returns a short filesystem path for a test unix socket.
//
// t.TempDir() names the directory after the test, and a unix socket path is
// capped by sockaddr_un.sun_path — 104 bytes on darwin, 108 on linux. The two
// tests below have names long enough to push t.TempDir()+"/a.sock" past the
// darwin cap, and the bind then fails with "invalid argument": the notifier
// downgrades itself to disabled and the test fails on Enabled() for a reason
// that has nothing to do with the code under test. A short temp directory
// keeps the path well inside both caps.
func tempSockPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "eg")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "a.sock")
}

func TestUnixSocketNotifier_Disabled(t *testing.T) {
	n := NewUnixSocketNotifier(UnixSocketConfig{Enabled: false}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	assert.Equal(t, "unix_socket", n.Name())
	assert.False(t, n.Enabled())
	// Send is a no-op when disabled.
	require.NoError(t, n.Send(context.Background(), types.Alert{ID: "x"}))
	require.NoError(t, n.Close())
}

func TestUnixSocketNotifier_StreamsAlert(t *testing.T) {
	sockPath := tempSockPath(t)
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

func TestUnixSocketNotifier_EnabledWithoutPath(t *testing.T) {
	// Enabled is requested but no path is configured: the notifier must stay
	// disabled rather than attempt to bind an empty socket path.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	n := NewUnixSocketNotifier(UnixSocketConfig{Enabled: true, Path: ""}, logger)
	assert.False(t, n.Enabled())
	require.NoError(t, n.Send(context.Background(), types.Alert{ID: "x"}))
	require.NoError(t, n.Close())
}

func TestUnixSocketNotifier_AcceptErrorWhileEnabled(t *testing.T) {
	sockPath := tempSockPath(t)
	sb := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(sb, nil))

	n := NewUnixSocketNotifier(UnixSocketConfig{Enabled: true, Path: sockPath}, logger)
	require.True(t, n.Enabled())
	t.Cleanup(func() { n.Close() })

	// Close the underlying listener directly, without going through Close()
	// (which would flip enabled to false first). acceptLoop then observes an
	// accept error while the notifier is still enabled and must log a warning.
	require.NoError(t, n.listener.Close())

	require.Eventually(t, func() bool {
		return strings.Contains(sb.String(), "accept error")
	}, time.Second, 5*time.Millisecond)
}

func TestUnixSocketNotifier_ListenError(t *testing.T) {
	// A path inside a non-existent directory cannot be bound; the notifier
	// must downgrade to disabled rather than panic.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	n := NewUnixSocketNotifier(UnixSocketConfig{Enabled: true, Path: "/nonexistent-dir/a.sock"}, logger)
	assert.False(t, n.Enabled())
}
