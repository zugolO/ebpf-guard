package exporter

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"sync"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// UnixSocketConfig holds configuration for the Unix socket alert streamer.
type UnixSocketConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Path    string `mapstructure:"path"`
}

// UnixSocketNotifier streams alerts as JSON lines to connected Unix socket clients.
// Each alert is written as a single JSON line followed by a newline character.
// Multiple clients may connect simultaneously; alerts are broadcast to all.
type UnixSocketNotifier struct {
	path     string
	enabled  bool
	listener net.Listener
	mu       sync.RWMutex
	conns    map[net.Conn]struct{}
	logger   *slog.Logger
}

// NewUnixSocketNotifier creates and starts a Unix domain socket alert streamer.
func NewUnixSocketNotifier(cfg UnixSocketConfig, logger *slog.Logger) *UnixSocketNotifier {
	n := &UnixSocketNotifier{
		path:    cfg.Path,
		enabled: cfg.Enabled && cfg.Path != "",
		conns:   make(map[net.Conn]struct{}),
		logger:  logger,
	}
	if !n.enabled {
		return n
	}

	// Remove stale socket file from a previous run.
	os.Remove(cfg.Path)

	ln, err := net.Listen("unix", cfg.Path)
	if err != nil {
		logger.Error("alert_socket: failed to listen on socket",
			slog.String("path", cfg.Path),
			slog.Any("error", err))
		n.enabled = false
		return n
	}
	os.Chmod(cfg.Path, 0660)

	n.listener = ln
	go n.acceptLoop()
	logger.Info("alert_socket: listening for alert consumers",
		slog.String("path", cfg.Path))
	return n
}

func (u *UnixSocketNotifier) Name() string  { return "unix_socket" }
func (u *UnixSocketNotifier) Enabled() bool { return u.enabled }

// Send marshals the alert to JSON and writes it as a newline-terminated line
// to every currently-connected client.
func (u *UnixSocketNotifier) Send(_ context.Context, alert types.Alert) error {
	if !u.enabled {
		return nil
	}
	data, err := json.Marshal(alert)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	u.mu.RLock()
	conns := make([]net.Conn, 0, len(u.conns))
	for c := range u.conns {
		conns = append(conns, c)
	}
	u.mu.RUnlock()

	for _, conn := range conns {
		if _, err := conn.Write(data); err != nil {
			u.removeConn(conn)
		}
	}
	return nil
}

// Close stops accepting new connections and closes all active ones.
func (u *UnixSocketNotifier) Close() error {
	u.enabled = false
	if u.listener != nil {
		u.listener.Close()
	}
	u.mu.Lock()
	for conn := range u.conns {
		conn.Close()
	}
	u.mu.Unlock()
	return nil
}

func (u *UnixSocketNotifier) acceptLoop() {
	for {
		conn, err := u.listener.Accept()
		if err != nil {
			if u.enabled {
				u.logger.Warn("alert_socket: accept error", slog.Any("error", err))
			}
			return
		}
		u.mu.Lock()
		u.conns[conn] = struct{}{}
		u.mu.Unlock()
		go u.drainConn(conn)
	}
}

// drainConn reads and discards any data from the client and cleans up on disconnect.
func (u *UnixSocketNotifier) drainConn(conn net.Conn) {
	buf := make([]byte, 64)
	for {
		if _, err := conn.Read(buf); err != nil {
			break
		}
	}
	u.removeConn(conn)
}

func (u *UnixSocketNotifier) removeConn(conn net.Conn) {
	u.mu.Lock()
	delete(u.conns, conn)
	u.mu.Unlock()
	conn.Close()
}
