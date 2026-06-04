package autolearn

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/zugolO/ebpf-guard/internal/util"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Session collects events during a learning window and builds a behavioral profile
// that can be exported as ebpf-guard YAML rules or a seccomp JSON profile.
type Session struct {
	mu sync.Mutex

	// Observed behavior sets
	syscalls   map[int64]struct{}
	netPeers   map[string]struct{} // "ip:port"
	destPorts  map[uint16]struct{}
	destIPs    map[string]struct{}
	filePaths  map[string]struct{} // full paths
	fileDirs   map[string]struct{} // directories
	comms      map[string]struct{} // process names (comm)
	execPaths  map[string]struct{} // executed binary paths

	// Filters
	namespace   string // empty = all namespaces
	containerID string // empty = all containers
	commFilter  string // empty = all comms

	// Timing
	startTime time.Time
	duration  time.Duration

	// Stats
	eventCount uint64

	logger *slog.Logger
}

// SessionConfig holds configuration for a learning session.
type SessionConfig struct {
	// Duration is how long to observe before generating the profile.
	Duration time.Duration
	// Namespace filters events to a specific Kubernetes namespace (empty = all).
	Namespace string
	// ContainerID filters events to a specific container ID (empty = all).
	ContainerID string
	// CommFilter filters events to processes matching this comm prefix (empty = all).
	CommFilter string
	// Logger is the structured logger to use.
	Logger *slog.Logger
}

// NewSession creates a new learning session.
func NewSession(cfg SessionConfig) *Session {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Session{
		syscalls:    make(map[int64]struct{}),
		netPeers:    make(map[string]struct{}),
		destPorts:   make(map[uint16]struct{}),
		destIPs:     make(map[string]struct{}),
		filePaths:   make(map[string]struct{}),
		fileDirs:    make(map[string]struct{}),
		comms:       make(map[string]struct{}),
		execPaths:   make(map[string]struct{}),
		namespace:   cfg.Namespace,
		containerID: cfg.ContainerID,
		commFilter:  cfg.CommFilter,
		startTime:   time.Now(),
		duration:    cfg.Duration,
		logger:      logger,
	}
}

// Ingest processes an event and folds it into the learned profile.
func (s *Session) Ingest(e types.Event) {
	if !s.matchesFilter(e) {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.eventCount++

	comm := util.BytesToString(e.Comm[:])
	if comm != "" {
		s.comms[comm] = struct{}{}
	}

	switch e.Type {
	case types.EventSyscall:
		if e.Syscall != nil {
			s.syscalls[e.Syscall.Nr] = struct{}{}
		}
	case types.EventTCPConnect:
		if e.Network != nil {
			ip := util.FormatIP16(e.Network.Daddr, e.Network.Family)
			port := e.Network.Dport
			s.destIPs[ip] = struct{}{}
			s.destPorts[port] = struct{}{}
			s.netPeers[fmt.Sprintf("%s:%d", ip, port)] = struct{}{}
		}
	case types.EventFileAccess:
		if e.File != nil {
			path := util.BytesToString(e.File.Filename[:])
			if path != "" {
				s.filePaths[path] = struct{}{}
				dir := extractDir(path)
				if dir != "" {
					s.fileDirs[dir] = struct{}{}
				}
				// Track executed binaries (open with O_EXEC or execve patterns)
				if isExecutablePath(path) {
					s.execPaths[path] = struct{}{}
				}
			}
		}
	}
}

// matchesFilter returns true if the event passes namespace/container/comm filters.
func (s *Session) matchesFilter(e types.Event) bool {
	if s.namespace != "" {
		if e.Enrichment == nil || e.Enrichment.Namespace != s.namespace {
			return false
		}
	}
	if s.containerID != "" {
		if e.Enrichment == nil || e.Enrichment.ContainerID != s.containerID {
			return false
		}
	}
	if s.commFilter != "" {
		comm := util.BytesToString(e.Comm[:])
		if !strings.HasPrefix(comm, s.commFilter) {
			return false
		}
	}
	return true
}

// Run starts the session, ingesting from eventCh until the duration expires or ctx is cancelled.
// Returns a snapshot of the learned profile.
func (s *Session) Run(ctx context.Context, eventCh <-chan types.Event) *Snapshot {
	deadline := time.NewTimer(s.duration)
	defer deadline.Stop()

	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()

	s.logger.Info("autolearn: session started",
		slog.Duration("duration", s.duration),
		slog.String("namespace", s.namespace),
		slog.String("container_id", s.containerID),
	)

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("autolearn: session cancelled", slog.Uint64("events", s.eventCount))
			return s.Snapshot()
		case <-deadline.C:
			s.logger.Info("autolearn: session complete", slog.Uint64("events", s.eventCount))
			return s.Snapshot()
		case <-tick.C:
			s.mu.Lock()
			cnt := s.eventCount
			scCnt := len(s.syscalls)
			netCnt := len(s.netPeers)
			fileCnt := len(s.filePaths)
			s.mu.Unlock()
			s.logger.Info("autolearn: progress",
				slog.Uint64("events", cnt),
				slog.Int("syscalls", scCnt),
				slog.Int("net_peers", netCnt),
				slog.Int("file_paths", fileCnt),
				slog.Duration("remaining", s.duration-time.Since(s.startTime)),
			)
		case event, ok := <-eventCh:
			if !ok {
				return s.Snapshot()
			}
			s.Ingest(event)
		}
	}
}

// Snapshot returns an immutable copy of the current learned profile.
func (s *Session) Snapshot() *Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	snap := &Snapshot{
		GeneratedAt: time.Now(),
		Duration:    s.duration,
		EventCount:  s.eventCount,
		Namespace:   s.namespace,
		ContainerID: s.containerID,
		CommFilter:  s.commFilter,
		Syscalls:    make([]int64, 0, len(s.syscalls)),
		DestPorts:   make([]uint16, 0, len(s.destPorts)),
		DestIPs:     make([]string, 0, len(s.destIPs)),
		FileDirs:    make([]string, 0, len(s.fileDirs)),
		ExecPaths:   make([]string, 0, len(s.execPaths)),
		Comms:       make([]string, 0, len(s.comms)),
	}
	for nr := range s.syscalls {
		snap.Syscalls = append(snap.Syscalls, nr)
	}
	for port := range s.destPorts {
		snap.DestPorts = append(snap.DestPorts, port)
	}
	for ip := range s.destIPs {
		snap.DestIPs = append(snap.DestIPs, ip)
	}
	for dir := range s.fileDirs {
		snap.FileDirs = append(snap.FileDirs, dir)
	}
	for path := range s.execPaths {
		snap.ExecPaths = append(snap.ExecPaths, path)
	}
	for comm := range s.comms {
		snap.Comms = append(snap.Comms, comm)
	}
	return snap
}

// Snapshot is an immutable view of a completed learning session.
type Snapshot struct {
	GeneratedAt time.Time
	Duration    time.Duration
	EventCount  uint64
	Namespace   string
	ContainerID string
	CommFilter  string

	// Observed behavior
	Syscalls  []int64
	DestPorts []uint16
	DestIPs   []string
	FileDirs  []string
	ExecPaths []string
	Comms     []string
}

func extractDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i+1]
		}
	}
	return ""
}

func isExecutablePath(path string) bool {
	for _, prefix := range []string{"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
