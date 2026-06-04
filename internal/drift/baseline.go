// Package drift implements container drift detection by comparing runtime
// behaviour against a per-container baseline captured at startup.
package drift

import (
	"sync"
	"time"
)

// ContainerBaseline holds observed behaviour during the initial baseline window.
// While Locked is false the baseline is still being built; once the window expires
// all subsequent deviations are reported as drift.
type ContainerBaseline struct {
	mu sync.RWMutex

	// Identity
	ContainerID string
	Namespace   string
	PodName     string

	// Timeline
	StartTime      time.Time
	BaselineExpiry time.Time // when the window closes
	Locked         bool      // true after baseline window elapsed

	// Allowed behaviour sets (populated during baseline window)
	Syscalls     map[int64]struct{}
	ExecPaths    map[string]struct{} // executable paths seen
	Libraries    map[string]struct{} // .so paths opened
	DestPorts    map[uint16]struct{} // outbound TCP ports
	DestIPs      map[string]struct{} // outbound TCP IPs
	FileDirs     map[string]struct{} // directories accessed

	// Counters (populated during drift phase)
	DriftCount uint64
}

// newContainerBaseline creates a baseline for a container with the given window.
func newContainerBaseline(containerID, namespace, podName string, window time.Duration) *ContainerBaseline {
	now := time.Now()
	return &ContainerBaseline{
		ContainerID:    containerID,
		Namespace:      namespace,
		PodName:        podName,
		StartTime:      now,
		BaselineExpiry: now.Add(window),
		Syscalls:       make(map[int64]struct{}),
		ExecPaths:      make(map[string]struct{}),
		Libraries:      make(map[string]struct{}),
		DestPorts:      make(map[uint16]struct{}),
		DestIPs:        make(map[string]struct{}),
		FileDirs:       make(map[string]struct{}),
	}
}

// tryLock checks if the baseline window has expired and sets Locked.
// Returns true if the baseline is now locked (drift-detection mode active).
func (b *ContainerBaseline) tryLock() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.Locked {
		return true
	}
	if time.Now().After(b.BaselineExpiry) {
		b.Locked = true
		return true
	}
	return false
}

// recordSyscall adds a syscall to the baseline (only while unlocked).
func (b *ContainerBaseline) recordSyscall(nr int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.Locked {
		b.Syscalls[nr] = struct{}{}
	}
}

// recordExecPath adds an executable path to the baseline (only while unlocked).
func (b *ContainerBaseline) recordExecPath(path string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.Locked {
		b.ExecPaths[path] = struct{}{}
	}
}

// recordLibrary adds a library path to the baseline (only while unlocked).
func (b *ContainerBaseline) recordLibrary(path string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.Locked {
		b.Libraries[path] = struct{}{}
	}
}

// recordNetworkPeer adds a destination IP+port pair (only while unlocked).
func (b *ContainerBaseline) recordNetworkPeer(ip string, port uint16) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.Locked {
		b.DestIPs[ip] = struct{}{}
		b.DestPorts[port] = struct{}{}
	}
}

// recordFileDir adds a directory to the baseline (only while unlocked).
func (b *ContainerBaseline) recordFileDir(dir string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.Locked {
		b.FileDirs[dir] = struct{}{}
	}
}

// hasSyscall returns true if the syscall was seen during baseline.
func (b *ContainerBaseline) hasSyscall(nr int64) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, ok := b.Syscalls[nr]
	return ok
}

// hasExecPath returns true if the executable was seen during baseline.
func (b *ContainerBaseline) hasExecPath(path string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, ok := b.ExecPaths[path]
	return ok
}

// hasLibrary returns true if the library was seen during baseline.
func (b *ContainerBaseline) hasLibrary(path string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, ok := b.Libraries[path]
	return ok
}

// hasNetworkPeer returns true if the ip+port pair was seen during baseline.
func (b *ContainerBaseline) hasNetworkPeer(ip string, port uint16) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, okIP := b.DestIPs[ip]
	_, okPort := b.DestPorts[port]
	return okIP && okPort
}

// hasFileDir returns true if the directory was seen during baseline.
func (b *ContainerBaseline) hasFileDir(dir string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, ok := b.FileDirs[dir]
	return ok
}

// incrementDrift atomically increments the drift counter.
func (b *ContainerBaseline) incrementDrift() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.DriftCount++
}

// Stats returns a snapshot of baseline counts (for metrics/display).
func (b *ContainerBaseline) Stats() BaselineStats {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return BaselineStats{
		ContainerID: b.ContainerID,
		Namespace:   b.Namespace,
		PodName:     b.PodName,
		Locked:      b.Locked,
		DriftCount:  b.DriftCount,
		Syscalls:    len(b.Syscalls),
		ExecPaths:   len(b.ExecPaths),
		Libraries:   len(b.Libraries),
		DestPorts:   len(b.DestPorts),
		DestIPs:     len(b.DestIPs),
		FileDirs:    len(b.FileDirs),
	}
}

// BaselineStats is a read-only snapshot of baseline counts.
type BaselineStats struct {
	ContainerID string
	Namespace   string
	PodName     string
	Locked      bool
	DriftCount  uint64
	Syscalls    int
	ExecPaths   int
	Libraries   int
	DestPorts   int
	DestIPs     int
	FileDirs    int
}
