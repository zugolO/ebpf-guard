// Package profiler provides behavioral profiling and anomaly detection for processes.
package profiler

import (
	"context"
	"sync"
	"time"

	"github.com/ebpf-guard/ebpf-guard/pkg/types"
)

// ProcessProfile tracks the behavioral baseline for a single process.
type ProcessProfile struct {
	// mu guards all mutable fields on this profile.
	// Lock order: pm.mu (ProfileManager) must be acquired before profile.mu
	// when both are needed simultaneously.
	mu sync.Mutex

	// Identity
	PID  uint32
	Comm string

	// Timestamps
	CreatedAt  time.Time
	LastSeenAt time.Time

	// Network behavior
	NetworkProfile NetworkProfile

	// File behavior
	FileProfile FileProfile

	// Syscall behavior
	SyscallProfile SyscallProfile

	// Anomaly detection state
	AnomalyScore float64
	AlertCount   uint64
}

// NetworkProfile tracks network connection patterns.
type NetworkProfile struct {
	// Destination ports seen (EWMA of frequency)
	DestPorts map[uint16]*EWMA
	// Destination IPs seen (EWMA of frequency)
	DestAddrs map[string]*EWMA
	// Total connection count
	TotalConnections uint64
}

// FileProfile tracks file access patterns.
type FileProfile struct {
	// Directories accessed (EWMA of frequency)
	Directories map[string]*EWMA
	// File extensions accessed
	Extensions map[string]*EWMA
	// Total file operations
	TotalOperations uint64
}

// SyscallProfile tracks syscall patterns.
type SyscallProfile struct {
	// Syscall numbers and their frequency (EWMA)
	Syscalls map[int64]*EWMA
	// Total syscall count
	TotalSyscalls uint64
}

// NewProcessProfile creates a new behavioral profile for a process.
func NewProcessProfile(pid uint32, comm string) *ProcessProfile {
	now := time.Now()
	return &ProcessProfile{
		PID:        pid,
		Comm:       comm,
		CreatedAt:  now,
		LastSeenAt: now,
		NetworkProfile: NetworkProfile{
			DestPorts: make(map[uint16]*EWMA),
			DestAddrs: make(map[string]*EWMA),
		},
		FileProfile: FileProfile{
			Directories: make(map[string]*EWMA),
			Extensions:  make(map[string]*EWMA),
		},
		SyscallProfile: SyscallProfile{
			Syscalls: make(map[int64]*EWMA),
		},
	}
}

// UpdateLastSeen updates the last seen timestamp.
func (p *ProcessProfile) UpdateLastSeen() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.LastSeenAt = time.Now()
}

// RecordNetworkEvent updates the network profile with a new connection.
func (p *ProcessProfile) RecordNetworkEvent(e *types.NetworkEvent, weight float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.recordNetworkEventLocked(e, weight)
}

// recordNetworkEventLocked updates the network profile (caller must hold lock).
func (p *ProcessProfile) recordNetworkEventLocked(e *types.NetworkEvent, weight float64) {
	p.LastSeenAt = time.Now()
	p.NetworkProfile.TotalConnections++

	// Update destination port EWMA
	if p.NetworkProfile.DestPorts[e.Dport] == nil {
		p.NetworkProfile.DestPorts[e.Dport] = NewEWMA(weight)
	}
	p.NetworkProfile.DestPorts[e.Dport].Update(1.0)

	// Update destination address EWMA
	daddr := formatIP(e.Daddr, e.Family)
	if p.NetworkProfile.DestAddrs[daddr] == nil {
		p.NetworkProfile.DestAddrs[daddr] = NewEWMA(weight)
	}
	p.NetworkProfile.DestAddrs[daddr].Update(1.0)
}

// RecordFileEvent updates the file profile with a new file access.
func (p *ProcessProfile) RecordFileEvent(e *types.FileEvent, weight float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.recordFileEventLocked(e, weight)
}

// recordFileEventLocked updates the file profile (caller must hold lock).
func (p *ProcessProfile) recordFileEventLocked(e *types.FileEvent, weight float64) {
	p.LastSeenAt = time.Now()
	p.FileProfile.TotalOperations++

	// Extract directory from filename
	filename := string(bytesToString(e.Filename[:]))
	dir := extractDirectory(filename)
	if dir != "" {
		if p.FileProfile.Directories[dir] == nil {
			p.FileProfile.Directories[dir] = NewEWMA(weight)
		}
		p.FileProfile.Directories[dir].Update(1.0)
	}

	// Extract and track file extension
	ext := extractExtension(filename)
	if ext != "" {
		if p.FileProfile.Extensions[ext] == nil {
			p.FileProfile.Extensions[ext] = NewEWMA(weight)
		}
		p.FileProfile.Extensions[ext].Update(1.0)
	}
}

// RecordSyscallEvent updates the syscall profile with a new syscall.
func (p *ProcessProfile) RecordSyscallEvent(e *types.SyscallEvent, weight float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.recordSyscallEventLocked(e, weight)
}

// recordSyscallEventLocked updates the syscall profile (caller must hold lock).
func (p *ProcessProfile) recordSyscallEventLocked(e *types.SyscallEvent, weight float64) {
	p.LastSeenAt = time.Now()
	p.SyscallProfile.TotalSyscalls++

	// Update syscall EWMA
	if p.SyscallProfile.Syscalls[e.Nr] == nil {
		p.SyscallProfile.Syscalls[e.Nr] = NewEWMA(weight)
	}
	p.SyscallProfile.Syscalls[e.Nr].Update(1.0)
}

// GetAnomalyScore returns the current anomaly score.
func (p *ProcessProfile) GetAnomalyScore() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.AnomalyScore
}

// SetAnomalyScore updates the anomaly score.
func (p *ProcessProfile) SetAnomalyScore(score float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.AnomalyScore = score
}

// IsExpired checks if the profile has expired based on TTL.
func (p *ProcessProfile) IsExpired(ttl time.Duration) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return time.Since(p.LastSeenAt) > ttl
}

// ProfileManager manages behavioral profiles for all processes.
type ProfileManager struct {
	mu       sync.RWMutex
	profiles map[uint32]*ProcessProfile
	weight   float64 // EWMA weight
	ttl      time.Duration
	maxPIDs  int // maximum number of tracked PIDs; 0 = unlimited
}

// NewProfileManager creates a new profile manager.
// Deprecated: use NewProfileManagerWithContext to enable background cleanup.
func NewProfileManager(weight float64, ttl time.Duration) *ProfileManager {
	return &ProfileManager{
		profiles: make(map[uint32]*ProcessProfile),
		weight:   weight,
		ttl:      ttl,
		maxPIDs:  65536,
	}
}

// NewProfileManagerWithContext creates a profile manager that runs a background
// cleanup goroutine which exits when ctx is cancelled.
func NewProfileManagerWithContext(ctx context.Context, weight float64, ttl time.Duration, maxPIDs int) *ProfileManager {
	if maxPIDs <= 0 {
		maxPIDs = 65536
	}
	pm := &ProfileManager{
		profiles: make(map[uint32]*ProcessProfile),
		weight:   weight,
		ttl:      ttl,
		maxPIDs:  maxPIDs,
	}
	go pm.cleanupLoop(ctx, ttl/4)
	return pm
}

// cleanupLoop periodically removes expired profiles until ctx is cancelled.
func (pm *ProfileManager) cleanupLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 90 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			pm.CleanupExpired()
		case <-ctx.Done():
			return
		}
	}
}

// GetOrCreate returns an existing profile or creates a new one.
// When the map is at capacity (maxPIDs), the least-recently-seen entry is evicted.
func (pm *ProfileManager) GetOrCreate(pid uint32, comm string) *ProcessProfile {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if profile, exists := pm.profiles[pid]; exists {
		return profile
	}

	if pm.maxPIDs > 0 && len(pm.profiles) >= pm.maxPIDs {
		pm.evictLRULocked()
	}

	profile := NewProcessProfile(pid, comm)
	pm.profiles[pid] = profile
	return profile
}

// evictLRULocked removes the profile with the oldest LastSeenAt timestamp.
// Caller must hold pm.mu (write lock).
func (pm *ProfileManager) evictLRULocked() {
	var lruPID uint32
	var lruTime time.Time
	first := true
	for pid, p := range pm.profiles {
		p.mu.Lock()
		seen := p.LastSeenAt
		p.mu.Unlock()
		if first || seen.Before(lruTime) {
			lruPID = pid
			lruTime = seen
			first = false
		}
	}
	if !first {
		delete(pm.profiles, lruPID)
	}
}

// Get returns an existing profile or nil.
func (pm *ProfileManager) Get(pid uint32) *ProcessProfile {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.profiles[pid]
}

// Remove deletes a profile.
func (pm *ProfileManager) Remove(pid uint32) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.profiles, pid)
}

// GetAll returns all profiles.
func (pm *ProfileManager) GetAll() map[uint32]*ProcessProfile {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// Return a copy
	result := make(map[uint32]*ProcessProfile, len(pm.profiles))
	for k, v := range pm.profiles {
		result[k] = v
	}
	return result
}

// CleanupExpired removes expired profiles.
func (pm *ProfileManager) CleanupExpired() int {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	removed := 0
	for pid, profile := range pm.profiles {
		if profile.IsExpired(pm.ttl) {
			delete(pm.profiles, pid)
			removed++
		}
	}
	return removed
}

// PIDs returns all tracked PIDs.
func (pm *ProfileManager) PIDs() []uint32 {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	pids := make([]uint32, 0, len(pm.profiles))
	for pid := range pm.profiles {
		pids = append(pids, pid)
	}
	return pids
}

// RecordEvent processes an event and updates the appropriate profile.
// Two-phase locking: pm.mu is held only for the map lookup/create, then
// released before the profile update runs under the per-profile mutex.
// This eliminates pm.mu contention on the hot path when many goroutines
// record events for different PIDs simultaneously.
//
// Lock order invariant: when both locks are needed, acquire pm.mu before
// profile.mu (e.g. in evictLRULocked). Here we hold only one at a time.
func (pm *ProfileManager) RecordEvent(e types.Event) {
	pm.mu.Lock()
	profile, exists := pm.profiles[e.PID]
	if !exists {
		if pm.maxPIDs > 0 && len(pm.profiles) >= pm.maxPIDs {
			pm.evictLRULocked()
		}
		profile = NewProcessProfile(e.PID, string(bytesToString(e.Comm[:])))
		pm.profiles[e.PID] = profile
	}
	pm.mu.Unlock()

	// Profile update runs under the per-profile mutex, not the map mutex.
	profile.mu.Lock()
	switch e.Type {
	case types.EventTCPConnect:
		if e.Network != nil {
			profile.recordNetworkEventLocked(e.Network, pm.weight)
		}
	case types.EventFileAccess:
		if e.File != nil {
			profile.recordFileEventLocked(e.File, pm.weight)
		}
	case types.EventSyscall:
		if e.Syscall != nil {
			profile.recordSyscallEventLocked(e.Syscall, pm.weight)
		}
	}
	profile.mu.Unlock()
}

// Helper functions

func extractDirectory(path string) string {
	// Simple directory extraction - find last '/'
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i+1]
		}
	}
	return ""
}

func extractExtension(path string) string {
	// Find last '.' after last '/'
	lastSlash := -1
	lastDot := -1
	for i, c := range path {
		if c == '/' {
			lastSlash = i
		} else if c == '.' {
			lastDot = i
		}
	}
	if lastDot > lastSlash {
		return path[lastDot:]
	}
	return ""
}

func bytesToString(b []byte) []byte {
	for i, c := range b {
		if c == 0 {
			return b[:i]
		}
	}
	return b
}
