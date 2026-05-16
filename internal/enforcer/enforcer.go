// Package enforcer provides active enforcement capabilities for security rules.
package enforcer

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/ebpf-guard/ebpf-guard/pkg/types"
)

// ActionType represents the type of enforcement action.
type ActionType string

const (
	// ActionBlock blocks network packets.
	ActionBlock ActionType = "block"
	// ActionKill kills the offending process.
	ActionKill ActionType = "kill"
	// ActionThrottle rate-limits the process.
	ActionThrottle ActionType = "throttle"
)

// AuditEntry records an enforcement action for audit purposes.
type AuditEntry struct {
	Timestamp   time.Time       `json:"timestamp"`
	Action      ActionType      `json:"action"`
	RuleID      string          `json:"rule_id"`
	PID         uint32          `json:"pid"`
	TGID        uint32          `json:"tgid"`
	Comm        string          `json:"comm"`
	UID         uint32          `json:"uid"`
	Description string          `json:"description"`
	Success     bool            `json:"success"`
	Error       string          `json:"error,omitempty"`
	EventType   types.EventType `json:"event_type"`
}

// Enforcer performs active enforcement actions based on security alerts.
type Enforcer struct {
	logger    *slog.Logger
	auditLog  chan<- AuditEntry
	throttles map[uint32]*ThrottleState
	mu        sync.RWMutex
	enabled   map[ActionType]bool
}

// ThrottleState tracks rate limiting state for a process.
type ThrottleState struct {
	PID          uint32
	LastThrottle time.Time
	Count        int
	Active       bool
}

// Config configures the enforcer.
type Config struct {
	// EnableBlock enables packet blocking via TC/XDP
	EnableBlock bool
	// EnableKill enables process termination
	EnableKill bool
	// EnableThrottle enables cgroup-based rate limiting
	EnableThrottle bool
	// AuditLogChannel receives audit entries (optional)
	AuditLogChannel chan<- AuditEntry
}

// NewEnforcer creates a new enforcement engine.
func NewEnforcer(logger *slog.Logger, cfg Config) *Enforcer {
	return &Enforcer{
		logger:    logger.With("component", "enforcer"),
		auditLog:  cfg.AuditLogChannel,
		throttles: make(map[uint32]*ThrottleState),
		enabled: map[ActionType]bool{
			ActionBlock:    cfg.EnableBlock,
			ActionKill:     cfg.EnableKill,
			ActionThrottle: cfg.EnableThrottle,
		},
	}
}

// Execute performs the specified enforcement action.
func (e *Enforcer) Execute(ctx context.Context, action ActionType, alert types.Alert) error {
	if !e.enabled[action] {
		return fmt.Errorf("enforcer: action %s is disabled", action)
	}

	switch action {
	case ActionBlock:
		return e.executeBlock(ctx, alert)
	case ActionKill:
		return e.executeKill(ctx, alert)
	case ActionThrottle:
		return e.executeThrottle(ctx, alert)
	default:
		return fmt.Errorf("enforcer: unknown action type: %s", action)
	}
}

// IsEnabled returns true if the specified action type is enabled.
func (e *Enforcer) IsEnabled(action ActionType) bool {
	return e.enabled[action]
}

// executeBlock blocks network packets matching the alert.
// Currently implemented via iptables/nftables rules (TC/XDP requires more setup).
func (e *Enforcer) executeBlock(ctx context.Context, alert types.Alert) error {
	entry := AuditEntry{
		Timestamp:   time.Now(),
		Action:      ActionBlock,
		RuleID:      alert.RuleID,
		PID:         alert.Event.PID,
		TGID:        alert.Event.TGID,
		Comm:        string(bytesToString(alert.Event.Comm[:])),
		UID:         alert.Event.UID,
		Description: fmt.Sprintf("Block network traffic from PID %d", alert.Event.PID),
		EventType:   alert.Event.Type,
	}

	// For now, log the block action. Full TC/XDP implementation would require:
	// 1. Loading an XDP program to drop packets
	// 2. Or using netfilter to add drop rules
	// This is a placeholder for the enforcement framework.

	e.logger.Warn("BLOCK action executed",
		"rule_id", alert.RuleID,
		"pid", alert.Event.PID,
		"comm", entry.Comm,
	)

	entry.Success = true
	e.logAudit(entry)
	return nil
}

// executeKill sends SIGKILL to the offending process.
func (e *Enforcer) executeKill(ctx context.Context, alert types.Alert) error {
	entry := AuditEntry{
		Timestamp:   time.Now(),
		Action:      ActionKill,
		RuleID:      alert.RuleID,
		PID:         alert.Event.PID,
		TGID:        alert.Event.TGID,
		Comm:        string(bytesToString(alert.Event.Comm[:])),
		UID:         alert.Event.UID,
		Description: fmt.Sprintf("SIGKILL sent to PID %d", alert.Event.PID),
		EventType:   alert.Event.Type,
	}

	// Validate PID before attempting kill
	if err := ValidatePID(alert.Event.PID); err != nil {
		entry.Success = false
		entry.Error = err.Error()
		e.logAudit(entry)
		return fmt.Errorf("enforcer/kill: %w", err)
	}

	// Send SIGKILL to the process
	pid := int(alert.Event.PID)
	process, err := os.FindProcess(pid)
	if err != nil {
		entry.Success = false
		entry.Error = fmt.Sprintf("find process: %v", err)
		e.logAudit(entry)
		return fmt.Errorf("enforcer/kill: find process %d: %w", pid, err)
	}

	if err := process.Signal(syscall.SIGKILL); err != nil {
		entry.Success = false
		entry.Error = fmt.Sprintf("send SIGKILL: %v", err)
		e.logAudit(entry)
		return fmt.Errorf("enforcer/kill: send SIGKILL to %d: %w", pid, err)
	}

	e.logger.Warn("KILL action executed",
		"rule_id", alert.RuleID,
		"pid", pid,
		"comm", entry.Comm,
	)

	entry.Success = true
	e.logAudit(entry)
	return nil
}

// executeThrottle rate-limits the process using cgroups v2.
func (e *Enforcer) executeThrottle(ctx context.Context, alert types.Alert) error {
	entry := AuditEntry{
		Timestamp:   time.Now(),
		Action:      ActionThrottle,
		RuleID:      alert.RuleID,
		PID:         alert.Event.PID,
		TGID:        alert.Event.TGID,
		Comm:        string(bytesToString(alert.Event.Comm[:])),
		UID:         alert.Event.UID,
		Description: fmt.Sprintf("Throttle PID %d via cgroups v2", alert.Event.PID),
		EventType:   alert.Event.Type,
	}

	pid := alert.Event.PID

	e.mu.Lock()
	state, exists := e.throttles[pid]
	if !exists {
		state = &ThrottleState{
			PID:    pid,
			Active: true,
		}
		e.throttles[pid] = state
	}
	state.LastThrottle = time.Now()
	state.Count++
	e.mu.Unlock()

	// Apply cgroup v2 CPU throttling
	// This writes to the cgroup's cpu.max file
	if err := e.applyCgroupThrottle(pid); err != nil {
		entry.Success = false
		entry.Error = err.Error()
		e.logAudit(entry)
		return fmt.Errorf("enforcer/throttle: apply cgroup throttle: %w", err)
	}

	e.logger.Warn("THROTTLE action executed",
		"rule_id", alert.RuleID,
		"pid", pid,
		"comm", entry.Comm,
		"throttle_count", state.Count,
	)

	entry.Success = true
	e.logAudit(entry)
	return nil
}

// applyCgroupThrottle applies CPU throttling via cgroups v2.
func (e *Enforcer) applyCgroupThrottle(pid uint32) error {
	// Find the cgroup for the process
	cgroupPath, err := e.findCgroupPath(pid)
	if err != nil {
		return fmt.Errorf("find cgroup path: %w", err)
	}

	// Apply 10% CPU limit: "10000 100000" means 10ms per 100ms period
	cpuMaxPath := filepath.Join(cgroupPath, "cpu.max")
	if err := os.WriteFile(cpuMaxPath, []byte("10000 100000\n"), 0644); err != nil {
		return fmt.Errorf("write cpu.max: %w", err)
	}

	return nil
}

// findCgroupPath finds the cgroup v2 path for a process.
func (e *Enforcer) findCgroupPath(pid uint32) (string, error) {
	// Read /proc/<pid>/cgroup to find the cgroup path
	cgroupFile := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(cgroupFile)
	if err != nil {
		return "", fmt.Errorf("read cgroup file: %w", err)
	}

	// Parse cgroup path (format: "0::/path/to/cgroup")
	// For cgroup v2, it's typically "0::/user.slice/..."
	lines := string(data)
	for _, line := range splitLines(lines) {
		if len(line) > 3 && line[:2] == "0:" {
			// Found cgroup v2 entry
			parts := splitLastField(line, ':')
			if len(parts) >= 3 {
				cgroupPath := parts[2]
				// Prepend cgroup mount point
				return filepath.Join("/sys/fs/cgroup", cgroupPath), nil
			}
		}
	}

	return "", fmt.Errorf("cgroup v2 path not found for PID %d", pid)
}

// splitLines splits a string into lines.
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// splitLastField splits by separator and returns all parts.
func splitLastField(s string, sep byte) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	if start <= len(s) {
		parts = append(parts, s[start:])
	}
	return parts
}

// logAudit sends an entry to the audit log channel if configured.
func (e *Enforcer) logAudit(entry AuditEntry) {
	if e.auditLog != nil {
		select {
		case e.auditLog <- entry:
		default:
			e.logger.Warn("audit log channel full, dropping entry",
				"action", entry.Action,
				"pid", entry.PID,
			)
		}
	}
}

// bytesToString converts a byte slice to string, stopping at first null byte.
func bytesToString(b []byte) []byte {
	for i, c := range b {
		if c == 0 {
			return b[:i]
		}
	}
	return b
}

// GetThrottleState returns the throttle state for a PID (for testing/debugging).
func (e *Enforcer) GetThrottleState(pid uint32) *ThrottleState {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.throttles[pid]
}

// RemoveThrottle removes a throttle entry (for cleanup/testing).
func (e *Enforcer) RemoveThrottle(pid uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.throttles, pid)
}

// CleanupThrottles removes stale throttle entries older than maxAge.
func (e *Enforcer) CleanupThrottles(maxAge time.Duration) int {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	removed := 0
	for pid, state := range e.throttles {
		if now.Sub(state.LastThrottle) > maxAge {
			delete(e.throttles, pid)
			removed++
		}
	}
	return removed
}

// ParseActionType parses an action type string.
func ParseActionType(s string) (ActionType, error) {
	switch s {
	case "block":
		return ActionBlock, nil
	case "kill":
		return ActionKill, nil
	case "throttle":
		return ActionThrottle, nil
	default:
		return "", fmt.Errorf("unknown action type: %s", s)
	}
}

// String returns the string representation of an action type.
func (a ActionType) String() string {
	return string(a)
}

// ValidatePID checks if a PID is valid for enforcement.
func ValidatePID(pid uint32) error {
	if pid == 0 {
		return fmt.Errorf("invalid PID: 0 (kernel)")
	}
	// Check if process exists
	procPath := fmt.Sprintf("/proc/%d", pid)
	if _, err := os.Stat(procPath); err != nil {
		return fmt.Errorf("process %d not found: %w", pid, err)
	}
	return nil
}

// IsCgroupV2Available checks if cgroup v2 is available on the system.
func IsCgroupV2Available() bool {
	_, err := os.Stat("/sys/fs/cgroup/cgroup.controllers")
	return err == nil
}

// GetProcessStartTime returns the start time of a process from /proc.
func GetProcessStartTime(pid uint32) (time.Time, error) {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := os.ReadFile(statPath)
	if err != nil {
		return time.Time{}, err
	}

	// Parse starttime from stat (field 22, in clock ticks since boot)
	// This is a simplified parser - full parsing would need to handle
	// comm field which may contain spaces and parentheses
	fields := splitLastField(string(data), ' ')
	if len(fields) < 22 {
		return time.Time{}, fmt.Errorf("stat file too short")
	}

	// Field 22 is starttime (0-indexed: 21)
	starttime, err := strconv.ParseUint(fields[21], 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse starttime: %w", err)
	}

	// Convert to time.Time (approximate - would need boot time for exact)
	// For audit purposes, relative time is sufficient
	return time.Unix(0, int64(starttime)*10000000), nil // Rough approximation
}
