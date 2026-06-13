// Package enforcer provides active enforcement capabilities for security rules.
package enforcer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
)

// ErrInvalidEvent is returned when an event fails validation before enforcement.
var ErrInvalidEvent = errors.New("enforcer: invalid event")

// maxLinuxPID is the maximum valid Linux PID.
const maxLinuxPID uint32 = 4194304

// sanitizeComm strips non-UTF-8 bytes and replaces non-printable characters
// with \xNN escapes so attacker-controlled comm fields are safe to log.
func sanitizeComm(raw string) string {
	out := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); {
		r, size := utf8.DecodeRuneInString(raw[i:])
		if r == utf8.RuneError && size == 1 {
			out = append(out, []byte(fmt.Sprintf(`\x%02x`, raw[i]))...)
			i++
			continue
		}
		if r < 0x20 || r == 0x7f {
			out = append(out, []byte(fmt.Sprintf(`\x%02x`, r))...)
		} else {
			out = append(out, raw[i:i+size]...)
		}
		i += size
	}
	return string(out)
}

// validateEvent checks UID and PID ranges before any enforcement action.
func validateEvent(e types.Event) error {
	if e.UID > 65535 {
		return fmt.Errorf("%w: UID %d out of range [0,65535]", ErrInvalidEvent, e.UID)
	}
	if e.PID < 1 || e.PID > maxLinuxPID {
		return fmt.Errorf("%w: PID %d out of range [1,%d]", ErrInvalidEvent, e.PID, maxLinuxPID)
	}
	return nil
}

// ActionType represents the type of enforcement action.
type ActionType string

const (
	// ActionBlock blocks network packets.
	ActionBlock ActionType = "block"
	// ActionKill kills the offending process.
	ActionKill ActionType = "kill"
	// ActionThrottle rate-limits the process.
	ActionThrottle ActionType = "throttle"
	// ActionLog only logs the action without enforcement.
	ActionLog ActionType = "log"
	// ActionLSMBlock uses LSM BPF for pre-execution blocking (Sprint 22.0).
	// Falls back to nftables if LSM is unavailable.
	ActionLSMBlock ActionType = "lsm_block"
	// ActionNetworkPolicy generates a Kubernetes NetworkPolicy for the affected pod.
	// In "suggest" mode the YAML is sent via the notification channel.
	// In "apply" mode it is applied directly via the Kubernetes API.
	ActionNetworkPolicy ActionType = "networkpolicy"
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

// BlockBackend represents the network blocking backend to use.
type BlockBackend string

const (
	// BlockBackendLog only logs block actions without actual blocking.
	BlockBackendLog BlockBackend = "log"
	// BlockBackendNFTables uses nftables for network blocking.
	BlockBackendNFTables BlockBackend = "nftables"
	// BlockBackendIPTables uses iptables for network blocking (legacy).
	BlockBackendIPTables BlockBackend = "iptables"
	// BlockBackendXDP uses an XDP eBPF program for high-performance packet dropping.
	BlockBackendXDP BlockBackend = "xdp"
)

// LSMBlocklistManager interface for LSM-based blocking.
// Implemented by collector.LSMCollector.
type LSMBlocklistManager interface {
	IsAvailable() bool
	// PID-based methods — used by the socket_connect hook.
	AddToBlocklist(pid uint32) error
	RemoveFromBlocklist(pid uint32) error
	// Path-based methods — used by the file_open hook (issue #33).
	// Paths are normalised with filepath.Clean before hashing; the BPF hook
	// checks the FNV-32a hash of bpf_d_path() output on every file open.
	AddPathToBlocklist(path string) error
	RemovePathFromBlocklist(path string) error
	// SetPathBlocklist atomically replaces the config-driven path set and
	// re-programs the BPF map.  Dynamically blocked paths are preserved.
	SetPathBlocklist(paths []string) error
}

// Enforcer performs active enforcement actions based on security alerts.
type Enforcer struct {
	logger      *slog.Logger
	auditLog    chan<- AuditEntry
	throttles   map[uint32]*ThrottleState
	mu          sync.RWMutex
	enabled     map[ActionType]bool
	stopCleanup context.CancelFunc // stops the background throttle cleanup goroutine
	// blockBackend is the network blocking backend to use
	blockBackend BlockBackend
	// nftablesMgr is the nftables manager (nil if not using nftables)
	nftablesMgr *NFTablesManager
	// iptablesMgr is the iptables manager (nil if not using iptables)
	iptablesMgr *IPTablesManager
	// xdpMgr is the XDP packet filter manager (nil if not using XDP)
	xdpMgr *XDPManager
	// lsmManager is the LSM blocklist manager (nil if not using LSM)
	lsmManager LSMBlocklistManager
	// networkPolicyMgr handles networkpolicy action enforcement (nil if disabled)
	networkPolicyMgr *NetworkPolicyManager
	// dryRun mode logs actions without enforcement
	dryRun bool
	// throttleCPUPercent is the CPU limit applied when throttling (1-99).
	throttleCPUPercent int
	// throttleMaxAge is the TTL for inactive throttle entries.
	throttleMaxAge time.Duration
	// throttleCleanupInterval is how often the cleanup goroutine runs.
	throttleCleanupInterval time.Duration

	actionsTotal *prometheus.CounterVec // ebpf_guard_enforcement_actions_total{action}
	auditDropped prometheus.Counter     // ebpf_guard_audit_log_dropped_total
	pidfdUsed    prometheus.Counter     // ebpf_guard_enforcer_kill_pidfd_used_total
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
	// BlockBackend specifies the network blocking backend (log, nftables, iptables, xdp)
	BlockBackend BlockBackend
	// XDPInterface is the network interface to attach the XDP program to (e.g. "eth0").
	// Only used when BlockBackend == BlockBackendXDP.
	XDPInterface string
	// DryRun mode logs actions without actual enforcement
	DryRun bool
	// AuditLogChannel receives audit entries (optional)
	AuditLogChannel chan<- AuditEntry
	// LSMManager is the LSM blocklist manager for pre-execution blocking (optional)
	LSMManager LSMBlocklistManager
	// NetworkPolicy configures the networkpolicy action type (optional)
	NetworkPolicy NetworkPolicyCfg
	// ThrottleCPUPercent is the CPU limit (1-99) applied when throttling via cgroup v2. Default: 10.
	ThrottleCPUPercent int
	// ThrottleMaxAge is how long a throttle entry is kept after last use. Default: 30m.
	ThrottleMaxAge time.Duration
	// ThrottleCleanupInterval is how often the stale-entry cleanup goroutine runs. Default: 5m.
	ThrottleCleanupInterval time.Duration
}

// NewEnforcer creates a new enforcement engine.
func NewEnforcer(logger *slog.Logger, cfg Config) (*Enforcer, error) {
	cpuPct := cfg.ThrottleCPUPercent
	if cpuPct < 1 || cpuPct > 99 {
		cpuPct = 10
	}
	maxAge := cfg.ThrottleMaxAge
	if maxAge <= 0 {
		maxAge = 30 * time.Minute
	}
	cleanupInterval := cfg.ThrottleCleanupInterval
	if cleanupInterval <= 0 {
		cleanupInterval = 5 * time.Minute
	}

	e := &Enforcer{
		logger:                  logger.With("component", "enforcer"),
		auditLog:                cfg.AuditLogChannel,
		throttles:               make(map[uint32]*ThrottleState),
		blockBackend:            cfg.BlockBackend,
		lsmManager:              cfg.LSMManager,
		dryRun:                  cfg.DryRun,
		throttleCPUPercent:      cpuPct,
		throttleMaxAge:          maxAge,
		throttleCleanupInterval: cleanupInterval,
		enabled: map[ActionType]bool{
			ActionBlock:         cfg.EnableBlock,
			ActionKill:          cfg.EnableKill,
			ActionThrottle:      cfg.EnableThrottle,
			ActionNetworkPolicy: cfg.NetworkPolicy.Enabled,
		},
		actionsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ebpf_guard_enforcement_actions_total",
			Help: "Total enforcement actions executed by action type.",
		}, []string{"action"}),
		auditDropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ebpf_guard_audit_log_dropped_total",
			Help: "Total audit log entries dropped due to a full channel.",
		}),
		pidfdUsed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "enforcer_kill_pidfd_used_total",
			Help: "Total number of process kills performed via pidfd (Linux 5.1+).",
		}),
	}

	// Initialise the NetworkPolicy manager if enabled.
	if cfg.NetworkPolicy.Enabled {
		e.networkPolicyMgr = NewNetworkPolicyManager(logger, cfg.NetworkPolicy)
	}

	// Initialise the configured block backend.
	if cfg.EnableBlock {
		switch cfg.BlockBackend {
		case BlockBackendNFTables:
			nftMgr, err := NewNFTablesManager(logger, NFTablesConfig{DryRun: cfg.DryRun})
			if err != nil {
				return nil, fmt.Errorf("enforcer: init nftables: %w", err)
			}
			e.nftablesMgr = nftMgr
		case BlockBackendIPTables:
			ipt, err := NewIPTablesManager(logger, IPTablesConfig{DryRun: cfg.DryRun})
			if err != nil {
				return nil, fmt.Errorf("enforcer: init iptables: %w", err)
			}
			e.iptablesMgr = ipt
		case BlockBackendXDP:
			xdpMgr, err := NewXDPManager(logger, XDPConfig{
				Interface: cfg.XDPInterface,
				DryRun:    cfg.DryRun,
			})
			if err != nil {
				return nil, fmt.Errorf("enforcer: init xdp: %w", err)
			}
			e.xdpMgr = xdpMgr
		}
	}

	// Background goroutine that evicts dead-PID throttle entries.
	cleanupCtx, cancel := context.WithCancel(context.Background())
	e.stopCleanup = cancel
	go func() {
		ticker := time.NewTicker(e.throttleCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-cleanupCtx.Done():
				return
			case <-ticker.C:
				if removed := e.CleanupThrottles(e.throttleMaxAge); removed > 0 {
					e.logger.Debug("cleaned up stale throttle entries", slog.Int("removed", removed))
				}
			}
		}
	}()

	return e, nil
}

// RegisterMetrics registers the Enforcer's Prometheus metrics with the given registerer.
func (e *Enforcer) RegisterMetrics(reg prometheus.Registerer) error {
	for _, c := range []prometheus.Collector{e.actionsTotal, e.auditDropped, e.pidfdUsed} {
		if c == nil {
			continue
		}
		if err := reg.Register(c); err != nil {
			return err
		}
	}
	return nil
}

// Execute performs the specified enforcement action.
func (e *Enforcer) Execute(ctx context.Context, action ActionType, alert types.Alert) error {
	if !e.enabled[action] && action != ActionLSMBlock {
		return fmt.Errorf("enforcer: action %s is disabled", action)
	}

	switch action {
	case ActionBlock:
		return e.executeBlock(ctx, alert)
	case ActionLSMBlock:
		return e.executeLSMBlock(ctx, alert)
	case ActionKill:
		return e.executeKill(ctx, alert)
	case ActionThrottle:
		return e.executeThrottle(ctx, alert)
	case ActionNetworkPolicy:
		return e.executeNetworkPolicy(ctx, alert)
	default:
		return fmt.Errorf("enforcer: unknown action type: %s", action)
	}
}

// IsEnabled returns true if the specified action type is enabled.
func (e *Enforcer) IsEnabled(action ActionType) bool {
	return e.enabled[action]
}

// ExecuteAction satisfies correlator.ActionExecutor.
// It converts the plain string action name to ActionType and delegates to Execute.
func (e *Enforcer) ExecuteAction(ctx context.Context, action string, alert types.Alert) error {
	return e.Execute(ctx, ActionType(action), alert)
}

// executeBlock blocks network packets matching the alert.
// For XDP it extracts the destination IP/port from network events and adds
// them to the BPF blocklist.  For nftables it falls back to UID-based blocking.
func (e *Enforcer) executeBlock(ctx context.Context, alert types.Alert) error {
	// PID validation is advisory for block — an invalid PID still warrants
	// blocking the destination IP.  Log a warning but continue.
	if err := validateEvent(alert.Event); err != nil {
		e.logger.Warn("block: event validation warning", slog.Any("error", err))
	}

	comm := sanitizeComm(string(bytesToString(alert.Event.Comm[:])))
	entry := AuditEntry{
		Timestamp:   time.Now(),
		Action:      ActionBlock,
		RuleID:      alert.RuleID,
		PID:         alert.Event.PID,
		TGID:        alert.Event.TGID,
		Comm:        comm,
		UID:         alert.Event.UID,
		Description: fmt.Sprintf("Block network traffic from PID %d", alert.Event.PID),
		EventType:   alert.Event.Type,
	}

	e.logger.Warn("BLOCK action executed",
		slog.String("rule_id", alert.RuleID),
		slog.Uint64("pid", uint64(alert.Event.PID)),
		slog.String("comm", comm),
		slog.String("backend", string(e.blockBackend)),
		slog.Bool("dry_run", e.dryRun),
	)

	switch e.blockBackend {
	case BlockBackendXDP:
		if err := e.executeBlockXDP(ctx, alert, &entry); err != nil {
			e.logAudit(entry)
			return err
		}
	case BlockBackendNFTables:
		if e.nftablesMgr != nil {
			if err := e.nftablesMgr.BlockUID(ctx, alert.Event.UID); err != nil {
				entry.Success = false
				entry.Error = err.Error()
				e.logAudit(entry)
				return fmt.Errorf("enforcer/block: nftables block UID %d: %w", alert.Event.UID, err)
			}
		}
	case BlockBackendIPTables:
		if e.iptablesMgr != nil {
			if err := e.iptablesMgr.BlockUID(ctx, alert.Event.UID); err != nil {
				entry.Success = false
				entry.Error = err.Error()
				e.logAudit(entry)
				return fmt.Errorf("enforcer/block: iptables block UID %d: %w", alert.Event.UID, err)
			}
		}
	case BlockBackendLog:
		// log-only — already logged above
	}

	entry.Success = true
	e.logAudit(entry)
	if e.actionsTotal != nil {
		e.actionsTotal.WithLabelValues("block").Inc()
	}
	return nil
}

// executeBlockXDP routes an alert to the XDP blocklist.
// It extracts the destination IP and port from network events.  When the event
// carries no network information, it falls back to blocking by source IP if
// available, or logs a warning and returns nil (log-only fallback).
func (e *Enforcer) executeBlockXDP(ctx context.Context, alert types.Alert, entry *AuditEntry) error {
	if e.xdpMgr == nil {
		e.logger.Warn("XDP backend selected but manager not initialised, logging only")
		return nil
	}

	net := alert.Event.Network
	if net == nil {
		e.logger.Warn("XDP block: no network event in alert, nothing to block",
			slog.String("rule_id", alert.RuleID))
		return nil
	}

	daddr := net.Daddr[:]
	// For IPv4 events (family == AF_INET) only the first 4 bytes are set.
	if alert.Event.Network.Family == 2 /* AF_INET */ {
		daddr = net.Daddr[:4]
	}

	if err := e.xdpMgr.BlockTuple(ctx, daddr, net.Dport); err != nil {
		entry.Success = false
		entry.Error = err.Error()
		return fmt.Errorf("enforcer/block: xdp block %s:%d: %w",
			ipBytesToString(daddr), net.Dport, err)
	}

	entry.Description = fmt.Sprintf("XDP: blocked %s:%d (rule %s)",
		ipBytesToString(daddr), net.Dport, alert.RuleID)
	return nil
}

// ipBytesToString converts raw IP bytes to a display string.
func ipBytesToString(raw []byte) string {
	ip := make(net.IP, len(raw))
	copy(ip, raw)
	return ip.String()
}

// executeLSMBlock uses LSM BPF for pre-execution blocking.
// Falls back to nftables if LSM is unavailable.
func (e *Enforcer) executeLSMBlock(ctx context.Context, alert types.Alert) error {
	if err := validateEvent(alert.Event); err != nil {
		e.logger.Warn("lsm_block rejected: invalid event", "error", err)
		return err
	}

	comm := sanitizeComm(string(bytesToString(alert.Event.Comm[:])))
	entry := AuditEntry{
		Timestamp:   time.Now(),
		Action:      ActionLSMBlock,
		RuleID:      alert.RuleID,
		PID:         alert.Event.PID,
		TGID:        alert.Event.TGID,
		Comm:        comm,
		UID:         alert.Event.UID,
		Description: fmt.Sprintf("LSM block PID %d", alert.Event.PID),
		EventType:   alert.Event.Type,
	}

	e.logger.Warn("LSM_BLOCK action executed",
		"rule_id", alert.RuleID,
		"pid", alert.Event.PID,
		"comm", comm,
		"dry_run", e.dryRun,
	)

	var execErr error

	// Route file-access events to the per-path blocklist so a blocked process
	// can still open files that are NOT in the blocklist (issue #33).
	if alert.Event.Type == types.EventFileAccess {
		if err := e.executeLSMBlockFile(ctx, alert); err != nil {
			entry.Success = false
			entry.Error = err.Error()
			e.logAudit(entry)
			return err
		}
		entry.Success = true
		entry.Description = fmt.Sprintf("LSM path-blocked %s (rule %s)", extractFilePath(alert), alert.RuleID)
		goto done
	}

	if e.dryRun {
		entry.Success = true
		entry.Description += " (dry run)"
	} else if e.lsmManager != nil && e.lsmManager.IsAvailable() {
		if err := e.lsmManager.AddToBlocklist(alert.Event.PID); err != nil {
			e.logger.Warn("LSM block failed, falling back to nftables", "error", err, "pid", alert.Event.PID)
			// fall through to nftables
			goto nftablesFallback
		}
		e.logger.Info("PID added to LSM blocklist", "pid", alert.Event.PID)
		entry.Success = true
	} else {
		goto nftablesFallback
	}
	goto done

nftablesFallback:
	if e.nftablesMgr != nil {
		if err := e.nftablesMgr.BlockUID(ctx, alert.Event.UID); err != nil {
			entry.Success = false
			entry.Error = err.Error()
			execErr = fmt.Errorf("enforcer/lsm_block: nftables fallback failed for UID %d: %w", alert.Event.UID, err)
		} else {
			e.logger.Info("LSM unavailable, used nftables fallback", "uid", alert.Event.UID)
			entry.Success = true
		}
	} else if e.iptablesMgr != nil {
		if err := e.iptablesMgr.BlockUID(ctx, alert.Event.UID); err != nil {
			entry.Success = false
			entry.Error = err.Error()
			execErr = fmt.Errorf("enforcer/lsm_block: iptables fallback failed for UID %d: %w", alert.Event.UID, err)
		} else {
			e.logger.Info("LSM unavailable, used iptables fallback", "uid", alert.Event.UID)
			entry.Success = true
		}
	} else {
		entry.Success = false
		entry.Error = "no blocking backend available (LSM, nftables, or iptables)"
		execErr = fmt.Errorf("enforcer/lsm_block: no blocking backend available")
	}

done:
	e.logAudit(entry)
	if entry.Success && e.actionsTotal != nil {
		e.actionsTotal.WithLabelValues("lsm_block").Inc()
	}
	return execErr
}

// executeNetworkPolicy generates (and optionally applies) a Kubernetes NetworkPolicy.
func (e *Enforcer) executeNetworkPolicy(ctx context.Context, alert types.Alert) error {
	if e.networkPolicyMgr == nil {
		e.logger.Warn("networkpolicy action triggered but manager not initialised; skipping",
			slog.String("rule_id", alert.RuleID))
		return nil
	}
	if err := e.networkPolicyMgr.Execute(ctx, alert); err != nil {
		return fmt.Errorf("enforcer/networkpolicy: %w", err)
	}
	if e.actionsTotal != nil {
		e.actionsTotal.WithLabelValues("networkpolicy").Inc()
	}
	return nil
}

// executeThrottle rate-limits the process using cgroups v2.
func (e *Enforcer) executeThrottle(ctx context.Context, alert types.Alert) error {
	if err := validateEvent(alert.Event); err != nil {
		e.logger.Warn("throttle rejected: invalid event", "error", err)
		return err
	}

	comm := sanitizeComm(string(bytesToString(alert.Event.Comm[:])))
	entry := AuditEntry{
		Timestamp:   time.Now(),
		Action:      ActionThrottle,
		RuleID:      alert.RuleID,
		PID:         alert.Event.PID,
		TGID:        alert.Event.TGID,
		Comm:        comm,
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
		"comm", comm,
		"throttle_count", state.Count,
	)

	entry.Success = true
	e.logAudit(entry)
	if e.actionsTotal != nil {
		e.actionsTotal.WithLabelValues("throttle").Inc()
	}
	return nil
}

// applyCgroupThrottle applies CPU throttling via cgroups v2.
func (e *Enforcer) applyCgroupThrottle(pid uint32) error {
	cgroupPath, err := e.findCgroupPath(pid)
	if err != nil {
		return fmt.Errorf("find cgroup path: %w", err)
	}

	const periodUS = 100_000 // 100ms scheduling period
	quotaUS := periodUS * e.throttleCPUPercent / 100
	cpuMaxPath := filepath.Join(cgroupPath, "cpu.max")
	if err := os.WriteFile(cpuMaxPath, []byte(fmt.Sprintf("%d %d\n", quotaUS, periodUS)), 0644); err != nil {
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
			if e.auditDropped != nil {
				e.auditDropped.Inc()
			}
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
	case "lsm_block":
		return ActionLSMBlock, nil
	case "kill":
		return ActionKill, nil
	case "throttle":
		return ActionThrottle, nil
	case "log":
		return ActionLog, nil
	case "networkpolicy":
		return ActionNetworkPolicy, nil
	default:
		return "", fmt.Errorf("unknown action type: %s", s)
	}
}

// ParseBlockBackend parses a block backend string.
func ParseBlockBackend(s string) (BlockBackend, error) {
	switch s {
	case "log":
		return BlockBackendLog, nil
	case "nftables":
		return BlockBackendNFTables, nil
	case "iptables":
		return BlockBackendIPTables, nil
	case "xdp":
		return BlockBackendXDP, nil
	default:
		return "", fmt.Errorf("unknown block backend: %s", s)
	}
}

// GetBlockBackend returns the configured block backend.
func (e *Enforcer) GetBlockBackend() BlockBackend {
	return e.blockBackend
}

// IsDryRun returns true if dry-run mode is enabled.
func (e *Enforcer) IsDryRun() bool {
	return e.dryRun
}

// SetLSMManager sets the LSM blocklist manager.
// This is called after initialization when the LSM collector is created.
func (e *Enforcer) SetLSMManager(manager LSMBlocklistManager) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lsmManager = manager
}

// Cleanup removes all enforcement rules.
func (e *Enforcer) Cleanup() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.nftablesMgr != nil {
		if err := e.nftablesMgr.Cleanup(); err != nil {
			return err
		}
	}
	if e.iptablesMgr != nil {
		if err := e.iptablesMgr.Cleanup(); err != nil {
			return err
		}
	}
	// Note: XDP blocklist is cleared by closing the BPF maps in Close().
	// Note: LSM blocklist is cleared by closing the BPF maps in LSMCollector.Close().
	return nil
}

// Close closes the enforcer and releases resources.
func (e *Enforcer) Close() error {
	if e.stopCleanup != nil {
		e.stopCleanup()
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.nftablesMgr != nil {
		if err := e.nftablesMgr.Close(); err != nil {
			return err
		}
	}
	if e.iptablesMgr != nil {
		if err := e.iptablesMgr.Close(); err != nil {
			return err
		}
	}
	if e.xdpMgr != nil {
		if err := e.xdpMgr.Close(); err != nil {
			return err
		}
	}
	if e.networkPolicyMgr != nil {
		e.networkPolicyMgr.Close()
	}
	return nil
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

// verifyPIDComm reads /proc/<pid>/comm and checks it matches expectedComm.
// Returns an error if the PID no longer exists or has a different comm,
// indicating that the PID was recycled by the kernel after the BPF event fired.
func verifyPIDComm(pid uint32, expectedComm string) error {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return fmt.Errorf("process %d vanished before kill: %w", pid, err)
	}
	// /proc/<pid>/comm is a newline-terminated string, trim it.
	currentComm := sanitizeComm(strings.TrimRight(string(data), "\n"))
	if currentComm != expectedComm {
		return fmt.Errorf("process %d comm changed: expected %q got %q (PID reuse detected)", pid, expectedComm, currentComm)
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
