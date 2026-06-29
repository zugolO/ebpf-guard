// Package selfprotect implements anti-tampering detection for the agent's BPF programs and maps.
//
// When an external process attempts to call BPF_PROG_DETACH, BPF_MAP_UPDATE_ELEM, or
// BPF_MAP_DELETE_ELEM targeting our objects, a Critical alert is generated and routed
// through the existing alert pipeline. An optional enforce mode (behind EnforceMode flag)
// signals the BPF LSM hook to return -EPERM, blocking the call outright.
//
// Kernel requirements: kernel 5.7+ with CONFIG_BPF_LSM=y for enforcement.
// Detection-only mode (default) works on any kernel that supports bpf() monitoring.
package selfprotect

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// dangerousCommands is the set of bpf() commands that can tamper with our objects.
// Keyed by command number; value is the human-readable name used in alerts.
var dangerousCommands = map[uint32]string{
	types.BPFCmdMapUpdate:  "BPF_MAP_UPDATE_ELEM",
	types.BPFCmdMapDelete:  "BPF_MAP_DELETE_ELEM",
	types.BPFCmdProgDetach: "BPF_PROG_DETACH",
}

// IsTamperingCmd reports whether the given bpf() command number is potentially
// used to tamper with BPF programs or maps.
func IsTamperingCmd(cmd uint32) bool {
	_, ok := dangerousCommands[cmd]
	return ok
}

// TamperingCmdName returns a human-readable name for a potentially dangerous
// bpf() command, or an empty string if the command is not considered dangerous.
func TamperingCmdName(cmd uint32) string {
	return dangerousCommands[cmd]
}

// OwnedObjects tracks the BPF program IDs and map IDs that belong to the agent.
// Thread-safe: all methods may be called concurrently.
type OwnedObjects struct {
	mu         sync.RWMutex
	programIDs map[uint32]struct{}
	mapIDs     map[uint32]struct{}
	pinPaths   map[string]struct{}
}

// NewOwnedObjects returns an empty OwnedObjects registry.
func NewOwnedObjects() *OwnedObjects {
	return &OwnedObjects{
		programIDs: make(map[uint32]struct{}),
		mapIDs:     make(map[uint32]struct{}),
		pinPaths:   make(map[string]struct{}),
	}
}

// AddProgramID registers a BPF program ID as owned by the agent.
func (o *OwnedObjects) AddProgramID(id uint32) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.programIDs[id] = struct{}{}
}

// RemoveProgramID unregisters a BPF program ID (called on graceful program close).
func (o *OwnedObjects) RemoveProgramID(id uint32) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.programIDs, id)
}

// AddMapID registers a BPF map ID as owned by the agent.
func (o *OwnedObjects) AddMapID(id uint32) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.mapIDs[id] = struct{}{}
}

// RemoveMapID unregisters a BPF map ID (called on graceful map close).
func (o *OwnedObjects) RemoveMapID(id uint32) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.mapIDs, id)
}

// AddPinPath registers a bpffs pin path as belonging to the agent.
func (o *OwnedObjects) AddPinPath(path string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.pinPaths[path] = struct{}{}
}

// HasProgramID reports whether id is a registered agent program.
func (o *OwnedObjects) HasProgramID(id uint32) bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	_, ok := o.programIDs[id]
	return ok
}

// HasMapID reports whether id is a registered agent map.
func (o *OwnedObjects) HasMapID(id uint32) bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	_, ok := o.mapIDs[id]
	return ok
}

// HasPinPath reports whether path is a registered agent pin path.
func (o *OwnedObjects) HasPinPath(path string) bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	_, ok := o.pinPaths[path]
	return ok
}

// ProgramCount returns the number of registered program IDs.
func (o *OwnedObjects) ProgramCount() int {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return len(o.programIDs)
}

// MapCount returns the number of registered map IDs.
func (o *OwnedObjects) MapCount() int {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return len(o.mapIDs)
}

// AgentAllowlist tracks PIDs and cgroup IDs that are permitted to interact
// with the agent's BPF objects (the agent itself and its upgrade process).
// Thread-safe: all methods may be called concurrently.
type AgentAllowlist struct {
	mu  sync.RWMutex
	pids map[uint32]struct{}
}

// NewAgentAllowlist returns an allowlist pre-seeded with the current process PID.
func NewAgentAllowlist() *AgentAllowlist {
	a := &AgentAllowlist{
		pids: make(map[uint32]struct{}),
	}
	a.pids[uint32(os.Getpid())] = struct{}{} //nolint:gosec // pid fits in uint32
	return a
}

// AddPID adds a PID to the allowlist (e.g., a new agent process during upgrade).
func (a *AgentAllowlist) AddPID(pid uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pids[pid] = struct{}{}
}

// RemovePID removes a PID from the allowlist (e.g., after upgrade completes).
func (a *AgentAllowlist) RemovePID(pid uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.pids, pid)
}

// IsPIDAllowed reports whether pid is in the agent allowlist.
func (a *AgentAllowlist) IsPIDAllowed(pid uint32) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	_, ok := a.pids[pid]
	return ok
}

// Count returns the number of allowed PIDs.
func (a *AgentAllowlist) Count() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.pids)
}

// AlertSink is the interface for emitting self-protection alerts into the pipeline.
type AlertSink interface {
	// SendAlert delivers a tamper alert. Implementations must be goroutine-safe.
	SendAlert(alert types.Alert)
}

// Config configures the self-protection detector.
type Config struct {
	// Enabled disables detection entirely when false (all ProcessEvent calls are no-ops).
	Enabled bool

	// EnforceMode requests that the BPF LSM hook return -EPERM for tampering calls.
	// In the Go layer this sets the Enforce flag on emitted alerts so the LSM hook
	// controller can pick up the signal.
	EnforceMode bool

	// AlertSeverity is the severity of generated alerts. Default: SeverityCritical.
	AlertSeverity types.Severity

	// ExtraAgentPIDs are added to the allowlist at construction time.
	ExtraAgentPIDs []uint32
}

// Detector monitors BPF events for self-tampering attempts.
// Create with NewDetector; call ProcessEvent for every incoming types.Event.
type Detector struct {
	cfg       Config
	objects   *OwnedObjects
	allowlist *AgentAllowlist
	sink      AlertSink
}

// NewDetector creates a Detector from cfg. sink may be nil (alerts are still
// returned by ProcessEvent but not forwarded to a pipeline).
func NewDetector(cfg Config, sink AlertSink) *Detector {
	if cfg.AlertSeverity == "" {
		cfg.AlertSeverity = types.SeverityCritical
	}

	d := &Detector{
		cfg:       cfg,
		objects:   NewOwnedObjects(),
		allowlist: NewAgentAllowlist(),
		sink:      sink,
	}
	for _, pid := range cfg.ExtraAgentPIDs {
		d.allowlist.AddPID(pid)
	}
	return d
}

// OwnedObjects returns the OwnedObjects registry so callers can register BPF IDs.
func (d *Detector) OwnedObjects() *OwnedObjects { return d.objects }

// Allowlist returns the AgentAllowlist so callers can add/remove PIDs dynamically
// (e.g., during a rolling upgrade).
func (d *Detector) Allowlist() *AgentAllowlist { return d.allowlist }

// IsEnabled reports whether the detector is active.
func (d *Detector) IsEnabled() bool { return d.cfg.Enabled }

// IsEnforceMode reports whether blocking mode is requested.
func (d *Detector) IsEnforceMode() bool { return d.cfg.EnforceMode }

// ProcessEvent inspects e for self-tampering indicators. If e represents an
// attempt by an external process to run a dangerous bpf() command, a Critical
// alert is returned and forwarded to the AlertSink (if configured).
//
// Returns nil when:
//   - the detector is disabled
//   - the event is not a BPF program event
//   - the command is not considered dangerous
//   - the caller PID is in the agent allowlist
func (d *Detector) ProcessEvent(e types.Event) *types.Alert {
	if !d.cfg.Enabled {
		return nil
	}
	if e.Type != types.EventBPFProgram || e.BPFProgram == nil {
		return nil
	}

	cmdName := TamperingCmdName(e.BPFProgram.Cmd)
	if cmdName == "" {
		return nil
	}

	// Caller is our own process — not a tamper attempt.
	if d.allowlist.IsPIDAllowed(e.PID) {
		return nil
	}

	comm := commToString(e.Comm[:])
	msg := fmt.Sprintf(
		"self-protection: external PID %d (%s) attempted %s on agent BPF objects",
		e.PID, comm, cmdName,
	)

	alert := &types.Alert{
		ID:        generateAlertID(e),
		Timestamp: time.Now(),
		RuleID:    "self_protection_001",
		RuleName:  "BPF Anti-Tampering",
		Severity:  d.cfg.AlertSeverity,
		PID:       e.PID,
		Comm:      comm,
		Message:   msg,
		Details: map[string]interface{}{
			"bpf_cmd":      cmdName,
			"cmd_number":   e.BPFProgram.Cmd,
			"enforce_mode": d.cfg.EnforceMode,
			"ret":          e.BPFProgram.Ret,
		},
		Event: e,
	}

	if d.sink != nil {
		d.sink.SendAlert(*alert)
	}

	return alert
}

// generateAlertID produces a stable, unique alert ID from the event timestamp and PID.
func generateAlertID(e types.Event) string {
	ts := e.Timestamp
	if ts == 0 {
		ts = uint64(time.Now().UnixNano()) //nolint:gosec // monotonic, not crypto
	}
	return fmt.Sprintf("sp-%d-%d", e.PID, ts)
}

// commToString converts a null-terminated [16]byte comm field to a Go string.
func commToString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
