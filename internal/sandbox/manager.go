package sandbox

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/internal/config"
)

// bpfMap is the subset of *ebpf.Map used by the sandbox manager. Extracted as
// an interface so the map-population logic can be unit-tested with an in-memory
// fake and no BPF-capable kernel.
type bpfMap interface {
	Update(key, value interface{}, flags ebpf.MapUpdateFlags) error
	Delete(key interface{}) error
}

// Maps groups the BPF maps that back the AI-agent sandbox.
type Maps struct {
	State      bpfMap // sandbox_state:          u32 -> u64 (active cgroup count)
	Cgroups    bpfMap // sandbox_cgroups:        u64 cgroup_id -> packed value
	PathPolicy bpfMap // sandbox_path_policy:    u64 -> u8 access bits
	HashSecret bpfMap // sandbox_hash_secret:    u32(0) -> u64 per-boot salt (issue #274)
	NetV4      bpfMap // sandbox_net_v4:         LPM CIDRv4Entry -> u8
	NetV6      bpfMap // sandbox_net_v6:         LPM CIDRv6Entry -> u8
	Ports      bpfMap // sandbox_ports:          u64 -> u8
	Protected  bpfMap // sandbox_protected_pids: u32 tgid -> u8 (self-protection)
	ExecPins   bpfMap // sandbox_exec_pins:      {u32 profile, u8[32] sha256} -> u32 path fnv (#225)
}

// Manager installs the compiled ai_sandbox policy into the kernel and tracks
// which cgroups are under a profile. When BPF LSM is unavailable it degrades to
// an audit-only mode: no kernel enforcement, but Policy.PathAllowed /
// EgressAllowed remain usable for userspace audit logging by callers.
type Manager struct {
	logger *slog.Logger
	policy *Policy
	cfg    config.AISandboxConfig

	mu         sync.Mutex
	maps       *Maps
	objs       *bpf.KmodObjects
	ownsObjs   bool // true when Load loaded objs itself and must Close it
	links      []link.Link
	registered map[uint64]uint32   // cgroup id -> profile id
	protected  map[uint32]struct{} // tgids protected from sandboxed signals (item 1)
	kernelMode bool                // true when BPF LSM enforcement is wired

	// execHookAttached is true only when the bprm_check_security exec-control
	// hook actually attached. When it fails to attach we must not claim
	// kernel-enforced exec: the file_open hook still gates exec against the
	// resolved path, but the dedicated exec gate is absent, so KernelEnforced
	// reports false rather than overstate coverage (issue #267 item 2).
	execHookAttached bool

	// dynEgress tracks the DNS-pinned egress rows currently installed per
	// profile id, keyed by IP string, so a refresh can diff and prune stale
	// entries without touching the static allowed_egress_cidrs rows (item 6).
	dynEgress map[uint32]map[string]net.IP

	// enforcementUnsafe latches true once a target is found that could tamper
	// with the enforcer (item 7). While set, KernelEnforced reports false: we
	// never claim enforcement for a workload that can defeat it.
	enforcementUnsafe bool
	unsafeReasons     []string
}

// New compiles the ai_sandbox config and returns a Manager. It does not touch
// the kernel; call Load to attach the LSM programs and install the policy.
func New(cfg config.AISandboxConfig, logger *slog.Logger) (*Manager, error) {
	if logger == nil {
		logger = slog.Default()
	}
	pol, err := Compile(cfg)
	if err != nil {
		return nil, fmt.Errorf("sandbox: compile policy: %w", err)
	}
	return &Manager{
		logger:     logger.With("component", "ai_sandbox"),
		policy:     pol,
		cfg:        cfg,
		registered: make(map[uint64]uint32),
		protected:  make(map[uint32]struct{}),
		dynEgress:  make(map[uint32]map[string]net.IP),
	}, nil
}

// Policy returns the compiled policy for userspace evaluation.
func (m *Manager) Policy() *Policy { return m.policy }

// LSMEvents returns the sandbox lsm_events ring-buffer map, or nil in
// audit-only mode (no kernel objects loaded). The `ebpf-guard run` wrapper opens
// a RingbufReader on it to drain and record sandbox_audit/sandbox_deny decisions
// that the attached LSM hooks emit (issue #268). Only valid after Load.
func (m *Manager) LSMEvents() *ebpf.Map {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.objs == nil {
		return nil
	}
	return m.objs.LsmEvents
}

// Mode returns "enforce" or "audit" as configured.
func (m *Manager) Mode() string {
	if m.policy.Mode == ModeEnforce {
		return "enforce"
	}
	return "audit"
}

// KernelEnforced reports whether BPF LSM enforcement is actually active AND
// trustworthy. False means the manager is running audit-only — because the
// kernel lacks BPF LSM / Load was skipped, because a sandboxed target was found
// privileged enough to tamper with the enforcer (item 7), or because the
// exec-control hook did not attach so exec cannot be fully enforced (issue #267
// item 2). It must never return true for a workload that can defeat enforcement.
func (m *Manager) KernelEnforced() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.kernelMode && m.execHookAttached &&
		m.policy.Mode == ModeEnforce && !m.enforcementUnsafe
}

// ExecEnforced reports whether the dedicated exec-control hook
// (bprm_check_security) is attached in an enforce-mode kernel session. It is
// the exec dimension of KernelEnforced, exposed separately so an operator can
// tell a missing exec hook (KernelEnforced=false, ExecEnforced=false) apart
// from an unsafe-target downgrade (KernelEnforced=false, ExecEnforced=true) —
// issue #267 item 2. It deliberately ignores the enforcement-unsafe latch,
// which it isolates.
func (m *Manager) ExecEnforced() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.kernelMode && m.execHookAttached && m.policy.Mode == ModeEnforce
}

// EnforcementUnsafe reports whether enforcement has been downgraded because a
// target could tamper with the enforcer, along with the reasons. Surfaced in
// logs and status so operators see why an enforce profile is not enforcing.
func (m *Manager) EnforcementUnsafe() (bool, []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enforcementUnsafe, append([]string(nil), m.unsafeReasons...)
}

// GuardTarget assesses a candidate enforce target (pid, or a proxy for the tree
// it heads) and, in enforce mode, latches enforcement-unsafe when the target
// could tamper with the enforcer. It returns the assessment so callers can warn
// with the specific reasons. In audit mode it assesses but never downgrades
// (there is nothing to weaken). Safe to call before or after Load.
func (m *Manager) GuardTarget(pid int) EnforcementSafety {
	safety := AssessProcess(pid)
	m.applyGuard(safety)
	return safety
}

// applyGuard latches enforcement-unsafe from an assessment. In enforce mode an
// unsafe verdict downgrades to audit-only exactly once (idempotent); in audit
// mode there is nothing to weaken so it is a no-op. Kept separate from process
// probing so the latch logic is unit-testable without a real /proc target.
func (m *Manager) applyGuard(safety EnforcementSafety) {
	if safety.Safe || m.policy.Mode != ModeEnforce {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.enforcementUnsafe {
		return
	}
	m.enforcementUnsafe = true
	m.unsafeReasons = safety.Reasons
	m.logger.Warn("ai_sandbox: enforce is UNSAFE for this target — it can tamper with the "+
		"enforcer; refusing to claim kernel enforcement, downgrading to audit-only",
		"reasons", safety.Reasons,
		"remediation", "run the agent without CAP_BPF/CAP_SYS_ADMIN/CAP_SYS_PTRACE and "+
			"without write access to /sys/fs/bpf or /sys/fs/cgroup")
}

// lsmAvailable reports whether the running kernel exposes BPF LSM.
func lsmAvailable() bool {
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "bpf")
}

// Load attaches the sandbox LSM hooks and installs the profile allow-lists. On
// a kernel without BPF LSM it logs and returns nil, leaving the manager in
// audit-only mode (Policy evaluation still works for userspace auditing).
//
// sharedObjs, when non-nil, is an already-loaded *bpf.KmodObjects to attach
// against instead of loading a second copy. bpf/lsm.bpf.c compiles into one
// object bundling both the sandbox hooks (file_open, socket_connect, ...) and
// the kernel-module-load hooks; loading it twice (once here, once in
// collector.KmodCollector) produces two independent copies of sandbox_state /
// sandbox_cgroups and two separate lsm_events ring buffers, so cgroup
// registration and policy writes never reach the copy the collector's hooks
// consult, and nothing ever reads the copy this Manager's hooks write into
// (issue #260). Callers that also run a KmodCollector must load it there
// first and pass collector.KmodCollector.Objects() here. Pass nil for a
// standalone Manager with no collector (e.g. the `ebpf-guard run` wrapper);
// Load then owns the load and its Close.
func (m *Manager) Load(sharedObjs *bpf.KmodObjects) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !lsmAvailable() {
		m.logger.Warn("BPF LSM unavailable (kernel < 5.7 or no CONFIG_BPF_LSM); " +
			"ai_sandbox running in userspace audit-only mode, no kernel enforcement")
		return nil
	}

	objs := sharedObjs
	if objs == nil {
		if err := rlimit.RemoveMemlock(); err != nil {
			return fmt.Errorf("sandbox: remove memlock: %w", err)
		}
		objs = &bpf.KmodObjects{}
		if err := bpf.LoadKmodObjects(objs, &ebpf.CollectionOptions{}); err != nil {
			return fmt.Errorf("sandbox: load LSM objects: %w", err)
		}
		m.ownsObjs = true
	}
	m.objs = objs
	m.maps = &Maps{
		State:      objs.SandboxState,
		Cgroups:    objs.SandboxCgroups,
		PathPolicy: objs.SandboxPathPolicy,
		HashSecret: objs.SandboxHashSecret,
		NetV4:      objs.SandboxNetV4,
		NetV6:      objs.SandboxNetV6,
		Ports:      objs.SandboxPorts,
		Protected:  objs.SandboxProtectedPids,
		ExecPins:   objs.SandboxExecPins,
	}

	// Attach the positive-policy hooks. bprm_check_security may be absent on
	// some kernels; treat its failure as non-fatal (exec control degrades).
	fo, err := link.AttachLSM(link.LSMOptions{Program: objs.LsmFileOpen})
	if err != nil {
		m.closeLocked()
		return fmt.Errorf("sandbox: attach file_open: %w", err)
	}
	m.links = append(m.links, fo)

	sc, err := link.AttachLSM(link.LSMOptions{Program: objs.LsmSocketConnect})
	if err != nil {
		m.closeLocked()
		return fmt.Errorf("sandbox: attach socket_connect: %w", err)
	}
	m.links = append(m.links, sc)

	if bc, berrr := link.AttachLSM(link.LSMOptions{Program: objs.LsmBprmCheck}); berrr != nil {
		// The dedicated exec gate is absent. file_open still enforces the exec
		// allow-list against the resolved path, but we must not report full
		// kernel enforcement: KernelEnforced() stays false so the operator is
		// never shown kernel_enforced=true while exec control is degraded
		// (issue #267 item 2).
		m.logger.Warn("ai_sandbox: bprm_check_security hook unavailable; dedicated exec gate "+
			"not enforced (file_open backstop only) — kernel_enforced downgraded", "error", berrr)
	} else {
		m.links = append(m.links, bc)
		m.execHookAttached = true
	}

	// Self-protection + escape-primitive hooks (issue #255, session 2). These
	// only act on tasks inside a sandboxed cgroup, so attaching them is safe on
	// any host. Each is best-effort: a kernel missing one hook must not defeat
	// the others, so failures downgrade that dimension with a warning.
	for _, h := range []struct {
		name string
		prog *ebpf.Program
	}{
		{"task_kill", objs.LsmTaskKill},
		{"bpf", objs.LsmSandboxBpf},
		{"ptrace", objs.LsmSandboxPtrace},
		{"mount", objs.LsmSandboxMount},
	} {
		l, aerr := link.AttachLSM(link.LSMOptions{Program: h.prog})
		if aerr != nil {
			m.logger.Warn("ai_sandbox: escape-primitive hook unavailable; that dimension is not contained",
				"hook", h.name, "error", aerr)
			continue
		}
		m.links = append(m.links, l)
	}

	if err := writePolicy(*m.maps, m.policy); err != nil {
		m.closeLocked()
		return fmt.Errorf("sandbox: install policy: %w", err)
	}
	if err := m.setActiveCountLocked(); err != nil {
		m.logger.Warn("sandbox: init active count", "error", err)
	}

	// Protect the agent process from a sandboxed task signalling it (item 1).
	if err := m.protectLocked(uint32(os.Getpid())); err != nil { // #nosec G115 -- os.Getpid() is bounded well under uint32 (Linux pid_max caps at 2^22)
		m.logger.Warn("ai_sandbox: could not self-protect agent PID", "error", err)
	}

	m.kernelMode = true
	m.logger.Info("ai_sandbox LSM enforcement active",
		"mode", m.Mode(), "profiles", len(m.policy.profiles))
	return nil
}

// RegisterCgroup places a cgroup subtree under the named profile. Processes in
// that cgroup (and its descendants) become deny-by-default. Safe to call before
// or after Load; in audit-only mode it records the mapping without kernel state.
func (m *Manager) RegisterCgroup(cgroupID uint64, profileName string) error {
	id, ok := m.policy.ProfileID(profileName)
	if !ok {
		return fmt.Errorf("sandbox: unknown profile %q", profileName)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	m.registered[cgroupID] = id
	if m.maps == nil {
		return nil // audit-only
	}
	cp := m.policy.byName[profileName]
	val := cgroupValue(id, cp.flags, m.policy.Mode)
	if err := m.maps.Cgroups.Update(cgroupID, val, ebpf.UpdateAny); err != nil {
		delete(m.registered, cgroupID)
		return fmt.Errorf("sandbox: register cgroup %d: %w", cgroupID, err)
	}
	if err := m.setActiveCountLocked(); err != nil {
		m.logger.Warn("sandbox: update active count", "error", err)
	}
	m.logger.Info("sandbox: cgroup registered", "cgroup_id", cgroupID, "profile", profileName)
	return nil
}

// UnregisterCgroup removes a cgroup from sandbox scope.
func (m *Manager) UnregisterCgroup(cgroupID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.registered[cgroupID]; !ok {
		return nil
	}
	delete(m.registered, cgroupID)
	if m.maps == nil {
		return nil
	}
	if err := m.maps.Cgroups.Delete(cgroupID); err != nil {
		m.logger.Warn("sandbox: delete cgroup entry", "cgroup_id", cgroupID, "error", err)
	}
	if err := m.setActiveCountLocked(); err != nil {
		m.logger.Warn("sandbox: update active count", "error", err)
	}
	m.logger.Info("sandbox: cgroup unregistered", "cgroup_id", cgroupID)
	return nil
}

// ProtectPID marks a tgid as protected from signals sent by sandboxed tasks
// (issue #255, session 2, item 1). The lsm_task_kill hook denies a signal to a
// protected PID when — and only when — the sender is inside a sandboxed cgroup,
// so protecting a PID never affects ordinary host signalling. Safe before or
// after Load; in audit-only mode it records intent without kernel state.
func (m *Manager) ProtectPID(pid uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.protectLocked(pid)
}

// ProtectSelf protects the agent's own process. Called automatically by Load;
// exposed so a supervisor can re-assert protection (e.g. after a fork of a
// worker that must also survive a contained agent).
func (m *Manager) ProtectSelf() error {
	return m.ProtectPID(uint32(os.Getpid())) // #nosec G115 -- os.Getpid() is bounded well under uint32 (Linux pid_max caps at 2^22)
}

// protectLocked records pid as protected and, when the kernel maps are live,
// installs it into sandbox_protected_pids. Caller must hold m.mu.
func (m *Manager) protectLocked(pid uint32) error {
	if pid == 0 {
		return fmt.Errorf("sandbox: refusing to protect pid 0")
	}
	m.protected[pid] = struct{}{}
	if m.maps == nil || m.maps.Protected == nil {
		return nil // audit-only
	}
	if err := m.maps.Protected.Update(pid, uint8(1), ebpf.UpdateAny); err != nil {
		delete(m.protected, pid)
		return fmt.Errorf("sandbox: protect pid %d: %w", pid, err)
	}
	m.logger.Info("ai_sandbox: PID protected from sandboxed signals", "pid", pid)
	return nil
}

// UnprotectPID removes a tgid from the self-protection set (e.g. a worker that
// has exited). No-op for a PID that was never protected.
func (m *Manager) UnprotectPID(pid uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.protected[pid]; !ok {
		return nil
	}
	delete(m.protected, pid)
	if m.maps == nil || m.maps.Protected == nil {
		return nil
	}
	if err := m.maps.Protected.Delete(pid); err != nil {
		m.logger.Warn("sandbox: unprotect pid", "pid", pid, "error", err)
	}
	return nil
}

// SetDomainEgress installs the DNS-pinned egress set for a profile: the given
// IPs become /32 (or /128) allow entries scoped to that profile, and any IP that
// was previously pinned but is absent from ips is removed (item 6). The static
// allowed_egress_cidrs rows are never touched. Loopback and unspecified
// addresses are skipped: loopback egress is governed by the profile's
// allow_loopback flag (SBX_F_ALLOW_LOOPBACK), not by dynamic CIDR rows
// (issue #274 item 3), and an unspecified address is never a valid connect
// target.
//
// Safe before or after Load; in audit-only mode it records the intended set so
// Policy-based auditing stays consistent, without kernel writes. Idempotent: an
// unchanged set produces no map operations.
func (m *Manager) SetDomainEgress(profileName string, ips []net.IP) error {
	id, ok := m.policy.ProfileID(profileName)
	if !ok {
		return fmt.Errorf("sandbox: unknown profile %q", profileName)
	}

	// Normalise/dedupe the desired set.
	desired := make(map[string]net.IP, len(ips))
	for _, ip := range ips {
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		desired[ip.String()] = ip
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	current := m.dynEgress[id]
	if current == nil {
		current = make(map[string]net.IP)
	}

	// Additions: in desired, not yet installed.
	var added, removed int
	for k, ip := range desired {
		if _, exists := current[k]; exists {
			continue
		}
		if err := m.addDynEgressLocked(id, ip); err != nil {
			return fmt.Errorf("sandbox: pin egress %s for %q: %w", k, profileName, err)
		}
		current[k] = ip
		added++
	}
	// Removals: installed, no longer desired.
	for k, ip := range current {
		if _, keep := desired[k]; keep {
			continue
		}
		if err := m.delDynEgressLocked(id, ip); err != nil {
			m.logger.Warn("sandbox: unpin egress", "ip", k, "profile", profileName, "error", err)
		}
		delete(current, k)
		removed++
	}
	m.dynEgress[id] = current

	if added > 0 || removed > 0 {
		m.logger.Info("ai_sandbox: DNS-pinned egress updated",
			"profile", profileName, "added", added, "removed", removed, "total", len(current))
	}
	return nil
}

// DomainEgressIPs returns the sorted IP strings currently pinned for a profile.
// Exposed for status/debugging and tests.
func (m *Manager) DomainEgressIPs(profileName string) []string {
	id, ok := m.policy.ProfileID(profileName)
	if !ok {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.dynEgress[id]
	out := make([]string, 0, len(cur))
	for k := range cur {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// addDynEgressLocked programs one host IP into the profile's egress maps. Caller
// holds m.mu. No-op on kernel maps in audit-only mode.
func (m *Manager) addDynEgressLocked(profileID uint32, ip net.IP) error {
	if m.maps == nil {
		return nil // audit-only: tracked in dynEgress only
	}
	if e, ok := hostCIDRv4(profileID, ip); ok {
		return m.maps.NetV4.Update(e, uint8(1), ebpf.UpdateAny)
	}
	if e, ok := hostCIDRv6(profileID, ip); ok {
		return m.maps.NetV6.Update(e, uint8(1), ebpf.UpdateAny)
	}
	return fmt.Errorf("unrecognised IP %v", ip)
}

// delDynEgressLocked removes one host IP from the profile's egress maps. Caller
// holds m.mu.
func (m *Manager) delDynEgressLocked(profileID uint32, ip net.IP) error {
	if m.maps == nil {
		return nil
	}
	if e, ok := hostCIDRv4(profileID, ip); ok {
		return m.maps.NetV4.Delete(e)
	}
	if e, ok := hostCIDRv6(profileID, ip); ok {
		return m.maps.NetV6.Delete(e)
	}
	return fmt.Errorf("unrecognised IP %v", ip)
}

// setActiveCountLocked writes the number of registered cgroups into
// sandbox_state[0], the fast-path gate read by every hook.
func (m *Manager) setActiveCountLocked() error {
	if m.maps == nil {
		return nil
	}
	return m.maps.State.Update(uint32(0), uint64(len(m.registered)), ebpf.UpdateAny)
}

// Close detaches all hooks and releases BPF resources.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeLocked()
	return nil
}

func (m *Manager) closeLocked() {
	for _, l := range m.links {
		_ = l.Close()
	}
	m.links = nil
	if m.objs != nil && m.ownsObjs {
		if err := m.objs.Close(); err != nil {
			m.logger.Warn("sandbox: close bpf objects", "error", err)
		}
	}
	m.objs = nil
	m.ownsObjs = false
	m.maps = nil
	m.kernelMode = false
	m.execHookAttached = false
}

// writePolicy installs every profile's path / CIDR / port rows into the maps.
// Split out from Manager so it can be unit-tested against in-memory fakes.
func writePolicy(maps Maps, p *Policy) error {
	// Install the path-policy hash secret before any path row, so a reader
	// racing the initial policy load never sees allow-list rows keyed on a
	// hash it could compute itself (issue #274 item 1).
	//
	// The map's absence (older/mismatched generated object) must not silently
	// degrade an enforce policy to unsalted keys — that is the original
	// forgeable state. Refuse to install an enforce policy in that case
	// (issue #276 item 2); audit mode has no enforcement claim to protect, so
	// it still degrades best-effort, matching the ExecPins pattern below.
	if maps.HashSecret == nil {
		if p.Mode == ModeEnforce {
			return fmt.Errorf("path policy hash secret: sandbox_hash_secret map absent; " +
				"refusing to enforce an unsalted (forgeable) path allow-list")
		}
	} else if err := maps.HashSecret.Update(uint32(0), p.secret, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("path policy hash secret: %w", err)
	}
	one := uint8(1)
	for _, cp := range p.profiles {
		for _, pe := range cp.paths {
			if err := maps.PathPolicy.Update(pe.Key, pe.Access, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("path policy %q: %w", pe.Prefix, err)
			}
		}
		for i := range cp.cidrv4 {
			if err := maps.NetV4.Update(cp.cidrv4[i], one, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("egress v4 (profile %s): %w", cp.name, err)
			}
		}
		for i := range cp.cidrv6 {
			if err := maps.NetV6.Update(cp.cidrv6[i], one, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("egress v6 (profile %s): %w", cp.name, err)
			}
		}
		for _, pt := range cp.ports {
			if err := maps.Ports.Update(portKey(cp.id, pt), one, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("egress port %d (profile %s): %w", pt, cp.name, err)
			}
		}
		// Hash-pinned exec entries (issue #255 / #225). The map may be absent on
		// an older generated object; skip rather than fail so the rest of the
		// policy still installs.
		if maps.ExecPins != nil {
			for i := range cp.execPins {
				if err := maps.ExecPins.Update(cp.execPins[i].Key, cp.execPins[i].PathFN, ebpf.UpdateAny); err != nil {
					return fmt.Errorf("exec pin %q (profile %s): %w", cp.execPins[i].Path, cp.name, err)
				}
			}
		}
	}
	return nil
}
