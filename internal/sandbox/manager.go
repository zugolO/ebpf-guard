package sandbox

import (
	"fmt"
	"log/slog"
	"os"
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

// Maps groups the six BPF maps that back the AI-agent sandbox.
type Maps struct {
	State      bpfMap // sandbox_state:       u32 -> u64 (active cgroup count)
	Cgroups    bpfMap // sandbox_cgroups:     u64 cgroup_id -> packed value
	PathPolicy bpfMap // sandbox_path_policy: u64 -> u8 access bits
	NetV4      bpfMap // sandbox_net_v4:      LPM CIDRv4Entry -> u8
	NetV6      bpfMap // sandbox_net_v6:      LPM CIDRv6Entry -> u8
	Ports      bpfMap // sandbox_ports:       u64 -> u8
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
	links      []link.Link
	registered map[uint64]uint32 // cgroup id -> profile id
	kernelMode bool              // true when BPF LSM enforcement is wired
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
	}, nil
}

// Policy returns the compiled policy for userspace evaluation.
func (m *Manager) Policy() *Policy { return m.policy }

// Mode returns "enforce" or "audit" as configured.
func (m *Manager) Mode() string {
	if m.policy.Mode == ModeEnforce {
		return "enforce"
	}
	return "audit"
}

// KernelEnforced reports whether BPF LSM enforcement is actually active. False
// means the manager is running audit-only (unsupported kernel or Load skipped).
func (m *Manager) KernelEnforced() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.kernelMode && m.policy.Mode == ModeEnforce
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
func (m *Manager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !lsmAvailable() {
		m.logger.Warn("BPF LSM unavailable (kernel < 5.7 or no CONFIG_BPF_LSM); " +
			"ai_sandbox running in userspace audit-only mode, no kernel enforcement")
		return nil
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("sandbox: remove memlock: %w", err)
	}

	objs := &bpf.KmodObjects{}
	if err := bpf.LoadKmodObjects(objs, &ebpf.CollectionOptions{}); err != nil {
		return fmt.Errorf("sandbox: load LSM objects: %w", err)
	}
	m.objs = objs
	m.maps = &Maps{
		State:      objs.SandboxState,
		Cgroups:    objs.SandboxCgroups,
		PathPolicy: objs.SandboxPathPolicy,
		NetV4:      objs.SandboxNetV4,
		NetV6:      objs.SandboxNetV6,
		Ports:      objs.SandboxPorts,
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
		m.logger.Warn("bprm_check_security hook unavailable; exec allow-list not enforced", "error", berrr)
	} else {
		m.links = append(m.links, bc)
	}

	if err := writePolicy(*m.maps, m.policy); err != nil {
		m.closeLocked()
		return fmt.Errorf("sandbox: install policy: %w", err)
	}
	if err := m.setActiveCountLocked(); err != nil {
		m.logger.Warn("sandbox: init active count", "error", err)
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
	if m.objs != nil {
		m.objs.Close()
		m.objs = nil
	}
	m.maps = nil
	m.kernelMode = false
}

// writePolicy installs every profile's path / CIDR / port rows into the maps.
// Split out from Manager so it can be unit-tested against in-memory fakes.
func writePolicy(maps Maps, p *Policy) error {
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
	}
	return nil
}
