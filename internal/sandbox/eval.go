package sandbox

import "net"

// Userspace policy evaluation. These functions reproduce, in Go, exactly what
// the BPF hooks in bpf/lsm.bpf.c decide from the same encoded map rows. They
// back two things: the userspace-audit fallback when BPF LSM is unavailable,
// and the unit tests that pin the kernel/userspace encoding contract.

// pathLookup indexes a profile's path policy by the FNV-1a hash of the prefix,
// mirroring the sandbox_path_policy map key (minus the profile id high bits).
func (cp *compiledProfile) pathLookup() map[uint32]uint8 {
	m := make(map[uint32]uint8, len(cp.paths))
	for _, e := range cp.paths {
		m[uint32(e.Key)] |= e.Access // #nosec G115 -- intentional: keep the low 32 bits (the fnv32a hash), discard the profile-id bits packed into the high 32
	}
	return m
}

// pathAllowed replays sandbox_path_allowed(): a rolling FNV-1a hash over the
// absolute path, consulted at every '/' boundary and at the end. A deny bit on
// any boundary wins; otherwise the path is allowed if some boundary carries one
// of the wanted access bits.
func pathAllowed(lookup map[uint32]uint8, p string, want uint8) bool {
	if len(p) == 0 || p[0] != '/' {
		return false // relative / unresolvable — deny-by-default
	}
	const offset = 2166136261
	const prime = 16777619
	h := uint32(offset)
	allowed := false
	for i := 0; i <= len(p) && i < 128; i++ {
		atEnd := i == len(p)
		boundary := atEnd || (p[i] == '/' && i > 0)
		if boundary {
			if bits, ok := lookup[h]; ok {
				if bits&accessDeny != 0 {
					return false
				}
				if bits&want != 0 {
					allowed = true
				}
			}
		}
		if atEnd {
			break
		}
		h ^= uint32(p[i])
		h *= prime
	}
	return allowed
}

// PathAllowed reports whether the named profile permits opening absPath with
// the given access (accessRead/accessWrite/accessExec). Unknown profile → false.
func (p *Policy) PathAllowed(profile, absPath string, want uint8) bool {
	cp, ok := p.byName[profile]
	if !ok {
		return false
	}
	return pathAllowed(cp.pathLookup(), absPath, want)
}

// EscapePrimitive names a kernel-contained sandbox-escape vector — a syscall or
// action a contained agent has no legitimate need for. Each maps to an LSM hook
// in bpf/lsm.bpf.c that denies it for a sandboxed task in enforce mode.
type EscapePrimitive string

const (
	// EscapeSignalProtected: signalling a protected PID (lsm_task_kill) — e.g.
	// killing the agent supervisor or the ebpf-guard process.
	EscapeSignalProtected EscapePrimitive = "kill"
	// EscapeBPF: the bpf() syscall (lsm_sandbox_bpf) — tampering with the guard's
	// own maps/links (map-write).
	EscapeBPF EscapePrimitive = "map-write"
	// EscapeMount: mount(2)/remount (lsm_sandbox_mount) — remapping the
	// filesystem view to break out of the cgroup/namespace boundary.
	EscapeMount EscapePrimitive = "cgroup-escape"
	// EscapePtrace: ptrace attach (lsm_sandbox_ptrace) — injecting into another
	// process.
	EscapePtrace EscapePrimitive = "ptrace"
	// EscapeModuleLoad: kernel module load (lsm_kernel_module_request) — ring-0
	// code execution.
	EscapeModuleLoad EscapePrimitive = "module-load"
)

// EscapeContained reports whether a sandboxed task's use of the given escape
// primitive is denied under this policy. It mirrors sandbox_escape_decide() in
// bpf/lsm.bpf.c: escape primitives are denied for any sandboxed task in enforce
// mode and audited (allowed) in audit mode. The primitive argument is accepted
// so callers and future policy can distinguish vectors even though the current
// decision is uniform across them.
func (p *Policy) EscapeContained(EscapePrimitive) bool {
	return p.Mode == ModeEnforce
}

// ExecAllowed reports whether the named profile permits execing absPath when the
// binary's content digest is digest. It layers hash pinning on top of the path
// allow-list (issue #255 / #225):
//
//   - The path must be covered by an allowed_exec prefix (exec access bit).
//   - If the path is hash-pinned, the digest must match one of its pins —
//     identity wins over location, so a swapped/rebuilt binary at a pinned path
//     is denied even though the path is allowed.
//   - An unpinned allowed path is permitted regardless of digest (prefix trust).
//
// This mirrors the intended bprm_check decision; the in-kernel digest lookup is
// delivered by #225 against the same sandbox_exec_pins rows.
func (p *Policy) ExecAllowed(profile, absPath string, digest [32]byte) bool {
	cp, ok := p.byName[profile]
	if !ok {
		return false
	}
	if !pathAllowed(cp.pathLookup(), absPath, accessExec) {
		return false
	}
	norm := normalizePrefix(absPath)
	if norm == "" {
		return false
	}
	if _, pinned := cp.pinnedPaths[fnv32a(norm)]; !pinned {
		return true // path allowed and not pinned — trust the prefix
	}
	for _, e := range cp.execPins {
		if e.PathFN == fnv32a(norm) && e.Key.Sha256 == digest {
			return true
		}
	}
	return false
}

// ExecPathPinned reports whether the profile hash-pins the given exec path.
// Callers use it to decide whether a digest must be supplied to ExecAllowed.
func (p *Policy) ExecPathPinned(profile, absPath string) bool {
	cp, ok := p.byName[profile]
	if !ok {
		return false
	}
	norm := normalizePrefix(absPath)
	if norm == "" {
		return false
	}
	_, pinned := cp.pinnedPaths[fnv32a(norm)]
	return pinned
}

// EgressAllowed reports whether the named profile permits an outbound
// connection to ip:port. Loopback is always allowed (matching the kernel
// fast-path); otherwise the address must fall inside an allowed CIDR and, when
// the profile filters ports, the port must be listed.
func (p *Policy) EgressAllowed(profile string, ip net.IP, port uint16) bool {
	cp, ok := p.byName[profile]
	if !ok {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	if !cp.cidrContains(ip) {
		return false
	}
	if cp.flags&flagPortsFilter != 0 {
		found := false
		for _, pt := range cp.ports {
			if pt == port {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// cidrContains reports whether ip is inside any of the profile's allowed CIDRs.
func (cp *compiledProfile) cidrContains(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		for _, e := range cp.cidrv4 {
			maskBits := int(e.PrefixLen) - 32 // strip the 32 profile-id bits
			if maskBits < 0 || maskBits > 32 {
				continue
			}
			net4 := net.IPNet{IP: net.IP(e.Data[4:8]), Mask: net.CIDRMask(maskBits, 32)}
			if net4.Contains(v4) {
				return true
			}
		}
		return false
	}
	v6 := ip.To16()
	if v6 == nil {
		return false
	}
	for _, e := range cp.cidrv6 {
		maskBits := int(e.PrefixLen) - 32
		if maskBits < 0 || maskBits > 128 {
			continue
		}
		net6 := net.IPNet{IP: net.IP(e.Data[4:20]), Mask: net.CIDRMask(maskBits, 128)}
		if net6.Contains(v6) {
			return true
		}
	}
	return false
}
