package sandbox

import (
	"net"
	"strings"

	"github.com/zugolO/ebpf-guard/internal/util"
)

// pathHashMax is the byte window the kernel resolves and hashes (PATH_HASH_MAX
// in bpf/lsm.bpf.c). bpf_d_path() writes the canonical path plus a NUL into a
// buffer of this size, so a path needing more than pathHashMax-1 bytes returns
// -ENAMETOOLONG. For a deny-by-default sandbox that unresolvable path is a
// violation, not an implicit allow (issue #267 item 1).
const pathHashMax = 128

// hasDotDotComponent reports whether p contains a ".." path component. Mirrors
// path_has_dotdot() in bpf/lsm.bpf.c: the bprm_check exec gate matches the raw,
// uncanonicalized execve argument, so a `..` traversal must be rejected before
// prefix matching — otherwise `/usr/bin/../../x` prefix-matches the allowed
// `/usr/bin` while the kernel executes /x (issue #267 item 3).
func hasDotDotComponent(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// Userspace policy evaluation. These functions reproduce, in Go, exactly what
// the BPF hooks in bpf/lsm.bpf.c decide from the same encoded map rows. They
// back two things: the userspace-audit fallback when BPF LSM is unavailable,
// and the unit tests that pin the kernel/userspace encoding contract.

// buildPathLookup indexes a profile's path policy by the full 64-bit SipHash of
// the prefix (profile id already folded into the PRF key), mirroring the
// sandbox_path_policy map key. Called once per profile at Compile() time and
// cached on compiledProfile.lookup — paths never changes afterward, so
// recomputing it on every PathAllowed/ExecAllowed call (once per file/exec event
// in the userspace audit fallback) would be wasted allocation.
func buildPathLookup(paths []PathEntry) map[uint64]uint8 {
	m := make(map[uint64]uint8, len(paths))
	for _, e := range paths {
		m[e.Key] |= e.Access
	}
	return m
}

// pathAllowed replays sandbox_path_allowed(): SipHash-2-4 of every '/'-boundary
// prefix of the absolute path (and the full path), consulted against the
// profile's lookup. A deny bit on any boundary wins; otherwise the path is
// allowed if some boundary carries one of the wanted access bits. The key must
// fold in the same profileID and use the same secret the lookup rows were built
// with (see pathKey) — issue #276 item 3 for why the hash is a keyed PRF.
func pathAllowed(lookup map[uint64]uint8, profileID uint32, p string, want uint8, secret util.SipHashKey) bool {
	if len(p) == 0 || p[0] != '/' {
		return false // relative / unresolvable — deny-by-default
	}
	if len(p) >= pathHashMax {
		// Too long for the kernel to resolve (bpf_d_path -ENAMETOOLONG); a
		// sandboxed task treats it as a violation, not an allow (issue #267
		// item 1).
		return false
	}
	allowed := false
	for i := 1; i <= len(p); i++ {
		// A boundary prefix is p[0:i] when i == len(p) (the full path) or when
		// p[i] starts a new component ('/', i>0). SipHash is not a rolling hash,
		// so each boundary re-hashes its prefix; the kernel side streams the same
		// prefixes incrementally, producing identical values.
		if i != len(p) && p[i] != '/' {
			continue
		}
		bits, ok := lookup[pathKey(profileID, p[:i], secret)]
		if !ok {
			continue
		}
		if bits&accessDeny != 0 {
			return false
		}
		if bits&want != 0 {
			allowed = true
		}
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
	return pathAllowed(cp.lookup, cp.id, absPath, want, p.secret)
}

// ReadAllowed reports whether the named profile permits reading absPath. Thin
// wrapper over PathAllowed for the read dimension, mirroring the file_open hook.
func (p *Policy) ReadAllowed(profile, absPath string) bool {
	return p.PathAllowed(profile, absPath, accessRead)
}

// WriteAllowed reports whether the named profile permits writing absPath. Thin
// wrapper over PathAllowed for the write dimension, mirroring the file_open hook.
func (p *Policy) WriteAllowed(profile, absPath string) bool {
	return p.PathAllowed(profile, absPath, accessWrite)
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
)

// EscapeContained reports whether a sandboxed task's escape attempts are
// denied under this policy. It mirrors sandbox_escape_decide() in
// bpf/lsm.bpf.c: escape primitives are denied for any sandboxed task in
// enforce mode and audited (allowed) in audit mode. The decision is currently
// uniform across all escape vectors (kill/map-write/mount all gate on Mode
// alone), so this takes no argument — an EscapePrimitive parameter would imply
// per-vector coverage the policy doesn't have (issue #270).
func (p *Policy) EscapeContained() bool {
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
	if hasDotDotComponent(absPath) {
		return false // uncanonicalized `..` traversal — deny (issue #267 item 3)
	}
	if !pathAllowed(cp.lookup, cp.id, absPath, accessExec, p.secret) {
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
// connection to ip:port. Loopback is only unconditionally allowed when the
// profile opts in via AllowLoopback (matching the kernel's SBX_F_ALLOW_LOOPBACK
// gate, issue #274 item 3); otherwise it is treated like any other address and
// must fall inside an allowed CIDR and, when the profile filters ports, the
// port must be listed.
func (p *Policy) EgressAllowed(profile string, ip net.IP, port uint16) bool {
	cp, ok := p.byName[profile]
	if !ok {
		return false
	}
	if ip.IsLoopback() && cp.flags&flagAllowLoopback != 0 {
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
// Uses the cidrv4Nets/cidrv6Nets slices precomputed once in addCIDR rather than
// rebuilding a net.IPNet from the raw map row on every call (issue #272).
func (cp *compiledProfile) cidrContains(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		for _, n := range cp.cidrv4Nets {
			if n.Contains(v4) {
				return true
			}
		}
		return false
	}
	v6 := ip.To16()
	if v6 == nil {
		return false
	}
	for _, n := range cp.cidrv6Nets {
		if n.Contains(v6) {
			return true
		}
	}
	return false
}
