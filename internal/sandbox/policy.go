// Package sandbox implements the AI-agent containment profile (issue #255):
// a deny-by-default, allow-known-good policy scoped to a designated agent
// process tree (its cgroup subtree). It translates the ai_sandbox config
// profiles into the cgroup-keyed BPF allow maps consumed by the LSM hooks in
// bpf/lsm.bpf.c, and provides an equivalent userspace-audit evaluation used
// when BPF LSM is unavailable (kernel < 5.7 / no CONFIG_BPF_LSM) and in tests.
//
// The encoding in this file is the contract with the kernel side: the key
// packing and FNV-1a path hashing here MUST stay byte-for-byte compatible with
// sandbox_path_allowed(), sandbox_lookup_current(), and the socket_connect /
// bprm_check hooks in bpf/lsm.bpf.c. It is deliberately kernel-independent so
// it can be unit-tested without a BPF-capable host.
package sandbox

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/zugolO/ebpf-guard/internal/config"
	"github.com/zugolO/ebpf-guard/internal/util"
)

// Enforcement mode codes — must match SANDBOX_MODE_* in bpf/lsm.bpf.c.
const (
	ModeAudit   uint8 = 0
	ModeEnforce uint8 = 1
)

// Profile flag bits — must match SBX_F_* in bpf/lsm.bpf.c.
const flagPortsFilter uint8 = 1 << 0

// Path access bits — must match SBX_ALLOW_* / SBX_DENY in bpf/lsm.bpf.c.
const (
	accessRead  uint8 = 1 << 0
	accessWrite uint8 = 1 << 1
	accessExec  uint8 = 1 << 2
	accessDeny  uint8 = 1 << 3
)

// PathEntry is one (profile, path-prefix) row of the positive path policy.
type PathEntry struct {
	Key    uint64 // profile_id<<32 | fnv32a(prefix)
	Access uint8  // accessRead|accessWrite|accessExec|accessDeny
	Prefix string // normalised prefix, retained for logging/tests
}

// CIDRv4Entry is one allowed IPv4 egress CIDR, scoped to a profile.
type CIDRv4Entry struct {
	PrefixLen uint32  // 32 (profile) + mask bits
	Data      [8]byte // profile_id big-endian + IPv4 network address
}

// CIDRv6Entry is one allowed IPv6 egress CIDR, scoped to a profile.
type CIDRv6Entry struct {
	PrefixLen uint32   // 32 (profile) + mask bits
	Data      [20]byte // profile_id big-endian + IPv6 network address
}

// ExecPinEntry is one hash-pinned exec binary, scoped to a profile (issue #255,
// stitched with #225). The key packs the profile id and the SHA-256 so the same
// digest may be pinned differently per profile; the value carries the pinned
// path's FNV hash so the kernel bprm hook (delivered by #225) can confirm the
// digest was pinned *for the path being executed*, not merely present.
type ExecPinEntry struct {
	Key    ExecPinKey // {profile_id, sha256}
	PathFN uint32     // fnv32a(normalised path) — path identity for the pin
	Path   string     // normalised absolute path, retained for logging/tests
}

// ExecPinKey is the sandbox_exec_pins map key: a profile id followed by the
// 32-byte binary digest. Fixed-layout so it maps 1:1 onto the C struct.
type ExecPinKey struct {
	ProfileID uint32
	Sha256    [32]byte
}

// compiledProfile is the encoded form of one AISandboxProfile.
type compiledProfile struct {
	id       uint32
	name     string
	flags    uint8
	paths    []PathEntry
	cidrv4   []CIDRv4Entry
	cidrv6   []CIDRv6Entry
	ports    []uint16
	execPins []ExecPinEntry
	// pinnedPaths is the set of exec paths that carry at least one hash pin, by
	// fnv32a(path). An exec of a pinned path is allowed only when the running
	// binary's digest matches one of its pins (identity), even though the path is
	// covered by an allowed_exec prefix.
	pinnedPaths map[uint32]struct{}
	// lookup caches buildPathLookup(paths)'s result. paths is only ever
	// appended to during Compile(), so this is built once it settles rather
	// than rebuilt on every PathAllowed/ExecAllowed call.
	lookup map[uint32]uint8
}

// Policy is the fully compiled ai_sandbox configuration: a stable name→id
// assignment plus the encoded BPF map rows for every profile. Building a Policy
// never touches the kernel, so it is safe to construct and test anywhere.
type Policy struct {
	Mode           uint8
	byName         map[string]*compiledProfile
	profiles       []*compiledProfile
	defaultProfile string
}

// Compile translates the ai_sandbox config into map-ready rows. Profile IDs are
// assigned 1..N in declaration order (0 is reserved for "not sandboxed").
func Compile(cfg config.AISandboxConfig) (*Policy, error) {
	mode := ModeAudit
	if cfg.Mode == "enforce" {
		mode = ModeEnforce
	}
	p := &Policy{
		Mode:           mode,
		byName:         make(map[string]*compiledProfile, len(cfg.Profiles)),
		defaultProfile: cfg.Selector.DefaultProfile,
	}
	for i, prof := range cfg.Profiles {
		id := uint32(i + 1)
		cp := &compiledProfile{id: id, name: prof.Name}

		for _, pfx := range prof.AllowedExec {
			cp.addPath(pfx, accessExec|accessRead)
		}
		for _, pfx := range prof.AllowedReadPaths {
			cp.addPath(pfx, accessRead)
		}
		for _, pfx := range prof.AllowedWritePaths {
			cp.addPath(pfx, accessWrite)
		}
		// Denied paths win over any allow: OR the deny bit onto the same key.
		// The operator's explicit denies come first, then an always-on baseline
		// (item 7 / #259) protecting ebpf-guard's own files and the kernel
		// tamper surfaces, so a sandboxed agent can't weaken its own enforcer
		// even when a profile forgets to list them.
		for _, pfx := range prof.DeniedPaths {
			cp.addPath(pfx, accessDeny)
		}
		for _, pfx := range baselineDeniedPaths(cfg) {
			cp.addPath(pfx, accessDeny)
		}

		for _, c := range prof.AllowedEgressCIDRs {
			if err := cp.addCIDR(c); err != nil {
				return nil, fmt.Errorf("profile %q: %w", prof.Name, err)
			}
		}
		if len(prof.AllowedEgressPorts) > 0 {
			cp.flags |= flagPortsFilter
			cp.ports = append(cp.ports, prof.AllowedEgressPorts...)
		}

		for _, pin := range prof.AllowedExecPins {
			if err := cp.addExecPin(pin.Path, pin.Sha256); err != nil {
				return nil, fmt.Errorf("profile %q: %w", prof.Name, err)
			}
		}

		cp.lookup = buildPathLookup(cp.paths)
		p.byName[prof.Name] = cp
		p.profiles = append(p.profiles, cp)
	}
	return p, nil
}

// baselineDeniedPathPrefixes are the well-known locations of ebpf-guard's own
// state and the kernel interfaces that back enforcement. A sandboxed agent that
// could write these could rewrite its own rules/config or unpin the LSM
// maps/links and defeat the sandbox, so they are denied for every profile
// regardless of what the profile allows (item 7 / issue #259). Only absolute
// prefixes take effect; relative/dev entries are ignored by normalizePrefix.
//
// The installed-binary entries are a fallback for when the running
// executable's own path cannot be resolved (see selfExecutablePath); normally
// baselineDeniedPaths derives the actual deployed path instead, so a
// non-standard install location (/opt/..., ~/go/bin, a container path) is
// still protected (issue #271).
var baselineDeniedPathPrefixes = []string{
	"/etc/ebpf-guard",           // config + rules (hot-reloaded via fsnotify)
	"/var/lib/ebpf-guard",       // alert store / persistent state
	"/run/ebpf-guard",           // control socket
	"/var/run/ebpf-guard",       // control socket (legacy path)
	"/usr/local/bin/ebpf-guard", // installed binary (common default)
	"/usr/bin/ebpf-guard",       // installed binary (distro path)
	"/sys/fs/bpf",               // pinned BPF maps/links
	"/sys/kernel/security",      // securityfs — LSM state
}

// selfExecutablePath resolves the path of the running ebpf-guard binary
// itself, following symlinks, so baselineDeniedPaths can protect wherever it
// actually lives rather than guessing common install locations. It is a
// package var so tests can stub it. Returns "" when the executable path
// cannot be resolved.
var selfExecutablePath = func() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return exe
	}
	return resolved
}

// baselineDeniedPaths returns the baseline deny prefixes plus the directory of
// the configured rules_path, so a non-standard rules location is protected too,
// plus the actual path of the running binary (whatever the install location —
// /opt/..., ~/go/bin, a container path — not just the two hardcoded guesses in
// baselineDeniedPathPrefixes).
func baselineDeniedPaths(cfg config.AISandboxConfig) []string {
	out := make([]string, 0, len(baselineDeniedPathPrefixes)+2)
	out = append(out, baselineDeniedPathPrefixes...)
	if rp := strings.TrimSpace(cfg.RulesPath); rp != "" {
		if dir := path.Dir(rp); dir != "" && dir != "." {
			out = append(out, dir)
		}
	}
	if self := selfExecutablePath(); self != "" {
		out = append(out, self)
	}
	return out
}

// normalizePrefix canonicalises a configured path prefix to the exact string
// the BPF FNV walk keys on: absolute, cleaned, and without a trailing slash
// (except root). Empty / relative inputs return "" and are skipped by callers.
func normalizePrefix(s string) string {
	if s == "" || !strings.HasPrefix(s, "/") {
		return ""
	}
	c := path.Clean(s)
	return c
}

func (cp *compiledProfile) addPath(prefix string, access uint8) {
	norm := normalizePrefix(prefix)
	if norm == "" {
		return
	}
	key := (uint64(cp.id) << 32) | uint64(fnv32a(norm))
	// Merge access bits when the same prefix appears for multiple dimensions.
	for i := range cp.paths {
		if cp.paths[i].Key == key {
			cp.paths[i].Access |= access
			return
		}
	}
	cp.paths = append(cp.paths, PathEntry{Key: key, Access: access, Prefix: norm})
}

func (cp *compiledProfile) addCIDR(cidr string) error {
	addr, err := util.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	if addr.IsIPv6 {
		var e CIDRv6Entry
		e.PrefixLen = 32 + uint32(addr.PrefixLen) // #nosec G115 -- addr.PrefixLen is util.ParseCIDR-validated, bounded to 0..128
		binary.BigEndian.PutUint32(e.Data[0:4], cp.id)
		copy(e.Data[4:20], addr.IPv6[:])
		cp.cidrv6 = append(cp.cidrv6, e)
		return nil
	}
	var e CIDRv4Entry
	e.PrefixLen = 32 + uint32(addr.PrefixLen) // #nosec G115 -- addr.PrefixLen is util.ParseCIDR-validated, bounded to 0..32
	binary.BigEndian.PutUint32(e.Data[0:4], cp.id)
	copy(e.Data[4:8], addr.IPv4[:])
	cp.cidrv4 = append(cp.cidrv4, e)
	return nil
}

// addExecPin records a hash-pinned exec entry. The path is normalised the same
// way allowed_exec prefixes are; a bad path or malformed digest is a compile
// error so the operator sees it at startup rather than silently losing the pin.
func (cp *compiledProfile) addExecPin(execPath, sha256hex string) error {
	norm := normalizePrefix(execPath)
	if norm == "" {
		return fmt.Errorf("exec pin path must be absolute, got %q", execPath)
	}
	digest, err := decodeSHA256(sha256hex)
	if err != nil {
		return fmt.Errorf("exec pin %q: %w", execPath, err)
	}
	pathFN := fnv32a(norm)
	cp.execPins = append(cp.execPins, ExecPinEntry{
		Key:    ExecPinKey{ProfileID: cp.id, Sha256: digest},
		PathFN: pathFN,
		Path:   norm,
	})
	if cp.pinnedPaths == nil {
		cp.pinnedPaths = make(map[uint32]struct{})
	}
	cp.pinnedPaths[pathFN] = struct{}{}
	return nil
}

// decodeSHA256 parses a 64-char hex SHA-256 into raw bytes.
func decodeSHA256(s string) ([32]byte, error) {
	var out [32]byte
	if len(s) != 64 {
		return out, fmt.Errorf("sha256 must be 64 hex chars, got %d", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("sha256 not valid hex: %w", err)
	}
	copy(out[:], b)
	return out, nil
}

// hostCIDRv4 builds a single-host (/32) egress LPM entry pinning ip to a
// profile, matching addCIDR's encoding. Returns ok=false when ip is not IPv4.
func hostCIDRv4(profileID uint32, ip net.IP) (CIDRv4Entry, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return CIDRv4Entry{}, false
	}
	var e CIDRv4Entry
	e.PrefixLen = 32 + 32 // full profile id + full IPv4 host
	binary.BigEndian.PutUint32(e.Data[0:4], profileID)
	copy(e.Data[4:8], v4)
	return e, true
}

// hostCIDRv6 builds a single-host (/128) egress LPM entry pinning ip to a
// profile. Returns ok=false when ip is not representable as IPv6.
func hostCIDRv6(profileID uint32, ip net.IP) (CIDRv6Entry, bool) {
	// An IPv4 address must be pinned as v4, not as a v4-mapped v6, so the
	// socket_connect hook (which keys v4 and v6 separately) can find it.
	if ip.To4() != nil {
		return CIDRv6Entry{}, false
	}
	v6 := ip.To16()
	if v6 == nil {
		return CIDRv6Entry{}, false
	}
	var e CIDRv6Entry
	e.PrefixLen = 32 + 128
	binary.BigEndian.PutUint32(e.Data[0:4], profileID)
	copy(e.Data[4:20], v6)
	return e, true
}

// portKey packs a profile id and destination port the way the socket_connect
// hook looks it up: profile_id<<16 | port.
func portKey(profileID uint32, port uint16) uint64 {
	return (uint64(profileID) << 16) | uint64(port)
}

// cgroupValue packs the sandbox_cgroups value: profile_id<<32 | flags<<8 | mode.
func cgroupValue(profileID uint32, flags, mode uint8) uint64 {
	return (uint64(profileID) << 32) | (uint64(flags) << 8) | uint64(mode)
}

// ProfileID returns the numeric id assigned to a profile name, or (0,false).
func (p *Policy) ProfileID(name string) (uint32, bool) {
	cp, ok := p.byName[name]
	if !ok {
		return 0, false
	}
	return cp.id, true
}

// fnv32a is the FNV-1a 32-bit hash, matching fnv32a()/sandbox_path_allowed()
// in bpf/lsm.bpf.c over the first 128 bytes of the string. Delegates to the
// single shared implementation in internal/util so this and
// internal/collector never diverge from each other or from the kernel
// (issue #271).
func fnv32a(s string) uint32 {
	return util.FNV32aPath(s)
}
