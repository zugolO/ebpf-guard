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
	"fmt"
	"net"
	"path"
	"strings"

	"github.com/zugolO/ebpf-guard/internal/config"
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

// compiledProfile is the encoded form of one AISandboxProfile.
type compiledProfile struct {
	id     uint32
	name   string
	flags  uint8
	paths  []PathEntry
	cidrv4 []CIDRv4Entry
	cidrv6 []CIDRv6Entry
	ports  []uint16
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
		for _, pfx := range prof.DeniedPaths {
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

		p.byName[prof.Name] = cp
		p.profiles = append(p.profiles, cp)
	}
	return p, nil
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
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	ones, _ := ipnet.Mask.Size()
	if v4 := ipnet.IP.To4(); v4 != nil {
		var e CIDRv4Entry
		e.PrefixLen = 32 + uint32(ones)
		binary.BigEndian.PutUint32(e.Data[0:4], cp.id)
		copy(e.Data[4:8], v4)
		cp.cidrv4 = append(cp.cidrv4, e)
		return nil
	}
	v6 := ipnet.IP.To16()
	if v6 == nil {
		return fmt.Errorf("unrecognised IP in CIDR %q", cidr)
	}
	var e CIDRv6Entry
	e.PrefixLen = 32 + uint32(ones)
	binary.BigEndian.PutUint32(e.Data[0:4], cp.id)
	copy(e.Data[4:20], v6)
	cp.cidrv6 = append(cp.cidrv6, e)
	return nil
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
// in bpf/lsm.bpf.c over the first 128 bytes of the string.
func fnv32a(s string) uint32 {
	const offset = 2166136261
	const prime = 16777619
	h := uint32(offset)
	for i := 0; i < len(s) && i < 128; i++ {
		h ^= uint32(s[i])
		h *= prime
	}
	return h
}
