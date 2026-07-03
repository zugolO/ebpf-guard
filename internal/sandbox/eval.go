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
