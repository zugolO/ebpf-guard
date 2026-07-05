package util

import (
	"fmt"
	"net"
)

// CIDRAddress is the validated, address-family-resolved result of parsing a
// CIDR string: either a 4-byte IPv4 network address or a 16-byte IPv6 network
// address, plus the prefix length within that resolved family (0..32 for
// IPv4, 0..128 for IPv6).
type CIDRAddress struct {
	IPv4      [4]byte
	IPv6      [16]byte
	IsIPv6    bool
	PrefixLen int
}

// ParseCIDR parses cidr (e.g. "10.0.0.0/8", "2001:db8::/32") into its network
// address, address family, and a validated in-family prefix length.
//
// This is the single address-family/validation core shared by
// bpf.parseSubnetKeys (net_block_ipv4/net_block_ipv6 LPM_TRIE keys) and
// sandbox.compiledProfile.addCIDR (sandbox egress CIDR LPM_TRIE keys) — both
// build a family-specific LPM key from the same CIDR syntax for the same
// LSM/XDP LPM_TRIE use case. Before this, the sandbox side reimplemented the
// parse without the prefix-length range check the bpf side had, so a
// malformed mask could silently build a wrong key instead of failing at
// profile-compile time (issue #271).
func ParseCIDR(cidr string) (CIDRAddress, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return CIDRAddress{}, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	ones, bits := ipnet.Mask.Size()
	switch bits {
	case 32:
		if ones < 0 || ones > 32 {
			return CIDRAddress{}, fmt.Errorf("CIDR %q: prefix length %d out of range for IPv4", cidr, ones)
		}
		v4 := ipnet.IP.To4()
		if v4 == nil {
			return CIDRAddress{}, fmt.Errorf("CIDR %q: failed to convert to IPv4", cidr)
		}
		var out CIDRAddress
		out.PrefixLen = ones
		copy(out.IPv4[:], v4)
		return out, nil
	case 128:
		if ones < 0 || ones > 128 {
			return CIDRAddress{}, fmt.Errorf("CIDR %q: prefix length %d out of range for IPv6", cidr, ones)
		}
		v6 := ipnet.IP.To16()
		if v6 == nil {
			return CIDRAddress{}, fmt.Errorf("CIDR %q: failed to convert to IPv6", cidr)
		}
		var out CIDRAddress
		out.IsIPv6 = true
		out.PrefixLen = ones
		copy(out.IPv6[:], v6)
		return out, nil
	default:
		return CIDRAddress{}, fmt.Errorf("CIDR %q: unsupported address family (bits=%d)", cidr, bits)
	}
}
