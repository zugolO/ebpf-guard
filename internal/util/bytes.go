// Package util provides shared low-level helpers used across internal packages.
package util

import (
	"net"

	"github.com/ebpf-guard/ebpf-guard/pkg/types"
)

// BytesToString converts a byte slice to a string, stopping at the first null byte.
func BytesToString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// FormatIP formats a byte slice as an IP address string based on address family.
// For IPv4, only the first 4 bytes are used; for IPv6, all 16 bytes.
// Returns "<invalid>" if the slice is too short for the address family.
func FormatIP(addr []byte, family types.AddressFamily) string {
	if family == types.AFInet6 {
		return net.IP(addr).String()
	}
	if len(addr) < 4 {
		return "<invalid>"
	}
	return net.IP(addr[:4]).String()
}

// FormatIP16 formats a fixed 16-byte array as an IP address string based on address family.
// For IPv4, only the first 4 bytes are used; for IPv6, all 16 bytes.
func FormatIP16(addr [16]byte, family types.AddressFamily) string {
	if family == types.AFInet6 {
		return net.IP(addr[:]).String()
	}
	return net.IP(addr[:4]).String()
}
