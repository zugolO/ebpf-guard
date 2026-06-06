// Package util provides shared low-level helpers used across internal packages.
package util

import (
	"net"
	"unsafe"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// BytesToString converts a byte slice to a string, stopping at the first null byte.
// The returned string is heap-allocated and owns its data — safe to store as map
// keys or in any data structure that outlives the source slice.
func BytesToString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// UnsafeBytesToString converts a byte slice to a string without copying.
// The returned string shares the underlying memory of b and is therefore only
// safe for transient use (comparison, map lookup, printing) within the lifetime
// of b.  Never store the result as a map key, struct field, or goroutine-captured
// value — use BytesToString instead for those cases.
func UnsafeBytesToString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			if i == 0 {
				return ""
			}
			return unsafe.String(unsafe.SliceData(b), i)
		}
	}
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
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
