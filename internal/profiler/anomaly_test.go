// Package profiler provides behavioral profiling and anomaly detection for processes.
package profiler

import (
	"testing"

	"github.com/zugolO/ebpf-guard/internal/util"
	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestFormatPort(t *testing.T) {
	tests := []struct {
		name     string
		port     uint16
		expected string
	}{
		{
			name:     "well known port 80",
			port:     80,
			expected: "80",
		},
		{
			name:     "well known port 443",
			port:     443,
			expected: "443",
		},
		{
			name:     "port 0",
			port:     0,
			expected: "0",
		},
		{
			name:     "max port 65535",
			port:     65535,
			expected: "65535",
		},
		{
			name:     "high port 8080",
			port:     8080,
			expected: "8080",
		},
		{
			name:     "ephemeral port 49152",
			port:     49152,
			expected: "49152",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatPort(tt.port)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatSyscall(t *testing.T) {
	tests := []struct {
		name     string
		nr       int64
		expected string
	}{
		{
			name:     "syscall 0 (read)",
			nr:       0,
			expected: "syscall_0",
		},
		{
			name:     "syscall 1 (write)",
			nr:       1,
			expected: "syscall_1",
		},
		{
			name:     "syscall 59 (execve)",
			nr:       59,
			expected: "syscall_59",
		},
		{
			name:     "large syscall number 300",
			nr:       300,
			expected: "syscall_300",
		},
		{
			name:     "very large syscall number 450",
			nr:       450,
			expected: "syscall_450",
		},
		{
			name:     "negative syscall number",
			nr:       -1,
			expected: "syscall_-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatSyscall(tt.nr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatIP(t *testing.T) {
	tests := []struct {
		name     string
		addr     [16]byte
		family   types.AddressFamily
		expected string
	}{
		{
			name:     "localhost",
			addr:     [16]byte{127, 0, 0, 1},
			family:   types.AFInet,
			expected: "127.0.0.1",
		},
		{
			name:     "private network 192.168.1.1",
			addr:     [16]byte{192, 168, 1, 1},
			family:   types.AFInet,
			expected: "192.168.1.1",
		},
		{
			name:     "private network 10.0.0.1",
			addr:     [16]byte{10, 0, 0, 1},
			family:   types.AFInet,
			expected: "10.0.0.1",
		},
		{
			name:     "private network 172.16.0.1",
			addr:     [16]byte{172, 16, 0, 1},
			family:   types.AFInet,
			expected: "172.16.0.1",
		},
		{
			name:     "public IP 8.8.8.8",
			addr:     [16]byte{8, 8, 8, 8},
			family:   types.AFInet,
			expected: "8.8.8.8",
		},
		{
			name:     "broadcast",
			addr:     [16]byte{255, 255, 255, 255},
			family:   types.AFInet,
			expected: "255.255.255.255",
		},
		{
			name:     "zero address",
			addr:     [16]byte{0, 0, 0, 0},
			family:   types.AFInet,
			expected: "0.0.0.0",
		},
		{
			name:     "IPv6 localhost",
			addr:     [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			family:   types.AFInet6,
			expected: "::1",
		},
		{
			name:     "IPv6 address",
			addr:     [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			family:   types.AFInet6,
			expected: "2001:db8::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := util.FormatIP16(tt.addr, tt.family)
			assert.Equal(t, tt.expected, result)
		})
	}
}
