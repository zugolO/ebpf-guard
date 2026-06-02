package util

import (
	"testing"

	"github.com/ebpf-guard/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestBytesToString(t *testing.T) {
	tests := []struct {
		input    []byte
		expected string
	}{
		{[]byte("hello\x00world"), "hello"},
		{[]byte("no-null"), "no-null"},
		{[]byte{}, ""},
		{[]byte{0, 'a'}, ""},
		{[]byte("abc"), "abc"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, BytesToString(tt.input))
	}
}

func TestFormatIP(t *testing.T) {
	tests := []struct {
		addr     []byte
		family   types.AddressFamily
		expected string
	}{
		{[]byte{192, 168, 1, 1}, types.AFInet, "192.168.1.1"},
		{[]byte{10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, types.AFInet, "10.0.0.1"},
		{[]byte{1}, types.AFInet, "<invalid>"},
		{nil, types.AFInet, "<invalid>"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, FormatIP(tt.addr, tt.family))
	}
}

func TestFormatIP16(t *testing.T) {
	var v4 [16]byte
	v4[0], v4[1], v4[2], v4[3] = 192, 168, 1, 100
	assert.Equal(t, "192.168.1.100", FormatIP16(v4, types.AFInet))
}
