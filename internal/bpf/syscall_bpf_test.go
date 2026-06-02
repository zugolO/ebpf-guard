package bpf

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func TestParseSyscallEvent(t *testing.T) {
	// Create a valid syscall event
	evt := SyscallEvent{
		Type:      1, // EVENT_TYPE_SYSCALL
		Timestamp: 1234567890,
		PID:       1234,
		TGID:      1234,
		UID:       1000,
		Comm:      [16]byte{'t', 'e', 's', 't'},
		Nr:        1, // sys_write
		Ret:       42,
		Args:      [6]uint64{1, 2, 3, 4, 5, 6},
	}

	// Serialize to bytes
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, evt)
	require.NoError(t, err)

	// Parse back
	parsed, err := ParseSyscallEvent(buf.Bytes())
	require.NoError(t, err)

	assert.Equal(t, evt.Type, parsed.Type)
	assert.Equal(t, evt.Timestamp, parsed.Timestamp)
	assert.Equal(t, evt.PID, parsed.PID)
	assert.Equal(t, evt.Nr, parsed.Nr)
	assert.Equal(t, evt.Ret, parsed.Ret)
}

func TestParseSyscallEvent_TooSmall(t *testing.T) {
	_, err := ParseSyscallEvent([]byte{0x01, 0x02})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too small")
}

func TestSyscallEvent_ToTypesEvent(t *testing.T) {
	evt := &SyscallEvent{
		Type:      1,
		Timestamp: 1234567890,
		PID:       1234,
		TGID:      1234,
		UID:       1000,
		Comm:      [16]byte{'t', 'e', 's', 't'},
		Nr:        1,
		Ret:       42,
		Args:      [6]uint64{1, 2, 3, 4, 5, 6},
	}

	result := evt.ToTypesEvent()

	assert.Equal(t, types.EventSyscall, result.Type)
	assert.Equal(t, evt.Timestamp, result.Timestamp)
	assert.Equal(t, evt.PID, result.PID)
	assert.NotNil(t, result.Syscall)
	assert.Equal(t, evt.Nr, result.Syscall.Nr)
	assert.Equal(t, evt.Ret, result.Syscall.Ret)
}

func TestParseNetworkEvent(t *testing.T) {
	evt := NetworkEvent{
		Type:      2, // EVENT_TYPE_TCP_CONNECT
		Timestamp: 1234567890,
		PID:       1234,
		TGID:      1234,
		UID:       1000,
		Comm:      [16]byte{'t', 'e', 's', 't'},
		Saddr:     [16]byte{192, 168, 1, 1},
		Daddr:     [16]byte{8, 8, 8, 8},
		Sport:     12345,
		Dport:     443,
		Proto:     6,  // TCP
		Family:    2,  // AF_INET
	}

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, evt)
	require.NoError(t, err)

	parsed, err := ParseNetworkEvent(buf.Bytes())
	require.NoError(t, err)

	assert.Equal(t, evt.Type, parsed.Type)
	assert.Equal(t, evt.Saddr, parsed.Saddr)
	assert.Equal(t, evt.Dport, parsed.Dport)
}

func TestNetworkEvent_ToTypesEvent(t *testing.T) {
	evt := &NetworkEvent{
		Type:   2,
		Saddr:  [16]byte{192, 168, 1, 1},
		Daddr:  [16]byte{8, 8, 8, 8},
		Sport:  12345,
		Dport:  443,
		Proto:  6,
		Family: 2, // AF_INET
	}

	result := evt.ToTypesEvent()

	assert.Equal(t, types.EventTCPConnect, result.Type)
	assert.NotNil(t, result.Network)
	assert.Equal(t, evt.Saddr, result.Network.Saddr)
	assert.Equal(t, evt.Dport, result.Network.Dport)
}

func TestParseFileaccessEvent(t *testing.T) {
	evt := FileaccessEvent{
		Type:     3, // EVENT_TYPE_FILE_ACCESS
		PID:      1234,
		Filename: [256]byte{'/', 'e', 't', 'c', '/', 'p', 'a', 's', 's', 'w', 'd'},
		Flags:    0,
		Mode:     0644,
		Op:       0, // open
	}

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, evt)
	require.NoError(t, err)

	parsed, err := ParseFileaccessEvent(buf.Bytes())
	require.NoError(t, err)

	assert.Equal(t, evt.Type, parsed.Type)
	assert.Equal(t, evt.Filename, parsed.Filename)
	assert.Equal(t, evt.Op, parsed.Op)
}

func TestFileaccessEvent_ToTypesEvent(t *testing.T) {
	evt := &FileaccessEvent{
		Type:     3,
		Filename: [256]byte{'/', 't', 'm', 'p', '/', 't', 'e', 's', 't'},
		Flags:    0,
		Mode:     0644,
		Op:       0,
	}

	result := evt.ToTypesEvent()

	assert.Equal(t, types.EventFileAccess, result.Type)
	assert.NotNil(t, result.File)
	assert.Equal(t, evt.Filename, result.File.Filename)
	assert.Equal(t, evt.Mode, result.File.Mode)
}
