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
	// ToTypesEvent converts the kernel monotonic clock to a wall-clock epoch,
	// so the raw ktime does not survive unchanged. On Linux the boot offset is
	// non-zero and asserting identity fails; on hosts without /proc/uptime the
	// offset is 0, which is why this passed on non-Linux dev machines only.
	assert.Equal(t, types.KtimeToEpoch(evt.Timestamp), result.Timestamp)
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
		Type:        3, // EVENT_TYPE_FILE_ACCESS
		PID:         1234,
		TGID:        1234,
		PPID:        100,
		UID:         1000,
		Comm:        [16]byte{'t', 'e', 's', 't'},
		ParentComm:  [16]byte{'b', 'a', 's', 'h'},
		Filename:    [256]byte{'/', 'e', 't', 'c', '/', 'p', 'a', 's', 's', 'w', 'd'},
		Flags:       0,
		Mode:        0644,
		Op:          0, // open
		FDTruncated: 0,
	}

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, evt)
	require.NoError(t, err)

	parsed, err := ParseFileaccessEvent(buf.Bytes())
	require.NoError(t, err)

	assert.Equal(t, evt.Type, parsed.Type)
	assert.Equal(t, evt.PPID, parsed.PPID)
	assert.Equal(t, evt.ParentComm, parsed.ParentComm)
	assert.Equal(t, evt.Filename, parsed.Filename)
	assert.Equal(t, evt.Op, parsed.Op)
	assert.Equal(t, evt.FDTruncated, parsed.FDTruncated)
}

func TestParseFileaccessEvent_FDTruncated(t *testing.T) {
	evt := FileaccessEvent{
		Type:        3,
		PID:         42,
		Filename:    [256]byte{'/', 'v', 'e', 'r', 'y', '/', 'l', 'o', 'n', 'g'},
		Op:          2, // write
		FDTruncated: 1, // truncated
	}

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, evt)
	require.NoError(t, err)

	parsed, err := ParseFileaccessEvent(buf.Bytes())
	require.NoError(t, err)
	assert.Equal(t, uint8(1), parsed.FDTruncated)
}

func TestFileaccessEvent_ToTypesEvent(t *testing.T) {
	var fname [256]byte
	copy(fname[:], "/tmp/test")

	evt := &FileaccessEvent{
		Type:        3,
		PID:         1234,
		TGID:        1234,
		PPID:        100,
		Comm:        [16]byte{'t', 'e', 's', 't'},
		ParentComm:  [16]byte{'b', 'a', 's', 'h'},
		Filename:    fname,
		Flags:       0,
		Mode:        0644,
		Op:          0,
		FDTruncated: 0,
	}

	result := evt.ToTypesEvent()

	assert.Equal(t, types.EventFileAccess, result.Type)
	assert.Equal(t, uint32(100), result.PPID)
	assert.NotNil(t, result.File)
	assert.Equal(t, evt.Filename, result.File.Filename)
	assert.Equal(t, evt.Mode, result.File.Mode)
	assert.Equal(t, "/tmp/test", result.File.FDPath)
	assert.False(t, result.File.FDPathTruncated)
}

func TestFileaccessEvent_ToTypesEvent_Truncated(t *testing.T) {
	var fname [256]byte
	for i := range fname {
		fname[i] = 'a' // fill completely — simulates a truncated path
	}

	evt := &FileaccessEvent{
		Type:        3,
		Filename:    fname,
		Op:          1,
		FDTruncated: 1,
	}

	result := evt.ToTypesEvent()

	require.NotNil(t, result.File)
	assert.True(t, result.File.FDPathTruncated)
	// FDPath should be the full 256-byte string (no NUL terminator since the
	// buffer is filled, nullTerminatedString returns the whole slice).
	assert.Equal(t, string(fname[:]), result.File.FDPath)
}

func TestNullTerminatedString(t *testing.T) {
	tests := []struct {
		input []byte
		want  string
	}{
		{[]byte("hello\x00world"), "hello"},
		{[]byte("noterm"), "noterm"},
		{[]byte("\x00"), ""},
		{[]byte{}, ""},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, nullTerminatedString(tc.input))
	}
}

// TestParseSyscallEvent_WireOffsets pins the parser to the C struct's real
// layout instead of to the Go struct's.
//
// The pre-existing TestParseSyscallEvent above round-trips a SyscallEvent
// through binary.Write and parses it back — which validates the parser against
// itself and passed for as long as the parser was wrong. This test builds the
// record byte by byte at the offsets `offsetof()` reports on the compiled
// `struct event` (packed: type 0, ts 4, pid 12, tgid 16, ppid 20, uid 24,
// comm 28, parent_comm 44, nr 60, ret 68, args 76) and is the only reason a
// future field insertion in bpf/common.h cannot silently shift the syscall
// stream again.
func TestParseSyscallEvent_WireOffsets(t *testing.T) {
	const recordSize = 124
	raw := make([]byte, recordSize)

	binary.LittleEndian.PutUint32(raw[0:], 1)          // type = EVENT_TYPE_SYSCALL
	binary.LittleEndian.PutUint64(raw[4:], 0xDEADBEEF) // timestamp
	binary.LittleEndian.PutUint32(raw[12:], 4242)      // pid
	binary.LittleEndian.PutUint32(raw[16:], 4242)      // tgid
	binary.LittleEndian.PutUint32(raw[20:], 1)         // ppid
	binary.LittleEndian.PutUint32(raw[24:], 0)         // uid = 0 (root: the case that read as an empty comm)
	copy(raw[28:44], "sshd")                           // comm
	copy(raw[44:60], "systemd")                        // parent_comm
	binary.LittleEndian.PutUint64(raw[60:], 59)        // nr = execve
	binary.LittleEndian.PutUint64(raw[68:], 0)         // ret
	binary.LittleEndian.PutUint64(raw[76:], 0xAABB)    // args[0]

	var out SyscallEvent
	require.NoError(t, ParseSyscallEventInto(raw, &out))

	assert.Equal(t, uint32(1), out.Type)
	assert.Equal(t, uint32(4242), out.PID)
	assert.Equal(t, uint32(1), out.PPID, "ppid sits between tgid and uid and must be read, not skipped")
	assert.Equal(t, uint32(0), out.UID)
	assert.Equal(t, "sshd", string(bytes.TrimRight(out.Comm[:], "\x00")),
		"comm starts at offset 28; reading it at 24 yields four NUL bytes for every uid=0 process — finding #40")
	assert.Equal(t, "systemd", string(bytes.TrimRight(out.ParentComm[:], "\x00")))
	assert.Equal(t, int64(59), out.Nr,
		"nr is the first union member at offset 60; reading it at 40 yields comm/parent_comm bytes, never a syscall number")
	assert.Equal(t, uint64(0xAABB), out.Args[0])

	// The conversion must carry the parent forward: the correlator's lineage
	// tracker and the observer-tree walk both key off e.PPID, and a syscall
	// event that always reported ppid=0 gave them nothing to walk.
	ev := out.ToTypesEvent()
	assert.Equal(t, uint32(1), ev.PPID)
	assert.Equal(t, "sshd", string(bytes.TrimRight(ev.Comm[:], "\x00")))
}

// A record shorter than the full syscall payload must be rejected, not parsed
// from whatever bytes happen to be there.
func TestParseSyscallEvent_RejectsShortRecord(t *testing.T) {
	var out SyscallEvent
	err := ParseSyscallEventInto(make([]byte, 123), &out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "124")
}
