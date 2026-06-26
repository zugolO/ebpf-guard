package bpf

// Wire-format regression tests for the raw ring-buffer parsers that previously
// had no direct coverage: ParsePrivescEvent, ParseIOUringEvent,
// ParseBpfMonitorEvent, ParseKmodEvent, ParseCgroupEscapeEvent and
// ParseTlsClientHelloEvent.
//
// Each test writes field values at their exact packed byte offsets (mirroring
// the layout comments in events.go) rather than serializing a Go struct, so any
// future drift in a parser's offset arithmetic surfaces as a failing canary.

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// putComm copies s into a fresh 16-byte comm field at raw[off:off+16].
func putComm(raw []byte, off int, s string) {
	copy(raw[off:off+16], s)
}

// --- ParsePrivescEvent -----------------------------------------------------
//
// Layout: type(4) ts(8) pid(4) tgid(4) ppid(4) uid(4) comm(16) parent_comm(16)
//         nr(8) ret(8) old_caps(8) new_caps(8) = 92 bytes.

func TestParsePrivescEvent_Wire(t *testing.T) {
	raw := make([]byte, 92)
	binary.LittleEndian.PutUint32(raw[0:], 6) // type: EVENT_TYPE_PRIVESC
	binary.LittleEndian.PutUint64(raw[4:], 42)
	binary.LittleEndian.PutUint32(raw[12:], 1234) // pid
	binary.LittleEndian.PutUint32(raw[16:], 1234) // tgid
	binary.LittleEndian.PutUint32(raw[20:], 1)    // ppid
	binary.LittleEndian.PutUint32(raw[24:], 1000) // uid
	putComm(raw, 28, "sudo")
	putComm(raw, 44, "bash")
	// nr@60, ret@68 are skipped by the parser.
	binary.LittleEndian.PutUint64(raw[76:], 0x00000000000003ff) // old_caps
	binary.LittleEndian.PutUint64(raw[84:], 0x000001ffffffffff) // new_caps

	evt, err := ParsePrivescEvent(raw)
	require.NoError(t, err)
	assert.Equal(t, uint32(1234), evt.PID)
	assert.Equal(t, uint32(1), evt.PPID)
	assert.Equal(t, uint32(1000), evt.UID)
	var wantComm [16]byte
	copy(wantComm[:], "sudo")
	assert.Equal(t, wantComm, evt.Comm)
	assert.Equal(t, uint64(0x00000000000003ff), evt.OldCaps)
	assert.Equal(t, uint64(0x000001ffffffffff), evt.NewCaps)
}

func TestParsePrivescEvent_TooSmall(t *testing.T) {
	_, err := ParsePrivescEvent(make([]byte, 91))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too small")
}

// --- ParseIOUringEvent -----------------------------------------------------
//
// Layout: type(4) ts(8) pid(4) tgid(4) ppid(4) uid(4) comm(16) parent_comm(16)
//         op(1) flags(4) fd(4) to_submit(4) = 73 bytes.

func TestParseIOUringEvent_Wire(t *testing.T) {
	raw := make([]byte, 73)
	binary.LittleEndian.PutUint32(raw[0:], 0) // type unused by parser
	binary.LittleEndian.PutUint64(raw[4:], 99)
	binary.LittleEndian.PutUint32(raw[12:], 4242) // pid
	binary.LittleEndian.PutUint32(raw[16:], 4242) // tgid
	binary.LittleEndian.PutUint32(raw[20:], 7)    // ppid
	binary.LittleEndian.PutUint32(raw[24:], 0)    // uid
	putComm(raw, 28, "io_worker")
	putComm(raw, 44, "containerd")
	fd := int32(-9)
	raw[60] = 18                                        // op (IORING_OP_*)
	binary.LittleEndian.PutUint32(raw[61:], 0x0000000a) // flags
	binary.LittleEndian.PutUint32(raw[65:], uint32(fd)) // fd (negative)
	binary.LittleEndian.PutUint32(raw[69:], 16)         // to_submit

	evt, err := ParseIOUringEvent(raw)
	require.NoError(t, err)
	assert.Equal(t, uint32(4242), evt.PID)
	assert.Equal(t, uint32(7), evt.PPID)
	assert.Equal(t, uint8(18), evt.Op)
	assert.Equal(t, uint32(0x0000000a), evt.Flags)
	assert.Equal(t, int32(-9), evt.Fd)
	assert.Equal(t, uint32(16), evt.ToSubmit)
}

func TestParseIOUringEvent_TooSmall(t *testing.T) {
	_, err := ParseIOUringEvent(make([]byte, 72))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too small")
}

// --- ParseBpfMonitorEvent --------------------------------------------------
//
// Layout: type(4) ts(8) pid(4) tgid(4) ppid(4) uid(4) comm(16) parent_comm(16)
//         cmd(4) prog_type(4) ret(4) = 72 bytes.

func TestParseBpfMonitorEvent_Wire(t *testing.T) {
	raw := make([]byte, 72)
	binary.LittleEndian.PutUint64(raw[4:], 7)
	binary.LittleEndian.PutUint32(raw[12:], 31337) // pid
	binary.LittleEndian.PutUint32(raw[16:], 31337) // tgid
	binary.LittleEndian.PutUint32(raw[20:], 1)     // ppid
	binary.LittleEndian.PutUint32(raw[24:], 0)     // uid
	putComm(raw, 28, "bpftool")
	putComm(raw, 44, "bash")
	ret := int32(-1)
	binary.LittleEndian.PutUint32(raw[60:], 5)           // cmd: BPF_PROG_LOAD
	binary.LittleEndian.PutUint32(raw[64:], 1)           // prog_type: BPF_PROG_TYPE_SOCKET_FILTER
	binary.LittleEndian.PutUint32(raw[68:], uint32(ret)) // ret (EPERM-ish, negative)

	evt, err := ParseBpfMonitorEvent(raw)
	require.NoError(t, err)
	assert.Equal(t, uint32(31337), evt.PID)
	assert.Equal(t, uint32(1), evt.PPID)
	assert.Equal(t, uint32(5), evt.Cmd)
	assert.Equal(t, uint32(1), evt.ProgType)
	assert.Equal(t, int32(-1), evt.Ret)
}

func TestParseBpfMonitorEvent_TooSmall(t *testing.T) {
	_, err := ParseBpfMonitorEvent(make([]byte, 71))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too small")
}

// --- ParseKmodEvent --------------------------------------------------------
//
// Layout (note: uid follows pid directly — no tgid — and ppid follows
// parent_comm): type(4) ts(8) pid(4) uid(4) comm(16) parent_comm(16) ppid(4)
// mod_name(64) from_tmpfs(1) = 121 bytes.

func TestParseKmodEvent_Wire(t *testing.T) {
	raw := make([]byte, 121)
	binary.LittleEndian.PutUint64(raw[4:], 11)
	binary.LittleEndian.PutUint32(raw[12:], 808) // pid
	binary.LittleEndian.PutUint32(raw[16:], 0)   // uid
	putComm(raw, 20, "insmod")
	putComm(raw, 36, "bash")
	binary.LittleEndian.PutUint32(raw[52:], 800) // ppid
	copy(raw[56:120], "evil_rootkit")            // mod_name[64]
	raw[120] = 1                                 // from_tmpfs

	evt, err := ParseKmodEvent(raw)
	require.NoError(t, err)
	assert.Equal(t, uint32(808), evt.PID)
	assert.Equal(t, uint32(800), evt.PPID)
	assert.Equal(t, uint32(0), evt.UID)
	var wantComm [16]byte
	copy(wantComm[:], "insmod")
	assert.Equal(t, wantComm, evt.Comm)
	var wantMod [64]byte
	copy(wantMod[:], "evil_rootkit")
	assert.Equal(t, wantMod, evt.ModName)
	assert.Equal(t, uint8(1), evt.FromTmpfs)
}

func TestParseKmodEvent_TooSmall(t *testing.T) {
	_, err := ParseKmodEvent(make([]byte, 120))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too small")
}

// --- ParseCgroupEscapeEvent ------------------------------------------------
//
// Layout: type(4) ts(8) pid(4) uid(4) comm(16) parent_comm(16) ppid(4)
//         init_cgroup_id(8) new_cgroup_id(8) = 72 bytes.

func TestParseCgroupEscapeEvent_Wire(t *testing.T) {
	raw := make([]byte, 72)
	binary.LittleEndian.PutUint64(raw[4:], 13)
	binary.LittleEndian.PutUint32(raw[12:], 555) // pid
	binary.LittleEndian.PutUint32(raw[16:], 0)   // uid
	putComm(raw, 20, "runc")
	putComm(raw, 36, "containerd")
	binary.LittleEndian.PutUint32(raw[52:], 550)                // ppid
	binary.LittleEndian.PutUint64(raw[56:], 0xdead0000beef0001) // init_cgroup_id
	binary.LittleEndian.PutUint64(raw[64:], 0xdead0000beef0002) // new_cgroup_id

	evt, err := ParseCgroupEscapeEvent(raw)
	require.NoError(t, err)
	assert.Equal(t, uint32(555), evt.PID)
	assert.Equal(t, uint32(550), evt.PPID)
	assert.Equal(t, uint64(0xdead0000beef0001), evt.InitCgroupID)
	assert.Equal(t, uint64(0xdead0000beef0002), evt.NewCgroupID)
}

func TestParseCgroupEscapeEvent_TooSmall(t *testing.T) {
	_, err := ParseCgroupEscapeEvent(make([]byte, 71))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too small")
}

// --- ParseTlsClientHelloEvent ----------------------------------------------
//
// Layout: type(4) ts(8) pid(4) tgid(4) ppid(4) uid(4) comm(16) parent_comm(16)
//         dport(2, BIG-endian) captured_len(2) original_len(4) data(captured_len).

func TestParseTlsClientHelloEvent_Wire(t *testing.T) {
	payload := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0xaa, 0xbb}
	raw := make([]byte, 68+len(payload))
	binary.LittleEndian.PutUint32(raw[0:], 4) // type: EVENT_TYPE_TLS
	binary.LittleEndian.PutUint64(raw[4:], 17)
	binary.LittleEndian.PutUint32(raw[12:], 6001) // pid
	binary.LittleEndian.PutUint32(raw[16:], 6001) // tgid
	binary.LittleEndian.PutUint32(raw[20:], 1)    // ppid
	binary.LittleEndian.PutUint32(raw[24:], 1000) // uid
	putComm(raw, 28, "openssl")
	putComm(raw, 44, "bash")
	binary.BigEndian.PutUint16(raw[60:], 443)                     // dport — network byte order
	binary.LittleEndian.PutUint16(raw[62:], uint16(len(payload))) // captured_len
	binary.LittleEndian.PutUint32(raw[64:], 1500)                 // original_len (full record)
	copy(raw[68:], payload)

	evt, err := ParseTlsClientHelloEvent(raw)
	require.NoError(t, err)
	assert.Equal(t, uint32(6001), evt.PID)
	assert.Equal(t, uint16(443), evt.Dport, "dport must be decoded as big-endian")
	assert.Equal(t, uint16(len(payload)), evt.CapturedLen)
	assert.Equal(t, uint32(1500), evt.OriginalLen)
	assert.Equal(t, payload, evt.Data[:evt.CapturedLen])
}

// TestParseTlsClientHelloEvent_CapturedLenClamped verifies an over-large
// captured_len is clamped to the 512-byte Data buffer without an out-of-range panic.
func TestParseTlsClientHelloEvent_CapturedLenClamped(t *testing.T) {
	raw := make([]byte, 68+512)
	binary.LittleEndian.PutUint16(raw[62:], 9000) // captured_len well over 512
	for i := 68; i < len(raw); i++ {
		raw[i] = 0x7f
	}

	evt, err := ParseTlsClientHelloEvent(raw)
	require.NoError(t, err)
	assert.Equal(t, uint16(512), evt.CapturedLen, "captured_len must be clamped to 512")
	assert.Equal(t, byte(0x7f), evt.Data[511])
}

func TestParseTlsClientHelloEvent_TooSmall(t *testing.T) {
	_, err := ParseTlsClientHelloEvent(make([]byte, 68))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too small")
}
