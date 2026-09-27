package bpf

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Wave 6.6 revision item 8: the trailing cgroup_id that struct event got in
// item 10, appended to the event structs item 10 did not cover. The offsets are
// written as LITERALS here, exactly as cgroup_tail_test.go does for 332, so a
// moved field in bpf/ and a moved constant in events.go cannot agree by
// construction — the C side asserts the same numbers with _Static_assert.
//
// NOT ACCEPTED: the BPF objects are not rebuilt here. make generate does not run
// on this host and the *_bpf_gen.go files are stubs, so a verifier reject would
// be invisible ([[bpf-gen-files-are-stubs]], [[stub-loader-hides-verifier-rejects]]).
// These tests pin the Go half of the wire contract only.
func TestItem8CgroupTailOffsets(t *testing.T) {
	require.Equal(t, 121, KmodEventCgroupIDOffset)
	require.Equal(t, 319, DNSEventCgroupIDOffset)
	require.Equal(t, 362, TLSEventCgroupIDOffset)
	require.Equal(t, 580, TLSClientHelloCgroupIDOffset)
	require.Equal(t, 325, HTTPEventCgroupIDOffset, "task 1 of the wave 6.6 revision follow-up list")
	require.Equal(t, 107, LSMAuditEventCgroupIDOffset, "хвост пункта 8: lsm_audit_event")
}

func TestKmodEventCgroupTail(t *testing.T) {
	const wantID = 0x1122334455667788
	const newSize = 129 // sizeof(struct kmod_event) after item 8
	const oldSize = 121 // before it

	build := func(n int) []byte {
		raw := make([]byte, n)
		binary.LittleEndian.PutUint32(raw[0:], 8) // EVENT_TYPE_KMOD_LOAD
		binary.LittleEndian.PutUint32(raw[12:], 777)
		copy(raw[20:], "insmod")
		copy(raw[56:], "evil.ko")
		raw[120] = 1 // from_tmpfs
		if n >= KmodEventCgroupIDOffset+8 {
			binary.LittleEndian.PutUint64(raw[KmodEventCgroupIDOffset:], wantID)
		}
		return raw
	}

	t.Run("new record carries the cgroup id through to types.Event", func(t *testing.T) {
		var ke KmodRawEvent
		require.NoError(t, ParseKmodEventInto(build(newSize), &ke))
		assert.Equal(t, uint64(wantID), ke.CgroupID)
		assert.Equal(t, uint32(777), ke.PID, "existing offsets unchanged")
		assert.Equal(t, uint8(1), ke.FromTmpfs, "existing offsets unchanged")
		assert.Equal(t, "evil.ko", ke.ToTypesEvent().Kmod.ModName)
		assert.Equal(t, uint64(wantID), ke.ToTypesEvent().CgroupID)
	})

	t.Run("old record still parses and yields cgroup id 0", func(t *testing.T) {
		var ke KmodRawEvent
		require.NoError(t, ParseKmodEventInto(build(oldSize), &ke))
		assert.Zero(t, ke.CgroupID, "absent is 0, and 0 means «no cgroup id» — the recovery path skips it")
		assert.Equal(t, uint32(777), ke.PID, "an old record must still decode everything it knew")
	})

	t.Run("reused out struct does not keep a stale id", func(t *testing.T) {
		var ke KmodRawEvent
		require.NoError(t, ParseKmodEventInto(build(newSize), &ke))
		require.NoError(t, ParseKmodEventInto(build(oldSize), &ke))
		assert.Zero(t, ke.CgroupID)
	})
}

func TestDNSEventCgroupTailFromRecord(t *testing.T) {
	const wantID = 0xAABBCCDD11223344
	// The kernel always reserves the full payload, so cgroup_id sits at a FIXED
	// offset past it — not after payload_len bytes.
	full := make([]byte, 327)
	binary.LittleEndian.PutUint64(full[DNSEventCgroupIDOffset:], wantID)
	assert.Equal(t, uint64(wantID), DNSCgroupIDFromRecord(full))

	old := make([]byte, 319)
	assert.Zero(t, DNSCgroupIDFromRecord(old), "a record from a pre-item-8 object yields 0, not garbage")
	assert.Zero(t, DNSCgroupIDFromRecord(nil))
	assert.Zero(t, DNSCgroupIDFromRecord(make([]byte, 63)), "short header only")
}

func TestTLSEventCgroupTailFromRecord(t *testing.T) {
	const wantID = 0x0102030405060708
	full := make([]byte, 370)
	binary.LittleEndian.PutUint64(full[TLSEventCgroupIDOffset:], wantID)
	assert.Equal(t, uint64(wantID), TLSCgroupIDFromRecord(full))

	assert.Zero(t, TLSCgroupIDFromRecord(make([]byte, 362)), "pre-item-8 record yields 0")
	assert.Zero(t, TLSCgroupIDFromRecord(make([]byte, 4)))
}

func TestHTTPEventCgroupTailFromRecord(t *testing.T) {
	const wantID = 0x1357924680ABCDEF
	full := make([]byte, 333)
	binary.LittleEndian.PutUint64(full[HTTPEventCgroupIDOffset:], wantID)
	assert.Equal(t, uint64(wantID), HTTPCgroupIDFromRecord(full))

	// The 325-byte record is the SHAPE http_plaintext actually produced until
	// this task: parsing it must still succeed and yield 0, not garbage or an
	// error — the collector's own binary.Read gate (httpEventRawSize) is
	// unaffected because HTTPEventRaw was deliberately left untouched, exactly
	// as TLSEventRaw was for the sibling above.
	old := make([]byte, 325)
	assert.Zero(t, HTTPCgroupIDFromRecord(old), "a record from a pre-task-1 object yields 0, not garbage")
	assert.Zero(t, HTTPCgroupIDFromRecord(nil))
	assert.Zero(t, HTTPCgroupIDFromRecord(make([]byte, 4)), "short header only")
}

func TestTLSClientHelloCgroupTail(t *testing.T) {
	const wantID = 0xDEADBEEFCAFEBABE
	const newSize = 588 // sizeof(struct tls_clienthello_event) after item 8
	const oldSize = 580 // before it — and the size its doc comment always stated

	build := func(n int) []byte {
		raw := make([]byte, n)
		binary.LittleEndian.PutUint32(raw[0:], 4) // EVENT_TYPE_TLS
		binary.LittleEndian.PutUint64(raw[4:], 12345)
		binary.LittleEndian.PutUint32(raw[12:], 4321)
		copy(raw[28:], "curl")
		binary.BigEndian.PutUint16(raw[60:], 443)
		binary.LittleEndian.PutUint16(raw[62:], 8)
		if n >= TLSClientHelloCgroupIDOffset+8 {
			binary.LittleEndian.PutUint64(raw[TLSClientHelloCgroupIDOffset:], wantID)
		}
		return raw
	}

	t.Run("new record carries the cgroup id through to types.Event", func(t *testing.T) {
		var ch TlsClientHelloRawEvent
		require.NoError(t, ParseTlsClientHelloEventInto(build(newSize), &ch))
		assert.Equal(t, uint64(wantID), ch.CgroupID)
		assert.Equal(t, uint32(4321), ch.PID, "existing offsets unchanged")
		assert.Equal(t, uint16(443), ch.Dport, "existing offsets unchanged")
		assert.Equal(t, uint64(wantID), ch.ToTypesEvent().CgroupID)
	})

	t.Run("old 580-byte record still parses, cgroup id 0", func(t *testing.T) {
		var ch TlsClientHelloRawEvent
		require.NoError(t, ParseTlsClientHelloEventInto(build(oldSize), &ch))
		assert.Zero(t, ch.CgroupID)
		assert.Equal(t, uint32(4321), ch.PID)
	})

	// Finding №488: the C struct was the only event struct in bpf/ without
	// __attribute__((packed)), while this parser has always walked packed
	// offsets. Unpacked, timestamp would sit at 8 and pid at 16, so a record
	// built to the PACKED layout — which is what the parser and every fixture
	// assume — would decode pid as the high half of timestamp. Pinning the two
	// offsets the mismatch would move is what keeps the C attribute from being
	// dropped again unnoticed; the C side asserts the same two numbers.
	t.Run("packed layout: timestamp at 4 and data at 68, not 8 and 72", func(t *testing.T) {
		raw := build(newSize)
		binary.LittleEndian.PutUint64(raw[4:], 0x7777777777777777)
		binary.LittleEndian.PutUint32(raw[12:], 99)
		var ch TlsClientHelloRawEvent
		require.NoError(t, ParseTlsClientHelloEventInto(raw, &ch))
		assert.Equal(t, uint64(0x7777777777777777), ch.Timestamp)
		assert.Equal(t, uint32(99), ch.PID, "pid at 12 — an unpacked producer would put it at 16")
	})
}

func TestLSMAuditCgroupTailFromRecord(t *testing.T) {
	const wantID = 0x2468ACE013579BDF
	full := make([]byte, 115)
	binary.LittleEndian.PutUint64(full[107:], wantID)
	assert.Equal(t, uint64(wantID), LSMAuditCgroupIDFromRecord(full))
	assert.Zero(t, LSMAuditCgroupIDFromRecord(make([]byte, 107)), "107-byte record from an older object yields 0")
	assert.Zero(t, LSMAuditCgroupIDFromRecord(nil))
}
