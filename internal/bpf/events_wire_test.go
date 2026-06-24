package bpf

// Wire-format regression tests for ParseNetworkEvent.
//
// These tests construct raw byte slices by writing values at their exact
// byte offsets (not via binary.Write on the Go struct), so that any future
// removal of PPID/ParentComm from the parser will cause dport — and all
// subsequent network fields — to be read from the wrong offsets, failing
// these assertions.
//
// Wire layout (packed, little-endian):
//   [0 ] type         uint32   (4)
//   [4 ] timestamp    uint64   (8)
//   [12] pid          uint32   (4)
//   [16] tgid         uint32   (4)
//   [20] ppid         uint32   (4)  ← added in bug fix (was missing)
//   [24] uid          uint32   (4)
//   [28] comm         [16]byte (16)
//   [44] parent_comm  [16]byte (16) ← added in bug fix (was missing)
//   [60] saddr        [16]byte (16)
//   [76] daddr        [16]byte (16)
//   [92] sport        uint16   (2)
//   [94] dport        uint16   (2)
//   [96] proto        uint8    (1)
//   [97] family       uint8    (1)
//   Total: 98 bytes

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildNetworkEventWire constructs a 98-byte wire-format slice for a network
// event, placing each field at its documented byte offset.
func buildNetworkEventWire(
	evtType uint32,
	timestamp uint64,
	pid, tgid, ppid, uid uint32,
	comm, parentComm [16]byte,
	saddr, daddr [16]byte,
	sport, dport uint16,
	proto, family uint8,
) []byte {
	raw := make([]byte, 98)

	binary.LittleEndian.PutUint32(raw[0:], evtType)
	binary.LittleEndian.PutUint64(raw[4:], timestamp)
	binary.LittleEndian.PutUint32(raw[12:], pid)
	binary.LittleEndian.PutUint32(raw[16:], tgid)
	binary.LittleEndian.PutUint32(raw[20:], ppid)
	binary.LittleEndian.PutUint32(raw[24:], uid)
	copy(raw[28:44], comm[:])
	copy(raw[44:60], parentComm[:])
	copy(raw[60:76], saddr[:])
	copy(raw[76:92], daddr[:])
	binary.LittleEndian.PutUint16(raw[92:], sport)
	binary.LittleEndian.PutUint16(raw[94:], dport)
	raw[96] = proto
	raw[97] = family

	return raw
}

// TestParseNetworkEvent_WireAlignment is the primary regression test for the
// 20-byte misalignment bug (missing ppid + parent_comm in the parser).
//
// It encodes dport=4444 at offset [94] and verifies the parser returns exactly
// that value. Before the fix, dport was read 20 bytes early (from offset [74],
// inside daddr), producing garbage.
func TestParseNetworkEvent_WireAlignment(t *testing.T) {
	var comm [16]byte
	copy(comm[:], "nginx")
	var parentComm [16]byte
	copy(parentComm[:], "bash")

	var saddr [16]byte
	saddr[0], saddr[1], saddr[2], saddr[3] = 192, 168, 1, 10
	var daddr [16]byte
	daddr[0], daddr[1], daddr[2], daddr[3] = 203, 0, 113, 5

	raw := buildNetworkEventWire(
		2,           // type: EVENT_TYPE_TCP_CONNECT
		9876543210,  // timestamp
		1111,        // pid
		1111,        // tgid
		1000,        // ppid
		500,         // uid
		comm,
		parentComm,
		saddr,
		daddr,
		54321, // sport
		4444,  // dport — the canary value
		6,     // proto: TCP
		2,     // family: AF_INET
	)

	evt, err := ParseNetworkEvent(raw)
	require.NoError(t, err)

	// Primary alignment assertion: dport must be 4444, not bytes from daddr.
	assert.Equal(t, uint16(4444), evt.Dport, "dport misaligned — ppid/parent_comm likely missing from parser")

	// Secondary assertions to catch partial regressions.
	assert.Equal(t, uint32(1111), evt.PID)
	assert.Equal(t, uint32(1000), evt.PPID)
	assert.Equal(t, uint32(500), evt.UID)
	assert.Equal(t, comm, evt.Comm)
	assert.Equal(t, parentComm, evt.ParentComm)
	assert.Equal(t, saddr, evt.Saddr)
	assert.Equal(t, daddr, evt.Daddr)
	assert.Equal(t, uint16(54321), evt.Sport)
	assert.Equal(t, uint8(6), evt.Proto)
	assert.Equal(t, uint8(2), evt.Family)
}

// TestParseNetworkEvent_DportAtExactOffset verifies the dport offset is [94]
// by zeroing all other bytes and writing only dport.
func TestParseNetworkEvent_DportAtExactOffset(t *testing.T) {
	raw := make([]byte, 98)
	// Write only dport at offset 94; every other field stays zero.
	binary.LittleEndian.PutUint16(raw[94:], 4444)

	evt, err := ParseNetworkEvent(raw)
	require.NoError(t, err)
	assert.Equal(t, uint16(4444), evt.Dport)
	// All fields written at zero should parse as zero.
	assert.Equal(t, uint32(0), evt.PID)
	assert.Equal(t, uint32(0), evt.PPID)
}

// TestParseNetworkEvent_TooSmall_Wire checks that a slice shorter than 98
// bytes is rejected.
func TestParseNetworkEvent_TooSmall_Wire(t *testing.T) {
	_, err := ParseNetworkEvent(make([]byte, 97))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too small")
}
