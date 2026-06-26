package bpf

import (
	"encoding/binary"
	"testing"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseNetworkCloseEvent(t *testing.T) {
	const networkUnionOffset = 60
	const durationOffset = networkUnionOffset + 16 // skip nr + ret (8+8)

	// The network tuple (saddr/daddr/sport/dport/proto/family) reaches offset 98,
	// and overlaps the syscall union where duration is encoded — give the buffer
	// generous headroom matching the real fixed-size struct.
	raw := make([]byte, 128)
	binary.LittleEndian.PutUint32(raw[0:], 7)        // Type
	binary.LittleEndian.PutUint64(raw[4:], 12345)    // Timestamp
	binary.LittleEndian.PutUint32(raw[12:], 1000)    // PID
	binary.LittleEndian.PutUint32(raw[16:], 1001)    // TGID
	binary.LittleEndian.PutUint32(raw[20:], 1)       // PPID
	binary.LittleEndian.PutUint32(raw[24:], 0)       // UID
	copy(raw[28:44], "curl")                         // Comm
	copy(raw[44:60], "bash")                         // ParentComm
	// network union at offset 60: saddr(16) daddr(16) sport(2) dport(2) proto(1) family(1)
	binary.LittleEndian.PutUint16(raw[92:], 54321)   // Sport
	binary.LittleEndian.PutUint16(raw[94:], 443)     // Dport
	raw[96] = 6                                       // Proto (TCP)
	raw[97] = 2                                       // Family (AF_INET)
	// Duration overlaps daddr in the union; set it last so the assertion holds.
	binary.LittleEndian.PutUint64(raw[durationOffset:], 5_000_000_000) // 5s

	evt, err := ParseNetworkCloseEvent(raw)
	require.NoError(t, err)
	assert.Equal(t, uint32(1000), evt.PID)
	assert.Equal(t, uint16(443), evt.Dport)
	assert.Equal(t, uint16(54321), evt.Sport)
	assert.Equal(t, uint8(6), evt.Proto)
	assert.Equal(t, uint64(5_000_000_000), evt.DurationNs)

	// Too-small buffers are rejected.
	_, err = ParseNetworkCloseEvent(make([]byte, 10))
	require.Error(t, err)
}

func TestTlsClientHelloRawEvent_ToTypesEvent(t *testing.T) {
	raw := &TlsClientHelloRawEvent{
		Timestamp:   99,
		PID:         55,
		Comm:        comm16("nginx"),
		Dport:       443,
		OriginalLen: 517,
	}
	e := raw.ToTypesEvent()
	assert.Equal(t, types.EventTLS, e.Type)
	require.NotNil(t, e.TLS)
	assert.Equal(t, uint32(517), e.TLS.DataLen)
	assert.Equal(t, uint32(55), e.PID)
}
