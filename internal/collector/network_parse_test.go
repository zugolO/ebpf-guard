package collector

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// networkWireSize is the packed on-wire size of a network event sample. The
// net_close variant overlays duration_ns into the syscall-union region, so a
// full-size buffer is used for both event kinds.
const networkWireSize = 98

// buildNetworkRaw assembles a packed little-endian network event sample with
// the given type, pid and comm. The remaining tuple fields are left zeroed
// except dport, which is set to a representative value.
func buildNetworkRaw(evtType uint32, pid uint32, comm string) []byte {
	raw := make([]byte, networkWireSize)
	binary.LittleEndian.PutUint32(raw[0:], evtType)   // type
	binary.LittleEndian.PutUint64(raw[4:], 123456789) // timestamp
	binary.LittleEndian.PutUint32(raw[12:], pid)      // pid
	binary.LittleEndian.PutUint32(raw[16:], pid)      // tgid
	binary.LittleEndian.PutUint32(raw[20:], 1)        // ppid
	binary.LittleEndian.PutUint32(raw[24:], 1000)     // uid
	copy(raw[28:44], comm)                            // comm[16]
	binary.LittleEndian.PutUint16(raw[94:], 443)      // dport
	return raw
}

func TestDecodeNetworkEvent_TCPConnect(t *testing.T) {
	raw := buildNetworkRaw(uint32(types.EventTCPConnect), 4242, "curl")

	evt, err := decodeNetworkEvent(raw)
	require.NoError(t, err)

	assert.Equal(t, types.EventTCPConnect, evt.Type)
	assert.Equal(t, uint32(4242), evt.PID)

	var wantComm [16]byte
	copy(wantComm[:], "curl")
	assert.Equal(t, wantComm, evt.Comm)
}

func TestDecodeNetworkEvent_NetClose(t *testing.T) {
	raw := buildNetworkRaw(uint32(types.EventNetClose), 555, "nginx")
	// duration_ns is read from the syscall-union args[0] offset (76).
	binary.LittleEndian.PutUint64(raw[76:], uint64(5*time.Millisecond))

	evt, err := decodeNetworkEvent(raw)
	require.NoError(t, err)

	assert.Equal(t, types.EventNetClose, evt.Type)
	assert.Equal(t, uint32(555), evt.PID)
	require.NotNil(t, evt.NetClose)
	assert.Equal(t, 5*time.Millisecond, evt.NetClose.Duration)
}

func TestDecodeNetworkEvent_TooShort(t *testing.T) {
	// Fewer than 4 bytes cannot even carry the event-type field.
	_, err := decodeNetworkEvent([]byte{0x02, 0x00})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "raw sample too short")
}

func TestDecodeNetworkEvent_TruncatedBody(t *testing.T) {
	// >=4 bytes so routing succeeds, but well below the 98-byte minimum so the
	// underlying parser rejects the sample.
	raw := make([]byte, 10)
	binary.LittleEndian.PutUint32(raw[0:], uint32(types.EventTCPConnect))

	_, err := decodeNetworkEvent(raw)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too small")
}
