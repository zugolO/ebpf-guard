package collector

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/zugolO/ebpf-guard/pkg/types"

	"github.com/stretchr/testify/require"
)

// №477: the wire sizes of the gpu, dns and lsm records are derived from their
// Go mirrors (binary.Size), and every one of them is pinned here against the
// number counted by hand from the C struct (bpf/gpu_uprobe.bpf.c,
// bpf/dns.bpf.c, bpf/common.h). The pre-fix tests compared the parser with the
// SAME constant, so a wrong constant passed them; here the literal is
// independent and a Go-side drift in EITHER direction fails.
// Round-trips serialise the record with the SAME struct, as http_event/tls_event do.

func TestGPUEventWireSize(t *testing.T) {
	require.Equal(t, 85, binary.Size(GPUEventRaw{}), "struct gpu_event is 85 bytes packed")
	require.Equal(t, binary.Size(GPUEventRaw{}), gpuEventRawSize)

	in := GPUEventRaw{Type: uint32(types.EventGPU), PID: 7, Op: 2, DevPtr: 1, HostPtr: 2, Size: 3}
	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, in))
	out, err := (&GPUCollector{}).parseEvent(buf.Bytes())
	require.NoError(t, err)
	require.Equal(t, in.PID, out.PID)
	require.Equal(t, in.Size, out.GPU.Size)
	_, err = (&GPUCollector{}).parseEvent(buf.Bytes()[:gpuEventRawSize-1])
	require.ErrorContains(t, err, "85", "the refusal must name the required size")
}

func TestLSMAuditEventWireSize(t *testing.T) {
	require.Equal(t, 107, binary.Size(lsmAuditEventRaw{}), "struct lsm_audit_event is 107 bytes packed")
	require.Equal(t, binary.Size(lsmAuditEventRaw{}), lsmAuditEventSize)

	in := lsmAuditEventRaw{PID: 9, TargetPID: 10, Action: 1, Hook: 2, Sig: 9}
	copy(in.Path[:], "/etc/shadow")
	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, in))
	out, err := parseLSMAuditEventRaw(buf.Bytes())
	require.NoError(t, err)
	require.Equal(t, in, out)
	_, err = parseLSMAuditEventRaw(buf.Bytes()[:lsmAuditEventSize-1])
	require.Error(t, err)
}

func TestDNSEventHeaderWireSize(t *testing.T) {
	require.Equal(t, 63, binary.Size(dnsEventHeaderRaw{}), "struct dns_event header is 63 bytes packed")
	require.Equal(t, binary.Size(dnsEventHeaderRaw{}), dnsRawEventFixedLen)

	// Direction and payload_len are read by offset in decodeDNSEvent; build
	// the record from the struct and confirm the offsets land on the fields.
	in := dnsEventHeaderRaw{PID: 5, Direction: 1, PayloadLen: 300}
	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, in))
	raw := buf.Bytes()
	require.Equal(t, in.Direction, raw[dnsRawEventFixedLen-3])
	require.Equal(t, in.PayloadLen, binary.LittleEndian.Uint16(raw[dnsRawEventFixedLen-2:]))
}
