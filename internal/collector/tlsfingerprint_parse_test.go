package collector

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// tlsHeaderLen is the fixed packed header size of a ClientHello event sample,
// up to the start of the captured handshake bytes.
const tlsHeaderLen = 68

// buildTLSRaw assembles a packed ClientHello event sample carrying hello as the
// captured handshake payload.
func buildTLSRaw(pid uint32, comm string, hello []byte) []byte {
	raw := make([]byte, tlsHeaderLen+len(hello))
	binary.LittleEndian.PutUint32(raw[0:], uint32(types.EventTLS)) // type
	binary.LittleEndian.PutUint64(raw[4:], 999)                    // timestamp
	binary.LittleEndian.PutUint32(raw[12:], pid)                   // pid
	binary.LittleEndian.PutUint32(raw[16:], pid)                   // tgid
	binary.LittleEndian.PutUint32(raw[20:], 1)                     // ppid
	binary.LittleEndian.PutUint32(raw[24:], 1000)                  // uid
	copy(raw[28:44], comm)                                         // comm[16]
	binary.BigEndian.PutUint16(raw[60:], 443)                      // dport (network order)
	binary.LittleEndian.PutUint16(raw[62:], uint16(len(hello)))    // captured_len
	binary.LittleEndian.PutUint32(raw[64:], uint32(len(hello)))    // original_len
	copy(raw[68:], hello)
	return raw
}

func appendU16(b []byte, v uint16) []byte { return append(b, byte(v>>8), byte(v)) }

// buildMinimalClientHello produces a syntactically valid TLS ClientHello record
// (version + ciphers, no extensions) — enough for ja3.ComputeJA3/JA4 to parse
// and emit non-empty fingerprints.
func buildMinimalClientHello() []byte {
	var body []byte
	body = appendU16(body, 0x0303)           // client version (TLS 1.2)
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // session ID length = 0

	ciphers := []uint16{0x002f, 0x0035}
	body = appendU16(body, uint16(len(ciphers)*2))
	for _, c := range ciphers {
		body = appendU16(body, c)
	}

	body = append(body, 1, 0) // compression methods: len=1, null

	// Handshake header: type(1) + length(3).
	hs := []byte{0x01}
	hsLen := len(body)
	hs = append(hs, byte(hsLen>>16), byte(hsLen>>8), byte(hsLen))
	hs = append(hs, body...)

	// TLS record header: ContentType(1) + Version(2) + Length(2).
	rec := []byte{0x16}
	rec = appendU16(rec, 0x0301)
	rec = appendU16(rec, uint16(len(hs)))
	rec = append(rec, hs...)
	return rec
}

func TestDecodeTLSClientHello_ValidHello(t *testing.T) {
	hello := buildMinimalClientHello()
	raw := buildTLSRaw(7777, "firefox", hello)

	evt, err := decodeTLSClientHello(raw)
	require.NoError(t, err)

	assert.Equal(t, types.EventTLS, evt.Type)
	assert.Equal(t, uint32(7777), evt.PID)
	require.NotNil(t, evt.TLS)
	assert.Equal(t, uint32(len(hello)), evt.TLS.DataLen)
	// A valid ClientHello must yield computed fingerprints.
	assert.NotEmpty(t, evt.TLS.JA3, "expected JA3 to be computed for a valid ClientHello")
	assert.NotEmpty(t, evt.TLS.JA4, "expected JA4 to be computed for a valid ClientHello")
}

func TestDecodeTLSClientHello_GarbageData(t *testing.T) {
	// Captured bytes that are not a TLS handshake: decode must still succeed
	// (fingerprinting is best-effort) but leave JA3/JA4 empty.
	garbage := []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03}
	raw := buildTLSRaw(8888, "curl", garbage)

	evt, err := decodeTLSClientHello(raw)
	require.NoError(t, err)

	assert.Equal(t, types.EventTLS, evt.Type)
	assert.Equal(t, uint32(8888), evt.PID)
	require.NotNil(t, evt.TLS)
	assert.Empty(t, evt.TLS.JA3, "garbage handshake must not yield a JA3")
	assert.Empty(t, evt.TLS.JA4, "garbage handshake must not yield a JA4")
}

func TestDecodeTLSClientHello_TooShort(t *testing.T) {
	_, err := decodeTLSClientHello(make([]byte, 10))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too small")
}
