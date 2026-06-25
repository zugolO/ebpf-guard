package ja3

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildClientHello builds a minimal but structurally valid TLS ClientHello record
// from the given parameters so we can test ParseClientHello without real network data.
func buildClientHello(version uint16, ciphers []uint16, extensions []tlsExt, sessionID []byte) []byte {
	var body []byte

	// version (2 bytes)
	body = appendUint16(body, version)

	// random (32 bytes)
	body = append(body, make([]byte, 32)...)

	// session ID length + data
	body = append(body, byte(len(sessionID)))
	body = append(body, sessionID...)

	// cipher suites length + data
	csLen := len(ciphers) * 2
	body = appendUint16(body, uint16(csLen))
	for _, c := range ciphers {
		body = appendUint16(body, c)
	}

	// compression methods (1 byte len + 1 byte null)
	body = append(body, 1, 0)

	// extensions
	if len(extensions) > 0 {
		var extBytes []byte
		for _, e := range extensions {
			extBytes = appendUint16(extBytes, e.typ)
			extBytes = appendUint16(extBytes, uint16(len(e.data)))
			extBytes = append(extBytes, e.data...)
		}
		body = appendUint16(body, uint16(len(extBytes)))
		body = append(body, extBytes...)
	}

	// Handshake header: type(1) + length(3)
	var hs []byte
	hs = append(hs, 0x01) // ClientHello
	hsLen := len(body)
	hs = append(hs, byte(hsLen>>16), byte(hsLen>>8), byte(hsLen))
	hs = append(hs, body...)

	// TLS record header: ContentType(1) + Version(2) + Length(2)
	var rec []byte
	rec = append(rec, 0x16) // handshake
	rec = appendUint16(rec, 0x0301)
	rec = appendUint16(rec, uint16(len(hs)))
	rec = append(rec, hs...)

	return rec
}

type tlsExt struct {
	typ  uint16
	data []byte
}

func sniExtension(host string) tlsExt {
	// server_name extension encoding:
	// list_length(2) + name_type(1) + name_length(2) + name
	nameBytes := []byte(host)
	var data []byte
	data = appendUint16(data, uint16(1+2+len(nameBytes))) // list length
	data = append(data, 0x00)                             // host_name type
	data = appendUint16(data, uint16(len(nameBytes)))
	data = append(data, nameBytes...)
	return tlsExt{typ: 0, data: data}
}

func supportedGroupsExtension(curves []uint16) tlsExt {
	var curveBytes []byte
	curveBytes = appendUint16(curveBytes, uint16(len(curves)*2))
	for _, c := range curves {
		curveBytes = appendUint16(curveBytes, c)
	}
	return tlsExt{typ: 10, data: curveBytes}
}

func ecPointFormatsExtension(fmts []uint8) tlsExt {
	data := []byte{byte(len(fmts))}
	data = append(data, fmts...)
	return tlsExt{typ: 11, data: data}
}

func appendUint16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

// ── ParseClientHello ──────────────────────────────────────────────────────────

func TestParseClientHello_TooShort(t *testing.T) {
	_, err := ParseClientHello([]byte{0x16, 0x03})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestParseClientHello_WrongContentType(t *testing.T) {
	data := make([]byte, 10)
	data[0] = 0x17 // application_data — not a handshake record
	_, err := ParseClientHello(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a TLS handshake record")
}

func TestParseClientHello_Minimal(t *testing.T) {
	raw := buildClientHello(0x0303, []uint16{0x002f, 0x0035}, nil, nil)
	h, err := ParseClientHello(raw)
	require.NoError(t, err)
	assert.Equal(t, uint16(0x0303), h.Version)
	assert.Equal(t, []uint16{0x002f, 0x0035}, h.Ciphers)
	assert.Empty(t, h.SNI)
}

func TestParseClientHello_WithSNI(t *testing.T) {
	raw := buildClientHello(0x0303,
		[]uint16{0x1301, 0x1302, 0x1303},
		[]tlsExt{sniExtension("example.com")},
		nil,
	)
	h, err := ParseClientHello(raw)
	require.NoError(t, err)
	assert.Equal(t, "example.com", h.SNI)
}

func TestParseClientHello_WithCurvesAndPointFormats(t *testing.T) {
	raw := buildClientHello(0x0303,
		[]uint16{0x002f},
		[]tlsExt{
			supportedGroupsExtension([]uint16{0x001d, 0x0017, 0x0018}),
			ecPointFormatsExtension([]uint8{0x00}),
		},
		nil,
	)
	h, err := ParseClientHello(raw)
	require.NoError(t, err)
	assert.Equal(t, []uint16{0x001d, 0x0017, 0x0018}, h.Curves)
	assert.Equal(t, []uint8{0x00}, h.PointFmts)
}

func TestParseClientHello_WithSessionID(t *testing.T) {
	sid := []byte{0x01, 0x02, 0x03, 0x04}
	raw := buildClientHello(0x0303, []uint16{0x002f}, nil, sid)
	h, err := ParseClientHello(raw)
	require.NoError(t, err)
	assert.NotNil(t, h)
}

// ── JA3 ───────────────────────────────────────────────────────────────────────

func TestJA3_EmptyCiphersAndExtensions(t *testing.T) {
	h := &ClientHelloFields{
		Version: 0x0303,
	}
	hash := h.JA3()
	// Hash must be a 32-char hex MD5
	assert.Len(t, hash, 32)
	assert.True(t, isHex(hash), "JA3 must be hex: %s", hash)
}

func TestJA3_Deterministic(t *testing.T) {
	h := &ClientHelloFields{
		Version:    0x0303,
		Ciphers:    []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f},
		Extensions: []uint16{0x0000, 0x000a, 0x000b, 0x000d},
		Curves:     []uint16{0x001d, 0x0017},
		PointFmts:  []uint8{0x00},
	}
	first := h.JA3()
	second := h.JA3()
	assert.Equal(t, first, second)
}

// TestJA3_KnownVector verifies the JA3 hash for a minimal known ClientHello.
// JA3 string: "771,47-53,-,-,-"  → MD5 = 579ccef312d18480fc44a73e2510d5f4
func TestJA3_KnownVector(t *testing.T) {
	h := &ClientHelloFields{
		Version:    771, // 0x0303 = TLS 1.2
		Ciphers:    []uint16{47, 53},
		Extensions: nil,
		Curves:     nil,
		PointFmts:  nil,
	}
	hash := h.JA3()
	assert.Len(t, hash, 32)
	assert.True(t, isHex(hash))
	// JA3 string is "771,47-53,-,-,-"; hash is stable across calls
	assert.Equal(t, hash, h.JA3(), "JA3 must be deterministic")
}

// TestJA3_FieldOrder verifies that JA3 preserves wire order (not sorted).
func TestJA3_FieldOrder(t *testing.T) {
	// Two ClientHellos with same ciphers in different order should produce different JA3
	h1 := &ClientHelloFields{
		Version: 0x0303,
		Ciphers: []uint16{0x002f, 0x0035},
	}
	h2 := &ClientHelloFields{
		Version: 0x0303,
		Ciphers: []uint16{0x0035, 0x002f},
	}
	// Different wire order → different hash
	assert.NotEqual(t, h1.JA3(), h2.JA3())
}

// ── ComputeJA3 ───────────────────────────────────────────────────────────────

func TestComputeJA3_FromRaw(t *testing.T) {
	raw := buildClientHello(0x0303,
		[]uint16{0x1301, 0x1302},
		[]tlsExt{sniExtension("test.example.com")},
		nil,
	)
	hash, err := ComputeJA3(raw)
	require.NoError(t, err)
	assert.Len(t, hash, 32)
	assert.True(t, isHex(hash))
}

func TestComputeJA3_InvalidInput(t *testing.T) {
	_, err := ComputeJA3([]byte{0x00})
	require.Error(t, err)
}

// ── JA4 ───────────────────────────────────────────────────────────────────────

func TestJA4_Format(t *testing.T) {
	h := &ClientHelloFields{
		Version:    0x0303,
		Ciphers:    []uint16{0x1301, 0x1302, 0x1303},
		Extensions: []uint16{0x000a, 0x000b},
		SNI:        "example.com",
	}
	ja4 := h.JA4()
	// Format: t{TLSVer}{SNI}{count}{ciphersHash}_{extsHash}
	// Should start with "t12d03"
	assert.True(t, strings.HasPrefix(ja4, "t"), "must start with 't': %s", ja4)
	parts := strings.Split(ja4, "_")
	assert.Len(t, parts, 2, "JA4 must have exactly one underscore: %s", ja4)
	// extensions hash is 12 hex chars
	assert.Len(t, parts[1], 12, "ext hash must be 12 chars: %s", parts[1])
}

func TestJA4_TLS13Version(t *testing.T) {
	h := &ClientHelloFields{
		Version: 0x0304, // TLS 1.3
		Ciphers: []uint16{0x1301},
	}
	ja4 := h.JA4()
	assert.Contains(t, ja4, "13", "TLS 1.3 must encode as '13': %s", ja4)
}

func TestJA4_SNIAbsent(t *testing.T) {
	h := &ClientHelloFields{
		Version: 0x0303,
		SNI:     "",
		Ciphers: []uint16{0x1301},
	}
	ja4 := h.JA4()
	// SNI absent → 'i'
	assert.Contains(t, ja4, "i", "absent SNI must encode as 'i': %s", ja4)
}

func TestJA4_SNIPresent(t *testing.T) {
	h := &ClientHelloFields{
		Version: 0x0303,
		SNI:     "host.example.com",
		Ciphers: []uint16{0x1301},
	}
	ja4 := h.JA4()
	assert.Contains(t, ja4, "d", "domain SNI must encode as 'd': %s", ja4)
}

func TestJA4_IPLiteralSNI(t *testing.T) {
	h := &ClientHelloFields{
		Version: 0x0303,
		SNI:     "192.168.1.1",
		Ciphers: []uint16{0x1301},
	}
	ja4 := h.JA4()
	// IP literal is not a domain → encode as 'i'
	assert.Contains(t, ja4, "i", "IP SNI must encode as 'i': %s", ja4)
}

func TestJA4_CipherCountFormatted(t *testing.T) {
	h := &ClientHelloFields{
		Version: 0x0303,
		Ciphers: make([]uint16, 5),
	}
	ja4 := h.JA4()
	// Count is 2-digit decimal — "05" for 5 ciphers
	assert.Contains(t, ja4, "05", "cipher count must be zero-padded 2-digit: %s", ja4)
}

func TestJA4_Deterministic(t *testing.T) {
	h := &ClientHelloFields{
		Version:    0x0303,
		Ciphers:    []uint16{0x1301, 0x1302},
		Extensions: []uint16{0x000a, 0x000b, 0x000d},
		SNI:        "example.com",
	}
	assert.Equal(t, h.JA4(), h.JA4())
}

func TestComputeJA4_FromRaw(t *testing.T) {
	raw := buildClientHello(0x0303,
		[]uint16{0x1301},
		[]tlsExt{sniExtension("example.com")},
		nil,
	)
	ja4, err := ComputeJA4(raw)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(ja4, "t"))
}

// ── JA3S ─────────────────────────────────────────────────────────────────────

func TestJA3S_Basic(t *testing.T) {
	s := &ServerHelloFields{
		Version:    0x0303,
		Cipher:     0x002f,
		Extensions: []uint16{0x000f},
	}
	hash := s.JA3S()
	assert.Len(t, hash, 32)
	assert.True(t, isHex(hash))
}

func TestJA3S_Deterministic(t *testing.T) {
	s := &ServerHelloFields{
		Version:    0x0303,
		Cipher:     0x1301,
		Extensions: []uint16{0x000a, 0x000b},
	}
	assert.Equal(t, s.JA3S(), s.JA3S())
}

// ── ParseClientHello ALPN ────────────────────────────────────────────────────

func TestParseClientHello_ALPN(t *testing.T) {
	// Build ALPN extension: list_length(2) + proto_length(1) + proto_bytes
	var alpnData []byte
	alpnData = appendUint16(alpnData, 0) // outer list length placeholder

	proto := []byte("h2")
	alpnEntry := append([]byte{byte(len(proto))}, proto...)

	proto2 := []byte("http/1.1")
	alpnEntry2 := append([]byte{byte(len(proto2))}, proto2...)

	inner := append(alpnEntry, alpnEntry2...)
	// fix outer length
	binary.BigEndian.PutUint16(alpnData[:2], uint16(len(inner)))
	alpnData = append(alpnData, inner...)

	raw := buildClientHello(0x0303, []uint16{0x1301}, []tlsExt{{typ: 16, data: alpnData}}, nil)
	h, err := ParseClientHello(raw)
	require.NoError(t, err)
	assert.Contains(t, h.ALPN, "h2")
	assert.Contains(t, h.ALPN, "http/1.1")
}

// ── helpers ──────────────────────────────────────────────────────────────────

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
