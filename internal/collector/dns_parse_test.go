package collector

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// encodeDNSName encodes a dotted domain name into RFC 1035 label format,
// terminated by a zero-length root label.
func encodeDNSName(name string) []byte {
	var out []byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			label := name[start:i]
			out = append(out, byte(len(label)))
			out = append(out, label...)
			start = i + 1
		}
	}
	out = append(out, 0) // root
	return out
}

// buildDNSQuery builds a minimal DNS query message for the given name/qtype.
func buildDNSQuery(name string, qtype uint16) []byte {
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:], 0x1234) // ID
	binary.BigEndian.PutUint16(hdr[2:], 0x0100) // flags: standard query, RD
	binary.BigEndian.PutUint16(hdr[4:], 1)      // qdcount
	// ancount/nscount/arcount stay zero

	q := encodeDNSName(name)
	q = appendBE16(q, qtype) // QTYPE
	q = appendBE16(q, 1)     // QCLASS IN
	return append(hdr, q...)
}

// buildDNSResponseWithA builds a DNS response carrying a single A record for
// name, using a compression pointer back to the question's QNAME.
func buildDNSResponseWithA(name string, ip [4]byte) []byte {
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:], 0x1234) // ID
	binary.BigEndian.PutUint16(hdr[2:], 0x8180) // flags: response, RD+RA, NOERROR
	binary.BigEndian.PutUint16(hdr[4:], 1)      // qdcount
	binary.BigEndian.PutUint16(hdr[6:], 1)      // ancount

	q := encodeDNSName(name)
	q = appendBE16(q, 1) // QTYPE A
	q = appendBE16(q, 1) // QCLASS IN

	msg := make([]byte, 0, len(hdr)+len(q))
	msg = append(msg, hdr...)
	msg = append(msg, q...)

	// Answer: name is a compression pointer to offset 12 (the question QNAME).
	var ans []byte
	ans = appendBE16(ans, 0xC00C)       // pointer to offset 12
	ans = appendBE16(ans, 1)            // TYPE A
	ans = appendBE16(ans, 1)            // CLASS IN
	ans = append(ans, 0, 0, 0x01, 0x2c) // TTL = 300
	ans = appendBE16(ans, 4)            // RDLENGTH
	ans = append(ans, ip[0], ip[1], ip[2], ip[3])

	return append(msg, ans...)
}

func appendBE16(b []byte, v uint16) []byte { return append(b, byte(v>>8), byte(v)) }

// buildDNSRawRecord wraps a DNS payload in the packed dns_event header that the
// BPF side emits.
func buildDNSRawRecord(direction types.DNSDirection, payload []byte) []byte {
	raw := make([]byte, dnsRawEventFixedLen+len(payload))
	binary.LittleEndian.PutUint32(raw[0:], uint32(types.EventDNS)) // type
	binary.LittleEndian.PutUint64(raw[4:], 1234567)                // timestamp
	binary.LittleEndian.PutUint32(raw[12:], 4321)                  // pid
	binary.LittleEndian.PutUint32(raw[16:], 4321)                  // tgid
	binary.LittleEndian.PutUint32(raw[20:], 1000)                  // uid
	copy(raw[24:40], "dig")                                        // comm[16]
	raw[40] = byte(direction)                                      // direction
	binary.LittleEndian.PutUint16(raw[41:], uint16(len(payload)))  // payload_len
	copy(raw[dnsRawEventFixedLen:], payload)
	return raw
}

// --- decodeDNSName ---------------------------------------------------------

func TestDecodeDNSName_Simple(t *testing.T) {
	payload := encodeDNSName("example.com")
	name, pos, ok := decodeDNSName(payload, 0)
	require.True(t, ok)
	assert.Equal(t, "example.com", name)
	assert.Equal(t, len(payload), pos)
}

func TestDecodeDNSName_Root(t *testing.T) {
	// A single zero byte is the root name.
	name, pos, ok := decodeDNSName([]byte{0x00}, 0)
	require.True(t, ok)
	assert.Equal(t, "", name)
	assert.Equal(t, 1, pos)
}

func TestDecodeDNSName_CompressionPointer(t *testing.T) {
	// payload: [0..] "a.com" at offset 0, then a pointer at the end pointing back.
	base := encodeDNSName("a.com") // 7 bytes: 1 'a' 3 'c' 'o' 'm' 0
	payload := make([]byte, len(base)+2)
	copy(payload, base)
	// Pointer to offset 0.
	binary.BigEndian.PutUint16(payload[len(base):], 0xC000)

	name, pos, ok := decodeDNSName(payload, len(base))
	require.True(t, ok)
	assert.Equal(t, "a.com", name)
	// endPos is right after the 2-byte pointer, not after the target.
	assert.Equal(t, len(base)+2, pos)
}

func TestDecodeDNSName_PointerLoopBounded(t *testing.T) {
	// A pointer at offset 0 that points to itself must terminate via the jump cap.
	payload := []byte{0xC0, 0x00}
	_, _, ok := decodeDNSName(payload, 0)
	assert.False(t, ok, "self-referential pointer must be rejected, not loop forever")
}

func TestDecodeDNSName_LabelOverrun(t *testing.T) {
	// Label length claims 9 bytes but only 3 remain.
	payload := []byte{0x09, 'a', 'b', 'c'}
	_, _, ok := decodeDNSName(payload, 0)
	assert.False(t, ok)
}

// --- parseDNSWireMessage ---------------------------------------------------

func TestParseDNSWireMessage_Query(t *testing.T) {
	msg, ok := parseDNSWireMessage(buildDNSQuery("example.com", 28)) // AAAA
	require.True(t, ok)
	assert.Equal(t, "example.com", msg.qname)
	assert.Equal(t, uint16(28), msg.qtype)
	assert.Equal(t, uint16(0), msg.rcode)
	assert.Empty(t, msg.responseIPs, "a query carries no answer IPs")
}

func TestParseDNSWireMessage_ResponseWithA(t *testing.T) {
	msg, ok := parseDNSWireMessage(buildDNSResponseWithA("example.com", [4]byte{93, 184, 216, 34}))
	require.True(t, ok)
	assert.Equal(t, "example.com", msg.qname)
	assert.Equal(t, uint16(1), msg.qtype)
	require.Len(t, msg.responseIPs, 1)
	assert.Equal(t, "93.184.216.34", msg.responseIPs[0])
}

func TestParseDNSWireMessage_TooShort(t *testing.T) {
	_, ok := parseDNSWireMessage([]byte{0x00, 0x01, 0x02})
	assert.False(t, ok)
}

func TestParseDNSWireMessage_NoQuestion(t *testing.T) {
	hdr := make([]byte, 12) // qdcount = 0
	_, ok := parseDNSWireMessage(hdr)
	assert.False(t, ok)
}

// --- decodeDNSEvent --------------------------------------------------------

func TestDecodeDNSEvent_Query(t *testing.T) {
	raw := buildDNSRawRecord(types.DNSDirection(0), buildDNSQuery("evil.example.com", 1))
	evt := decodeDNSEvent(raw)
	require.NotNil(t, evt)
	assert.Equal(t, types.EventDNS, evt.Type)
	assert.Equal(t, uint32(4321), evt.PID)
	require.NotNil(t, evt.DNS)
	assert.Equal(t, "evil.example.com", evt.DNS.QName)
	assert.Equal(t, uint16(1), evt.DNS.QType)
}

func TestDecodeDNSEvent_TooShort(t *testing.T) {
	assert.Nil(t, decodeDNSEvent(make([]byte, dnsRawEventFixedLen-1)))
}

func TestDecodeDNSEvent_WrongType(t *testing.T) {
	raw := buildDNSRawRecord(types.DNSDirection(0), buildDNSQuery("a.com", 1))
	binary.LittleEndian.PutUint32(raw[0:], uint32(types.EventSyscall)) // not DNS
	assert.Nil(t, decodeDNSEvent(raw))
}

func TestDecodeDNSEvent_PayloadLenOverflow(t *testing.T) {
	raw := buildDNSRawRecord(types.DNSDirection(0), buildDNSQuery("a.com", 1))
	// Claim a payload far larger than what's present.
	binary.LittleEndian.PutUint16(raw[41:], 9000)
	assert.Nil(t, decodeDNSEvent(raw))
}

// --- string helpers --------------------------------------------------------

func TestQtypeToString(t *testing.T) {
	cases := map[uint16]string{
		1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
		15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
		999: "TYPE999",
	}
	for in, want := range cases {
		assert.Equal(t, want, qtypeToString(in), "qtype=%d", in)
	}
}

func TestRcodeToString(t *testing.T) {
	cases := map[uint16]string{
		0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
		4: "NOTIMP", 5: "REFUSED", 99: "RCODE99",
	}
	for in, want := range cases {
		assert.Equal(t, want, rcodeToString(in), "rcode=%d", in)
	}
}

func TestIntToIPv4(t *testing.T) {
	// 0x7f000001 = 127.0.0.1 in network byte order.
	assert.Equal(t, "127.0.0.1", intToIPv4(0x7f000001))
	assert.Equal(t, "0.0.0.0", intToIPv4(0))
}
