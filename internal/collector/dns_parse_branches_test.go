package collector

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestParseDNSWireMessage_NameWithoutQType covers the early return where a
// QNAME is decoded but the message ends before QTYPE/QCLASS — the name is still
// returned to the caller with a zero qtype.
func TestParseDNSWireMessage_NameWithoutQType(t *testing.T) {
	payload := make([]byte, 12)
	binary.BigEndian.PutUint16(payload[4:], 1) // qdcount = 1
	payload = append(payload, encodeDNSName("a.com")...)

	msg, ok := parseDNSWireMessage(payload)
	require.True(t, ok)
	assert.Equal(t, "a.com", msg.qname)
	assert.Equal(t, uint16(0), msg.qtype, "qtype is zero when QTYPE/QCLASS are absent")
	assert.Empty(t, msg.responseIPs)
}

// TestParseDNSWireMessage_BadQName covers parseDNSWireMessage's failure path when
// the question's QNAME is malformed (a label overruns the buffer).
func TestParseDNSWireMessage_BadQName(t *testing.T) {
	payload := make([]byte, 12)
	binary.BigEndian.PutUint16(payload[4:], 1) // qdcount = 1
	payload = append(payload, 0x09, 'a')       // label claims 9 bytes, only 1 present

	_, ok := parseDNSWireMessage(payload)
	assert.False(t, ok, "a malformed QNAME must fail the whole message")
}

// TestParseDNSWireMessage_ResponseNonARecord covers decodeDNSAnswerIPs skipping a
// non-A answer record (here a CNAME) so no IPs are collected.
func TestParseDNSWireMessage_ResponseNonARecord(t *testing.T) {
	payload := make([]byte, 12)
	binary.BigEndian.PutUint16(payload[2:], 0x8180) // response, NOERROR
	binary.BigEndian.PutUint16(payload[4:], 1)      // qdcount
	binary.BigEndian.PutUint16(payload[6:], 1)      // ancount

	payload = append(payload, encodeDNSName("a.com")...)
	payload = appendBE16(payload, 1) // QTYPE A
	payload = appendBE16(payload, 1) // QCLASS IN

	payload = appendBE16(payload, 0xC00C)       // answer name: pointer to QNAME
	payload = appendBE16(payload, 5)            // TYPE CNAME (not A)
	payload = appendBE16(payload, 1)            // CLASS IN
	payload = append(payload, 0, 0, 0x01, 0x2c) // TTL
	payload = appendBE16(payload, 4)            // RDLENGTH
	payload = append(payload, 10, 0, 0, 1)      // RDATA

	msg, ok := parseDNSWireMessage(payload)
	require.True(t, ok)
	assert.Empty(t, msg.responseIPs, "non-A answers must not yield IPs")
}

// TestParseDNSWireMessage_ResponseTruncatedAnswer covers decodeDNSAnswerIPs
// breaking out when the answer record is truncated before its fixed fields.
func TestParseDNSWireMessage_ResponseTruncatedAnswer(t *testing.T) {
	payload := make([]byte, 12)
	binary.BigEndian.PutUint16(payload[2:], 0x8180) // response
	binary.BigEndian.PutUint16(payload[4:], 1)      // qdcount
	binary.BigEndian.PutUint16(payload[6:], 1)      // ancount

	payload = append(payload, encodeDNSName("a.com")...)
	payload = appendBE16(payload, 1) // QTYPE A
	payload = appendBE16(payload, 1) // QCLASS IN

	// Answer name pointer only — no TYPE/CLASS/TTL/RDLENGTH follow.
	payload = appendBE16(payload, 0xC00C)

	msg, ok := parseDNSWireMessage(payload)
	require.True(t, ok)
	assert.Empty(t, msg.responseIPs, "a truncated answer must not yield IPs")
}

// TestParseDNSWireMessage_ResponseRDataTruncated covers the break where an A
// record's RDLENGTH points past the end of the buffer.
func TestParseDNSWireMessage_ResponseRDataTruncated(t *testing.T) {
	payload := make([]byte, 12)
	binary.BigEndian.PutUint16(payload[2:], 0x8180) // response
	binary.BigEndian.PutUint16(payload[4:], 1)      // qdcount
	binary.BigEndian.PutUint16(payload[6:], 1)      // ancount

	payload = append(payload, encodeDNSName("a.com")...)
	payload = appendBE16(payload, 1) // QTYPE A
	payload = appendBE16(payload, 1) // QCLASS IN

	payload = appendBE16(payload, 0xC00C)       // answer name pointer
	payload = appendBE16(payload, 1)            // TYPE A
	payload = appendBE16(payload, 1)            // CLASS IN
	payload = append(payload, 0, 0, 0x01, 0x2c) // TTL
	payload = appendBE16(payload, 4)            // RDLENGTH = 4
	payload = append(payload, 1, 2)             // only 2 of the 4 RDATA bytes

	msg, ok := parseDNSWireMessage(payload)
	require.True(t, ok)
	assert.Empty(t, msg.responseIPs, "an A record with truncated RDATA must be skipped")
}

// TestParseDNSWireMessage_ResponseBadAnswerName covers decodeDNSAnswerIPs
// breaking out when an answer record's own name is malformed.
func TestParseDNSWireMessage_ResponseBadAnswerName(t *testing.T) {
	payload := make([]byte, 12)
	binary.BigEndian.PutUint16(payload[2:], 0x8180) // response
	binary.BigEndian.PutUint16(payload[4:], 1)      // qdcount
	binary.BigEndian.PutUint16(payload[6:], 1)      // ancount

	payload = append(payload, encodeDNSName("a.com")...)
	payload = appendBE16(payload, 1) // QTYPE A
	payload = appendBE16(payload, 1) // QCLASS IN

	// Answer name is a single label claiming 9 bytes with nothing after it, so
	// decodeDNSName fails and the answer walk aborts.
	payload = append(payload, 0x09)

	msg, ok := parseDNSWireMessage(payload)
	require.True(t, ok)
	assert.Empty(t, msg.responseIPs, "a malformed answer name must abort answer parsing")
}

// TestDecodeDNSName_TruncatedPointer covers the path where a compression
// pointer's second byte is missing.
func TestDecodeDNSName_TruncatedPointer(t *testing.T) {
	_, _, ok := decodeDNSName([]byte{0xC0}, 0)
	assert.False(t, ok, "a one-byte compression pointer must be rejected")
}

// TestDecodeDNSName_PointerOutOfRange covers the pos>=len guard reached after a
// compression pointer jumps to an offset at or beyond the end of the buffer.
func TestDecodeDNSName_PointerOutOfRange(t *testing.T) {
	// A readable 2-byte pointer whose target offset (5) equals the buffer length.
	payload := []byte{0xC0, 0x05, 0x00, 0x00, 0x00}
	_, _, ok := decodeDNSName(payload, 0)
	assert.False(t, ok, "a pointer past the end of the message must be rejected")
}

// TestDecodeDNSEvent_PayloadLenExceedsBuffer covers the second operand of the
// payload-length bounds check: a payload_len within the cap but larger than the
// bytes actually present.
func TestDecodeDNSEvent_PayloadLenExceedsBuffer(t *testing.T) {
	raw := buildDNSRawRecord(types.DNSDirection(0), buildDNSQuery("a.com", 1))
	binary.LittleEndian.PutUint16(raw[41:], 200) // <= dnsMaxPayload but > present bytes
	assert.Nil(t, decodeDNSEvent(raw))
}

// TestDecodeDNSEvent_UnparseablePayload covers decodeDNSEvent's nil return when
// the header is valid but the DNS payload itself cannot be parsed.
func TestDecodeDNSEvent_UnparseablePayload(t *testing.T) {
	// A 6-byte payload is shorter than the 12-byte DNS header, so
	// parseDNSWireMessage fails and decodeDNSEvent must return nil.
	raw := buildDNSRawRecord(types.DNSDirection(0), []byte{0, 0, 0, 0, 0, 0})
	assert.Nil(t, decodeDNSEvent(raw))
}
