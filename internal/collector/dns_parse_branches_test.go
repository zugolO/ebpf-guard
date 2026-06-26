package collector

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseDNSWireMessage_NameWithoutQType covers the early return where a
// QNAME is decoded but the message ends before QTYPE/QCLASS — the name is still
// returned to the caller with a zero qtype.
func TestParseDNSWireMessage_NameWithoutQType(t *testing.T) {
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[4:], 1) // qdcount = 1
	payload := append(hdr, encodeDNSName("a.com")...)

	msg, ok := parseDNSWireMessage(payload)
	require.True(t, ok)
	assert.Equal(t, "a.com", msg.qname)
	assert.Equal(t, uint16(0), msg.qtype, "qtype is zero when QTYPE/QCLASS are absent")
	assert.Empty(t, msg.responseIPs)
}

// TestParseDNSWireMessage_ResponseNonARecord covers decodeDNSAnswerIPs skipping a
// non-A answer record (here a CNAME) so no IPs are collected.
func TestParseDNSWireMessage_ResponseNonARecord(t *testing.T) {
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[2:], 0x8180) // response, NOERROR
	binary.BigEndian.PutUint16(hdr[4:], 1)      // qdcount
	binary.BigEndian.PutUint16(hdr[6:], 1)      // ancount

	q := encodeDNSName("a.com")
	q = appendBE16(q, 1) // QTYPE A
	q = appendBE16(q, 1) // QCLASS IN

	var ans []byte
	ans = appendBE16(ans, 0xC00C)       // pointer to QNAME at offset 12
	ans = appendBE16(ans, 5)            // TYPE CNAME (not A)
	ans = appendBE16(ans, 1)            // CLASS IN
	ans = append(ans, 0, 0, 0x01, 0x2c) // TTL
	ans = appendBE16(ans, 4)            // RDLENGTH
	ans = append(ans, 10, 0, 0, 1)      // RDATA

	payload := append(append(hdr, q...), ans...)

	msg, ok := parseDNSWireMessage(payload)
	require.True(t, ok)
	assert.Empty(t, msg.responseIPs, "non-A answers must not yield IPs")
}

// TestParseDNSWireMessage_ResponseTruncatedAnswer covers decodeDNSAnswerIPs
// breaking out when the answer record is truncated before its fixed fields.
func TestParseDNSWireMessage_ResponseTruncatedAnswer(t *testing.T) {
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[2:], 0x8180) // response
	binary.BigEndian.PutUint16(hdr[4:], 1)      // qdcount
	binary.BigEndian.PutUint16(hdr[6:], 1)      // ancount

	q := encodeDNSName("a.com")
	q = appendBE16(q, 1) // QTYPE A
	q = appendBE16(q, 1) // QCLASS IN

	// Answer name pointer only — no TYPE/CLASS/TTL/RDLENGTH follow.
	ans := appendBE16(nil, 0xC00C)

	payload := append(append(hdr, q...), ans...)

	msg, ok := parseDNSWireMessage(payload)
	require.True(t, ok)
	assert.Empty(t, msg.responseIPs, "a truncated answer must not yield IPs")
}

// TestDecodeDNSName_TruncatedPointer covers the path where a compression
// pointer's second byte is missing.
func TestDecodeDNSName_TruncatedPointer(t *testing.T) {
	_, _, ok := decodeDNSName([]byte{0xC0}, 0)
	assert.False(t, ok, "a one-byte compression pointer must be rejected")
}
