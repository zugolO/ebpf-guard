package collector

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestIntToIPv4ByteOrder verifies that BPF network-byte-order (big-endian) uint32 values
// are decoded correctly. The MSB of the uint32 is the first octet of the IP address.
func TestIntToIPv4ByteOrder(t *testing.T) {
	tests := []struct {
		name     string
		ip       uint32 // network byte order (big-endian), as stored by BPF
		expected string
	}{
		{
			name:     "google DNS 8.8.8.8",
			ip:       0x08080808,
			expected: "8.8.8.8",
		},
		{
			name:     "cloudflare DNS 1.1.1.1",
			ip:       0x01010101,
			expected: "1.1.1.1",
		},
		{
			name:     "localhost 127.0.0.1",
			ip:       0x7f000001,
			expected: "127.0.0.1",
		},
		{
			name:     "private 192.168.1.1",
			ip:       0xC0A80101,
			expected: "192.168.1.1",
		},
		{
			name:     "example.com 93.184.216.34",
			ip:       0x5DB8D822,
			expected: "93.184.216.34",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := intToIPv4(tt.ip)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// encodeDNSName encodes a dotted domain name into DNS wire format
// (length-prefixed labels, null-terminated). No compression.
func encodeDNSName(name string) []byte {
	var buf []byte
	for _, label := range strings.Split(name, ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	return append(buf, 0)
}

// buildMockRawEvent builds a raw ring buffer record matching struct
// dns_event in dns.bpf.c: a fixed header followed by a raw DNS wire-format
// payload (what the BPF side actually captures post-redesign).
func buildMockRawEvent(direction types.DNSDirection, payload []byte) []byte {
	header := make([]byte, dnsRawEventFixedLen)
	offset := 0

	binary.LittleEndian.PutUint32(header[offset:], 5) // EVENT_TYPE_DNS
	offset += 4
	binary.LittleEndian.PutUint64(header[offset:], 1234567890)
	offset += 8
	binary.LittleEndian.PutUint32(header[offset:], 1234) // pid
	offset += 4
	binary.LittleEndian.PutUint32(header[offset:], 1234) // tgid
	offset += 4
	binary.LittleEndian.PutUint32(header[offset:], 1000) // uid
	offset += 4
	copy(header[offset:], "curl\x00")
	offset += 16
	header[offset] = byte(direction)
	offset += 1
	binary.LittleEndian.PutUint16(header[offset:], uint16(len(payload)))

	return append(header, payload...)
}

// buildDNSResponsePayload builds a raw DNS response message: header +
// question (qname/A) + one A-record answer pointing back at the question
// name via a compression pointer.
func buildDNSResponsePayload(qname string, ip net.IP) []byte {
	qnameWire := encodeDNSName(qname)

	payload := make([]byte, 12)
	binary.BigEndian.PutUint16(payload[2:4], 0x8180) // QR=1 (response), RCODE=0
	binary.BigEndian.PutUint16(payload[4:6], 1)      // QDCOUNT
	binary.BigEndian.PutUint16(payload[6:8], 1)      // ANCOUNT

	questionStart := len(payload)
	payload = append(payload, qnameWire...)
	payload = binary.BigEndian.AppendUint16(payload, 1) // QTYPE A
	payload = binary.BigEndian.AppendUint16(payload, 1) // QCLASS IN

	// Answer: name = compression pointer back to the question's qname.
	ptr := uint16(0xC000) | uint16(questionStart)
	payload = binary.BigEndian.AppendUint16(payload, ptr)
	payload = binary.BigEndian.AppendUint16(payload, 1)   // TYPE A
	payload = binary.BigEndian.AppendUint16(payload, 1)   // CLASS IN
	payload = binary.BigEndian.AppendUint32(payload, 300) // TTL
	payload = binary.BigEndian.AppendUint16(payload, 4)   // RDLENGTH
	payload = append(payload, ip.To4()...)

	return payload
}

func TestParseEvent(t *testing.T) {
	collector := &DNSCollector{enabled: true}

	respPayload := buildDNSResponsePayload("example.com", net.IPv4(93, 184, 216, 34))
	raw := buildMockRawEvent(types.DNSDirectionResponse, respPayload)

	event := collector.parseEvent(raw)

	require.NotNil(t, event)
	assert.Equal(t, types.EventDNS, event.Type)
	assert.Equal(t, uint64(1234567890), event.Timestamp)
	assert.Equal(t, uint32(1234), event.PID)
	assert.Equal(t, uint32(1000), event.UID)
	assert.Equal(t, "example.com", event.DNS.QName)
	assert.Equal(t, uint16(1), event.DNS.QType)
	assert.Equal(t, uint16(0), event.DNS.RCode)
	assert.Equal(t, types.DNSDirectionResponse, event.DNS.Direction)
	assert.Len(t, event.DNS.ResponseIPs, 1)
	assert.Equal(t, "93.184.216.34", event.DNS.ResponseIPs[0])
}

func TestParseEvent_Query(t *testing.T) {
	collector := &DNSCollector{enabled: true}

	qnameWire := encodeDNSName("example.com")
	payload := make([]byte, 12)
	binary.BigEndian.PutUint16(payload[2:4], 0x0100) // QR=0 (query)
	binary.BigEndian.PutUint16(payload[4:6], 1)      // QDCOUNT
	payload = append(payload, qnameWire...)
	payload = binary.BigEndian.AppendUint16(payload, 1) // QTYPE A
	payload = binary.BigEndian.AppendUint16(payload, 1) // QCLASS IN

	raw := buildMockRawEvent(types.DNSDirectionQuery, payload)
	event := collector.parseEvent(raw)

	require.NotNil(t, event)
	assert.Equal(t, "example.com", event.DNS.QName)
	assert.Equal(t, uint16(1), event.DNS.QType)
	assert.Equal(t, types.DNSDirectionQuery, event.DNS.Direction)
	assert.Empty(t, event.DNS.ResponseIPs)
}

func TestParseEvent_InvalidType(t *testing.T) {
	collector := &DNSCollector{enabled: true}

	// Build a mock event with wrong type
	buf := make([]byte, 32)
	binary.LittleEndian.PutUint32(buf, 99) // Wrong type

	event := collector.parseEvent(buf)
	assert.Nil(t, event)
}

func TestParseEvent_TooShort(t *testing.T) {
	collector := &DNSCollector{enabled: true}

	event := collector.parseEvent([]byte{1, 2, 3}) // Too short
	assert.Nil(t, event)
}

func TestDNSCollector_Name(t *testing.T) {
	c := &DNSCollector{}
	assert.Equal(t, "dns", c.Name())
}

func TestNewDNSCollector_Disabled(t *testing.T) {
	collector, err := NewDNSCollector(false)
	require.NoError(t, err)
	assert.NotNil(t, collector)
	assert.False(t, collector.enabled)
}
