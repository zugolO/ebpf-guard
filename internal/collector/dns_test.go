package collector

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ebpf-guard/ebpf-guard/pkg/types"
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

func TestQtypeToString(t *testing.T) {
	tests := []struct {
		qtype    uint16
		expected string
	}{
		{1, "A"},
		{2, "NS"},
		{5, "CNAME"},
		{6, "SOA"},
		{12, "PTR"},
		{15, "MX"},
		{16, "TXT"},
		{28, "AAAA"},
		{33, "SRV"},
		{255, "ANY"},
		{999, "TYPE999"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := qtypeToString(tt.qtype)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRcodeToString(t *testing.T) {
	tests := []struct {
		rcode    uint16
		expected string
	}{
		{0, "NOERROR"},
		{1, "FORMERR"},
		{2, "SERVFAIL"},
		{3, "NXDOMAIN"},
		{4, "NOTIMP"},
		{5, "REFUSED"},
		{99, "RCODE99"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := rcodeToString(tt.rcode)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseEvent(t *testing.T) {
	collector := &DNSCollector{enabled: true}

	// Build a mock dns_event structure
	// This matches the layout in dns.bpf.c
	buildMockEvent := func() []byte {
		buf := make([]byte, 256)
		offset := 0

		// type (4 bytes) = EVENT_TYPE_DNS (5)
		binary.LittleEndian.PutUint32(buf[offset:], 5)
		offset += 4

		// timestamp (8 bytes)
		binary.LittleEndian.PutUint64(buf[offset:], 1234567890)
		offset += 8

		// pid (4 bytes)
		binary.LittleEndian.PutUint32(buf[offset:], 1234)
		offset += 4

		// tgid (4 bytes)
		binary.LittleEndian.PutUint32(buf[offset:], 1234)
		offset += 4

		// uid (4 bytes)
		binary.LittleEndian.PutUint32(buf[offset:], 1000)
		offset += 4

		// comm (16 bytes)
		copy(buf[offset:], "curl\x00")
		offset += 16

		// qname (128 bytes)
		copy(buf[offset:], "example.com")
		offset += 128

		// qtype (2 bytes) = A (1)
		binary.LittleEndian.PutUint16(buf[offset:], 1)
		offset += 2

		// rcode (2 bytes) = NOERROR (0)
		binary.LittleEndian.PutUint16(buf[offset:], 0)
		offset += 2

		// direction (1 byte) = query (0)
		buf[offset] = 0
		offset += 1

		// qname_len (1 byte)
		buf[offset] = 11
		offset += 1

		// response_count (1 byte) = 1
		buf[offset] = 1
		offset += 1

		// response_ips (4 bytes each) = 93.184.216.34 (example.com)
		// Stored in network byte order (big-endian): 0x5DB8D822
		binary.BigEndian.PutUint32(buf[offset:], 0x5DB8D822)

		return buf
	}

	raw := buildMockEvent()
	event := collector.parseEvent(raw)

	require.NotNil(t, event)
	assert.Equal(t, types.EventDNS, event.Type)
	assert.Equal(t, uint64(1234567890), event.Timestamp)
	assert.Equal(t, uint32(1234), event.PID)
	assert.Equal(t, uint32(1000), event.UID)
	assert.Equal(t, "example.com", event.DNS.QName)
	assert.Equal(t, uint16(1), event.DNS.QType)
	assert.Equal(t, uint16(0), event.DNS.RCode)
	assert.Equal(t, types.DNSDirectionQuery, event.DNS.Direction)
	assert.Len(t, event.DNS.ResponseIPs, 1)
	assert.Equal(t, "93.184.216.34", event.DNS.ResponseIPs[0])
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
