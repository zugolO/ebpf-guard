package bpf

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildSyscallRaw returns a 104-byte wire encoding of a SyscallEvent.
func buildSyscallRaw() []byte {
	evt := SyscallEvent{
		Type:      1,
		Timestamp: 1234567890,
		PID:       42,
		TGID:      42,
		UID:       1000,
		Comm:      [16]byte{'n', 'g', 'i', 'n', 'x'},
		Nr:        1,
		Ret:       0,
		Args:      [6]uint64{1, 2, 3, 4, 5, 6},
	}
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, evt)
	return buf.Bytes()
}

// buildNetworkRaw returns a 98-byte wire encoding of a NetworkEvent.
func buildNetworkRaw() []byte {
	var comm [16]byte
	copy(comm[:], "nginx")
	var parent [16]byte
	copy(parent[:], "bash")
	var saddr, daddr [16]byte
	saddr[0], saddr[1], saddr[2], saddr[3] = 192, 168, 1, 1
	daddr[0], daddr[1], daddr[2], daddr[3] = 8, 8, 8, 8
	raw := make([]byte, 98)
	binary.LittleEndian.PutUint32(raw[0:], 2)
	binary.LittleEndian.PutUint64(raw[4:], 9876543210)
	binary.LittleEndian.PutUint32(raw[12:], 1111)
	binary.LittleEndian.PutUint32(raw[16:], 1111)
	binary.LittleEndian.PutUint32(raw[20:], 1000)
	binary.LittleEndian.PutUint32(raw[24:], 500)
	copy(raw[28:44], comm[:])
	copy(raw[44:60], parent[:])
	copy(raw[60:76], saddr[:])
	copy(raw[76:92], daddr[:])
	binary.LittleEndian.PutUint16(raw[92:], 54321)
	binary.LittleEndian.PutUint16(raw[94:], 443)
	raw[96] = 6
	raw[97] = 2
	return raw
}

// buildFileaccessRaw returns a 326-byte wire encoding of a FileaccessEvent.
func buildFileaccessRaw() []byte {
	var comm, parent [16]byte
	copy(comm[:], "nginx")
	copy(parent[:], "bash")
	var filename [256]byte
	copy(filename[:], "/etc/passwd")
	raw := make([]byte, 326)
	binary.LittleEndian.PutUint32(raw[0:], 3)
	binary.LittleEndian.PutUint64(raw[4:], 1234567890)
	binary.LittleEndian.PutUint32(raw[12:], 42)
	binary.LittleEndian.PutUint32(raw[16:], 42)
	binary.LittleEndian.PutUint32(raw[20:], 1)
	binary.LittleEndian.PutUint32(raw[24:], 1000)
	copy(raw[28:44], comm[:])
	copy(raw[44:60], parent[:])
	copy(raw[60:316], filename[:])
	binary.LittleEndian.PutUint32(raw[316:], 0)
	binary.LittleEndian.PutUint32(raw[320:], 0644)
	raw[324] = 0
	raw[325] = 0
	return raw
}

// ---------------------------------------------------------------------------
// ParseSyscallEvent — pointer-returning (allocates) vs Into (stack-friendly)
// ---------------------------------------------------------------------------

func BenchmarkParseSyscallEvent(b *testing.B) {
	raw := buildSyscallRaw()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseSyscallEvent(raw)
	}
}

func BenchmarkParseSyscallEventInto(b *testing.B) {
	raw := buildSyscallRaw()
	b.ReportAllocs()
	var out SyscallEvent
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ParseSyscallEventInto(raw, &out)
	}
}

// ---------------------------------------------------------------------------
// ParseNetworkEvent
// ---------------------------------------------------------------------------

func BenchmarkParseNetworkEvent(b *testing.B) {
	raw := buildNetworkRaw()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseNetworkEvent(raw)
	}
}

func BenchmarkParseNetworkEventInto(b *testing.B) {
	raw := buildNetworkRaw()
	b.ReportAllocs()
	var out NetworkEvent
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ParseNetworkEventInto(raw, &out)
	}
}

// ---------------------------------------------------------------------------
// ParseFileaccessEvent (largest struct — 326 bytes)
// ---------------------------------------------------------------------------

func BenchmarkParseFileaccessEvent(b *testing.B) {
	raw := buildFileaccessRaw()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseFileaccessEvent(raw)
	}
}

func BenchmarkParseFileaccessEventInto(b *testing.B) {
	raw := buildFileaccessRaw()
	b.ReportAllocs()
	var out FileaccessEvent
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ParseFileaccessEventInto(raw, &out)
	}
}
