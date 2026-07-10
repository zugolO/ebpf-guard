package util

import "testing"

// TestSipHash24Vectors pins siphash24Core against the published SipHash-2-4
// reference vectors (the key 00 01 02 ... 0f; messages 00 01 ... of growing
// length). If these drift, the kernel side (bpf/lsm.bpf.c) and Go side no longer
// agree and the sandbox path allow-list silently stops matching.
func TestSipHash24Vectors(t *testing.T) {
	// k0 = little-endian of bytes 00..07, k1 = little-endian of bytes 08..0f.
	const k0 = 0x0706050403020100
	const k1 = 0x0f0e0d0c0b0a0908

	cases := []struct {
		msg  []byte
		want uint64
	}{
		{[]byte{}, 0x726fdb47dd0e0e31},
		{[]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e}, 0xa129ca6149be45e5},
	}
	for _, c := range cases {
		if got := siphash24Core(c.msg, k0, k1); got != c.want {
			t.Errorf("siphash24Core(len=%d) = %#016x, want %#016x", len(c.msg), got, c.want)
		}
	}
}

// TestSipHash24PathTruncation verifies the path wrapper stops at PathHashMax and
// at the first NUL, matching the kernel's bounded, NUL-terminated path walk.
func TestSipHash24PathTruncation(t *testing.T) {
	key := SipHashKey{K0: 0x1122334455667788, K1: 0x99aabbccddeeff00}

	// A NUL truncates: everything after it is ignored.
	if a, b := SipHash24Path("/usr/bin", key), SipHash24Path("/usr/bin\x00ignored", key); a != b {
		t.Errorf("NUL not treated as terminator: %#x vs %#x", a, b)
	}

	// The window caps at PathHashMax bytes: two strings sharing the first
	// PathHashMax bytes hash identically regardless of the tail.
	base := make([]byte, PathHashMax)
	for i := range base {
		base[i] = 'a'
	}
	s1 := string(base) + "X"
	s2 := string(base) + "Y"
	if a, b := SipHash24Path(s1, key), SipHash24Path(s2, key); a != b {
		t.Errorf("path window not capped at PathHashMax: %#x vs %#x", a, b)
	}

	// Distinct short paths hash distinctly (sanity, not a collision proof).
	if SipHash24Path("/workspace", key) == SipHash24Path("/etc", key) {
		t.Error("distinct paths collided under SipHash")
	}
}

// TestSipHash24KeyDependence confirms the output depends on the key: the same
// path under two keys must differ (the whole point of a keyed PRF).
func TestSipHash24KeyDependence(t *testing.T) {
	k1 := SipHashKey{K0: 1, K1: 2}
	k2 := SipHashKey{K0: 1, K1: 3}
	if SipHash24Path("/workspace/secret", k1) == SipHash24Path("/workspace/secret", k2) {
		t.Error("SipHash output did not change with the key")
	}
}
