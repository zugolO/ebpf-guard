package util

import "math/bits"

// PathHashMax is the maximum number of bytes hashed for a path, matching
// PATH_HASH_MAX in bpf/lsm.bpf.c. bpf_d_path() resolves a path into a buffer of
// this size; anything longer (or an embedded NUL) is where the kernel's rolling
// hash walk stops, so the Go side must stop at the same point or the two hashes
// diverge for long paths.
const PathHashMax = 128

// FNV32aPath is the single Go implementation of the FNV-1a 32-bit path hash
// used to key the sandbox_path_policy / sandbox_exec_pins BPF maps. It MUST
// stay byte-for-byte compatible with fnv32a() in bpf/lsm.bpf.c: same offset
// basis, same prime, capped at PathHashMax bytes, stopping early at a NUL byte.
//
// This used to be reimplemented independently in internal/collector/lsm.go
// (via hash/fnv, uncapped) and internal/sandbox/policy.go (inline, capped);
// the two could silently diverge from the kernel and from each other for any
// path at or beyond the 128-byte cap. Callers on both sides now share this one
// implementation (issue #271).
func FNV32aPath(s string) uint32 {
	const offsetBasis = 2166136261
	const prime = 16777619
	h := uint32(offsetBasis)
	for i := 0; i < len(s) && i < PathHashMax; i++ {
		c := s[i]
		if c == 0 {
			break
		}
		h ^= uint32(c)
		h *= prime
	}
	return h
}

// SipHashKey is the 128-bit key for the sandbox path-policy PRF: two 64-bit
// halves generated once per boot by internal/sandbox (crypto/rand) and installed
// into the sandbox_hash_secret BPF map. Its byte layout (K0 then K1, little
// endian) is the contract with the kernel side (struct sbx_siphash_key in
// bpf/lsm.bpf.c), so a workload and the kernel derive the same map keys.
type SipHashKey struct {
	K0 uint64
	K1 uint64
}

// SipHash24Path computes SipHash-2-4 over the first PathHashMax bytes of s
// (stopping early at a NUL byte, exactly like FNV32aPath), keyed by key. It backs
// the `sandbox_path_policy` allow-list (issue #276 item 3) — replacing the
// earlier secret-salted FNV-1a (issue #274 item 1).
//
// Why a keyed PRF and not salted FNV-1a: FNV-1a's round `h = (h ^ b) * prime`
// is an invertible bijection, so even with a secret seed a single observed
// (path, stored_hash) pair lets an attacker unwind the rolling hash, recover the
// seed, and then compute H_secret(anything) — the forge is back. Security then
// rests entirely on the fragile invariant "a path-policy hash value must never
// appear anywhere the workload can read it". SipHash-2-4 is a keyed PRF designed
// so the key is not recoverable from observed outputs (it is what the kernel
// itself uses against hash-flooding), which removes that fragility and lets the
// map key be the full 64-bit hash. The key never leaves the BPF map, which is
// gated by the same bpf()-syscall denial that already protects the sandbox's own
// maps, so a sandboxed workload cannot read it.
//
// Must stay byte-for-byte compatible with sandbox_path_allowed() in
// bpf/lsm.bpf.c, which streams the same SipHash-2-4 over the resolved path.
func SipHash24Path(s string, key SipHashKey) uint64 {
	if len(s) > PathHashMax {
		s = s[:PathHashMax]
	}
	if i := indexNUL(s); i >= 0 {
		s = s[:i]
	}
	return siphash24Core([]byte(s), key.K0, key.K1)
}

// indexNUL returns the index of the first NUL byte in s, or -1 if none.
func indexNUL(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return i
		}
	}
	return -1
}

// siphash24Core is the reference SipHash-2-4 (2 compression rounds, 4
// finalization rounds) over an arbitrary byte slice, keyed by (k0, k1). Kept
// general (no path truncation) so it can be pinned against the published
// SipHash test vectors; SipHash24Path is the path-specific wrapper.
func siphash24Core(data []byte, k0, k1 uint64) uint64 {
	v0 := k0 ^ 0x736f6d6570736575
	v1 := k1 ^ 0x646f72616e646f6d
	v2 := k0 ^ 0x6c7967656e657261
	v3 := k1 ^ 0x7465646279746573

	n := len(data)
	end := n - (n % 8)
	for i := 0; i < end; i += 8 {
		m := uint64(data[i]) | uint64(data[i+1])<<8 | uint64(data[i+2])<<16 |
			uint64(data[i+3])<<24 | uint64(data[i+4])<<32 | uint64(data[i+5])<<40 |
			uint64(data[i+6])<<48 | uint64(data[i+7])<<56
		v3 ^= m
		v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
		v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
		v0 ^= m
	}

	// Final block: the 0..7 trailing bytes in the low positions, with the total
	// length (mod 256) in the top byte.
	b := uint64(n) << 56
	for i := end; i < n; i++ {
		b |= uint64(data[i]) << (8 * (i - end))
	}
	v3 ^= b
	v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
	v0 ^= b

	v2 ^= 0xff
	for r := 0; r < 4; r++ {
		v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
	}
	return v0 ^ v1 ^ v2 ^ v3
}

// sipround is one SipHash round. Must match SIPROUND in bpf/lsm.bpf.c.
func sipround(v0, v1, v2, v3 uint64) (uint64, uint64, uint64, uint64) {
	v0 += v1
	v1 = bits.RotateLeft64(v1, 13)
	v1 ^= v0
	v0 = bits.RotateLeft64(v0, 32)
	v2 += v3
	v3 = bits.RotateLeft64(v3, 16)
	v3 ^= v2
	v0 += v3
	v3 = bits.RotateLeft64(v3, 21)
	v3 ^= v0
	v2 += v1
	v1 = bits.RotateLeft64(v1, 17)
	v1 ^= v2
	v2 = bits.RotateLeft64(v2, 32)
	return v0, v1, v2, v3
}
