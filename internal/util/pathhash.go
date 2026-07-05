package util

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

// SaltedFNV32aPath is a keyed variant of FNV32aPath: the offset basis is XORed
// with an unpredictable per-boot secret before the rolling hash begins. It
// backs the `sandbox_path_policy` allow-list only (issue #274 item 1) — never
// the plain FNV32aPath uses (path_blocklist / exec-pin path identity), which
// don't gate a deny-by-default boundary the same way.
//
// FNV-1a's round `h = (h ^ b) * prime` is an invertible bijection mod 2^32
// (the prime is odd), so a sandboxed agent that knows the algorithm and a
// target hash value can construct an arbitrary byte sequence colliding with
// it — that's the forgeable-hash bypass. Salting with a secret the workload
// never observes (the secret lives only in a BPF map gated by the same
// bpf()-syscall denial that already protects the sandbox's own maps) removes
// the attacker's ability to compute H_secret(anything) at all, since the
// secret is an unknown input to the function, not just an unknown output.
//
// Must stay byte-for-byte compatible with the salted seed computation in
// sandbox_path_allowed() in bpf/lsm.bpf.c: seed = offsetBasis ^ uint32(secret)
// ^ uint32(secret>>32).
func SaltedFNV32aPath(s string, secret uint64) uint32 {
	const offsetBasis = 2166136261
	const prime = 16777619
	h := uint32(offsetBasis) ^ uint32(secret) ^ uint32(secret>>32) // #nosec G115 -- intentional 64-to-32-bit fold of the random secret, not a bounds-dependent conversion
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
