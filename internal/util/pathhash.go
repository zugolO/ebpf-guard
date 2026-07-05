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
