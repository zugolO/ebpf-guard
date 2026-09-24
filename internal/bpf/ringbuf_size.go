package bpf

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

const (
	// ringBufMinBytes is the smallest valid BPF ring buffer (kernel enforced minimum).
	ringBufMinBytes = 4 * 1024 * 1024 // 4 MB
	// ringBufMaxBytes caps memory usage per ring buffer in constrained environments.
	ringBufMaxBytes = 32 * 1024 * 1024 // 32 MB
	// ringBufPageSize is the required alignment (BPF ring buffers must be page-aligned).
	ringBufPageSize = 4096
)

// RingBufSizeConfig controls ring buffer auto-sizing.
type RingBufSizeConfig struct {
	// SizeBytes overrides auto-detection when > 0. Non-multiples of 4096 are
	// rounded up to the next page boundary, then to the next power of two
	// (both are required by BPF_MAP_TYPE_RINGBUF).
	SizeBytes int
	// MemFractionPct is the percentage of available RAM to allocate per ring
	// buffer when SizeBytes is 0. Zero falls back to the default of 1%.
	MemFractionPct int
}

// ComputeRingBufSize returns the ring buffer byte size to use for a single
// BPF ring buffer map. The returned value is:
//   - cfg.SizeBytes (rounded to page size) when explicitly set
//   - cfg.MemFractionPct % of MemAvailable from /proc/meminfo otherwise
//
// The result is always in [4 MB, 32 MB], a multiple of 4096, and a power of
// two. The power-of-two constraint is not optional: BPF_MAP_TYPE_RINGBUF uses
// max_entries-1 as a bitmask, so the kernel/map layer rejects any other value
// with EINVAL. Page alignment alone does not satisfy it.
func ComputeRingBufSize(cfg RingBufSizeConfig) int {
	if cfg.SizeBytes > 0 {
		return clampRingBuf(roundUpToPow2(roundUpToPage(cfg.SizeBytes)))
	}

	pct := cfg.MemFractionPct
	if pct <= 0 {
		pct = 1
	}

	freeKB := readMemAvailableKB()
	sizeBytes := (freeKB * 1024 * pct) / 100
	return clampRingBuf(roundUpToPow2(roundUpToPage(sizeBytes)))
}

func clampRingBuf(n int) int {
	if n < ringBufMinBytes {
		return ringBufMinBytes
	}
	if n > ringBufMaxBytes {
		return ringBufMaxBytes
	}
	return n
}

func roundUpToPage(n int) int {
	if n <= 0 {
		return ringBufPageSize
	}
	rem := n % ringBufPageSize
	if rem == 0 {
		return n
	}
	return n + ringBufPageSize - rem
}

// roundUpToPow2 rounds n up to the next power of two. BPF ring buffers require
// max_entries to be a power of two in addition to being page-aligned; a
// non-power-of-two size (e.g. 5 MiB) is rejected by the map layer with EINVAL.
func roundUpToPow2(n int) int {
	if n <= 1 {
		return 1
	}
	p := 1
	for p < n {
		next := p << 1
		if next <= 0 {
			// Overflow on absurd inputs (n > 2^62): saturate at the
			// largest power of two instead of wrapping to a negative
			// value and looping forever. clampRingBuf brings any such
			// result down to ringBufMaxBytes anyway.
			return p
		}
		p = next
	}
	return p
}

// readMemAvailableKB reads MemAvailable from /proc/meminfo (in KB).
// Falls back to 512 MB if the file is unavailable (non-Linux, containers without procfs).
func readMemAvailableKB() int {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 512 * 1024
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "MemAvailable:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			if v, err := strconv.Atoi(fields[1]); err == nil && v > 0 {
				return v
			}
		}
		break
	}
	return 512 * 1024
}
