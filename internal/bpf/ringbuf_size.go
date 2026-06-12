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
	// rounded up to the next page boundary (required by the BPF subsystem).
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
// The result is always in [4 MB, 32 MB] and a multiple of 4096, matching
// the kernel's BPF_MAP_TYPE_RINGBUF alignment constraints.
func ComputeRingBufSize(cfg RingBufSizeConfig) int {
	if cfg.SizeBytes > 0 {
		return clampRingBuf(roundUpToPage(cfg.SizeBytes))
	}

	pct := cfg.MemFractionPct
	if pct <= 0 {
		pct = 1
	}

	freeKB := readMemAvailableKB()
	sizeBytes := (freeKB * 1024 * pct) / 100
	return clampRingBuf(roundUpToPage(sizeBytes))
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
