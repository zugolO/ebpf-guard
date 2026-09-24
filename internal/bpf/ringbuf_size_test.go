package bpf

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputeRingBufSize_Explicit(t *testing.T) {
	cases := []struct {
		name  string
		input int
		want  int
	}{
		// 4096 < ringBufMinBytes (4 MB), so it clamps to the minimum.
		{"below min", 4096, ringBufMinBytes},
		{"exact min", ringBufMinBytes, ringBufMinBytes},
		// 5 MiB is page-aligned but not a power of two, so it rounds up to 8 MiB.
		{"not power of two", 5 * 1024 * 1024, 8 * 1024 * 1024},
		// 6*1024*1024+1 = 6291457; next page = 6295552, then next power of two = 8 MiB.
		{"not page aligned", 6*1024*1024 + 1, 8 * 1024 * 1024},
		{"max clamp", 64 * 1024 * 1024, ringBufMaxBytes},
		{"at max", ringBufMaxBytes, ringBufMaxBytes},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ComputeRingBufSize(RingBufSizeConfig{SizeBytes: tc.input})
			assert.Equal(t, tc.want, got)
			assert.Zero(t, got%ringBufPageSize, "result must be page-aligned")
			assert.Zero(t, got&(got-1), "result must be a power of two")
		})
	}
}

func TestComputeRingBufSize_AutoFraction(t *testing.T) {
	// With auto-sizing, result must be page-aligned, a power of two, and within [min, max].
	got := ComputeRingBufSize(RingBufSizeConfig{})
	assert.GreaterOrEqual(t, got, ringBufMinBytes, "must be >= minimum")
	assert.LessOrEqual(t, got, ringBufMaxBytes, "must be <= maximum")
	assert.Zero(t, got%ringBufPageSize, "result must be page-aligned")
	assert.Zero(t, got&(got-1), "result must be a power of two")
}

func TestComputeRingBufSize_CustomFraction(t *testing.T) {
	// 100% of RAM would exceed maxBytes — should clamp to max.
	got := ComputeRingBufSize(RingBufSizeConfig{MemFractionPct: 100})
	assert.Equal(t, ringBufMaxBytes, got)
	assert.Zero(t, got%ringBufPageSize)
}

func TestComputeRingBufSize_ZeroFractionFallsToDefault(t *testing.T) {
	a := ComputeRingBufSize(RingBufSizeConfig{MemFractionPct: 0})
	b := ComputeRingBufSize(RingBufSizeConfig{MemFractionPct: 1})
	// Both use the 1% default, so results should be equal.
	assert.Equal(t, a, b)
}

func TestRoundUpToPage(t *testing.T) {
	cases := []struct{ in, want int }{
		{0, ringBufPageSize},
		{1, ringBufPageSize},
		{4095, ringBufPageSize},
		{4096, 4096},
		{4097, 2 * ringBufPageSize},
		{8192, 8192},
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, roundUpToPage(tc.in), "roundUpToPage(%d)", tc.in)
	}
}

func TestRoundUpToPow2(t *testing.T) {
	cases := []struct{ in, want int }{
		{0, 1},
		{1, 1},
		{2, 2},
		{3, 4},
		{4096, 4096},
		{5 * 1024 * 1024, 8 * 1024 * 1024},
		{8 * 1024 * 1024, 8 * 1024 * 1024},
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, roundUpToPow2(tc.in), "roundUpToPow2(%d)", tc.in)
	}
}

// TestRoundUpToPow2_MaxIntDoesNotHang pins the overflow guard: without it the
// shift wraps to a negative value and the loop never terminates.
func TestRoundUpToPow2_MaxIntDoesNotHang(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	done := make(chan int, 1)
	go func() { done <- roundUpToPow2(maxInt) }()
	select {
	case got := <-done:
		assert.Greater(t, got, 0, "must saturate to a positive power of two, not wrap")
	case <-time.After(2 * time.Second):
		t.Fatal("roundUpToPow2(MaxInt) did not terminate")
	}
}

func TestClampRingBuf(t *testing.T) {
	assert.Equal(t, ringBufMinBytes, clampRingBuf(0))
	assert.Equal(t, ringBufMinBytes, clampRingBuf(ringBufMinBytes-1))
	assert.Equal(t, ringBufMinBytes, clampRingBuf(ringBufMinBytes))
	assert.Equal(t, 5*1024*1024, clampRingBuf(5*1024*1024))
	assert.Equal(t, ringBufMaxBytes, clampRingBuf(ringBufMaxBytes))
	assert.Equal(t, ringBufMaxBytes, clampRingBuf(ringBufMaxBytes+1))
}

func TestReadMemAvailableKB_ReturnsPositive(t *testing.T) {
	// /proc/meminfo is available on Linux; on other platforms the fallback kicks in.
	kb := readMemAvailableKB()
	assert.Greater(t, kb, 0, "memory value must be positive")
}
