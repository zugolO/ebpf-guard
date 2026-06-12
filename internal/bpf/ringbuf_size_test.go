package bpf

import (
	"testing"

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
		{"already aligned", 5 * 1024 * 1024, 5 * 1024 * 1024},
		// 6*1024*1024+1 = 6291457; next page = ceil(6291457/4096)*4096 = 1537*4096 = 6295552
		{"not page aligned", 6*1024*1024 + 1, 1537 * 4096},
		{"max clamp", 64 * 1024 * 1024, ringBufMaxBytes},
		{"at max", ringBufMaxBytes, ringBufMaxBytes},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ComputeRingBufSize(RingBufSizeConfig{SizeBytes: tc.input})
			assert.Equal(t, tc.want, got)
			assert.Zero(t, got%ringBufPageSize, "result must be page-aligned")
		})
	}
}

func TestComputeRingBufSize_AutoFraction(t *testing.T) {
	// With auto-sizing, result must be page-aligned and within [min, max].
	got := ComputeRingBufSize(RingBufSizeConfig{})
	assert.GreaterOrEqual(t, got, ringBufMinBytes, "must be >= minimum")
	assert.LessOrEqual(t, got, ringBufMaxBytes, "must be <= maximum")
	assert.Zero(t, got%ringBufPageSize, "result must be page-aligned")
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
