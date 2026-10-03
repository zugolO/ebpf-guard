package bpf

import "testing"

func TestComputeUprobeRingBufSize(t *testing.T) {
	if got := ComputeUprobeRingBufSize(RingBufSizeConfig{}); got != 4*1024*1024 {
		t.Fatalf("unset must be the 4 MiB minimum regardless of node RAM, got %d", got)
	}
	if got := ComputeUprobeRingBufSize(RingBufSizeConfig{MemFractionPct: 50}); got != 4*1024*1024 {
		t.Fatalf("MemFractionPct must not size a uprobe ring, got %d", got)
	}
	if got := ComputeUprobeRingBufSize(RingBufSizeConfig{SizeBytes: 16 * 1024 * 1024}); got != 16*1024*1024 {
		t.Fatalf("explicit size must be honoured, got %d", got)
	}
}
