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

// Волна 8.7, П6: кольцо TLS по умолчанию 1 МиБ, явный размер уважается (страница, степень двойки).
func TestComputeTLSRingBufSize(t *testing.T) {
	if got := ComputeTLSRingBufSize(RingBufSizeConfig{}); got != 1<<20 {
		t.Fatalf("по умолчанию %d, ожидался 1 МиБ", got)
	}
	if got := ComputeTLSRingBufSize(RingBufSizeConfig{MemFractionPct: 50}); got != 1<<20 {
		t.Fatalf("доля RAM не должна раздувать кольцо TLS: %d", got)
	}
	if got := ComputeTLSRingBufSize(RingBufSizeConfig{SizeBytes: 8 << 20}); got != 8<<20 {
		t.Fatalf("явный размер не уважен: %d", got)
	}
	if got := ComputeTLSRingBufSize(RingBufSizeConfig{}); got&(got-1) != 0 || got%4096 != 0 {
		t.Fatalf("размер не степень двойки, кратная странице: %d", got)
	}
}
