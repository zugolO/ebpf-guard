package correlator

import (
	"context"
	"runtime"
	"testing"
)

// Волна 8.5, A1 (бывший 8.3.8): поток аллокаций на НОВОМ миксе событий.
//
// После F1 из потока уходит ≈ 90% syscall-событий (mmap/mprotect/arch_prctl
// дают ≈ 95% syscall-потока), и доля файловых событий — самых дорогих по
// аллокациям (`*types.FileEvent` 288 Б) — растёт. Бенч A2 на миксе ночи №4
// (87,3% file) этого не видит: в его syscall-наборе горячих номеров нет вовсе.
// Здесь тот же детерминированный микс, но с прореженным на 90% syscall-потоком.
// Доля — ОЦЕНКА до стенда (открытый вопрос в plan.md): настоящий микс снимается
// на стенде после F1 из by_nr + kernel_filtered + events_total по типам.

// w85PostF1Mix — микс A2 с оставленным каждым десятым syscall-событием.
func w85PostF1Mix(n int) []w82Rec {
	src := w82Mix(n * 2)
	out := make([]w82Rec, 0, n)
	sys := 0
	for _, r := range src {
		if r.sys != nil {
			if sys++; sys%10 != 0 {
				continue
			}
		}
		out = append(out, r)
		if len(out) == n {
			break
		}
	}
	return out
}

// TestW85_A1_AllocPerEventPostF1Mix — информационная строка метки 8.5.8:
// Б/событие на миксе после F1. Порог ≤ 300 судит ночь закрытия; здесь печатается
// величина и доля file, а регресс держит тот же потолок, что и A2.
func TestW85_A1_AllocPerEventPostF1Mix(t *testing.T) {
	if testing.Short() {
		t.Skip("A1: полный микс с поставляемыми правилами")
	}
	if raceEnabled {
		t.Skip("A1: под -race аллокации раздуты")
	}
	mix := w85PostF1Mix(w82MixSize)
	var file, sys int
	for _, r := range mix {
		switch {
		case r.file != nil:
			file++
		case r.sys != nil:
			sys++
		}
	}

	eng := w82Engine(t)
	defer eng.Close()
	ctx := context.Background()
	ts := w82Run(ctx, eng, mix, 0, w82Warmup, 1_000_000_000)

	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	w82Run(ctx, eng, mix, w82Warmup, w82Measure, ts)
	runtime.ReadMemStats(&m1)

	perEvent := float64(m1.TotalAlloc-m0.TotalAlloc) / w82Measure
	allocs := float64(m1.Mallocs-m0.Mallocs) / w82Measure
	verdict := "ДОСТИГНУТО"
	if perEvent > 300 {
		verdict = "ПРОВАЛЕН"
	}
	t.Logf("%s: 8.5.8 %s (поток %.0f Б/событие, %.1f аллокаций/событие против ≤ 300; микс после F1: file %.1f%% syscall %.1f%%, %d событий)",
		verdict, verdict, perEvent, allocs, 100*float64(file)/float64(len(mix)), 100*float64(sys)/float64(len(mix)), w82Measure)
	if w82AllocCeiling > 0 && perEvent > w82AllocCeiling+10 {
		t.Fatalf("регресс потока аллокаций на миксе после F1: %.0f Б/событие > %.0f", perEvent, w82AllocCeiling+10)
	}
}

// BenchmarkW85_PostF1MixIngest — Б/op на событие микса после F1; для
// -memprofile при разборе, откуда берутся байты.
func BenchmarkW85_PostF1MixIngest(b *testing.B) {
	eng := w82Engine(b)
	defer eng.Close()
	ctx := context.Background()
	mix := w85PostF1Mix(w82MixSize)
	ts := w82Run(ctx, eng, mix, 0, w82Warmup, 1_000_000_000)
	b.ReportAllocs()
	b.ResetTimer()
	w82Run(ctx, eng, mix, w82Warmup, b.N, ts)
}
