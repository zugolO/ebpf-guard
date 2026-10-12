package correlator

import (
	"context"
	"runtime"
	"sort"
	"testing"
)

// Волна 8.5, A1 (бывший 8.3.8): поток аллокаций на МЕРЕНОМ миксе после F1.
//
// После F1 из потока уходит ≈ 90% syscall-событий (mmap/mprotect/arch_prctl дают
// ≈ 95% syscall-потока), и доля файловых событий — самых дорогих по аллокациям —
// растёт. Бенч A2 на миксе ночи №4 (87,3% file) этого не видит: в его syscall-наборе
// горячих номеров нет вовсе.
//
// Первая версия бенча взяла ОЦЕНКУ микса (file 98,4%) до стенда. Настоящий микс
// снят 12.10.2026 на поде с включённым F1 (три прогона D1, server-logs/collect-8.5-d1;
// events_total по типам и by_nr + kernel_filtered): оценка оказалась далека.
//
//	старт + ≈5 мин idle: file 79,9…81,3%, syscall 18,2…19,5%, network 0,6%
//	                     syscall после F1: nr 321 64%, 59 24,5%, 41 8,8%, прочее ≈ 2,7%
//	пакет атак:          file 71,1…71,4%, syscall 24,0…24,1%, network 4,6…4,8%
//	                     syscall после F1: nr 321 52%, 59 24%, 41 23%, прочее ≈ 0,5%
//
// Здесь тот же генератор A2 с этими долями. Метка 8.5.8 ДОСТИГНУТО, только если ОБА микса ≤ 300.

// w85Mix — мерёный микс (доли в тысячных; остаток — network) и номера syscall после F1.
func w85Mix(n int, fileMilli, sysMilli int, nrWeights map[int64]int) []w82Rec {
	var nrs []int64
	for nr, w := range nrWeights {
		for i := 0; i < w; i++ {
			nrs = append(nrs, nr)
		}
	}
	// Порядок обхода map недетерминирован — сортируем, иначе микс «плывёт» между запусками.
	sort.Slice(nrs, func(i, j int) bool { return nrs[i] < nrs[j] })
	return w82MixSpec(n, w82MixProportions{fileMilli: fileMilli, sysMilli: sysMilli, nrs: nrs})
}

// w85IdleMix — старт + idle пода после F1 (файл 80,8%, syscall 18,6%, network 0,6%).
func w85IdleMix(n int) []w82Rec {
	return w85Mix(n, 808, 186, map[int64]int{321: 644, 59: 245, 41: 88, 157: 10, 62: 7, 105: 6})
}

// w85AttackMix — пакет атак пода после F1 (файл 71,1%, syscall 24,1%, network 4,8%).
func w85AttackMix(n int) []w82Rec {
	return w85Mix(n, 711, 241, map[int64]int{321: 520, 59: 242, 41: 233, 157: 3, 62: 2})
}

// w85PostF1Mix — основной микс бенча (idle).
func w85PostF1Mix(n int) []w82Rec { return w85IdleMix(n) }

func w85MeasureMix(t testing.TB, mix []w82Rec) (perEvent, allocs float64, filePct, sysPct float64) {
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
	return float64(m1.TotalAlloc-m0.TotalAlloc) / w82Measure, float64(m1.Mallocs-m0.Mallocs) / w82Measure,
		100 * float64(file) / float64(len(mix)), 100 * float64(sys) / float64(len(mix))
}

// TestW85_A1_AllocPerEventPostF1Mix — эмиттер метки 8.5.8: Б/событие на двух мерёных
// миксах после F1. Порог ≤ 300 на КАЖДОМ; регресс держит тот же потолок, что и A2.
func TestW85_A1_AllocPerEventPostF1Mix(t *testing.T) {
	if testing.Short() {
		t.Skip("A1: полный микс с поставляемыми правилами")
	}
	if raceEnabled {
		t.Skip("A1: под -race аллокации раздуты")
	}
	idle, idleAllocs, idleFile, idleSys := w85MeasureMix(t, w85IdleMix(w82MixSize))
	att, attAllocs, attFile, attSys := w85MeasureMix(t, w85AttackMix(w82MixSize))
	worst := idle
	if att > worst {
		worst = att
	}
	verdict := "ДОСТИГНУТО"
	if worst > 300 {
		verdict = "ПРОВАЛЕН"
	}
	t.Logf("%s: 8.5.8 %s (худший микс %.0f Б/событие против ≤ 300; idle после F1: %.0f Б/событие, %.1f аллокаций, file %.1f%% syscall %.1f%%; пакет атак после F1: %.0f Б/событие, %.1f аллокаций, file %.1f%% syscall %.1f%%; микс снят на поде 12.10.2026; %d событий)",
		verdict, verdict, worst, idle, idleAllocs, idleFile, idleSys, att, attAllocs, attFile, attSys, w82Measure)
	if w82AllocCeiling > 0 && worst > w82AllocCeiling+10 {
		t.Fatalf("регресс потока аллокаций на миксе после F1: %.0f Б/событие > %.0f", worst, w82AllocCeiling+10)
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
