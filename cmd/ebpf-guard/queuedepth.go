package main

import "math"

// Волна 8.8, обвал за потолком (8.8.2 под 1 ядро = 0,41).
//
// Под перегрузкой обе очереди событий (protected и bulk) заполняются до дна, и
// каждое ждущее событие — живой объект с указателями. В поде чарт задаёт
// GOMEMLIMIT (85 МиБ при limits.memory 192Mi): две полные очереди по 65 536
// событий (≈36 МиБ) поверх рабочей кучи (≈45 МиБ) упирают живую кучу в предел,
// и GC крутится без остановки (next_gc < heap_inuse; до 33% CPU профиля на
// разметке при квоте в 1 ядро). CPU уходит из обработки, очереди остаются
// полными — петля: 60 000 оп/с → 25 тыс. соб./с, max → 16 тыс. против 38 тыс.
// у потолка. При глубине 8192 (плечо h, 18.10) та же лестница держит плато:
// 43,9 / 43,5 тыс. соб./с, куча 45–52 МиБ.
//
// Поэтому при заданном мягком пределе памяти глубина каждой очереди
// ограничивается так, чтобы ОБЕ полные очереди занимали не больше
// queueMemShare от предела. Без предела (хост) ничего не меняется: там
// GC-петли нет, а глубина 65 536 держит всплески пакета атак (пик event_low
// 11 043, правило владельца волны 8.1, item 10).

// queuedEventBytes — живая куча на одно событие в очереди: указатель в буфере
// канала, types.Event из пула и его подобъекты (File/Syscall/Network, строки).
// Замер: +36 МиБ кучи при заполнении 2×65 536 (под 1 ядро, ступени 45 000 → 60 000).
const queuedEventBytes = 288

// queueMemShare — доля мягкого предела памяти на обе очереди вместе. Плечи
// 18.10 (под 1 ядро, предел 85 МиБ): 16 384 держит плато, но на max куча 69 МиБ
// и next_gc снова ниже heap_inuse — край; 8192 — 45 МиБ с запасом. 0,05 даёт
// ≈ 7 740 на очередь; пик под пакетом атак в поде — 392 (1 ядро) и 493 (2 ядра).
const queueMemShare = 0.05

// minQueueDepth — нижняя граница: под пакетом атак пик в поде 392 (1 ядро)
// и 493 (2 ядра); правило владельца — пик < 25% ёмкости.
const minQueueDepth = 4096

// capQueueDepthByMemLimit returns the per-queue depth to use given the
// configured depth and the Go soft memory limit (debug.SetMemoryLimit(-1);
// math.MaxInt64 means no limit). The second result reports whether the
// depth was lowered.
func capQueueDepthByMemLimit(depth int, memLimit int64) (int, bool) {
	if depth <= 0 || memLimit <= 0 || memLimit == math.MaxInt64 {
		return depth, false
	}
	capDepth := int(float64(memLimit) * queueMemShare / (2 * queuedEventBytes))
	if capDepth < minQueueDepth {
		capDepth = minQueueDepth
	}
	if depth <= capDepth {
		return depth, false
	}
	return capDepth, true
}
