package correlator

// №556 (волна 8.3.5): тесты сбрасывали глобальные трекеры ПЕРЕПРИСВАИВАНИЕМ
// указателя (`globalBeaconInterval.resetForTest()`), а фоновая
// горутина очистки любого живого CorrelationEngine (engine.go, тикер ≥ 1 мин)
// читает тот же указатель без синхронизации — `-race` ловил это на стенде как
// «race detected» в TestWave6_2_2_BeaconFixedInterval_RequiresPeriodicity.
// В проде указатели не переприсваиваются; сброс содержимого под собственным
// мьютексом трекера даёт тестам ту же чистую доску без гонки.

func (b *BeaconIntervalTracker) resetForTest() {
	b.mu.Lock()
	b.state = make(map[beaconKey]*beaconState)
	b.mu.Unlock()
}

func (c *ConnFrequencyTracker) resetForTest() {
	c.mu.Lock()
	c.state = make(map[connFreqKey]*timeRing)
	c.mu.Unlock()
}

func (b *BurstTracker) resetForTest() {
	b.mu.Lock()
	b.state = make(map[burstKey]*burstState)
	b.mu.Unlock()
}
