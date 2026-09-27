package exporter

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

// TestConsumerStartDelayMaterializedAtInit: серия существует В ЭКСПОЗИЦИИ до
// того, как её кто-либо выставил (находка №473). Читается ЧЕРЕЗ gatherer, а не
// через саму переменную: обращение к переменной материализовало бы серию и тест
// прошёл бы на бинаре, где её в /metrics нет
// ([[metric-anchor-must-carry-full-series-name]] — отсутствие серии не есть её
// ноль, и снимок прогона обязан отличать эти два случая).
func TestConsumerStartDelayMaterializedAtInit(t *testing.T) {
	mfs, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)

	const name = "ebpf_guard_consumer_start_delay_seconds"
	var found bool
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		found = true
		require.Len(t, mf.GetMetric(), 1, "серия без лейблов обязана быть одной")
		require.NotNil(t, mf.GetMetric()[0].GetGauge())
	}
	require.True(t, found, "серии %s нет в экспозиции — снимок прогона не сможет отличить её ноль от её отсутствия", name)
}

// TestConsumerStartDelayIsReadAsSnapshot: величина выставляется РОВНО один раз
// за жизнь процесса, поэтому читатель берёт её снимком. Тест держит именно это
// свойство: повторная установка ЗАМЕЩАЕТ величину, а не накапливает её —
// иначе прибор превратился бы в счётчик, и дельта между снимками стала бы
// бессмысленной.
func TestConsumerStartDelayIsReadAsSnapshot(t *testing.T) {
	ConsumerStartDelay.Set(0.25)
	require.InDelta(t, 0.25, testutil.ToFloat64(ConsumerStartDelay), 1e-9)
	ConsumerStartDelay.Set(0.05)
	require.InDelta(t, 0.05, testutil.ToFloat64(ConsumerStartDelay), 1e-9,
		"величина обязана ЗАМЕЩАТЬСЯ: накопление сделало бы снимок нечитаемым")
	ConsumerStartDelay.Set(0)
}

// TestConsumerStartDelayUnsetIsNotZero: до установки серия НЕ равна нулю.
// Иначе «потребитель был готов раньше коллекторов» (здоровая величина — доли
// миллисекунды, в разрезе это 0) стало бы неотличимо от «величину никто не
// выставил», и вердикт о порядке старта читался бы с выключенного прибора
// ([[gated-metric-cannot-carry-product-verdict]]).
func TestConsumerStartDelayUnsetIsNotZero(t *testing.T) {
	require.Less(t, float64(ConsumerStartDelayUnset), 0.0,
		"величина «не выставлено» обязана быть недостижимой для измерения")
}
