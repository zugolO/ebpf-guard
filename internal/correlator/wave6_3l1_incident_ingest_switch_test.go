package correlator

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 6.3.L.1, item 2 (№423): тумблер инцидентного слоя.
//
// Цена восстановления слоя (№418) совпала с RSS 254,9 → 269,3 МиБ при лимите
// чарта 256Mi и с потерями кольцевого буфера 41 → 3005 — но между архивами
// сменился весь бинарь, и атрибуция оставалась догадкой. A/B на ОДНОМ бинаре
// держится на двух свойствах тумблера, и оба проверяются здесь: выключенный
// слой НЕ строит инцидентов, и при этом НЕ трогает алерты — иначе A/B мерил
// бы заодно и падение объёма.
func TestWave6_3L1_IncidentIngestSwitch(t *testing.T) {
	newEngine := func(disabled bool) *CorrelationEngine {
		cfg := DefaultCorrelationEngineConfig()
		cfg.Rules = []Rule{{
			ID:        "switch_probe",
			EventType: types.EventDNS,
			Condition: RuleCondition{Field: "qname_length", Op: OpGreaterThan, Values: []string{"10"}},
			Severity:  types.SeverityWarning,
			Action:    ActionAlert,
		}}
		cfg.EnableRateLimit = false
		cfg.EnableAnomaly = false
		cfg.EnableDedup = false
		cfg.IncidentIngestDisabled = disabled
		return NewCorrelationEngineWithConfig(cfg)
	}

	ev := types.Event{
		Type: types.EventDNS,
		PID:  4242,
		DNS:  &types.DNSEvent{QName: "a-long-enough-name.example.com"},
	}

	t.Run("default keeps the layer on", func(t *testing.T) {
		ce := newEngine(false)
		defer ce.Close()
		require.True(t, ce.IncidentIngestEnabled())
		require.Len(t, ce.Ingest(context.Background(), ev), 1)
		assert.Len(t, ce.IncidentTracker().GetAll("", "", 0), 1)
	})

	t.Run("disabled produces alerts but no incidents", func(t *testing.T) {
		ce := newEngine(true)
		defer ce.Close()
		require.False(t, ce.IncidentIngestEnabled())
		alerts := ce.Ingest(context.Background(), ev)
		require.Len(t, alerts, 1, "детект не зависит от тумблера: алерт обязан остаться")
		assert.Empty(t, ce.IncidentTracker().GetAll("", "", 0))
	})

	// Главное свойство для A/B: переключение НА ХОДУ, без пересоздания движка.
	// Рестарт между окнами обнулил бы базы и кучу и измерил бы сам себя
	// ([[ab-toggle-measures-the-restart]]).
	t.Run("flipping at runtime needs no restart", func(t *testing.T) {
		ce := newEngine(false)
		defer ce.Close()

		ce.SetIncidentIngestEnabled(false)
		require.Len(t, ce.Ingest(context.Background(), ev), 1)
		require.Empty(t, ce.IncidentTracker().GetAll("", "", 0), "окно B: слой выключен на том же процессе")

		ce.SetIncidentIngestEnabled(true)
		require.Len(t, ce.Ingest(context.Background(), ev), 1)
		assert.Len(t, ce.IncidentTracker().GetAll("", "", 0), 1, "окно A: слой возвращается без рестарта")
	})

	// №428: A/B прогона collect-6.3-L1 прошёл БЕЗ положительного контроля
	// тумблера — incidents_total стояла на 4 во всех шести снимках, то есть
	// ни одно окно не предъявило, что переключение вообще что-то делает.
	// Сторож — счётчик подачи с ОБЕИМИ ветками: «оба нуля» обязаны читаться
	// как отсутствие нагрузки, а не как работа тумблера.
	t.Run("both outcomes are counted so an empty window cannot pass for a working switch", func(t *testing.T) {
		ce := newEngine(false)
		defer ce.Close()

		read := func(outcome string) float64 {
			return testutil.ToFloat64(incidentIngestTotal.WithLabelValues(outcome))
		}
		on0, gated0 := read(incidentIngestAccepted), read(incidentIngestGated)

		require.Len(t, ce.Ingest(context.Background(), ev), 1)
		onA, gatedA := read(incidentIngestAccepted), read(incidentIngestGated)
		assert.Greater(t, onA, on0, "окно A: включённый слой обязан двигать ingested")
		assert.Equal(t, gated0, gatedA, "окно A: gated стоит")

		ce.SetIncidentIngestEnabled(false)
		require.Len(t, ce.Ingest(context.Background(), ev), 1)
		onB, gatedB := read(incidentIngestAccepted), read(incidentIngestGated)
		assert.Equal(t, onA, onB, "окно B: выключенный слой НЕ двигает ingested")
		assert.Greater(t, gatedB, gatedA, "окно B: gated обязан вырасти — иначе окно было пустым, а не выключенным")
	})
}
