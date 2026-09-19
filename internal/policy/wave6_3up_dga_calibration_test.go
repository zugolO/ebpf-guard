//go:build rego

package policy

import (
	"context"
	"os"
	"testing"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// №394 (волна 6.3-up). dns.rego's is_dga_domain теперь конъюнкция структурной
// половины (длина первой метки, отсутствие словарного куска, наличие цифры) и
// ИЗМЕРЕННОЙ шкалы — оценки биграммной модели, приезжающей в
// details.dns_ngram_score.
//
// Тест исполняет НАСТОЯЩИЙ rules/rego/dns.rego через OPA — то есть проверяет
// не пересказ предиката в Go (это делает TestWave6_3up_RegoDGAIsSubsetOf
// PrefilterGate в correlator), а сам файл, который поедет на ноду. Две
// половины продукта разъезжаются молча: зеркало в Go можно поправить, забыв
// про .rego, и ровно этот класс стоил волне находки №384.
//
// Оценки в фикстурах измерены 19.09.2026 на DefaultNgramDGADetector: имя
// кластера prometheus-k8s-0 — 0.398, DGA-подобное a7f3k9x2m5p8q1z4 — 0.612.
func TestWave6_3up_RegoDGADependsOnMeasuredScore(t *testing.T) {
	if _, err := os.Stat(regoRulesDir); os.IsNotExist(err) {
		t.Skip("rules/rego not found")
	}
	engine, err := NewRegoEngine(RegoEngineConfig{Enabled: true, RulesDir: regoRulesDir})
	if err != nil {
		t.Fatalf("NewRegoEngine: %v", err)
	}

	alertFor := func(qname string, score interface{}) types.Alert {
		a := types.Alert{
			RuleID:  "dns_any_query",
			Comm:    "python3",
			PID:     4242,
			Details: map[string]interface{}{},
			Event: types.Event{
				Type: types.EventDNS,
				DNS: &types.DNSEvent{
					QName:     qname,
					QType:     255,
					Direction: types.DNSDirectionQuery,
				},
			},
		}
		if score != nil {
			a.Details["dns_ngram_score"] = score
		}
		return a
	}
	firesDGA := func(t *testing.T, a types.Alert) bool {
		t.Helper()
		decisions, err := engine.Evaluate(context.Background(), a)
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		for _, d := range decisions {
			if d.RuleID == "dga_domain" {
				return true
			}
		}
		return false
	}

	// Структура ИСТИНА у обоих имён — различает их только шкала.
	if !firesDGA(t, alertFor("a7f3k9x2m5p8q1z4.invalid", 0.612)) {
		t.Error("DGA-подобное имя с оценкой 0.612 НЕ подняло dga_domain — " +
			"правило недостижимо, и положительный контроль 6.3u.3 провалится на стенде")
	}
	if firesDGA(t, alertFor("prometheus-k8s-0.monitoring.svc.cluster.local", 0.398)) {
		t.Error("штатное кластерное имя с оценкой 0.398 подняло dga_domain — " +
			"калибровка №394 не применена к файлу правил, ложный класс жив")
	}

	// Граница читается как >=, тем же сравнением, что в префильтре.
	if !firesDGA(t, alertFor("zxcvbnmasdfgh123.invalid", 0.55)) {
		t.Error("оценка РОВНО 0.55 не поднимает правило — граница в dns.rego " +
			"разошлась с границей префильтра (>= против >)")
	}

	// Поля нет вовсе: предикат неопределён, правило молчит. Отказ закрытый, и
	// он обязан быть проверен, а не подразумеваться.
	if firesDGA(t, alertFor("a7f3k9x2m5p8q1z4.invalid", nil)) {
		t.Error("правило сработало БЕЗ details.dns_ngram_score — значит конъюнкт " +
			"по измеренной шкале не читается, и калибровка не действует")
	}
}
