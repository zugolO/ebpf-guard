package exporter

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// Волна 6.3.1, item 6 (№327/№335) + аудит 16.09.2026, открытый вопрос 1:
// RecordAlertVolumeByEventType была покрыта только компиляцией. Здесь
// проверяется то единственное, ради чего ось заведена: вклад ОДНОГО правила
// (anomaly_detection, у которого собственной оси типа события нет вовсе —
// [[anomaly-detection-bypasses-rule-layer]]) разделяется по типу
// ЗАПУСТИВШЕГО события внутри одного окна, без рестарта и без второго окна.
func TestRecordAlertVolumeByEventType_SplitsOneRuleByEventType(t *testing.T) {
	before := func(et, rule string) float64 {
		return testutil.ToFloat64(AlertVolumeByEventType.WithLabelValues(et, rule))
	}
	dnsBefore := before("dns", "anomaly_detection")
	sysBefore := before("syscall", "anomaly_detection")
	ruleBefore := before("dns", "dns_dga_ngram")

	RecordAlertVolumeByEventType("dns", "anomaly_detection")
	RecordAlertVolumeByEventType("dns", "anomaly_detection")
	RecordAlertVolumeByEventType("syscall", "anomaly_detection")
	RecordAlertVolumeByEventType("dns", "dns_dga_ngram")

	if got := before("dns", "anomaly_detection") - dnsBefore; got != 2 {
		t.Errorf("{dns, anomaly_detection}: got +%v, want +2", got)
	}
	if got := before("syscall", "anomaly_detection") - sysBefore; got != 1 {
		t.Errorf("{syscall, anomaly_detection}: got +%v, want +1 — типы события не разделены", got)
	}
	if got := before("dns", "dns_dga_ngram") - ruleBefore; got != 1 {
		t.Errorf("{dns, dns_dga_ngram}: got +%v, want +1", got)
	}
}

// Лейбл event_type обязан быть замкнутым перечислением — иначе счётчик
// становится картой неограниченной кардинальности на ветке, которую никто не
// сторожит. EventTypeLabel отвечает "other" на всё незнакомое.
func TestEventTypeLabel_IsClosedEnum(t *testing.T) {
	if got := EventTypeLabel(255); got != "other" {
		t.Errorf("неизвестный тип события дал %q, а не \"other\" — ось не замкнута", got)
	}
}
