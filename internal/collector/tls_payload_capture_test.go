package collector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/zugolO/ebpf-guard/internal/exporter"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// counterValue reads one series of a CounterVec by its label values.
func counterValue(t *testing.T, vec *prometheus.CounterVec, labels ...string) float64 {
	t.Helper()
	m := &dto.Metric{}
	c, err := vec.GetMetricWithLabelValues(labels...)
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues(%v): %v", labels, err)
	}
	if err := c.(prometheus.Metric).Write(m); err != nil {
		t.Fatalf("write metric: %v", err)
	}
	return m.GetCounter().GetValue()
}

// №496 (разбор №493): событие, у которого захват нагрузки не удался, обязано
// быть отличимо от события, чья нагрузка не подошла ни одному правилу. До этой
// величины оба случая читались снаружи одинаково: events_total вырос, алертов
// нет, слои подавления пусты.
func TestRecordTLSPayloadCaptureSplitsEmptyFromCaptured(t *testing.T) {
	before := map[string]float64{
		"write/captured": counterValue(t, exporter.TLSPayloadCapture, exporter.TLSDirectionWriteLabel, exporter.TLSCaptureCaptured),
		"write/empty":    counterValue(t, exporter.TLSPayloadCapture, exporter.TLSDirectionWriteLabel, exporter.TLSCaptureEmpty),
		"read/captured":  counterValue(t, exporter.TLSPayloadCapture, exporter.TLSDirectionReadLabel, exporter.TLSCaptureCaptured),
		"read/empty":     counterValue(t, exporter.TLSPayloadCapture, exporter.TLSDirectionReadLabel, exporter.TLSCaptureEmpty),
	}

	exporter.RecordTLSPayloadCapture(types.TLSDirectionWrite, 48)
	exporter.RecordTLSPayloadCapture(types.TLSDirectionWrite, 0)
	exporter.RecordTLSPayloadCapture(types.TLSDirectionRead, 0)
	exporter.RecordTLSPayloadCapture(types.TLSDirectionRead, 0)

	got := map[string]float64{
		"write/captured": counterValue(t, exporter.TLSPayloadCapture, exporter.TLSDirectionWriteLabel, exporter.TLSCaptureCaptured) - before["write/captured"],
		"write/empty":    counterValue(t, exporter.TLSPayloadCapture, exporter.TLSDirectionWriteLabel, exporter.TLSCaptureEmpty) - before["write/empty"],
		"read/captured":  counterValue(t, exporter.TLSPayloadCapture, exporter.TLSDirectionReadLabel, exporter.TLSCaptureCaptured) - before["read/captured"],
		"read/empty":     counterValue(t, exporter.TLSPayloadCapture, exporter.TLSDirectionReadLabel, exporter.TLSCaptureEmpty) - before["read/empty"],
	}
	want := map[string]float64{"write/captured": 1, "write/empty": 1, "read/captured": 0, "read/empty": 2}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: дельта %v, ожидалось %v", k, got[k], v)
		}
	}
}

// applyMaxDataSize — источник величины, которую считает счётчик: окно, которое
// увидит слой правил. Провалившийся в ядре захват (captured_len=0) обязан
// доехать сюда нулём, а не длиной записи.
func TestApplyMaxDataSizeReportsEmptyCapture(t *testing.T) {
	c := &TLSCollector{maxDataSize: 256}

	empty := &types.TLSEvent{DataLen: 48, CapturedLen: 0, CapturedSet: true}
	copy(empty.Data[:], "Authorization: Basic dGVzdDp0ZXN0")
	if n := c.applyMaxDataSize(empty); n != 0 {
		t.Fatalf("захват не удался, а окно = %d", n)
	}
	if len(empty.CapturedData()) != 0 {
		t.Fatalf("слою правил видна нагрузка после неудавшегося захвата: %q", empty.CapturedData())
	}

	full := &types.TLSEvent{DataLen: 21, CapturedLen: 21, CapturedSet: true}
	copy(full.Data[:], "Authorization: Basic ")
	if n := c.applyMaxDataSize(full); n != 21 {
		t.Fatalf("окно удавшегося захвата = %d, ожидалось 21", n)
	}
}

// №497: упробе привязывается к ИНОДЕ библиотеки и срабатывает на всех
// процессах, которые её отображают. Ключ тождества обязан совпадать для двух
// путей к одному файлу (host-путь и путь через /proc/<pid>/root) и различаться
// для разных файлов — иначе повторная привязка либо дублирует события, либо
// пропускает чужой mount-ns (№380).
func TestLibraryIdentityKey(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "libssl.so.3")
	if err := os.WriteFile(a, []byte("elf"), 0o644); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(dir, "same-file")
	if err := os.Link(a, linked); err != nil {
		t.Skipf("hard link недоступен: %v", err)
	}
	b := filepath.Join(dir, "other-libssl.so.3")
	if err := os.WriteFile(b, []byte("elf"), 0o644); err != nil {
		t.Fatal(err)
	}

	ka, kl, kb := libraryIdentityKey(a), libraryIdentityKey(linked), libraryIdentityKey(b)
	if ka == "" || kb == "" {
		t.Fatalf("пустой ключ тождества: %q / %q", ka, kb)
	}
	if ka != kl {
		t.Errorf("два пути к одному файлу дали разные ключи: %q != %q", ka, kl)
	}
	if ka == kb {
		t.Errorf("разные файлы дали один ключ: %q", ka)
	}
	if got := libraryIdentityKey(filepath.Join(dir, "нет-такого")); got != "" {
		t.Errorf("несуществующий путь дал ключ %q — привязка была бы пропущена молча", got)
	}
}
