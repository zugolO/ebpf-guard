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
//
// №504 (28.09.2026): у «пусто» ДВЕ причины, и они разного класса. Ноль
// захваченных байт при kernelDataLen==0 — это SSL_write(num<=0), вызов,
// которому нечего было нести (на живом стенде таких 4 из 5); ноль при
// kernelDataLen>0 — отказ bpf_probe_read_user, и только он даёт право на
// продуктовый вердикт о продюсере. Одно слово "empty" на обе причины
// заставляло эмиттер 6.4.3 объявлять продуктовый дефект по первой.
func TestRecordTLSPayloadCaptureSplitsEmptyByCause(t *testing.T) {
	read := func(dir, res string) float64 {
		return counterValue(t, exporter.TLSPayloadCapture, dir, res)
	}
	type key struct{ dir, res string }
	keys := []key{}
	for _, d := range []string{exporter.TLSDirectionWriteLabel, exporter.TLSDirectionReadLabel} {
		for _, r := range exporter.TLSCaptureResults {
			keys = append(keys, key{d, r})
		}
	}
	before := map[key]float64{}
	for _, k := range keys {
		before[k] = read(k.dir, k.res)
	}

	// Ровно тот профиль вызовов, который bpftrace снял на ebaka2 28.09.2026 на
	// обмене контроля item 5: четыре SSL_write с num=0 и один с num=53.
	exporter.RecordTLSPayloadCapture(types.TLSDirectionWrite, 53, 53)
	for i := 0; i < 4; i++ {
		exporter.RecordTLSPayloadCapture(types.TLSDirectionWrite, 0, 0)
	}
	// И отдельно — настоящий отказ чтения: ядро видело 48 байт, захватило ноль.
	exporter.RecordTLSPayloadCapture(types.TLSDirectionRead, 0, 48)

	want := map[key]float64{
		{exporter.TLSDirectionWriteLabel, exporter.TLSCaptureCaptured}:        1,
		{exporter.TLSDirectionWriteLabel, exporter.TLSCaptureEmptyZeroLen}:    4,
		{exporter.TLSDirectionWriteLabel, exporter.TLSCaptureEmptyReadFailed}: 0,
		{exporter.TLSDirectionReadLabel, exporter.TLSCaptureCaptured}:         0,
		{exporter.TLSDirectionReadLabel, exporter.TLSCaptureEmptyZeroLen}:     0,
		{exporter.TLSDirectionReadLabel, exporter.TLSCaptureEmptyReadFailed}:  1,
	}
	for _, k := range keys {
		got := read(k.dir, k.res) - before[k]
		if got != want[k] {
			t.Errorf("%s/%s: дельта %v, ожидалось %v", k.dir, k.res, got, want[k])
		}
	}
}

// Каждое значение result=, которое способна выдать RecordTLSPayloadCapture,
// обязано быть в TLSCaptureResults — иначе init() его не материализует, и
// отсутствие ряда прочитается как «бинарь старее величины», а не как ноль.
func TestTLSCaptureResultsCoverEveryBranch(t *testing.T) {
	in := map[string]bool{}
	for _, r := range exporter.TLSCaptureResults {
		in[r] = true
	}
	for _, r := range []string{
		exporter.TLSCaptureCaptured,
		exporter.TLSCaptureEmptyZeroLen,
		exporter.TLSCaptureEmptyReadFailed,
	} {
		if !in[r] {
			t.Errorf("ветвь result=%q не объявлена в TLSCaptureResults — ряд не будет материализован", r)
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
