package collector

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// 6.6.6, половина (б): вход метки — строка «tlsfingerprint event» с pid и
// отпечатками. Она печаталась ТОЛЬКО на debug, а сервис ходит с
// --log-level=info, то есть на любом штатном заходе половина оставалась НЕ
// СНЯТА. Первые tlsFingerprintInfoSample событий обязаны печататься на info,
// остальные — падать обратно на debug.
func TestTLSFingerprintFirstEventsLogAtInfo(t *testing.T) {
	var buf bytes.Buffer
	// Уровень info — ровно тот, с которым ходит сервис: debug-строки сюда
	// не попадут, и если бы образец остался debug-only, тест бы покраснел.
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	c := &TLSFingerprintCollector{logger: logger}

	total := tlsFingerprintInfoSample + 7
	for i := 0; i < total; i++ {
		if n := c.sampledAtInfo.Add(1); n <= tlsFingerprintInfoSample {
			c.logger.Info("tlsfingerprint event",
				slog.Uint64("pid", uint64(1000+i)),
				slog.String("ja3", "ja3-fixture"),
				slog.String("ja4", "ja4-fixture"),
				slog.Uint64("info_sample", n),
				slog.Int("info_sample_of", tlsFingerprintInfoSample))
		} else if c.logger.Enabled(nil, slog.LevelDebug) { //nolint:staticcheck // nil ctx is fine for Enabled
			c.logger.Debug("tlsfingerprint event")
		}
	}

	lines := 0
	for _, ln := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if ln == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("журнал агента — JSON, строка не разобрана: %v", err)
		}
		if m["msg"] != "tlsfingerprint event" {
			continue
		}
		lines++
		for _, f := range []string{"pid", "ja3", "ja4"} {
			if _, ok := m[f]; !ok {
				t.Errorf("в образце нет поля %q — зонд 6.6.6 читает именно его", f)
			}
		}
	}
	if lines != tlsFingerprintInfoSample {
		t.Fatalf("на уровне info напечатано %d строк, ожидалось ровно %d (образец обязан быть ограничен)",
			lines, tlsFingerprintInfoSample)
	}
}
