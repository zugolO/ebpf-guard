package collector

import (
	"bytes"
	"encoding/binary"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/internal/bpf"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// TestHTTPEventWireSize_MatchesBPFStruct — №471. Коллектор http_plaintext не
// отдал НИ ОДНОГО события за историю проекта: проверка длины требовала 340
// байт (литерал, скопированный от tls_event, который на 37 байт длиннее), а
// ring buffer отдавал ровно 325 — размер packed-структуры http_event. Хук,
// ring buffer и раскладка были в порядке; событие отбивала одна константа, и
// увидеть это можно было ТОЛЬКО живым прогоном (офлайн «код есть» выполнялось).
//
// Тест не повторяет число: он строит событие ТОЙ ЖЕ структурой, которой его
// читает разбор, и требует, чтобы разбор его принял. Любая правка раскладки —
// в C или в Go-зеркале — ломает тест, а не прогон на стенде.
func TestHTTPEventWireSize_MatchesBPFStruct(t *testing.T) {
	// Размер зеркала — та же величина, которой судит разбор.
	require.Equal(t, 325, binary.Size(HTTPEventRaw{}),
		"раскладка http_event разъехалась с bpf/http_uprobe.bpf.c (packed: 4+8+4+4+4+4+16+16+1+4+4+256)")
	require.Equal(t, binary.Size(HTTPEventRaw{}), httpEventRawSize,
		"граница разбора обязана быть вычислена из структуры, а не повторена цифрой")

	raw := HTTPEventRaw{
		Type:        uint32(types.EventHTTPPlaintext),
		Timestamp:   1,
		PID:         4242,
		TGID:        4242,
		UID:         0,
		Direction:   0,
		DataLen:     18,
		CapturedLen: 18,
	}
	copy(raw.Comm[:], "python3")
	copy(raw.Data[:], "GET / HTTP/1.1\r\n\r\n")

	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, &raw))
	require.Equal(t, 325, buf.Len(), "проволочный размер события")

	c := &HTTPCollector{logger: slog.Default()}
	ev, err := c.parseEvent(buf.Bytes())
	require.NoError(t, err, "325-байтовое событие ОБЯЗАНО разбираться: ровно его отбивал литерал 340")
	require.Equal(t, types.EventHTTPPlaintext, ev.Type)
	require.Equal(t, uint32(4242), ev.PID)
	require.Equal(t, "python3", string(bytes.TrimRight(ev.Comm[:], "\x00")), "comm держателя доезжает до события")

	// Отрицательная половина: на один байт короче — отказ, и он НАЗЫВАЕТ обе
	// величины, а не только пришедшую.
	_, err = c.parseEvent(buf.Bytes()[:324])
	require.Error(t, err)
	require.Contains(t, err.Error(), "324")
	require.Contains(t, err.Error(), "325")
}

// TestHTTPEventCgroupID_RoundTripsAndOldRecordStillParses — task 1 of the
// wave 6.6 revision follow-up list. HTTPEventRaw is deliberately left
// untouched (no CgroupID field, httpEventRawSize stays 325 — exactly what
// TestHTTPEventWireSize_MatchesBPFStruct above pins), so a record that grew a
// trailing cgroup_id still passes the same binary.Read gate, and a record of
// the OLD 325-byte size still parses and yields CgroupID 0 rather than an
// error — the failure mode this collector already lost a live run to once
// (№471) is exactly "this record no longer parses at all".
func TestHTTPEventCgroupID_RoundTripsAndOldRecordStillParses(t *testing.T) {
	c := &HTTPCollector{logger: slog.Default()}

	base := HTTPEventRaw{
		Type:        uint32(types.EventHTTPPlaintext),
		Timestamp:   1,
		PID:         4242,
		Direction:   0,
		DataLen:     4,
		CapturedLen: 4,
	}
	copy(base.Comm[:], "curl")
	copy(base.Data[:], "GET ")

	t.Run("old 325-byte record parses and yields CgroupID 0", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, binary.Write(&buf, binary.LittleEndian, &base))
		require.Equal(t, 325, buf.Len())

		ev, err := c.parseEvent(buf.Bytes())
		require.NoError(t, err, "a pre-task-1 record must still decode everything it knew")
		require.Zero(t, ev.CgroupID, "absent is 0, and 0 means «no cgroup id», never «cgroup zero»")
		require.Equal(t, uint32(4242), ev.PID)
	})

	t.Run("new 333-byte record carries the cgroup id through to types.Event", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, binary.Write(&buf, binary.LittleEndian, &base))
		raw := buf.Bytes()
		raw = append(raw, make([]byte, 8)...)
		// Литерал, а не bpf.HTTPEventCgroupIDOffset: записью по той же
		// константе, которой читает разбор, сдвинутая константа согласилась бы
		// сама с собой (образец cgroup_tail_test.go).
		binary.LittleEndian.PutUint64(raw[325:], 0xC0FFEE)
		require.Equal(t, 325, bpf.HTTPEventCgroupIDOffset)

		ev, err := c.parseEvent(raw)
		require.NoError(t, err)
		require.Equal(t, uint64(0xC0FFEE), ev.CgroupID)
		require.Equal(t, uint32(4242), ev.PID, "existing offsets unchanged")
	})
}

// TestTLSEventWireSize_MatchesBPFStruct — сиблинг №471: литерал 340 пришёл
// ИЗ tls.go, где он был не фатален (tls_event весит 362), и стал приборным
// нулём в http_uprobe.go. Граница вычисляется из структуры и здесь.
func TestTLSEventWireSize_MatchesBPFStruct(t *testing.T) {
	require.Equal(t, 362, binary.Size(TLSEventRaw{}),
		"раскладка tls_event разъехалась с bpf/tls_uprobe.bpf.c")
	require.Equal(t, binary.Size(TLSEventRaw{}), tlsEventRawSize)
	require.Greater(t, tlsEventRawSize, httpEventRawSize,
		"tls_event длиннее http_event на информацию о соединении — общий литерал для обоих невозможен по построению")
}
