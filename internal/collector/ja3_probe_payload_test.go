package collector

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Нагрузка зонда №488 и её ожидаемые отпечатки живут В РЕПОЗИТОРИИ рядом с
// самим зондом, а не константами здесь: те же байты отправляет на стенде
// deploy/docker-test-setup/wave6.6-ja3-probe.sh, и две копии разошлись бы
// молча — тест продолжал бы проходить, доказывая уже НЕ ту нагрузку, которую
// подаёт прогон.
const (
	ja3ProbePayloadFile = "../../deploy/docker-test-setup/wave6.6-ja3-probe.clienthello.hex"
	ja3ProbeExpectFile  = "../../deploy/docker-test-setup/wave6.6-ja3-probe.expect"
)

// ja3ProbeReadKV читает формат «# комментарий» + «ключ=величина», тем же
// разбором, что и шелл-читатели (всё после ПЕРВОГО «=» — величина,
// [[attr-value-containing-equals-breaks-F-split]]).
func ja3ProbeReadKV(t *testing.T, path string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(path))
	require.NoError(t, err, "файл ожиданий зонда №488 обязан лежать рядом с зондом")
	kv := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "="); i > 0 {
			kv[line[:i]] = line[i+1:]
		}
	}
	return kv
}

func ja3ProbePayload(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(ja3ProbePayloadFile))
	require.NoError(t, err, "нагрузка зонда №488 обязана лежать рядом с зондом")
	var sb strings.Builder
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		sb.WriteString(line)
	}
	raw, err := hex.DecodeString(sb.String())
	require.NoError(t, err, "нагрузка обязана быть чистым hex после снятия комментариев")
	return raw
}

// TestJA3ProbePayloadIsAValidClientHello: нагрузка проходит ЧЕТЫРЕ предиката
// фильтра bpf/tls_clienthello.bpf.c и порог длины. Без этого зонд на стенде
// дал бы приборный ноль (пакет ушёл, фильтр его не взял), и ноль читался бы
// как «парсер мёртв» ([[verdict-zero-needs-its-class-presented]]).
func TestJA3ProbePayloadIsAValidClientHello(t *testing.T) {
	p := ja3ProbePayload(t)
	require.Greater(t, len(p), 10, "len<10 отбрасывается фильтром до чтения байт")
	require.LessOrEqual(t, len(p), 512, "TLS_CH_CAPTURE_MAX=512: запись обязана захватываться ЦЕЛИКОМ")
	require.Equal(t, byte(0x16), p[0], "ContentType Handshake")
	require.Equal(t, byte(0x03), p[1])
	require.LessOrEqual(t, p[2], byte(0x04))
	require.Equal(t, byte(0x01), p[5], "HandshakeType ClientHello")
	// Длина записи обязана совпадать с фактической: хендшейк, обрезанный
	// на границе записи, дал бы ПУСТОЙ JA3 и тот же приборный ноль.
	require.Equal(t, len(p)-5, int(binary.BigEndian.Uint16(p[3:5])), "record length ≠ фактической длине нагрузки")
}

// TestJA3ProbeExpectedFingerprintsMatchPayload: ожидаемые отпечатки — это
// ПЕРЕСЧЁТ по нагрузке тем же кодом, что зовёт продукт (decodeTLSClientHello),
// а не числа, переписанные из прогона рукой
// ([[verdict-input-must-be-computed-by-emitter]]). Раскладка здесь УПАКОВАННАЯ,
// то есть тест заодно держит саму №488: сдвиг data с 68 на 72 меняет хеш.
func TestJA3ProbeExpectedFingerprintsMatchPayload(t *testing.T) {
	p := ja3ProbePayload(t)
	exp := ja3ProbeReadKV(t, ja3ProbeExpectFile)

	require.Equal(t, exp["payload_len"], itoa(len(p)), "payload_len в файле ожиданий разошёлся с нагрузкой")
	sum := sha256.Sum256(p)
	require.Equal(t, exp["payload_sha256"], hex.EncodeToString(sum[:]),
		"тождество байтов нагрузки: отпечатки ожидаются для ДРУГИХ байт")

	raw := make([]byte, 68+len(p))
	binary.LittleEndian.PutUint32(raw[0:], 4)               // EVENT_TYPE_TLS
	binary.LittleEndian.PutUint32(raw[12:], 424242)         // pid
	binary.BigEndian.PutUint16(raw[60:], 443)               // dport
	binary.LittleEndian.PutUint16(raw[62:], uint16(len(p))) // captured_len
	binary.LittleEndian.PutUint32(raw[64:], uint32(len(p))) // original_len
	copy(raw[68:], p)

	evt, err := decodeTLSClientHello(raw)
	require.NoError(t, err)
	require.Equal(t, uint32(424242), evt.PID, "pid читается со смещения 12 — упакованная раскладка (№488)")
	require.Equal(t, exp["ja3"], evt.TLS.JA3, "ожидаемый JA3 разошёлся с пересчитанным по нагрузке")
	require.Equal(t, exp["ja4"], evt.TLS.JA4, "ожидаемый JA4 разошёлся с пересчитанным по нагрузке")
	require.NotEmpty(t, evt.TLS.JA3, "пустой отпечаток сделал бы сверку зонда бессодержательной")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
