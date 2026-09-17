package collector

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// Волна 6.3.1, находка №357. TCP-DNS доходил до парсера и отбрасывался как
// bad_header, потому что двухбайтовый префикс длины кадра (RFC 1035 §4.2.2)
// ложится ровно туда, где парсер ждёт ID сообщения.
//
// Фикстура — НЕ придуманная: это `sample_hex` из журнала агента на стенде
// ebaka2 за 17.09.2026, 19:43:22Z, секунда TCP-пробы контроля 6.3.7. Обрезана
// капчур-лимитом ядра, поэтому проверяется и усечённый кадр тоже.
const w631TCPFrameFromStand = "0048f09d81a00001000200000001076578616d706c6503636f6d0000010001"

func TestWave6_3_1_TCPFramedDNSFromStandParses(t *testing.T) {
	payload, err := hex.DecodeString(w631TCPFrameFromStand)
	require.NoError(t, err)

	// Половина 1: до правки эти байты были ошибкой декода, и именно ею.
	_, reason := parseDNSWireMessage(payload)
	require.Equal(t, dnsDecodeReasonBadHeader, reason,
		"без снятия кадра байты со стенда обязаны оставаться bad_header — иначе фикстура не о том")

	// Половина 2: с распознанным кадром это валидный ответ про example.com.
	msg, transport, reason := parseDNSMessageAnyTransport(payload)
	require.Empty(t, reason)
	require.Equal(t, dnsTransportTCP, transport)
	require.Equal(t, "example.com", msg.qname)
}

func TestWave6_3_1_UDPMessageIsNeverReadAsTCP(t *testing.T) {
	udp := buildDNSQuery("example.com", 1)

	msg, transport, reason := parseDNSMessageAnyTransport(udp)
	require.Empty(t, reason)
	require.Equal(t, dnsTransportUDP, transport,
		"обычный UDP-запрос обязан разбираться как UDP: снятие кадра пробуется ТОЛЬКО после отказа прямого разбора")
	require.Equal(t, "example.com", msg.qname)
}

// Злонамеренное совпадение: UDP-сообщение, чей ID случайно равен len-2, то есть
// выглядит как префикс длины. Прямой разбор такого сообщения проходит, значит
// ветка кадра не должна даже пробоваться.
func TestWave6_3_1_UDPWhoseIDLooksLikeAFrameLengthStaysUDP(t *testing.T) {
	udp := buildDNSQuery("example.com", 1)
	binary.BigEndian.PutUint16(udp[0:2], uint16(len(udp)-2))

	msg, transport, reason := parseDNSMessageAnyTransport(udp)
	require.Empty(t, reason)
	require.Equal(t, dnsTransportUDP, transport,
		"совпадение ID с длиной не делает сообщение TCP-кадром — порядок попыток и есть защита")
	require.Equal(t, "example.com", msg.qname)
}

func TestWave6_3_1_TCPFrameShorterThanBufferIsNotFraming(t *testing.T) {
	payload, err := hex.DecodeString(w631TCPFrameFromStand)
	require.NoError(t, err)

	// Префикс объявляет МЕНЬШЕ, чем байтов в буфере — это не кадр, а совпадение.
	binary.BigEndian.PutUint16(payload[0:2], uint16(len(payload)-3))
	_, ok := tcpFramedPayload(payload)
	require.False(t, ok, "префикс короче наличных байтов кадром не является")

	// Ровно столько, сколько есть, и больше (капчур-лимит срезал хвост) — кадр.
	binary.BigEndian.PutUint16(payload[0:2], uint16(len(payload)-2))
	_, ok = tcpFramedPayload(payload)
	require.True(t, ok)
	binary.BigEndian.PutUint16(payload[0:2], 512)
	_, ok = tcpFramedPayload(payload)
	require.True(t, ok, "усечённый капчуром кадр остаётся кадром — иначе TCP-сообщения длиннее лимита снова слепы")
}

// Сквозная проверка на уровне записи кольца: транспорт доезжает до вызывающего,
// то есть до счётчика ebpf_guard_dns_messages_by_transport_total.
func TestWave6_3_1_DecodeReportsTransport(t *testing.T) {
	framed, err := hex.DecodeString(w631TCPFrameFromStand)
	require.NoError(t, err)

	for _, tc := range []struct {
		name      string
		payload   []byte
		transport string
	}{
		{"tcp-кадр со стенда", framed, dnsTransportTCP},
		{"обычный udp-запрос", buildDNSQuery("example.com", 1), dnsTransportUDP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event, transport, reason := decodeDNSEventWithTransport(buildDNSRawRecord(types.DNSDirectionQuery, tc.payload))
			require.Empty(t, reason)
			require.NotNil(t, event)
			require.Equal(t, tc.transport, transport)
			require.Equal(t, "example.com", event.DNS.QName)
		})
	}
}
