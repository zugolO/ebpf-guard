package collector

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Волна 6.3.9, находка №359. Запись коллектора о своих слепых зонах отстала
// от продукта: №357 научил парсер снимать кадр RFC 1035 §4.2.2, а строка
// blind_spots продолжала называть TCP-DNS слепой зоной — в ТОЙ ЖЕ строке
// журнала, где visibility уже объявляла TCP поддержанным. То же устаревшее
// утверждение стояло в двух likely_causes сторожа немоты.
//
// Цена находки не в самой строке: критерий 6.3.7 держит половину IPv6 на
// формуле «ограничение остаётся ЗАПИСАННЫМ (startup-лог dns.go)» — то есть
// ссылается ровно на эти строки как на доказательство. Пока запись лжёт про
// один транспорт, ею нельзя доказывать ограничение по другому.
//
// Сторож спрашивает ПАРСЕР, что тот умеет, и требует, чтобы объявление этому
// не противоречило — а не сверяет запись с копией самой себя.
func TestWave6_3_9_BlindSpotRecordMatchesParserBehaviour(t *testing.T) {
	// Опорные величины берёт не человек, а сам продукт.
	frame, err := hex.DecodeString(w631TCPFrameFromStand)
	require.NoError(t, err)
	_, tcpTransport, tcpReason := parseDNSMessageAnyTransport(frame)
	_, udpTransport, udpReason := parseDNSMessageAnyTransport(buildDNSQuery("example.com", 1))

	parses := map[string]bool{
		"TCP": tcpReason == "" && tcpTransport == dnsTransportTCP,
		"UDP": udpReason == "" && udpTransport == dnsTransportUDP,
	}

	declared := make(map[string]bool, len(dnsParsedTransports))
	for _, t := range dnsParsedTransports {
		declared[t] = true
	}

	// Половина 1: объявление совпадает с поведением по СОСТАВУ, а не по
	// вхождению — лишний транспорт в объявлении такой же дефект, как забытый.
	for transport, ok := range parses {
		require.Equal(t, ok, declared[transport],
			"транспорт %s: парсер разбирает=%v, dnsParsedTransports заявляет=%v — "+
				"это находка №359: продукт и запись о нём разъехались", transport, ok, declared[transport])
	}
	require.Len(t, dnsParsedTransports, len(parses),
		"в dnsParsedTransports заявлен транспорт, для которого сторож не предъявил фикстуры — "+
			"незамеренное заявление о видимости")

	// Половина 2: поддержанный транспорт не может стоять ни в слепых зонах,
	// ни в гипотезах о недоборе событий. Проверка идёт по ОБЪЯВЛЕНИЮ, а не
	// подстрокой свободного текста: первая версия этой правки хранила обе
	// строки литералами, и подстрока «udp» в пути /proc/<pid>/net/udp
	// оказалась неотличима от заявления о транспорте UDP.
	for _, blind := range dnsBlindTransports {
		require.False(t, declared[blind],
			"транспорт %s заявлен и разбираемым, и слепым одновременно", blind)
	}
	for transport := range declared {
		require.Contains(t, strings.ToUpper(dnsVisibilityRecord()), transport,
			"транспорт %s разбирается, но в visibility не назван — тогда о нём нет записи вовсе", transport)
	}
}

// Вторая половина того же контракта: ограничения, которые ПРОДУКТ не снял,
// обязаны остаться названными. Иначе правка №359 превратилась бы в тихое
// расширение области видимости — ровно то, чего постановка 6.3.7 требует не
// делать («измерить или записать, но НЕ молча»).
func TestWave6_3_9_UnclosedBlindSpotsStayNamed(t *testing.T) {
	record := dnsBlindSpotsRecord()
	for _, must := range []string{
		"IPv6",                     // ни is_dns_packet, ни бэкфилл не читают udp6
		"nss-resolve",              // AF_UNIX/varlink мимо порта 53
		"before the agent started", // остаток №328, бэкфилл закрывает лишь часть
	} {
		require.Contains(t, record, must,
			"незакрытая слепая зона %q пропала из записи — расширение области видимости молчанием", must)
	}

	// Сторож немоты обязан нести те же зоны: до №359 он перечислял TCP как
	// вероятную причину недобора событий, то есть предлагал человеку
	// гипотезу, опровергнутую самим продуктом.
	require.Contains(t, dnsMutenessLikelyCauses(), "nss-resolve",
		"гипотезы сторожа немоты разъехались с записью о слепых зонах")
}
