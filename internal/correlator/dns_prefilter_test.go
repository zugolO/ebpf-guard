package correlator

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// makeQueryEvent is a test helper that builds a DNS query DNSEvent.
func makeQueryEvent(qname string, qtype uint16) *types.DNSEvent {
	return &types.DNSEvent{
		QName:     qname,
		QType:     qtype,
		Direction: types.DNSDirectionQuery,
		RCode:     0,
	}
}

func TestDNSPrefilter_BenignDomains(t *testing.T) {
	f := DefaultDNSPrefilter()

	benign := []string{
		"google.com",
		"github.com",
		"api.github.com",
		"cdn.example.com",
		"mail.example.org",
	}
	for _, domain := range benign {
		ev := makeQueryEvent(domain, 1 /* A */)
		if f.ShouldEvaluate(ev, "curl", "") {
			t.Errorf("benign domain %q: ShouldEvaluate=true, want false", domain)
		}
	}
}

func TestDNSPrefilter_DGADomains(t *testing.T) {
	f := DefaultDNSPrefilter()

	// These domains should trigger either high entropy or high ngram DGA score.
	dga := []string{
		"xvzk8f2p9qmj3.com",      // random alphanum — high entropy
		"q3f9mxzp2kvj8yw4.net",   // random alphanum — high entropy
		"a1b2c3d4e5f6g7h8i9j.io", // random chars
	}
	for _, domain := range dga {
		ev := makeQueryEvent(domain, 1)
		if !f.ShouldEvaluate(ev, "bash", "") {
			t.Errorf("DGA domain %q: ShouldEvaluate=false, want true", domain)
		}
	}
}

// Wave 6.3 item 1 (plan.md, ревизия 19.09.2026): the default dgaThreshold
// (internal/correlator/dns_prefilter.go) was 0.8, picked from a "<1% FP"
// comment rather than a measurement. DefaultNgramDGADetector().Score() on
// the DGA strings measured that day tops out at 0.612 — every one of them
// sat under 0.8 on the NgramScore path alone, so if IsDGA's own conjunct
// gate (entropy>3.5 AND per-label score>0.5) had not separately caught
// them, none would ever have been forwarded to Rego. This pins the
// threshold to the measured scale directly, independent of the IsDGA path.
func TestDNSPrefilter_DGAThresholdMatchesMeasuredScale(t *testing.T) {
	f := DefaultDNSPrefilter()
	if f.dgaThreshold != 0.55 {
		t.Fatalf("dgaThreshold = %v, want 0.55 (dns_dga_ngram rule threshold, rules/dns-threats.yaml) — "+
			"a stricter value can again make DGA forwarding unreachable, see plan.md wave 6.3 item 1",
			f.dgaThreshold)
	}

	// Of the four DGA strings measured 19.09.2026, only these two clear the
	// rule's own 0.55 line (0.548 and 0.544 do not — the same thin margin
	// the dns_dga_ngram rule comment already documents). This test only
	// claims what the measurement supports: that raising dgaThreshold above
	// 0.55 would again make the NgramScore path unreachable for domains the
	// rule itself is meant to catch.
	for _, s := range []string{
		"a7f3k9x2m5p8q1z4", // measured 0.612, 19.09.2026
		"kq3x9zvbmwr7ntpd", // measured 0.572
	} {
		score := DefaultNgramDGADetector().Score(s)
		if score <= f.dgaThreshold {
			t.Fatalf("%q: NgramDGADetector.Score()=%v no longer clears dgaThreshold=%v — "+
				"the measured scale moved, re-measure and re-pin both", s, score, f.dgaThreshold)
		}
	}
}

func TestDNSPrefilter_SuspiciousTLD(t *testing.T) {
	f := DefaultDNSPrefilter()

	tlds := []struct {
		domain string
	}{
		{"malware.tk"},
		{"evil.ml"},
		{"phishing.xyz"},
		{"c2.top"},
		{"backdoor.click"},
		{"evil.onion"}, // in DNSEntropyCalculator list
		{"hidden.bit"}, // in DNSEntropyCalculator list
	}
	for _, tc := range tlds {
		ev := makeQueryEvent(tc.domain, 1)
		if !f.ShouldEvaluate(ev, "curl", "") {
			t.Errorf("suspicious TLD %q: ShouldEvaluate=false, want true", tc.domain)
		}
	}
}

func TestDNSPrefilter_TXTRecord(t *testing.T) {
	f := DefaultDNSPrefilter()
	// TXT queries from any domain must pass through (potential tunneling).
	ev := &types.DNSEvent{
		QName:     "google.com",
		QType:     16, // TXT
		Direction: types.DNSDirectionQuery,
	}
	if !f.ShouldEvaluate(ev, "curl", "") {
		t.Error("TXT query: ShouldEvaluate=false, want true")
	}
}

func TestDNSPrefilter_NXDOMAIN(t *testing.T) {
	f := DefaultDNSPrefilter()
	ev := &types.DNSEvent{
		QName:     "google.com",
		QType:     1,
		Direction: types.DNSDirectionResponse,
		RCode:     3, // NXDOMAIN
	}
	if !f.ShouldEvaluate(ev, "bash", "") {
		t.Error("NXDOMAIN response: ShouldEvaluate=false, want true")
	}
}

func TestDNSPrefilter_LongQuery(t *testing.T) {
	f := DefaultDNSPrefilter()
	// 51-char label without other suspicious signals.
	long := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa12.com" // len > 50
	ev := makeQueryEvent(long, 1)
	if !f.ShouldEvaluate(ev, "curl", "") {
		t.Errorf("long query %q: ShouldEvaluate=false, want true", long)
	}
}

func TestDNSPrefilter_MinerProcess(t *testing.T) {
	f := DefaultDNSPrefilter()
	// Benign domain but queried by a miner process.
	ev := makeQueryEvent("pool.example.com", 1)
	if !f.ShouldEvaluate(ev, "xmrig", "") {
		t.Error("miner comm xmrig: ShouldEvaluate=false, want true")
	}
	if !f.ShouldEvaluate(ev, "minerd", "") {
		t.Error("miner comm minerd: ShouldEvaluate=false, want true")
	}
	if !f.ShouldEvaluate(ev, "cgminer", "") {
		t.Error("miner comm cgminer: ShouldEvaluate=false, want true")
	}
}

func TestDNSPrefilter_MiningDomain(t *testing.T) {
	f := DefaultDNSPrefilter()

	miners := []string{
		"xmrig.com",
		"minexmr.com",
		"nanopool.org",
		"hashvault.pro",
		"moneroocean.stream",
		"stratum.pool.example",
		"mine.pool.example",
	}
	for _, d := range miners {
		ev := makeQueryEvent(d, 1)
		if !f.ShouldEvaluate(ev, "python", "") {
			t.Errorf("mining domain %q: ShouldEvaluate=false, want true", d)
		}
	}
}

func TestDNSPrefilter_TorExitDomain(t *testing.T) {
	f := DefaultDNSPrefilter()
	ev := makeQueryEvent("tor.exit.somenode.org", 1)
	if !f.ShouldEvaluate(ev, "curl", "") {
		t.Error("tor exit domain: ShouldEvaluate=false, want true")
	}
}

func TestDNSPrefilter_DynamicDNS(t *testing.T) {
	f := DefaultDNSPrefilter()

	ddns := []string{
		"myhome.dyndns.org",
		"evil.ddns.net",
		"c2.duckdns.org",
		"bot.hopto.org",
		"host.zapto.org",
		"srv.sytes.net",
	}
	for _, d := range ddns {
		ev := makeQueryEvent(d, 1)
		if !f.ShouldEvaluate(ev, "nc", "") {
			t.Errorf("dynamic DNS domain %q: ShouldEvaluate=false, want true", d)
		}
	}
}

func TestDNSPrefilter_NilEvent(t *testing.T) {
	f := DefaultDNSPrefilter()
	// nil event must not panic and must return true (safe default).
	if !f.ShouldEvaluate(nil, "curl", "") {
		t.Error("nil DNSEvent: ShouldEvaluate=false, want true")
	}
}

// BenchmarkDNSPrefilter measures the fast path (benign domain, cached) and the
// slow path (uncached suspicious domain).
//
// Expected results (linux/amd64):
//
//	benign/cached       ~200 ns/op  0 allocs
//	suspicious/uncached ~6 µs/op    ~30 allocs (first analysis)
//	suspicious/cached   ~200 ns/op  0 allocs
//
// Wave 6.3 item 1 (findings №384/№385) added two Go mirrors of Rego predicates
// in front of the analyzer. Measured on darwin/arm64, 19.09.2026: benign/cached
// 90.9 → 94.0 ns/op (the two mirrors exit early), suspicious/dga_cached
// 33.0 → 105.8 ns/op — the positive path is the one that must run the whole
// fourteen-word dictionary scan before it can answer "yes". Both stay well
// inside the ~200 ns budget above, and this path runs once per DNS ALERT
// (evaluateRegoPolicies is post-YAML-filter), not once per DNS event.
func BenchmarkDNSPrefilter(b *testing.B) {
	f := DefaultDNSPrefilter()

	b.Run("benign/cached", func(b *testing.B) {
		ev := makeQueryEvent("google.com", 1)
		// Warm the cache.
		f.ShouldEvaluate(ev, "curl", "")
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			f.ShouldEvaluate(ev, "curl", "")
		}
	})

	b.Run("suspicious/dga_cached", func(b *testing.B) {
		ev := makeQueryEvent("xvzk8f2p9qmj3.com", 1)
		// Warm the cache.
		f.ShouldEvaluate(ev, "bash", "")
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			f.ShouldEvaluate(ev, "bash", "")
		}
	})
}

// Finding №384 → №394. dns.rego's is_dga_domain WAS a length+digit heuristic
// that the n-gram score neither implies nor is implied by, and the prefilter
// gated the whole dga_domain rule on the score alone — that class was dropped
// at EVERY value of dgaThreshold (№384). №394 closed it from the other end:
// the predicate now carries the score as a conjunct, so it became a strict
// subset of the prefilter's n-gram gate, and coverage holds by construction
// rather than by a mirrored branch.
//
// This test proves the subset relation directly, on both halves of the
// measured table: names the calibration REMOVED from the rule (score < 0.55)
// and names it KEPT (score >= 0.55). Scores were measured 19.09.2026 on
// DefaultDNSPrefilter's analyzer and are pinned here, so a model change shows
// up as a failing assertion rather than as a silently different product.
func TestWave6_3up_RegoDGAIsSubsetOfPrefilterGate(t *testing.T) {
	f := DefaultDNSPrefilter()

	// Штатные кластерные имена: структурная половина предиката ИСТИНА на
	// каждом, и до №394 правило dga_domain поднималось на всех них.
	benign := []struct {
		qname string
		ngram float64
	}{
		{"prometheus-k8s-0.monitoring.svc.cluster.local", 0.398},
		{"elasticsearch-data-2.logging.svc.cluster.local", 0.310},
		{"redis-master-0.default.svc.cluster.local", 0.316},
		{"postgres-primary-1.db.svc.cluster.local", 0.353},
		{"kafka-broker-0.kafka.svc.cluster.local", 0.515},
		{"node-000000000001.cluster.local", 0.525},
		{"server1234567890.example.com", 0.430},
		{"grafana-agent-7d9f8b6c4-x2m5p.monitoring.svc", 0.523},
		{"ip-10-0-14-233.eu-central-1.compute.internal", 0.542},
		{"worker-node-12.internal.example.com", 0.410},
		{"user1234-workspace-42.dev.example.com", 0.407},
		{"backup-2026-09-19.storage.example.com", 0.471},
		{"cache-node-0f3a91.internal", 0.497},
		{"argocd-repo-server-6b5.argocd.svc.cluster.local", 0.460},
		{"otel-collector-7c9.observability.svc", 0.440},
	}
	// DGA-подобные: и структура, и шкала. Эти правило ловило и ловит.
	dga := []struct {
		qname string
		ngram float64
	}{
		{"a7f3k9x2m5p8q1z4.com", 0.612},
		{"xkqjw3mzp9vbn2ld.net", 0.618},
		{"q9z8x7c6v5b4n3m2.info", 0.611},
		{"zxcvbnmasdfgh123.org", 0.551},
		{"h7g2k9p4m1n8b3v6.biz", 0.619},
		{"kqwmdlrpxbqmzz12.com", 0.625},
		{"1z2x3c4v5b6n7m8q.top", 0.611},
	}

	// Порог один на три читателя: здесь, в префильтре и в rules/rego/dns.rego.
	require.InDelta(t, dnsRegoNgramThreshold, f.dgaThreshold, 1e-9,
		"порог префильтра разошёлся с порогом предиката dns.rego — "+
			"инвариант подмножества перестал держаться")

	for _, tc := range benign {
		score := DefaultNgramDGADetector().Score(tc.qname)
		require.InDelta(t, tc.ngram, score, 0.002,
			"%q: измеренная оценка сдвинулась (было %.3f, стало %.3f) — "+
				"модель изменилась, таблицу калибровки №394 надо переснять", tc.qname, tc.ngram, score)
		require.True(t, dnsRegoDGAHeuristic(tc.qname),
			"%q: структурная половина перестала матчить — имя больше не показывает "+
				"класс ложных срабатываний, ради которого стоит в таблице", tc.qname)
		require.Less(t, score, dnsRegoNgramThreshold,
			"%q: штатное имя перешагнуло порог — калибровка №394 больше не "+
				"убирает этот ложный класс", tc.qname)
	}

	for _, tc := range dga {
		score := DefaultNgramDGADetector().Score(tc.qname)
		require.InDelta(t, tc.ngram, score, 0.002,
			"%q: измеренная оценка сдвинулась (было %.3f, стало %.3f)", tc.qname, tc.ngram, score)
		require.True(t, dnsRegoDGAHeuristic(tc.qname),
			"%q: структурная половина не матчит — имя не может поднять dga_domain "+
				"ни при какой оценке", tc.qname)
		require.GreaterOrEqual(t, score, dnsRegoNgramThreshold,
			"%q: DGA-имя не добирает до порога — калибровка №394 потеряла бы его", tc.qname)

		// ИНВАРИАНТ ПОКРЫТИЯ: всё, на чём срабатывает предикат Rego, обязано
		// доехать до Rego. Проверяется на comm/parent_comm, которые сами по
		// себе не форвардят ничего.
		ev := &types.DNSEvent{QName: tc.qname, QType: 1, Direction: types.DNSDirectionQuery}
		require.True(t, f.ShouldEvaluate(ev, "curl", "systemd"),
			"%q: предикат dns.rego истинен, а префильтр событие выбрасывает — "+
				"дыра класса №384 вернулась", tc.qname)
	}
}

// Граница читается ОДИНАКОВО по обе стороны: Rego сравнивает `>= 0.55`, и
// префильтр обязан форвардить ровно от того же значения. Пока сравнение здесь
// было строгим `>`, имя с оценкой в точности 0.55 удовлетворяло бы правилу и
// никогда до него не доезжало — та же дыра №384 шириной в одну точку.
func TestWave6_3up_PrefilterForwardsExactlyAtThreshold(t *testing.T) {
	f := NewDNSPrefilter(3.5, 0.55, nil)
	analysis := f.analyzer.AnalyzeDomain("zxcvbnmasdfgh123.org")
	require.GreaterOrEqual(t, analysis.NgramScore, f.dgaThreshold)
	require.True(t, f.ShouldEvaluate(
		&types.DNSEvent{QName: "zxcvbnmasdfgh123.org", QType: 1, Direction: types.DNSDirectionQuery},
		"curl", "systemd"))

	// И обратная сторона: имя ПОД порогом со структурой предиката больше не
	// форвардится вовсе — цена калибровки, которую №384 платил наоборот.
	require.False(t, f.ShouldEvaluate(
		&types.DNSEvent{QName: "prometheus-k8s-0.monitoring.svc.cluster.local", QType: 1, Direction: types.DNSDirectionQuery},
		"curl", "systemd"),
		"штатное кластерное имя снова уезжает в OPA — калибровка не даёт выигрыша, ради которого делалась")
}

// withDNSNgramScore кладёт в детали ИМЕННО ту величину, по которой судит
// dns.rego: без неё предикат неопределён и правило не срабатывает вовсе
// ([[rule-fields-and-binary-ship-together]] — поле условия и бинарь едут
// вместе, и здесь это одна и та же сборка).
func TestWave6_3up_NgramScoreTravelsInAlertDetails(t *testing.T) {
	alert := types.Alert{Event: types.Event{Type: types.EventDNS, DNS: &types.DNSEvent{
		QName: "a7f3k9x2m5p8q1z4.com", QType: 1, Direction: types.DNSDirectionQuery,
	}}}
	got := withDNSNgramScore(alert)
	score, ok := got.Details["dns_ngram_score"].(float64)
	require.True(t, ok, "поле dns_ngram_score не положено в details — предикат dns.rego "+
		"останется неопределённым, и dga_domain не сработает НИ РАЗУ")
	require.InDelta(t, 0.612, score, 0.002)
	require.GreaterOrEqual(t, score, dnsRegoNgramThreshold)

	// Не-DNS алерт не трогается вовсе.
	plain := types.Alert{Event: types.Event{Type: types.EventSyscall}}
	require.Nil(t, withDNSNgramScore(plain).Details)
}

// The mirror must stay a mirror, not a superset: ordinary cluster names that
// dns.rego itself would NOT call DGA must keep skipping Rego, or the prefilter
// stops paying for itself.
func TestDNSPrefilter_RegoDGAHeuristicIsNotASuperset(t *testing.T) {
	f := DefaultDNSPrefilter()
	for _, qname := range []string{
		"kubernetes.default.svc.cluster.local",    // first label ≤ 12 chars
		"api-gateway-prod-7.example.com",          // contains "api"
		"grafana.monitoring.svc.cluster.local",    // short, no digit
		"elasticsearch.logging.svc.cluster.local", // long label, no digit
	} {
		ev := &types.DNSEvent{QName: qname, QType: 1, Direction: types.DNSDirectionQuery}
		if f.ShouldEvaluate(ev, "curl", "systemd") {
			t.Errorf("%q: forwarded to Rego, but no rule of the dns partition can fire on it", qname)
		}
	}
}

// Finding №385 (wave 6.3 item 1). lineage.rego is compiled into the SAME "dns"
// Rego partition as dns.rego (regoPartitionModules, internal/policy/rego_enabled.go),
// and five of its rules read only comm/parent_comm — a shell resolving a wholly
// ordinary name, spawned by a web server, is the reverse-shell shape they exist
// to catch. The prefilter dropped those events because the qname was benign.
func TestDNSPrefilter_ForwardsLineageReachableParents(t *testing.T) {
	f := DefaultDNSPrefilter()
	benign := "kubernetes.default.svc.cluster.local"
	ev := &types.DNSEvent{QName: benign, QType: 1, Direction: types.DNSDirectionQuery}

	for _, tc := range []struct{ comm, parent, rule string }{
		{"bash", "nginx", "reverse_shell_webserver"},
		{"python3", "httpd", "reverse_shell_webserver"},
		{"sh", "postgres", "shell_from_database"},
		{"bash", "init", "init_spawns_shell"},
		{"bash", "cron", "cron_spawns_shell"},
		{"perl", "apt-get", "package_manager_shell"},
	} {
		if !f.ShouldEvaluate(ev, tc.comm, tc.parent) {
			t.Errorf("comm=%s parent=%s: dropped before Rego, but lineage.rego %s matches it",
				tc.comm, tc.parent, tc.rule)
		}
	}

	// And the complement: neither half alone is a signal, so a benign name
	// from a non-shell child or an uninteresting parent still skips Rego.
	for _, tc := range []struct{ comm, parent string }{
		{"curl", "nginx"},   // not a shell
		{"bash", "systemd"}, // parent no lineage rule names
		{"bash", ""},        // parent unknown
	} {
		if f.ShouldEvaluate(ev, tc.comm, tc.parent) {
			t.Errorf("comm=%s parent=%q: forwarded to Rego with no rule able to fire",
				tc.comm, tc.parent)
		}
	}
}

// ФИКСТУРЫ СТЕНДОВЫХ КОНТРОЛЕЙ 6.3u.3 и 6.3u.4, пришпиленные ОФЛАЙН.
//
// Оба контроля (deploy/docker-test-setup/wave6.3.9f-item3-baseline-controls.sh)
// доказывают, что событие дошло до Rego ИМЕННО по своему механизму: 6.3u.3 —
// по зеркалу dns.rego is_dga_domain (№384), 6.3u.4 — по оси parent_comm
// (№385). Это верно лишь пока имя зонда не форвардится НИ ОДНОЙ другой
// проверкой префильтра. Свойство хрупкое и уже однажды ломалось: первая
// версия 6.3u.3 несла 8-значный случайный суффикс, и вторая метка имени
// «w63u3<tag>» сама набирала 0.55…0.64 по n-gram — контроль прошёл бы,
// измеряя чужой механизм.
//
// Сторож живёт здесь, а не на стенде, потому что на стенде такая поломка
// выглядит как УСПЕХ ([[self-test-fixtures-miss-live-log-shape]] наоборот:
// здесь офлайн видит то, чего живой прогон увидеть не может).
func TestWave6_3u_StandProbeFixturesStayAttributable(t *testing.T) {
	f := DefaultDNSPrefilter()

	// ── 6.3u.3 после калибровки №394 — ДВА зонда, и оба обязаны остаться
	// тем, чем задуманы, при любом из 65536 суффиксов контроля.
	//
	//   положительный: структура ∧ оценка >= 0.55  -> dga_domain обязан подняться;
	//   отрицательный: структура ∧ оценка <  0.55  -> обязан НЕ подниматься.
	//
	// Отрицательный зонд и есть контроль самой калибровки: до №394 он поднимал
	// dga_domain (это и был класс ложных срабатываний на кластерных именах), и
	// его ноль на стенде значим только рядом с единицей положительного — иначе
	// это ноль неизвестного происхождения ([[positive-control-needs-result-sentinel]]).
	for _, tag := range []string{"a1b2", "ffff", "0f1e", "0000", "dead", "9c4e"} {
		pos := "a7f3k9x2m5p8q1z4.w63u3" + tag + ".invalid"
		neg := "server1234567890.w63u3" + tag + ".invalid"

		for _, qname := range []string{pos, neg} {
			require.True(t, dnsRegoDGAHeuristic(qname),
				"%q: зонд 6.3u.3 перестал удовлетворять структурной половине "+
					"is_dga_domain — контроль перестал спрашивать про калибровку", qname)
			require.LessOrEqual(t, len(qname), 50,
				"%q: имя переросло 50 символов — форвард пойдёт по long_dns_query", qname)
		}

		posScore := DefaultNgramDGADetector().Score(pos)
		require.GreaterOrEqual(t, posScore, dnsRegoNgramThreshold,
			"%q: положительный зонд не добирает до порога (%.3f) — 6.3u.3 недостижим "+
				"по построению и потратит прогон", pos, posScore)
		require.True(t, f.ShouldEvaluate(
			&types.DNSEvent{QName: pos, QType: 255, Direction: types.DNSDirectionQuery}, "python3", "bash"),
			"%q: положительный зонд не форвардится вовсе", pos)

		negScore := DefaultNgramDGADetector().Score(neg)
		require.Less(t, negScore, dnsRegoNgramThreshold,
			"%q: отрицательный зонд перешагнул порог (%.3f) — он перестал быть "+
				"контролем калибровки и его ноль на стенде нечего будет читать", neg, negScore)
		require.False(t, f.ShouldEvaluate(
			&types.DNSEvent{QName: neg, QType: 255, Direction: types.DNSDirectionQuery}, "python3", "bash"),
			"%q: отрицательный зонд всё ещё уезжает в OPA — калибровка №394 не "+
				"даёт выигрыша, и её контроль это не заметит", neg)
	}

	// ── 6.3u.4: имя доброкачественное во ВСЕХ смыслах, форвард даёт только
	// пара (comm из is_shell, parent_comm из множества lineage.rego).
	const u4 = "control-probe.w63u4.invalid"
	ev4 := &types.DNSEvent{QName: u4, QType: 255, Direction: types.DNSDirectionQuery}
	require.False(t, f.ShouldEvaluate(ev4, "python3", "bash"),
		"%q: зонд 6.3u.4 форвардится и БЕЗ родителя из lineage.rego — контроль "+
			"не сможет отличить ось parent_comm от чужой причины", u4)
	require.False(t, f.ShouldEvaluate(ev4, "dig", "nginx"),
		"%q: форвардится с родителем nginx, но НЕ шеллом — тогда правило "+
			"reverse_shell_webserver не сматчит, а событие в Rego уйдёт: "+
			"ПРОВАЛ контроля будет ложным", u4)
	require.True(t, f.ShouldEvaluate(ev4, "python3", "nginx"),
		"%q: пара (python3, nginx) не форвардится — 6.3u.4 недостижим по построению", u4)
}
