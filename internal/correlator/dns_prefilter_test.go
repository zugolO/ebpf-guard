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

// Finding №384 (wave 6.3 item 1, plan.md ревизия 19.09.2026). dns.rego's own
// is_dga_domain is a length+digit heuristic and is NOT the n-gram model: it
// fires on names whose n-gram score is nowhere near any usable threshold. The
// prefilter gated the whole dga_domain rule on the n-gram score alone, so this
// entire class was silently dropped at EVERY value of dgaThreshold — the
// threshold fix of item 1 could not reach it. Each name below was measured on
// DefaultDNSPrefilter's analyzer, 19.09.2026; the score is recorded so a later
// model change shows up here as a changed comment, not as silent regression.
func TestDNSPrefilter_ForwardsRegoOwnDGAHeuristic(t *testing.T) {
	f := DefaultDNSPrefilter()
	for _, tc := range []struct {
		qname string
		ngram float64
	}{
		{"server1234567890.example.com", 0.430},
		{"node-000000000001.cluster.local", 0.525},
		{"prometheus-k8s-0.monitoring.svc.cluster.local", 0.398},
	} {
		if !dnsRegoDGAHeuristic(tc.qname) {
			t.Fatalf("%q: fixture no longer satisfies dns.rego is_dga_domain — "+
				"pick another name, the test has stopped testing anything", tc.qname)
		}
		if score := DefaultNgramDGADetector().Score(tc.qname); score > f.dgaThreshold {
			t.Fatalf("%q: n-gram score %v now clears dgaThreshold %v on its own — "+
				"the fixture no longer demonstrates the gap (measured %v on 19.09.2026)",
				tc.qname, score, f.dgaThreshold, tc.ngram)
		}
		ev := &types.DNSEvent{QName: tc.qname, QType: 1, Direction: types.DNSDirectionQuery}
		if !f.ShouldEvaluate(ev, "curl", "systemd") {
			t.Errorf("%q: dropped before Rego, but dns.rego's dga_domain rule matches it", tc.qname)
		}
	}
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

	// ── 6.3u.3: форвард обязан идти ТОЛЬКО через зеркало is_dga_domain.
	// Перебор суффиксов покрывает случайность зонда: у контроля их 65536,
	// и «обычно проходит» здесь не годится.
	for _, tag := range []string{"a1b2", "ffff", "0f1e", "0000", "dead", "9c4e"} {
		qname := "server1234567890.w63u3" + tag + ".invalid"
		ev := &types.DNSEvent{QName: qname, QType: 255, Direction: types.DNSDirectionQuery}

		require.True(t, dnsRegoDGAHeuristic(qname),
			"%q: зонд 6.3u.3 перестал удовлетворять предикату dns.rego is_dga_domain — "+
				"контроль на стенде вынесет НЕИЗМЕРИМ и потратит прогон", qname)
		require.True(t, f.ShouldEvaluate(ev, "python3", "bash"),
			"%q: зонд 6.3u.3 не форвардится вовсе", qname)

		analysis := f.analyzer.AnalyzeDomain(qname)
		require.False(t, analysis.IsDGA || analysis.NgramScore > f.dgaThreshold,
			"%q: имя форвардится ещё и по ветке n-gram (score=%.3f, IsDGA=%v) — "+
				"6.3u.3 зачтёт себе чужой механизм и НЕ докажет №384. Суффикс обязан "+
				"оставаться короче ngramMinLabelLen", qname, analysis.NgramScore, analysis.IsDGA)
		require.LessOrEqual(t, len(qname), 50,
			"%q: имя переросло 50 символов — форвард пойдёт по long_dns_query", qname)
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
