package correlator

import (
	"testing"

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
		if f.ShouldEvaluate(ev, "curl") {
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
		if !f.ShouldEvaluate(ev, "bash") {
			t.Errorf("DGA domain %q: ShouldEvaluate=false, want true", domain)
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
		{"evil.onion"},  // in DNSEntropyCalculator list
		{"hidden.bit"},  // in DNSEntropyCalculator list
	}
	for _, tc := range tlds {
		ev := makeQueryEvent(tc.domain, 1)
		if !f.ShouldEvaluate(ev, "curl") {
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
	if !f.ShouldEvaluate(ev, "curl") {
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
	if !f.ShouldEvaluate(ev, "bash") {
		t.Error("NXDOMAIN response: ShouldEvaluate=false, want true")
	}
}

func TestDNSPrefilter_LongQuery(t *testing.T) {
	f := DefaultDNSPrefilter()
	// 51-char label without other suspicious signals.
	long := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa12.com" // len > 50
	ev := makeQueryEvent(long, 1)
	if !f.ShouldEvaluate(ev, "curl") {
		t.Errorf("long query %q: ShouldEvaluate=false, want true", long)
	}
}

func TestDNSPrefilter_MinerProcess(t *testing.T) {
	f := DefaultDNSPrefilter()
	// Benign domain but queried by a miner process.
	ev := makeQueryEvent("pool.example.com", 1)
	if !f.ShouldEvaluate(ev, "xmrig") {
		t.Error("miner comm xmrig: ShouldEvaluate=false, want true")
	}
	if !f.ShouldEvaluate(ev, "minerd") {
		t.Error("miner comm minerd: ShouldEvaluate=false, want true")
	}
	if !f.ShouldEvaluate(ev, "cgminer") {
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
		if !f.ShouldEvaluate(ev, "python") {
			t.Errorf("mining domain %q: ShouldEvaluate=false, want true", d)
		}
	}
}

func TestDNSPrefilter_TorExitDomain(t *testing.T) {
	f := DefaultDNSPrefilter()
	ev := makeQueryEvent("tor.exit.somenode.org", 1)
	if !f.ShouldEvaluate(ev, "curl") {
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
		if !f.ShouldEvaluate(ev, "nc") {
			t.Errorf("dynamic DNS domain %q: ShouldEvaluate=false, want true", d)
		}
	}
}

func TestDNSPrefilter_NilEvent(t *testing.T) {
	f := DefaultDNSPrefilter()
	// nil event must not panic and must return true (safe default).
	if !f.ShouldEvaluate(nil, "curl") {
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
func BenchmarkDNSPrefilter(b *testing.B) {
	f := DefaultDNSPrefilter()

	b.Run("benign/cached", func(b *testing.B) {
		ev := makeQueryEvent("google.com", 1)
		// Warm the cache.
		f.ShouldEvaluate(ev, "curl")
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			f.ShouldEvaluate(ev, "curl")
		}
	})

	b.Run("suspicious/dga_cached", func(b *testing.B) {
		ev := makeQueryEvent("xvzk8f2p9qmj3.com", 1)
		// Warm the cache.
		f.ShouldEvaluate(ev, "bash")
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			f.ShouldEvaluate(ev, "bash")
		}
	})
}
