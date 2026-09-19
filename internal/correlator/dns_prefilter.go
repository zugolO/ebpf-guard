// Package correlator provides DNS pre-filtering to avoid expensive OPA/Rego
// evaluation on benign DNS events (issue #69).
//
// At 10k DNS queries/sec a typical cluster sees <5% suspicious traffic.  The
// OPA `shannon_entropy` helper (implemented as distinct-character count in Rego)
// costs ~370 µs per call because the interpreter walks every character on each
// evaluation.  This pre-filter runs the same checks in Go (~1.5 µs total, 0
// allocs for cached domains) so Rego is only invoked for the ≈5% of events
// that show at least one suspicious signal.
//
// Coverage: every Rego rule REACHABLE FROM A DNS EVENT has a corresponding Go
// check here, so no rule can fire on an event that ShouldEvaluate returns false
// for.  "Reachable from a DNS event" is the whole "dns" partition of
// regoPartitionModules (internal/policy/rego_enabled.go), which is
// {base.rego, dns.rego, LINEAGE.REGO} — not dns.rego alone.  Wave 6.3 item 1,
// findings №384/№385 (plan.md, ревизия 19.09.2026) found this claim false on
// two counts: dns.rego's own is_dga_domain was a length+digit heuristic that
// the n-gram score does not imply (№384), and lineage.rego's parent_comm rules
// fire on a DNS event whose qname is entirely benign (№385).  №385 is covered
// by an explicit check here; №384 was closed from the other side by №394 —
// is_dga_domain now carries the n-gram score as a conjunct, which makes it a
// strict subset of this file's n-gram gate, so the coverage claim for that rule
// is a proved invariant (TestWave6_3up_RegoDGAIsSubsetOfPrefilterGate) rather
// than a mirrored branch.
package correlator

import (
	"strings"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// DNSPrefilter evaluates DNS events in Go before forwarding them to OPA/Rego.
// Benign events (ShouldEvaluate → false) skip Rego entirely; suspicious events
// are forwarded so the full policy rule set can fire.
type DNSPrefilter struct {
	// entropyThreshold is the minimum Shannon entropy (bits/char) that marks a
	// domain label as suspicious.  Mirrors DNSEntropyCalculator.DGAThreshold.
	entropyThreshold float64

	// dgaThreshold is the minimum NgramDGA score [0,1] that marks a domain as
	// algorithm-generated. Must sit at or below the dns_dga_ngram rule's own
	// threshold (0.55, rules/dns-threats.yaml) — this prefilter's job is to
	// guarantee that every event able to trigger a Rego/rule-engine match gets
	// forwarded, so it can never be stricter than the rule it feeds.
	//
	// Finding wave-6.3 item 1 (plan.md, 19.09.2026): the previous 0.8 default
	// was picked from a "<1% FP" code comment, not a measurement. Measured
	// DefaultNgramDGADetector().Score() on explicit DGA strings tops out at
	// 0.612 (a7f3k9x2m5p8q1z4) — below 0.8 for every case — so DGA domains
	// never cleared this gate and were never forwarded.
	dgaThreshold float64

	// analyzer is the shared DNS analysis engine with its 512-entry FIFO cache.
	// Reusing the global instance avoids duplicate cache warming across callers.
	analyzer *DNSEntropyCalculator
}

// DefaultDNSPrefilter returns a DNSPrefilter with production-ready defaults:
//   - entropyThreshold: 3.5 bits/char  (matches DNSEntropyCalculator.DGAThreshold)
//   - dgaThreshold:     0.55           (NgramDGA score; matches dns_dga_ngram
//     rule threshold — the measured scale, see field comment above)
func DefaultDNSPrefilter() *DNSPrefilter {
	return &DNSPrefilter{
		entropyThreshold: 3.5,
		dgaThreshold:     0.55,
		analyzer:         globalDNSAnalyzer,
	}
}

// NewDNSPrefilter creates a DNSPrefilter with explicit thresholds.
// Pass nil for analyzer to use the package-global instance.
func NewDNSPrefilter(entropyThreshold, dgaThreshold float64, analyzer *DNSEntropyCalculator) *DNSPrefilter {
	if analyzer == nil {
		analyzer = globalDNSAnalyzer
	}
	return &DNSPrefilter{
		entropyThreshold: entropyThreshold,
		dgaThreshold:     dgaThreshold,
		analyzer:         analyzer,
	}
}

// ShouldEvaluate returns true when the DNS event carries at least one signal
// that could trigger a Rego dns.rego rule, false when all checks pass cleanly
// and OPA evaluation can be skipped.
//
// comm is the process command name (Event.Comm, trimmed of null bytes).
// It is needed to cover the miner_dns_query and nxdomain_response rules.
// parentComm is Event.ParentComm, trimmed the same way; it is needed to cover
// lineage.rego, which is compiled into the same "dns" partition and whose
// rules read input.event.parent_comm and never look at the qname at all
// (finding №385).  Pass "" only where no parent is known — never as a
// convenience: an empty parentComm matches no lineage rule, so it silently
// narrows coverage back to what №385 found broken.
//
// Performance: ~1.5 µs/call for cached domains, ~6 µs for uncached.
// Zero allocations for domains already in the 512-entry analysis cache.
func (f *DNSPrefilter) ShouldEvaluate(dns *types.DNSEvent, comm, parentComm string) bool {
	if dns == nil {
		return true
	}

	qname := dns.QName
	lower := strings.ToLower(qname)

	// ── dns_txt_query rule ───────────────────────────────────────────────────
	// TXT records are a common DNS-tunneling carrier; always forward.
	if dns.QType == 16 {
		return true
	}

	// ── nxdomain_response rule ───────────────────────────────────────────────
	// Shell processes receiving NXDOMAIN may be running DGA malware.
	if dns.Direction == types.DNSDirectionResponse && dns.RCode == 3 {
		return true
	}

	// ── long_dns_query rule ──────────────────────────────────────────────────
	// Queries longer than 50 chars may encode data in subdomains (tunneling).
	if len(qname) > 50 {
		return true
	}

	// ── miner_dns_query rule ─────────────────────────────────────────────────
	if isMinerComm(comm) {
		return true
	}

	// ── lineage.rego rules reachable from a DNS event (finding №385) ─────────
	// lineage.rego is compiled into the SAME "dns" partition as dns.rego, and
	// five of its rules need nothing but comm and parent_comm: a shell that
	// resolves a perfectly ordinary name, spawned by nginx/postgres/init/cron/
	// apt, is exactly the reverse-shell shape those rules exist to catch. The
	// file-based lineage rules (container_escape_proc, sudoers_modification,
	// ssh_key_access) require input.event.file and cannot fire here.
	// Pure string comparisons — cheaper than the analyzer call below, so this
	// sits in front of it.
	if dnsRegoLineageReachable(comm, parentComm) {
		return true
	}

	// ── DGA checks: dns.rego's dga_domain and the n-gram gate ───────────────
	// AnalyzeDomain uses the shared 512-entry FIFO cache; repeated queries for
	// the same domain cost only a map lookup (~50 ns, 0 allocs).
	//
	// Finding №384 added a separate branch here that mirrored dns.rego's
	// is_dga_domain (a length+digit heuristic the n-gram score neither implies
	// nor is implied by). №394 removed the need for it: is_dga_domain now
	// carries the n-gram score as a conjunct, so the Rego predicate became a
	// STRICT SUBSET of this gate and the mirror branch could never forward
	// anything this one does not. The mirror itself (dnsRegoDGAHeuristic)
	// stays as the reference the coverage invariant is proved against —
	// TestWave6_3up_RegoDGAIsSubsetOfPrefilterGate walks it directly, so the
	// claim is a test, not a comment.
	//
	// The comparison is >=, not >, ON PURPOSE: Rego compares the same score
	// against the same 0.55 with >=, and a domain scoring exactly at the
	// threshold would otherwise satisfy the rule while never reaching it.
	analysis := f.analyzer.AnalyzeDomain(qname)
	if analysis.IsDGA || analysis.NgramScore >= f.dgaThreshold {
		return true
	}

	// ── suspicious_tld rule ──────────────────────────────────────────────────
	if analysis.HasSuspiciousTLD {
		return true
	}
	// dns.rego also checks .tk/.ml/.ga/.cf/.gq/.top/.xyz/.click/.link
	if hasDNSRegoSuspiciousTLD(lower) {
		return true
	}

	// ── mining_pool_dns rule ─────────────────────────────────────────────────
	if isMiningDomain(lower) {
		return true
	}

	// ── tor_dns_query rule ───────────────────────────────────────────────────
	if strings.Contains(lower, "tor") && strings.Contains(lower, "exit") {
		return true
	}

	// ── dynamic_dns_query rule ───────────────────────────────────────────────
	if isDynamicDNSDomain(lower) {
		return true
	}

	return false
}

// hasDNSRegoSuspiciousTLD checks the TLD list from dns.rego is_suspicious_tld.
// These are in addition to the ones maintained by DNSEntropyCalculator.
func hasDNSRegoSuspiciousTLD(lower string) bool {
	for _, tld := range dnsRegoSuspiciousTLDs {
		if strings.HasSuffix(lower, tld) {
			return true
		}
	}
	return false
}

// dnsRegoSuspiciousTLDs mirrors the is_suspicious_tld helper in dns.rego.
var dnsRegoSuspiciousTLDs = []string{
	".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".click", ".link",
}

// isMiningDomain checks domain keywords from dns.rego is_mining_domain.
func isMiningDomain(lower string) bool {
	return strings.Contains(lower, "xmrig") ||
		strings.Contains(lower, "minexmr") ||
		strings.Contains(lower, "supportxmr") ||
		strings.Contains(lower, "nanopool") ||
		strings.Contains(lower, "stratum") ||
		strings.Contains(lower, "hashvault") ||
		strings.Contains(lower, "moneroocean") ||
		(strings.Contains(lower, "pool") && strings.Contains(lower, "mine"))
}

// isDynamicDNSDomain checks keywords from dns.rego is_dynamic_dns_domain.
func isDynamicDNSDomain(lower string) bool {
	return strings.Contains(lower, "ddns") ||
		strings.Contains(lower, "dyndns") ||
		strings.Contains(lower, "no-ip") ||
		strings.Contains(lower, "duckdns") ||
		strings.HasSuffix(lower, ".hopto.org") ||
		strings.HasSuffix(lower, ".zapto.org") ||
		strings.HasSuffix(lower, ".sytes.net") ||
		strings.HasSuffix(lower, ".ddns.net")
}

// isMinerComm checks process name keywords from dns.rego / base.rego is_miner.
func isMinerComm(comm string) bool {
	lower := strings.ToLower(comm)
	return lower == "xmrig" ||
		lower == "minerd" ||
		lower == "cgminer" ||
		lower == "bfgminer" ||
		strings.Contains(lower, "miner") ||
		strings.Contains(lower, "xmr")
}

// dnsRegoDGAHeuristic mirrors the STRUCTURAL half of dns.rego's is_dga_domain:
//
//	parts := split(domain, "."); count(parts) > 1
//	name  := parts[0]; count(name) > 12
//	not contains_dictionary_word(name); contains_digit(name)
//
// Finding №384 (wave 6.3 item 1, plan.md ревизия 19.09.2026). This predicate
// is INDEPENDENT of NgramDGADetector: it knows nothing about bigram
// likelihood, and the n-gram score knows nothing about label length or
// digits. Measured on the analyzer, 19.09.2026:
//
//	server1234567890.example.com                  ngram 0.430  rego DGA ✓
//	node-000000000001.cluster.local               ngram 0.525  rego DGA ✓
//	prometheus-k8s-0.monitoring.svc.cluster.local ngram 0.398  rego DGA ✓
//
// — every one of them was dropped by the prefilter before this check, so the
// dga_domain rule could not fire on them at ANY dgaThreshold. Raising or
// lowering the threshold, which is all item 1 originally did, never reached
// this class at all.
//
// №394 added the second half — `input.details.dns_ngram_score >= 0.55` — after
// the names in that table turned out to be exactly what the rule was firing on
// in a normal cluster. This function stays the STRUCTURAL half alone, and the
// full predicate is structural ∧ score >= threshold. It is no longer a branch
// of ShouldEvaluate (the n-gram gate there subsumes it); it is the reference
// the coverage invariant is proved against in the tests.
//
// The length test uses len() (bytes) against OPA's count() (runes), which can
// only over-forward on a non-ASCII label — the safe direction for a prefilter.
func dnsRegoDGAHeuristic(qname string) bool {
	dot := strings.IndexByte(qname, '.')
	if dot < 0 {
		return false // count(parts) > 1
	}
	name := qname[:dot]
	if len(name) <= 12 {
		return false
	}
	// contains_digit before contains_dictionary_word: one pass over a short
	// label, against fourteen substring scans. Rego evaluates the conjuncts in
	// the other order, but a conjunction has no order — and most long benign
	// labels carry no digit, so this is where the common case exits. Measured:
	// puts the prefilter's suspicious/dga_cached benchmark back at ~35 ns/op
	// instead of ~109 with the dictionary scan first.
	if !strings.ContainsAny(name, "0123456789") {
		return false
	}
	lower := strings.ToLower(name)
	for _, w := range dnsRegoDictionaryWords {
		if strings.Contains(lower, w) {
			return false // contains_dictionary_word
		}
	}
	return true
}

// dnsRegoDictionaryWords mirrors the contains_dictionary_word helper in
// dns.rego. Order matters only for speed; "ns" and "api" are the two that
// actually carry most of the exclusions on cluster-internal names.
var dnsRegoDictionaryWords = []string{
	"www", "mail", "ftp", "smtp", "pop", "imap", "ns", "dns",
	"api", "cdn", "app", "blog", "shop", "news",
}

// dnsRegoLineageReachable reports whether a DNS event with this comm/parentComm
// pair can satisfy any lineage.rego rule — that is, any rule in the "dns" Rego
// partition that reads parent_comm and never touches the qname.
//
// Finding №385 (wave 6.3 item 1). The five reachable rules are
// reverse_shell_webserver, shell_from_database, init_spawns_shell,
// cron_spawns_shell and package_manager_shell; all five require is_shell(comm)
// first, so that test gates the rest and the common case costs one failed
// switch. Comparisons are exact and un-lowered because lineage.rego's helpers
// are exact string equality, and a looser match here would forward events no
// rule can fire on.
func dnsRegoLineageReachable(comm, parentComm string) bool {
	if parentComm == "" || !isRegoShellComm(comm) {
		return false
	}
	switch parentComm {
	case "init", "cron": // init_spawns_shell, cron_spawns_shell
		return true
	case "nginx", "apache", "apache2", "httpd", "lighttpd", "caddy": // is_webserver
		return true
	case "mysql", "postgres", "mongodb", "redis-server": // is_database
		return true
	case "apt", "apt-get", "yum", "dnf", "pip", "pip3", "npm": // is_package_manager
		return true
	}
	return false
}

// isRegoShellComm mirrors the is_shell helper, which dns.rego (nxdomain_response)
// and lineage.rego define identically.
func isRegoShellComm(comm string) bool {
	switch comm {
	case "bash", "sh", "zsh", "dash", "fish", "python", "python3", "perl", "ruby":
		return true
	}
	return false
}

// dnsRegoNgramThreshold is the n-gram score at or above which dns.rego's
// is_dga_domain treats a name as algorithm-generated (№394). It is the SAME
// number as the dns_dga_ngram rule's threshold and as DefaultDNSPrefilter's
// dgaThreshold — one measured scale, one boundary, three readers. Changing it
// here without changing rules/rego/dns.rego breaks the subset invariant, and
// TestWave6_3up_RegoDGAIsSubsetOfPrefilterGate says so.
const dnsRegoNgramThreshold = 0.55

// withDNSNgramScore attaches the bigram-model score of the query name to the
// alert's details so dns.rego can compare against it (№394). Returns the alert
// unchanged for non-DNS events.
func withDNSNgramScore(alert types.Alert) types.Alert {
	if alert.Event.DNS == nil {
		return alert
	}
	if alert.Details == nil {
		alert.Details = getDetailsMap()
	}
	alert.Details["dns_ngram_score"] = globalDNSAnalyzer.AnalyzeDomain(alert.Event.DNS.QName).NgramScore
	return alert
}
