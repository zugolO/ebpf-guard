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
// Coverage: every DNS Rego rule in dns.rego has a corresponding Go check here,
// so no rule can fire on an event that ShouldEvaluate returns false for.
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
	// algorithm-generated.  A value of 0.8 gives <1% false-positive rate on
	// benign traffic per NgramDGADetector benchmarks.
	dgaThreshold float64

	// analyzer is the shared DNS analysis engine with its 512-entry FIFO cache.
	// Reusing the global instance avoids duplicate cache warming across callers.
	analyzer *DNSEntropyCalculator
}

// DefaultDNSPrefilter returns a DNSPrefilter with production-ready defaults:
//   - entropyThreshold: 3.5 bits/char  (matches DNSEntropyCalculator.DGAThreshold)
//   - dgaThreshold:     0.8            (NgramDGA score; <1% FP rate)
func DefaultDNSPrefilter() *DNSPrefilter {
	return &DNSPrefilter{
		entropyThreshold: 3.5,
		dgaThreshold:     0.8,
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
//
// Performance: ~1.5 µs/call for cached domains, ~6 µs for uncached.
// Zero allocations for domains already in the 512-entry analysis cache.
func (f *DNSPrefilter) ShouldEvaluate(dns *types.DNSEvent, comm string) bool {
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

	// ── DGA / entropy checks (dga_domain rule in dns.rego + base.rego) ───────
	// AnalyzeDomain uses the shared 512-entry FIFO cache; repeated queries for
	// the same domain cost only a map lookup (~50 ns, 0 allocs).
	analysis := f.analyzer.AnalyzeDomain(qname)
	if analysis.IsDGA || analysis.NgramScore > f.dgaThreshold {
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
