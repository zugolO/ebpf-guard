// Package correlator provides DNS threat detection via entropy analysis.
package correlator

import (
	"math"
	"strings"
	"sync"
	"unicode"
)

// runeFreqPool reuses map[rune]int allocations across CalculateShannonEntropy calls.
var runeFreqPool = sync.Pool{
	New: func() interface{} { return make(map[rune]int, 64) },
}

// analysisCacheMaxSize is the capacity of the per-instance analysis cache.
// When the cache is full the oldest entry is evicted (FIFO), not the entire map.
const analysisCacheMaxSize = 512

// DNSEntropyCalculator computes Shannon entropy for DNS domain names.
// High entropy domains are characteristic of DGA (Domain Generation Algorithm)
// malware and DNS tunneling.
type DNSEntropyCalculator struct {
	// DGAThreshold is the entropy threshold for DGA detection (bits per character).
	// Domains with entropy above this threshold are flagged as suspicious.
	// Default: 3.5
	DGAThreshold float64

	// TunnelingMinLength is the minimum domain length to consider for tunneling detection.
	// Default: 50
	TunnelingMinLength int

	// SuspiciousTLDs contains known suspicious top-level domains used by malware.
	SuspiciousTLDs map[string]bool

	// analysisCache caches recent AnalyzeDomain results to avoid recomputing
	// entropy + n-gram scores when the same domain appears in multiple rule
	// conditions during the same event evaluation pass.
	// cacheEvictQ is a fixed-size ring that records insertion order so a single
	// oldest entry can be evicted in O(1) when the cache is full, instead of
	// discarding the entire map at once (which caused CPU spikes on each reset).
	cacheMu       sync.Mutex
	analysisCache map[string]DomainAnalysis
	cacheEvictQ   [analysisCacheMaxSize]string // FIFO eviction ring
	cacheHead     int                          // index of the oldest entry
	cacheTail     int                          // next write slot
}

// NewDNSEntropyCalculator creates a new entropy calculator with default settings.
func NewDNSEntropyCalculator() *DNSEntropyCalculator {
	return &DNSEntropyCalculator{
		DGAThreshold:       3.5,
		TunnelingMinLength: 50,
		analysisCache:      make(map[string]DomainAnalysis, analysisCacheMaxSize),
		SuspiciousTLDs: map[string]bool{
			".onion": true, // Tor hidden services
			".bit":   true, // Namecoin / Emercoin
			".bazar": true, // Emercoin
			".coin":  true, // Emercoin
			".lib":   true, // Emercoin
			".emc":   true, // Emercoin
			".zip":   true, // Often used for phishing
			".mov":   true, // Often used for phishing
			".phd":   true, // Often used for phishing
			".xxx":   true, // Often used for malicious sites
		},
	}
}

// CalculateShannonEntropy computes the Shannon entropy of a string in bits per character.
// Formula: H(X) = -sum(p(x) * log2(p(x)))
// Higher entropy indicates more randomness (characteristic of DGA domains).
func (c *DNSEntropyCalculator) CalculateShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := runeFreqPool.Get().(map[rune]int)
	for _, r := range s {
		freq[r]++
	}

	length := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		probability := float64(count) / length
		if probability > 0 {
			entropy -= probability * math.Log2(probability)
		}
	}

	// Clear before returning to pool so next caller gets a clean map.
	for k := range freq {
		delete(freq, k)
	}
	runeFreqPool.Put(freq)

	return entropy
}

// IsDGADomain checks if a domain name exhibits characteristics of DGA-generated domains.
// Returns true if the domain has high entropy and sufficient length.
func (c *DNSEntropyCalculator) IsDGADomain(domain string) bool {
	// Normalize domain
	domain = strings.ToLower(domain)

	// Scored PER LABEL, not over the labels concatenated. Finding №329: the
	// concatenation (extractBaseDomain) grows the alphabet with the number of
	// levels in a name rather than with its randomness, so every ordinary
	// "*.svc.cluster.local" cleared DGAThreshold while a random 8-character
	// label did not. The length gate stays, per label: entropy of an
	// n-character string is bounded by log2(n), so scoring a 3-character label
	// says nothing either way.
	baseDomain := c.extractBaseDomain(domain)
	if len(baseDomain) < 10 {
		return false // Too short for reliable DGA detection
	}

	for _, label := range strings.Split(domain, ".") {
		if len(label) < 10 {
			continue
		}
		// Both tests must hold FOR THE SAME LABEL. Entropy alone cannot
		// separate the populations at any threshold — measured 15.09.2026,
		// wave 6.3: legitimate "local-path-provisioner" scores 3.698 and
		// "authorization-microservice" 3.719, above a random 20-character
		// label at 3.522. What separates them is the bigram model, which
		// reads character sequences rather than alphabet size: the same
		// legitimate labels score 0.30–0.42 against 0.56–0.63 for random
		// ones.
		if c.CalculateShannonEntropy(label) <= c.DGAThreshold {
			continue
		}
		if DefaultNgramDGADetector().scoreLabel(label) > dgaNgramConjunctThreshold {
			return true
		}
	}
	return false
}

// dgaNgramConjunctThreshold is the bigram-model score above which a label is
// treated as algorithm-generated when it ALSO clears the entropy threshold.
// Measured spread (wave 6.3, 15.09.2026): legitimate labels of 10 characters
// or more top out at 0.459, random ones start at 0.562. The standalone
// dns_dga_ngram rule carries a stricter threshold of its own, since it has no
// second condition to lean on.
const dgaNgramConjunctThreshold = 0.5

// IsDNSTunneling checks if a domain name exhibits DNS tunneling characteristics.
// Returns true if the domain is excessively long (data encoded in subdomains).
func (c *DNSEntropyCalculator) IsDNSTunneling(domain string) bool {
	return len(domain) > c.TunnelingMinLength
}

// HasSuspiciousTLD checks if the domain uses a known suspicious TLD.
func (c *DNSEntropyCalculator) HasSuspiciousTLD(domain string) bool {
	domain = strings.ToLower(domain)
	for tld := range c.SuspiciousTLDs {
		if strings.HasSuffix(domain, tld) {
			return true
		}
	}
	return false
}

// IsHighFrequencyQuery checks if a domain query pattern indicates high-frequency DNS.
// This is useful for detecting DNS-based C2 beaconing.
func (c *DNSEntropyCalculator) IsHighFrequencyQuery(domain string, uniqueDomains int, windowSeconds int) bool {
	if uniqueDomains <= 0 {
		return false
	}
	if windowSeconds <= 0 {
		windowSeconds = 60
	}
	// Threshold: more than 100 unique domains in 60 seconds, scaled proportionally.
	// Ceiling division avoids truncation to 0 for very short windows.
	threshold := (100*windowSeconds + 59) / 60
	return uniqueDomains > threshold
}

// AnalyzeDomain performs a comprehensive analysis of a domain name.
// Results are cached — repeated calls for the same domain within a burst
// return immediately without recomputing entropy or n-gram scores.
func (c *DNSEntropyCalculator) AnalyzeDomain(domain string) DomainAnalysis {
	domain = strings.ToLower(domain)

	c.cacheMu.Lock()
	if cached, ok := c.analysisCache[domain]; ok {
		c.cacheMu.Unlock()
		return cached
	}
	c.cacheMu.Unlock()

	// Expensive computation runs outside the lock.
	baseDomain := c.extractBaseDomain(domain)
	entropy := c.CalculateShannonEntropy(baseDomain)
	maxLabelEntropy := c.maxLabelEntropy(domain)
	maxLabelLen := 0
	for _, label := range strings.Split(domain, ".") {
		if len(label) > maxLabelLen {
			maxLabelLen = len(label)
		}
	}
	ngramScore := Score(domain)

	result := DomainAnalysis{
		Domain:              domain,
		BaseDomain:          baseDomain,
		Entropy:             entropy,
		IsDGA:               c.IsDGADomain(domain),
		IsTunneling:         c.IsDNSTunneling(domain),
		HasSuspiciousTLD:    c.HasSuspiciousTLD(domain),
		Length:              len(domain),
		SubdomainCount:      c.countSubdomains(domain),
		DigitRatio:          c.calculateDigitRatio(baseDomain),
		ConsonantVowelRatio: c.calculateConsonantVowelRatio(baseDomain),
		NgramScore:          ngramScore,
		MaxLabelEntropy:     maxLabelEntropy,
		MaxLabelLen:         maxLabelLen,
	}

	c.cacheMu.Lock()
	// Double-check: another goroutine may have stored this domain while we
	// were computing. Skip the write (and eviction) if it is already present.
	if _, exists := c.analysisCache[domain]; !exists {
		if len(c.analysisCache) >= analysisCacheMaxSize {
			// Evict the single oldest entry via the FIFO ring — O(1), no
			// full-map reset, no CPU spike.
			oldest := c.cacheEvictQ[c.cacheHead]
			c.cacheHead = (c.cacheHead + 1) % analysisCacheMaxSize
			delete(c.analysisCache, oldest)
		}
		c.cacheEvictQ[c.cacheTail] = domain
		c.cacheTail = (c.cacheTail + 1) % analysisCacheMaxSize
		c.analysisCache[domain] = result
	}
	c.cacheMu.Unlock()

	return result
}

// DomainAnalysis holds the results of domain analysis.
type DomainAnalysis struct {
	Domain              string  `json:"domain"`
	BaseDomain          string  `json:"base_domain"`
	Entropy             float64 `json:"entropy"`
	IsDGA               bool    `json:"is_dga"`
	IsTunneling         bool    `json:"is_tunneling"`
	HasSuspiciousTLD    bool    `json:"has_suspicious_tld"`
	Length              int     `json:"length"`
	SubdomainCount      int     `json:"subdomain_count"`
	DigitRatio          float64 `json:"digit_ratio"`
	ConsonantVowelRatio float64 `json:"consonant_vowel_ratio"`
	// NgramScore is the DGA probability [0,1] from the character bigram model.
	// Higher values indicate the domain is more likely algorithm-generated.
	// This complements Entropy: modern DGAs can mimic normal entropy profiles
	// but still produce unusual character-level n-gram sequences.
	NgramScore float64 `json:"ngram_score"`
	// MaxLabelEntropy is the highest Shannon entropy of any single DNS label
	// (dot-separated component) of the qname. Unlike Entropy — which is computed
	// over extractBaseDomain, i.e. every label except the TLD concatenated —
	// this value does not grow with the number of levels in the name. Finding
	// №329: the concatenation makes the alphabet of a long, ordinary multi-level
	// name wide by construction, so every "*.svc.cluster.local" sits above 3.5
	// while a genuinely random 8-character DGA label sits at 3.0. Per label the
	// two populations separate the right way round.
	MaxLabelEntropy float64 `json:"max_label_entropy"`
	// MaxLabelLen is the length of the longest single label of the qname.
	// Finding №83 already established that this — not the length of the whole
	// name — is what the long-label rules actually reason about, but it only
	// ever reached the alert Details map (dnsAlertDetails); as a rule-condition
	// field it did not exist. A name made of several ordinary labels clears a
	// whole-name threshold without any one label looking unusual: an ordinary
	// k8s FQDN runs past 50 characters on service and namespace names alone.
	MaxLabelLen int `json:"max_label_len"`
}

// maxLabelEntropy returns the highest Shannon entropy among the individual
// labels of a domain. Labels are scored as they appear, TLD included: a short
// label cannot reach a high value anyway (entropy of an n-character string is
// bounded by log2(n)), so "com"/"local" self-exclude without a length gate and
// a DGA label is caught wherever in the name it sits.
func (c *DNSEntropyCalculator) maxLabelEntropy(domain string) float64 {
	max := 0.0
	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			continue
		}
		if h := c.CalculateShannonEntropy(label); h > max {
			max = h
		}
	}
	return max
}

// extractBaseDomain extracts the domain part without TLD for entropy calculation.
// For "sub.example.com" returns "subexample" (removes dots and TLD).
func (c *DNSEntropyCalculator) extractBaseDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		// Single domain like "example.com" -> "example"
		if len(parts) > 0 {
			return parts[0]
		}
		return domain
	}

	// Multi-level domain: join all except TLD
	// "a.b.c.example.com" -> "abcexample"
	var result strings.Builder
	for i := 0; i < len(parts)-1; i++ {
		result.WriteString(parts[i])
	}
	return result.String()
}

// countSubdomains returns the number of subdomains in a domain.
func (c *DNSEntropyCalculator) countSubdomains(domain string) int {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return 0
	}
	return len(parts) - 2 // Exclude domain and TLD
}

// calculateDigitRatio returns the ratio of digits to total characters.
func (c *DNSEntropyCalculator) calculateDigitRatio(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	digits := 0
	for _, r := range s {
		if unicode.IsDigit(r) {
			digits++
		}
	}
	return float64(digits) / float64(len(s))
}

// calculateConsonantVowelRatio returns the ratio of consonants to vowels.
// High consonant ratio can indicate DGA domains.
func (c *DNSEntropyCalculator) calculateConsonantVowelRatio(s string) float64 {
	vowels := "aeiou"
	vowelCount := 0
	consonantCount := 0

	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) {
			if strings.ContainsRune(vowels, r) {
				vowelCount++
			} else {
				consonantCount++
			}
		}
	}

	if vowelCount == 0 {
		return float64(consonantCount)
	}
	return float64(consonantCount) / float64(vowelCount)
}

// SetDGAThreshold updates the DGA detection threshold.
func (c *DNSEntropyCalculator) SetDGAThreshold(threshold float64) {
	c.DGAThreshold = threshold
}

// SetTunnelingMinLength updates the minimum length for tunneling detection.
func (c *DNSEntropyCalculator) SetTunnelingMinLength(length int) {
	c.TunnelingMinLength = length
}

// AddSuspiciousTLD adds a TLD to the suspicious list.
func (c *DNSEntropyCalculator) AddSuspiciousTLD(tld string) {
	if !strings.HasPrefix(tld, ".") {
		tld = "." + tld
	}
	c.SuspiciousTLDs[strings.ToLower(tld)] = true
}

// RemoveSuspiciousTLD removes a TLD from the suspicious list.
func (c *DNSEntropyCalculator) RemoveSuspiciousTLD(tld string) {
	if !strings.HasPrefix(tld, ".") {
		tld = "." + tld
	}
	delete(c.SuspiciousTLDs, strings.ToLower(tld))
}
