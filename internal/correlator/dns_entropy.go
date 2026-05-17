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
}

// NewDNSEntropyCalculator creates a new entropy calculator with default settings.
func NewDNSEntropyCalculator() *DNSEntropyCalculator {
	return &DNSEntropyCalculator{
		DGAThreshold:       3.5,
		TunnelingMinLength: 50,
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

	// Remove TLD for entropy calculation (TLDs have predictable patterns)
	baseDomain := c.extractBaseDomain(domain)
	if len(baseDomain) < 10 {
		return false // Too short for reliable DGA detection
	}

	entropy := c.CalculateShannonEntropy(baseDomain)
	return entropy > c.DGAThreshold
}

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
// Returns a struct with all detection results.
func (c *DNSEntropyCalculator) AnalyzeDomain(domain string) DomainAnalysis {
	domain = strings.ToLower(domain)
	baseDomain := c.extractBaseDomain(domain)

	entropy := c.CalculateShannonEntropy(baseDomain)

	return DomainAnalysis{
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
	}
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
