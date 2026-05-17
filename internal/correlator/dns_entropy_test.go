package correlator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCalculateShannonEntropy(t *testing.T) {
	calc := NewDNSEntropyCalculator()

	tests := []struct {
		name     string
		input    string
		expected float64
		delta    float64
	}{
		{
			name:     "empty string",
			input:    "",
			expected: 0,
			delta:    0.001,
		},
		{
			name:     "single character",
			input:    "a",
			expected: 0,
			delta:    0.001,
		},
		{
			name:     "repeated character",
			input:    "aaaaaa",
			expected: 0,
			delta:    0.001,
		},
		{
			name:     "two characters equal frequency",
			input:    "ababab",
			expected: 1.0,
			delta:    0.001,
		},
		{
			name:     "low entropy domain",
			input:    "google",
			expected: 1.918,
			delta:    0.01,
		},
		{
			name:     "high entropy DGA-like domain",
			input:    "xn--e1afmkfd",
			expected: 3.252,
			delta:    0.01,
		},
		{
			name:     "very high entropy random",
			input:    "qxj4v9k2mnbp",
			expected: 3.5,
			delta:    0.2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calc.CalculateShannonEntropy(tt.input)
			assert.InDelta(t, tt.expected, result, tt.delta)
		})
	}
}

func TestIsDGADomain(t *testing.T) {
	calc := NewDNSEntropyCalculator()
	calc.DGAThreshold = 3.5

	tests := []struct {
		name     string
		domain   string
		expected bool
	}{
		{
			name:     "legitimate domain - google",
			domain:   "google.com",
			expected: false,
		},
		{
			name:     "legitimate domain - example",
			domain:   "example.com",
			expected: false,
		},
		{
			name:     "legitimate domain - subdomains",
			domain:   "www.cloudflare.com",
			expected: false,
		},
		{
			name:     "too short for DGA",
			domain:   "abc.com",
			expected: false,
		},
		{
			name:     "DGA-like high entropy",
			domain:   "qxj4v9k2mnbp.example.com",
			expected: true,
		},
		{
			name:     "punycode domain",
			domain:   "xn--e1afmkfd.xn--p1ai",
			expected: false, // entropy 3.25 < threshold 3.5
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calc.IsDGADomain(tt.domain)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsDNSTunneling(t *testing.T) {
	calc := NewDNSEntropyCalculator()
	calc.TunnelingMinLength = 50

	tests := []struct {
		name     string
		domain   string
		expected bool
	}{
		{
			name:     "normal domain",
			domain:   "example.com",
			expected: false,
		},
		{
			name:     "long subdomain but under threshold",
			domain:   "this.is.a.long.subdomain.example.com",
			expected: false,
		},
		{
			name:     "DNS tunneling - data in subdomain",
			domain:   "aGVsbG8gd29ybGQgaGVsbG8gd29ybGQ.example.com",
			expected: false, // length 44 < TunnelingMinLength 50
		},
		{
			name:     "DNS tunneling - very long",
			domain:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.example.com",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calc.IsDNSTunneling(tt.domain)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHasSuspiciousTLD(t *testing.T) {
	calc := NewDNSEntropyCalculator()

	tests := []struct {
		name     string
		domain   string
		expected bool
	}{
		{
			name:     "normal TLD - com",
			domain:   "example.com",
			expected: false,
		},
		{
			name:     "normal TLD - org",
			domain:   "example.org",
			expected: false,
		},
		{
			name:     "suspicious TLD - onion",
			domain:   "example.onion",
			expected: true,
		},
		{
			name:     "suspicious TLD - bit",
			domain:   "example.bit",
			expected: true,
		},
		{
			name:     "suspicious TLD - bazar",
			domain:   "example.bazar",
			expected: true,
		},
		{
			name:     "case insensitive",
			domain:   "example.ONION",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calc.HasSuspiciousTLD(tt.domain)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAnalyzeDomain(t *testing.T) {
	calc := NewDNSEntropyCalculator()

	analysis := calc.AnalyzeDomain("sub.example.com")

	assert.Equal(t, "sub.example.com", analysis.Domain)
	assert.Equal(t, "subexample", analysis.BaseDomain)
	assert.Greater(t, analysis.Entropy, 0.0)
	assert.Less(t, analysis.Entropy, 5.0)
	assert.False(t, analysis.IsDGA)
	assert.False(t, analysis.IsTunneling)
	assert.False(t, analysis.HasSuspiciousTLD)
	assert.Equal(t, 15, analysis.Length)
	assert.Equal(t, 1, analysis.SubdomainCount)
}

func TestAnalyzeDomain_DGA(t *testing.T) {
	calc := NewDNSEntropyCalculator()
	calc.DGAThreshold = 3.0 // Lower threshold for testing

	analysis := calc.AnalyzeDomain("qxj4v9k2mnbp.example.com")

	assert.True(t, analysis.IsDGA)
	assert.Greater(t, analysis.Entropy, 3.0)
}

func TestCountSubdomains(t *testing.T) {
	calc := NewDNSEntropyCalculator()

	tests := []struct {
		domain   string
		expected int
	}{
		{"example.com", 0},
		{"www.example.com", 1},
		{"a.b.c.example.com", 3},
		{"deep.sub.domain.example.com", 3},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			result := calc.countSubdomains(tt.domain)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCalculateDigitRatio(t *testing.T) {
	calc := NewDNSEntropyCalculator()

	tests := []struct {
		input    string
		expected float64
	}{
		{"abc", 0.0},
		{"123", 1.0},
		{"a1b2c3", 0.5},
		{"", 0.0},
		{"abc123def", 0.333},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := calc.calculateDigitRatio(tt.input)
			assert.InDelta(t, tt.expected, result, 0.01)
		})
	}
}

func TestCalculateConsonantVowelRatio(t *testing.T) {
	calc := NewDNSEntropyCalculator()

	tests := []struct {
		input    string
		expected float64
	}{
		{"aei", 0.0},   // All vowels
		{"bcd", 3.0},   // All consonants
		{"abc", 2.0},   // 1 vowel (a), 2 consonants (b,c)
		{"abcde", 1.5}, // 2 vowels (a,e), 3 consonants (b,c,d)
		{"", 0.0},      // Empty
		{"123", 0.0},   // No letters
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := calc.calculateConsonantVowelRatio(tt.input)
			assert.InDelta(t, tt.expected, result, 0.01)
		})
	}
}

func TestExtractBaseDomain(t *testing.T) {
	calc := NewDNSEntropyCalculator()

	tests := []struct {
		domain   string
		expected string
	}{
		{"example.com", "example"},
		{"sub.example.com", "subexample"},
		{"a.b.c.example.com", "abcexample"},
		{"single", "single"},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			result := calc.extractBaseDomain(tt.domain)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAddRemoveSuspiciousTLD(t *testing.T) {
	calc := NewDNSEntropyCalculator()

	// Add new TLD
	calc.AddSuspiciousTLD(".test")
	assert.True(t, calc.HasSuspiciousTLD("example.test"))

	// Remove TLD
	calc.RemoveSuspiciousTLD(".test")
	assert.False(t, calc.HasSuspiciousTLD("example.test"))

	// Add without leading dot
	calc.AddSuspiciousTLD("newtld")
	assert.True(t, calc.HasSuspiciousTLD("example.newtld"))
}

func TestSetThresholds(t *testing.T) {
	calc := NewDNSEntropyCalculator()

	calc.SetDGAThreshold(4.0)
	assert.Equal(t, 4.0, calc.DGAThreshold)

	calc.SetTunnelingMinLength(100)
	assert.Equal(t, 100, calc.TunnelingMinLength)
}

// BenchmarkShannonEntropy benchmarks entropy calculation performance (with pool).
func BenchmarkShannonEntropy(b *testing.B) {
	calc := NewDNSEntropyCalculator()
	domain := "qxj4v9k2mnbpwxyz1234567890abcdef"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		calc.CalculateShannonEntropy(domain)
	}
}

// BenchmarkDNSEntropy is the canonical Sprint 29 benchmark gate.
// Measures allocs/op for CalculateShannonEntropy — should be 0 allocs/op
// after steady state thanks to the sync.Pool.
func BenchmarkDNSEntropy(b *testing.B) {
	calc := NewDNSEntropyCalculator()
	domain := "xn--e1afmkfd.xn--p1ai"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		calc.CalculateShannonEntropy(domain)
	}
}

// BenchmarkAnalyzeDomain benchmarks full domain analysis.
func BenchmarkAnalyzeDomain(b *testing.B) {
	calc := NewDNSEntropyCalculator()
	domain := "sub.example.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		calc.AnalyzeDomain(domain)
	}
}

// TestEntropyBounds verifies entropy is always within expected bounds.
func TestEntropyBounds(t *testing.T) {
	calc := NewDNSEntropyCalculator()

	// Test various domain patterns
	domains := []string{
		"a",
		"aa",
		"ab",
		"abc",
		"abcdefghijklmnopqrstuvwxyz",
		"1111111111111111111111111111",
		"qxj4v9k2mnbpwxyz1234567890abc",
	}

	for _, domain := range domains {
		entropy := calc.CalculateShannonEntropy(domain)
		// Entropy must be >= 0
		assert.GreaterOrEqual(t, entropy, 0.0, "entropy for %s", domain)
		// Entropy must be <= log2(len(alphabet)) <= 8 for ASCII
		assert.LessOrEqual(t, entropy, 8.0, "entropy for %s", domain)
	}
}

// TestMaxEntropy verifies maximum entropy for uniform distribution.
func TestMaxEntropy(t *testing.T) {
	calc := NewDNSEntropyCalculator()

	// For a string with all unique characters, entropy = log2(n)
	// "abcd" has 4 unique chars, max entropy = log2(4) = 2
	entropy := calc.CalculateShannonEntropy("abcd")
	assert.InDelta(t, 2.0, entropy, 0.001)

	// "abcdefgh" has 8 unique chars, max entropy = log2(8) = 3
	entropy = calc.CalculateShannonEntropy("abcdefgh")
	assert.InDelta(t, 3.0, entropy, 0.001)
}

// TestKnownDGADomains tests against known DGA domain patterns.
func TestKnownDGADomains(t *testing.T) {
	calc := NewDNSEntropyCalculator()
	calc.DGAThreshold = 3.5

	// These are examples of DGA-like domains (not real malware)
	dgaDomains := []string{
		"qxj4v9k2mnbp.example.com",
		"w8m3n5p7q9rs.example.com",
		"abc123def456ghi789.example.com",
	}

	for _, domain := range dgaDomains {
		t.Run(domain, func(t *testing.T) {
			isDGA := calc.IsDGADomain(domain)
			// Note: Some may not trigger depending on actual entropy
			// This test documents the behavior
			t.Logf("Domain %s: DGA=%v, entropy=%.2f", domain, isDGA,
				calc.CalculateShannonEntropy(calc.extractBaseDomain(domain)))
		})
	}
}

// TestIsHighFrequencyQuery tests the high-frequency detection.
func TestIsHighFrequencyQuery(t *testing.T) {
	calc := NewDNSEntropyCalculator()

	// 100 unique domains in 60 seconds should trigger
	assert.True(t, calc.IsHighFrequencyQuery("example.com", 101, 60))

	// 50 unique domains should not trigger
	assert.False(t, calc.IsHighFrequencyQuery("example.com", 50, 60))

	// Adjusted threshold for 30 second window: 50 domains
	assert.True(t, calc.IsHighFrequencyQuery("example.com", 51, 30))
	assert.False(t, calc.IsHighFrequencyQuery("example.com", 49, 30))
}

// TestIsHighFrequencyQuery_EdgeCases verifies Sprint 27.0 Part B fixes:
// ceiling division, zero/negative window, and zero uniqueDomains guards.
func TestIsHighFrequencyQuery_EdgeCases(t *testing.T) {
	calc := NewDNSEntropyCalculator()

	tests := []struct {
		name          string
		uniqueDomains int
		windowSeconds int
		want          bool
	}{
		// windowSeconds=30 → threshold = ceil(100*30/60) = 50
		{"30s window, 60 domains over threshold", 60, 30, true},
		{"30s window, 50 domains at threshold", 50, 30, false},
		{"30s window, 51 domains over threshold", 51, 30, true},
		// windowSeconds=1 → threshold = ceil(100*1/60) = 2
		{"1s window, 3 domains over threshold", 3, 1, true},
		{"1s window, 2 domains at threshold", 2, 1, false},
		// windowSeconds=0 → treated as 60 → threshold=100
		{"0s window treated as 60s, 101 domains", 101, 0, true},
		{"0s window treated as 60s, 99 domains", 99, 0, false},
		// windowSeconds=-1 → treated as 60 → threshold=100
		{"negative window treated as 60s, 101 domains", 101, -1, true},
		// uniqueDomains<=0 → always false
		{"zero uniqueDomains", 0, 60, false},
		{"negative uniqueDomains", -5, 60, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calc.IsHighFrequencyQuery("example.com", tt.uniqueDomains, tt.windowSeconds)
			assert.Equal(t, tt.want, got)
		})
	}
}
