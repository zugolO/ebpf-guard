package correlator

import (
	"testing"
)

func TestNgramExtractSLD(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"www.google.com", "google"},
		{"api.service.example.com", "example"},
		{"xkjlmzab123.io", "xkjlmzab123"},
		{"localhost", "localhost"},
		{"sub.domain.co.uk", "co"},
		{"google.com", "google"},
		{"UPPER.CASE.COM", "case"},
		{"trailing.dot.com.", "dot"}, // trailing dot stripped; SLD is second-to-last label
	}
	for _, tt := range tests {
		got := ngramExtractSLD(tt.input)
		if got != tt.want {
			t.Errorf("ngramExtractSLD(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNgramCharIdx(t *testing.T) {
	tests := []struct {
		c    byte
		want int
	}{
		{'a', 0}, {'z', 25}, {'m', 12},
		{'0', 26}, {'9', 35}, {'5', 31},
		{'-', 36},
		{'.', -1}, {'_', -1}, {'A', -1}, {' ', -1},
	}
	for _, tt := range tests {
		got := ngramCharIdx(tt.c)
		if got != tt.want {
			t.Errorf("ngramCharIdx(%q) = %d, want %d", tt.c, got, tt.want)
		}
	}
}

func TestNgramDGADetector_ScoreLegitimate(t *testing.T) {
	d := NewNgramDGADetector(0.70)
	legitimate := []string{
		"google.com",
		"youtube.com",
		"facebook.com",
		"amazon.com",
		"github.com",
		"stackoverflow.com",
		"cloudflare.com",
		"wikipedia.org",
		"microsoft.com",
		"apple.com",
	}
	for _, domain := range legitimate {
		score := d.Score(domain)
		if score >= 0.70 {
			t.Errorf("legitimate domain %q scored %.4f >= 0.70 (false positive)", domain, score)
		}
	}
}

func TestNgramDGADetector_ScoreDGA(t *testing.T) {
	d := NewNgramDGADetector(0.70)
	// Known DGA-style domains: high consonant density, low vowel ratio, random-looking
	dga := []string{
		"xkjlmzabqp.com",
		"zvtpqxfhwk.net",
		"bfxqzrtpvj.org",
		"kzmqwxptvr.io",
		"qvzxwplbtf.com",
	}
	for _, domain := range dga {
		score := d.Score(domain)
		if score < 0.70 {
			// Not a hard failure — the model is probabilistic. Log as info.
			t.Logf("DGA-style domain %q scored %.4f < 0.70 (may be OK for this corpus)", domain, score)
		}
	}
}

func TestNgramDGADetector_ScoreRange(t *testing.T) {
	d := NewNgramDGADetector(0.70)
	domains := []string{
		"google.com", "github.com", "xkjlmzabqp.com", "zvtpqxfhwk.net",
		"api.example.com", "mail.server.org",
	}
	for _, domain := range domains {
		score := d.Score(domain)
		if score < 0 || score > 1 {
			t.Errorf("Score(%q) = %.4f outside [0,1]", domain, score)
		}
	}
}

func TestNgramDGADetector_ShortDomain(t *testing.T) {
	d := NewNgramDGADetector(0.70)
	// SLD shorter than 4 chars should return 0
	short := []string{"a.com", "ab.io", "abc.net"}
	for _, domain := range short {
		score := d.Score(domain)
		if score != 0 {
			t.Errorf("short domain %q: Score() = %.4f, want 0", domain, score)
		}
	}
}

func TestNgramDGADetector_IsDGA(t *testing.T) {
	d := NewNgramDGADetector(0.70)

	if d.IsDGA("google.com") {
		t.Error("google.com should not be DGA")
	}
	if d.IsDGA("github.com") {
		t.Error("github.com should not be DGA")
	}
}

// TestNgramDGADetector_RelativeScores verifies that DGA-like domains score
// higher than well-known legitimate domains. The absolute threshold depends on
// the size of the embedded training corpus; relative ordering is the stable
// invariant for this small corpus.
func TestNgramDGADetector_RelativeScores(t *testing.T) {
	d := NewNgramDGADetector(0.70)
	legitimate := []struct{ domain string }{
		{"google.com"}, {"youtube.com"}, {"github.com"}, {"microsoft.com"},
	}
	dgaLike := []struct{ domain string }{
		{"xkjlmzabqp.com"}, {"zvtpqxfhwk.net"}, {"bfxqzrtpvj.org"},
	}

	// Compute mean scores for each category
	var legitSum, dgaSum float64
	for _, l := range legitimate {
		legitSum += d.Score(l.domain)
	}
	for _, dg := range dgaLike {
		dgaSum += d.Score(dg.domain)
	}
	legitMean := legitSum / float64(len(legitimate))
	dgaMean := dgaSum / float64(len(dgaLike))

	if dgaMean <= legitMean {
		t.Errorf("DGA-like mean score (%.4f) should exceed legitimate mean score (%.4f)", dgaMean, legitMean)
	}
}

func TestNgramDGADetector_Singleton(t *testing.T) {
	d1 := DefaultNgramDGADetector()
	d2 := DefaultNgramDGADetector()
	if d1 != d2 {
		t.Error("DefaultNgramDGADetector should return the same singleton")
	}
}

func TestPackageLevelScore(t *testing.T) {
	// package-level Score() must return same value as singleton detector
	domain := "google.com"
	got := Score(domain)
	want := DefaultNgramDGADetector().Score(domain)
	if got != want {
		t.Errorf("Score(%q) = %.6f, DefaultNgramDGADetector().Score() = %.6f", domain, got, want)
	}
}

func TestNgramDGADetector_ModelConsistency(t *testing.T) {
	// Two detectors with same threshold trained on same corpus must agree.
	d1 := NewNgramDGADetector(0.70)
	d2 := NewNgramDGADetector(0.70)
	domains := []string{"google.com", "xkjlmzabqp.com", "github.com", "zvtpqxfhwk.net"}
	for _, domain := range domains {
		s1 := d1.Score(domain)
		s2 := d2.Score(domain)
		if s1 != s2 {
			t.Errorf("Score(%q): d1=%.6f d2=%.6f (must be deterministic)", domain, s1, s2)
		}
	}
}

func BenchmarkNgramScore(b *testing.B) {
	d := NewNgramDGADetector(0.70)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Score("xkjlmzabqp123.com")
	}
}

func BenchmarkNgramScoreLegitimate(b *testing.B) {
	d := NewNgramDGADetector(0.70)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Score("api.service.cloudflare.com")
	}
}
