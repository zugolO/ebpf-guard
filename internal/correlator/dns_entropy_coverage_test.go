package correlator

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRemoveSuspiciousTLD_AddsLeadingDotWhenMissing(t *testing.T) {
	calc := NewDNSEntropyCalculator()
	calc.AddSuspiciousTLD(".xyz-test-tld")
	assert.True(t, calc.SuspiciousTLDs[".xyz-test-tld"])

	// Passing the TLD without its leading dot must still remove the same entry.
	calc.RemoveSuspiciousTLD("xyz-test-tld")
	assert.False(t, calc.SuspiciousTLDs[".xyz-test-tld"])
}

func TestAnalyzeDomain_CacheHitReturnsSameResult(t *testing.T) {
	calc := NewDNSEntropyCalculator()
	first := calc.AnalyzeDomain("cache-hit-test.example.com")
	second := calc.AnalyzeDomain("cache-hit-test.example.com")
	assert.Equal(t, first, second)
}

func TestAnalyzeDomain_CacheEvictsOldestWhenFull(t *testing.T) {
	calc := NewDNSEntropyCalculator()

	// Fill the cache to capacity, then push one more unique domain through to
	// force the FIFO eviction path.
	for i := 0; i < analysisCacheMaxSize; i++ {
		calc.AnalyzeDomain(fmt.Sprintf("host%d.example.com", i))
	}
	calc.AnalyzeDomain("overflow.example.com")

	calc.cacheMu.Lock()
	size := len(calc.analysisCache)
	_, oldestStillPresent := calc.analysisCache["host0.example.com"]
	calc.cacheMu.Unlock()

	assert.Equal(t, analysisCacheMaxSize, size, "cache must stay capped at its max size")
	assert.False(t, oldestStillPresent, "the oldest entry must have been evicted")
}
