package correlator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNgramDGADetector_Score_NoScorableBigramsReturnsZero(t *testing.T) {
	d := DefaultNgramDGADetector()
	// SLD is long enough (>=4) but every character maps to ngramCharIdx == -1,
	// so no bigram contributes to the score and n stays 0.
	assert.Equal(t, 0.0, d.Score("!@#$.com"))
}

func TestNgramDGADetector_IsDGA_WhitelistPresentButNoMatch(t *testing.T) {
	d := DefaultNgramDGADetector()
	d.SetWhitelist([]string{"google"})

	// SLD ("example") is not in the whitelist, so IsDGA must fall through to
	// the normal Score/threshold check instead of short-circuiting to false.
	got := d.IsDGA("www.example.com")
	want := d.Score("www.example.com") >= d.threshold
	assert.Equal(t, want, got)
}
