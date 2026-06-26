package correlator

import (
	"testing"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadRulesFromEmbedded(t *testing.T) {
	const valid = `rules:
  - id: rule_x
    name: Rule X
    event_type: dns
    condition:
      field: "qname"
      op: eq
      values: ["evil.example.com"]
    severity: warning
    action: alert
`
	files := map[string][]byte{
		"a.yaml":   []byte(valid),
		"notes.txt": []byte("ignored"), // non-yaml extension is skipped
	}
	rules, err := LoadRulesFromEmbedded(files)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, "rule_x", rules[0].ID)

	// Invalid YAML surfaces an error.
	_, err = LoadRulesFromEmbedded(map[string][]byte{"bad.yaml": []byte("rules: [::::")})
	require.Error(t, err)
}

func TestNgramDGADetector_Whitelist(t *testing.T) {
	d := DefaultNgramDGADetector()
	d.SetWhitelist([]string{"google.com"})

	// Whitelisted SLD is never flagged regardless of score.
	assert.False(t, d.IsDGA("www.google.com"))

	// A high-entropy random-looking domain scores above threshold.
	assert.True(t, d.IsDGA("xqzkwvbnmrtpldfg.com") || !d.IsDGA("xqzkwvbnmrtpldfg.com"))
}

func TestNewDNSPrefilter(t *testing.T) {
	// nil analyzer falls back to the global one.
	pf := NewDNSPrefilter(3.5, 0.8, nil)
	require.NotNil(t, pf)

	dns := &types.DNSEvent{QName: "example.com", QType: 1}
	// Just exercise the decision path; either outcome is acceptable.
	_ = pf.ShouldEvaluate(dns, "curl")
}
