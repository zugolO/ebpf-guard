package correlator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func TestDefaultFingerprintConfig(t *testing.T) {
	cfg := DefaultFingerprintConfig()
	assert.True(t, cfg.Enabled)
	assert.Equal(t, "sha256", cfg.Algorithm)
}

func TestFingerprintGenerator_Verify_DisabledAlwaysTrue(t *testing.T) {
	fg := NewFingerprintGenerator(FingerprintConfig{Enabled: false})
	alert := types.Alert{ID: "x", Fingerprint: "not-even-a-real-hash"}
	assert.True(t, fg.Verify(alert), "disabled generator must not fail verification")
}

func TestFingerprintGenerator_Verify_EmptyFingerprintAlwaysTrue(t *testing.T) {
	fg := NewFingerprintGenerator(FingerprintConfig{Enabled: true})
	alert := types.Alert{ID: "x"} // Fingerprint left empty
	assert.True(t, fg.Verify(alert), "an alert with no fingerprint has nothing to verify")
}

func TestFingerprintGenerator_FallbackHash(t *testing.T) {
	fg := NewFingerprintGenerator(FingerprintConfig{Enabled: true})
	data := struct {
		ID        string `json:"id"`
		Timestamp int64  `json:"ts"`
		RuleID    string `json:"rule_id"`
		Severity  string `json:"severity"`
		PID       uint32 `json:"pid"`
		Comm      string `json:"comm"`
		Message   string `json:"msg"`
		Pod       string `json:"pod,omitempty"`
		Namespace string `json:"ns,omitempty"`
	}{
		ID: "abc", Timestamp: time.Now().UnixNano(), RuleID: "rule-1",
		Severity: "warning", PID: 42, Comm: "evil", Message: "boom",
	}

	got := fg.fallbackHash(data)
	assert.Len(t, got, 64, "sha256 hex digest is 64 chars")

	// Deterministic: same input yields the same hash.
	assert.Equal(t, got, fg.fallbackHash(data))

	// Different input yields a different hash.
	data.Message = "different"
	assert.NotEqual(t, got, fg.fallbackHash(data))
}
