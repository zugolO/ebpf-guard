package correlator

import (
	"testing"
	"time"

	"github.com/ebpf-guard/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestFingerprintGenerator_Generate(t *testing.T) {
	config := FingerprintConfig{Enabled: true, Algorithm: "sha256"}
	fg := NewFingerprintGenerator(config)

	alert := types.Alert{
		ID:        "test-id",
		Timestamp: time.Unix(1234567890, 0),
		RuleID:    "rule-001",
		Severity:  types.SeverityCritical,
		PID:       1234,
		Comm:      "test-process",
		Message:   "Test alert message",
		Enrichment: types.EnrichmentInfo{
			PodName:   "test-pod",
			Namespace: "test-ns",
		},
	}

	// Generate fingerprint
	fp := fg.Generate(alert)
	assert.NotEmpty(t, fp)
	assert.Len(t, fp, 64) // SHA-256 hex string is 64 characters

	// Same alert should produce same fingerprint
	fp2 := fg.Generate(alert)
	assert.Equal(t, fp, fp2)

	// Different alert should produce different fingerprint
	alert2 := alert
	alert2.Message = "Different message"
	fp3 := fg.Generate(alert2)
	assert.NotEqual(t, fp, fp3)
}

func TestFingerprintGenerator_Disabled(t *testing.T) {
	config := FingerprintConfig{Enabled: false}
	fg := NewFingerprintGenerator(config)

	alert := types.Alert{
		ID:      "test-id",
		RuleID:  "rule-001",
		Message: "Test alert",
	}

	fp := fg.Generate(alert)
	assert.Empty(t, fp)
}

func TestFingerprintGenerator_Verify(t *testing.T) {
	config := FingerprintConfig{Enabled: true, Algorithm: "sha256"}
	fg := NewFingerprintGenerator(config)

	alert := types.Alert{
		ID:        "test-id",
		Timestamp: time.Unix(1234567890, 0),
		RuleID:    "rule-001",
		Severity:  types.SeverityWarning,
		PID:       5678,
		Comm:      "test",
		Message:   "Test",
	}

	// Generate and set fingerprint
	alert.Fingerprint = fg.Generate(alert)

	// Verify should pass
	assert.True(t, fg.Verify(alert))

	// Tampered alert should fail verification
	alert.Message = "Tampered"
	assert.False(t, fg.Verify(alert))
}

func TestGenerateID(t *testing.T) {
	ts := time.Unix(1234567890, 0)
	id1 := GenerateID(ts, "rule-001", 1234)
	id2 := GenerateID(ts, "rule-001", 1234)
	id3 := GenerateID(ts, "rule-002", 1234)

	// Same inputs should produce same ID
	assert.Equal(t, id1, id2)

	// Different inputs should produce different ID
	assert.NotEqual(t, id1, id3)

	// ID should be 32 characters (16 bytes hex encoded)
	assert.Len(t, id1, 32)
}
