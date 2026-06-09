package correlator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

func TestFingerprintGenerator_Generate(t *testing.T) {
	config := FingerprintConfig{Enabled: true, Algorithm: "xxhash"}
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
	assert.Len(t, fp, 16) // xxHash64 hex string is 16 characters

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
	config := FingerprintConfig{Enabled: true, Algorithm: "xxhash"}
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

	// ID should be 16 characters (xxHash64 hex encoded)
	assert.Len(t, id1, 16)
}

func BenchmarkGenerateID(b *testing.B) {
	ts := time.Now()
	for i := 0; i < b.N; i++ {
		GenerateID(ts, "rule-001", 1234)
	}
}

func BenchmarkFingerprintGenerator_Generate(b *testing.B) {
	fg := NewFingerprintGenerator(DefaultFingerprintConfig())
	alert := types.Alert{
		ID:        "bench-id",
		Timestamp: time.Now(),
		RuleID:    "rule-001",
		Severity:  types.SeverityCritical,
		PID:       1234,
		Comm:      "bench-proc",
		Message:   "benchmark alert message",
		Enrichment: types.EnrichmentInfo{
			PodName:   "bench-pod",
			Namespace: "default",
		},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		fg.Generate(alert)
	}
}
