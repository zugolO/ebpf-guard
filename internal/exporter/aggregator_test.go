package exporter

import (
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestAlertAggregator_Add(t *testing.T) {
	agg := NewAlertAggregator(1*time.Second, 5)

	alert := types.Alert{
		ID:        "alert-1",
		Timestamp: time.Now(),
		RuleID:    "rule_001",
		RuleName:  "Test Rule",
		Severity:  types.SeverityWarning,
		PID:       1234,
		Event: types.Event{
			PID: 1234,
		},
	}

	// First alert should create new bucket
	isNew := agg.Add(alert)
	assert.True(t, isNew)

	// Same alert should not create new bucket
	isNew = agg.Add(alert)
	assert.False(t, isNew)
}

func TestAlertAggregator_Flush(t *testing.T) {
	agg := NewAlertAggregator(100*time.Millisecond, 5)

	alert1 := types.Alert{
		ID:        "alert-1",
		Timestamp: time.Now(),
		RuleID:    "rule_001",
		RuleName:  "Test Rule 1",
		Severity:  types.SeverityWarning,
		Message:   "Test description 1",
		PID:       1234,
		Event:     types.Event{PID: 1234},
	}

	alert2 := types.Alert{
		ID:        "alert-2",
		Timestamp: time.Now(),
		RuleID:    "rule_002",
		RuleName:  "Test Rule 2",
		Severity:  types.SeverityCritical,
		Message:   "Test description 2",
		PID:       5678,
		Event:     types.Event{PID: 5678},
	}

	// Add alerts
	agg.Add(alert1)
	agg.Add(alert1) // Duplicate - should aggregate
	agg.Add(alert2)

	// Immediately flush - nothing should be flushed (window not expired)
	flushed := agg.Flush()
	assert.Empty(t, flushed)

	// Wait for window to expire
	time.Sleep(150 * time.Millisecond)

	// Now flush should return aggregated alerts
	flushed = agg.Flush()
	assert.Len(t, flushed, 2)

	// Check aggregation
	for _, alert := range flushed {
		if alert.RuleID == "rule_001" {
			assert.Contains(t, alert.Message, "occurred 2 times")
		} else if alert.RuleID == "rule_002" {
			assert.Contains(t, alert.Message, "occurred 1 times")
		}
	}
}

func TestAlertAggregator_GetAll(t *testing.T) {
	agg := NewAlertAggregator(1*time.Hour, 5)

	alert := types.Alert{
		ID:        "alert-1",
		Timestamp: time.Now(),
		RuleID:    "rule_001",
		RuleName:  "Test Rule",
		Severity:  types.SeverityWarning,
		PID:       1234,
		Event:     types.Event{PID: 1234},
	}

	agg.Add(alert)
	agg.Add(alert)

	// GetAll should return all buckets and clear them
	all := agg.GetAll()
	assert.Len(t, all, 1)
	assert.Contains(t, all[0].Message, "occurred 2 times")

	// Buckets should be empty now
	flushed := agg.Flush()
	assert.Empty(t, flushed)
}

func TestAlertAggregator_makeKey(t *testing.T) {
	agg := NewAlertAggregator(1*time.Second, 5)

	alert := types.Alert{
		ID:        "alert-1",
		Timestamp: time.Now(),
		RuleID:    "rule_001",
		Severity:  types.SeverityWarning,
		PID:       1234,
		Event:     types.Event{PID: 1234},
	}

	key := agg.makeKey(alert)
	assert.Equal(t, "rule_001:1234", key)
}

func TestAlertBucket_add(t *testing.T) {
	bucket := &alertBucket{
		key:        "test",
		ruleID:     "rule_001",
		severity:   types.SeverityWarning,
		summary:    "Test",
		firstSeen:  time.Now(),
		lastSeen:   time.Now(),
		count:      0,
		samples:    []types.Alert{},
		maxSamples: 3,
	}

	alert := types.Alert{RuleID: "rule_001"}

	// Add samples up to max
	bucket.add(alert)
	bucket.add(alert)
	bucket.add(alert)
	bucket.add(alert) // This one should not be added

	assert.Equal(t, 4, bucket.count)
	assert.Len(t, bucket.samples, 3) // Max samples
}

func TestAlertBucket_toAlert(t *testing.T) {
	bucket := &alertBucket{
		key:        "test",
		ruleID:     "rule_001",
		severity:   types.SeverityCritical,
		summary:    "Test Rule",
		firstSeen:  time.Now().Add(-5 * time.Minute),
		lastSeen:   time.Now(),
		count:      10,
		samples:    []types.Alert{{RuleID: "rule_001"}},
		maxSamples: 5,
	}

	alert := bucket.toAlert()

	assert.Equal(t, "rule_001", alert.RuleID)
	assert.Equal(t, "Test Rule", alert.RuleName)
	assert.Equal(t, types.SeverityCritical, alert.Severity)
	assert.Contains(t, alert.Message, "occurred 10 times")
	assert.Contains(t, alert.Message, "over 5m0s")
}
