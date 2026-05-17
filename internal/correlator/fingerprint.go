// Package correlator provides event correlation and rule matching.
package correlator

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ebpf-guard/ebpf-guard/pkg/types"
)

// FingerprintConfig holds configuration for alert fingerprinting.
type FingerprintConfig struct {
	Enabled   bool
	Algorithm string // "sha256" (default)
}

// DefaultFingerprintConfig returns the default fingerprint configuration.
func DefaultFingerprintConfig() FingerprintConfig {
	return FingerprintConfig{
		Enabled:   true,
		Algorithm: "sha256",
	}
}

// FingerprintGenerator generates fingerprints for alerts.
type FingerprintGenerator struct {
	config FingerprintConfig
}

// NewFingerprintGenerator creates a new fingerprint generator.
func NewFingerprintGenerator(config FingerprintConfig) *FingerprintGenerator {
	return &FingerprintGenerator{
		config: config,
	}
}

// Generate creates a fingerprint for the given alert.
// The fingerprint is a hash of critical alert fields for tamper detection.
func (fg *FingerprintGenerator) Generate(alert types.Alert) string {
	if !fg.config.Enabled {
		return ""
	}

	// Create a canonical representation of critical fields
	data := struct {
		ID        string `json:"id"`
		Timestamp int64  `json:"ts"` // Unix timestamp for precision
		RuleID    string `json:"rule_id"`
		Severity  string `json:"severity"`
		PID       uint32 `json:"pid"`
		Comm      string `json:"comm"`
		Message   string `json:"msg"`
		Pod       string `json:"pod,omitempty"`
		Namespace string `json:"ns,omitempty"`
	}{
		ID:        alert.ID,
		Timestamp: alert.Timestamp.UnixNano(),
		RuleID:    alert.RuleID,
		Severity:  string(alert.Severity),
		PID:       alert.PID,
		Comm:      alert.Comm,
		Message:   alert.Message,
		Pod:       alert.Enrichment.PodName,
		Namespace: alert.Enrichment.Namespace,
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		// Fallback to simple string concatenation
		return fg.fallbackHash(data)
	}

	hash := sha256.Sum256(jsonBytes)
	return hex.EncodeToString(hash[:])
}

// fallbackHash creates a simple hash without JSON marshaling.
func (fg *FingerprintGenerator) fallbackHash(data struct {
	ID        string `json:"id"`
	Timestamp int64  `json:"ts"`
	RuleID    string `json:"rule_id"`
	Severity  string `json:"severity"`
	PID       uint32 `json:"pid"`
	Comm      string `json:"comm"`
	Message   string `json:"msg"`
	Pod       string `json:"pod,omitempty"`
	Namespace string `json:"ns,omitempty"`
}) string {
	str := fmt.Sprintf("%s|%d|%s|%s|%d|%s|%s|%s|%s",
		data.ID, data.Timestamp, data.RuleID, data.Severity,
		data.PID, data.Comm, data.Message, data.Pod, data.Namespace)
	hash := sha256.Sum256([]byte(str))
	return hex.EncodeToString(hash[:])
}

// Verify checks if the alert's fingerprint matches its content.
func (fg *FingerprintGenerator) Verify(alert types.Alert) bool {
	if !fg.config.Enabled || alert.Fingerprint == "" {
		return true // Nothing to verify
	}

	expected := fg.Generate(alert)
	return expected == alert.Fingerprint
}

// GenerateID creates a unique alert ID based on timestamp and content.
func GenerateID(timestamp time.Time, ruleID string, pid uint32) string {
	data := fmt.Sprintf("%d:%s:%d", timestamp.UnixNano(), ruleID, pid)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:16]) // Use first 16 bytes for shorter ID
}
