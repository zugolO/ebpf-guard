// Package correlator provides event correlation and rule matching.
package correlator

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	xxhash "github.com/cespare/xxhash/v2"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// FingerprintConfig holds configuration for alert fingerprinting.
type FingerprintConfig struct {
	Enabled   bool
	Algorithm string // "xxhash" (default)
}

// DefaultFingerprintConfig returns the default fingerprint configuration.
func DefaultFingerprintConfig() FingerprintConfig {
	return FingerprintConfig{
		Enabled:   true,
		Algorithm: "xxhash",
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
// Returns a 16-character hex string (xxHash64).
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

	return fmt.Sprintf("%016x", xxhash.Sum64(jsonBytes))
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
	return fmt.Sprintf("%016x", xxhash.Sum64([]byte(str)))
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
// Fields are written directly to the hasher to avoid intermediate string allocations.
// Returns a 16-character hex string (xxHash64).
func GenerateID(timestamp time.Time, ruleID string, pid uint32) string {
	h := xxhash.New()
	var tmp [12]byte
	binary.LittleEndian.PutUint64(tmp[:8], uint64(timestamp.UnixNano()))
	binary.LittleEndian.PutUint32(tmp[8:], pid)
	h.Write(tmp[:])
	h.WriteString(ruleID) //nolint:errcheck
	return fmt.Sprintf("%016x", h.Sum64())
}
