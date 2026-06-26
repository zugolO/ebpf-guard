//go:build cgo
// +build cgo

package store

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSQLiteStore_EncryptionRoundTrip(t *testing.T) {
	t.Setenv("EG_SQLITE_KEY", hex.EncodeToString(testKey()))

	s, err := NewSQLiteStore(SQLiteConfig{
		Path:              ":memory:",
		EncryptionEnabled: true,
		EncryptionKeyEnv:  "EG_SQLITE_KEY",
	})
	require.NoError(t, err)
	defer s.Close()

	ctx := context.Background()
	alert := types.Alert{
		ID:        "enc-1",
		Timestamp: time.Now(),
		RuleID:    "rule-secret",
		Severity:  types.SeverityCritical,
		PID:       4242,
		Comm:      "leak",
		Message:   "highly sensitive payload with PII",
		Details:   map[string]interface{}{"token": "s3cr3t"},
	}
	require.NoError(t, s.Store(ctx, alert))

	// QueryByID must transparently decrypt the message and details.
	got, err := s.QueryByID(ctx, "enc-1")
	require.NoError(t, err)
	assert.Equal(t, "highly sensitive payload with PII", got.Message)
	assert.Equal(t, "s3cr3t", got.Details["token"])

	// Query path also decrypts.
	results, err := s.Query(ctx, QueryFilters{})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "highly sensitive payload with PII", results[0].Message)
}

func TestNewSQLiteStore_EncryptionMissingKey(t *testing.T) {
	// Encryption requested but no key source configured → constructor error.
	_, err := NewSQLiteStore(SQLiteConfig{
		Path:              ":memory:",
		EncryptionEnabled: true,
		EncryptionKeyEnv:  "EG_DEFINITELY_UNSET_KEY",
	})
	require.Error(t, err)
}
