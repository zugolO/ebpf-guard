// Package store provides pluggable storage backends for alerts and profiles.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/ebpf-guard/ebpf-guard/pkg/types"
)

// AlertStore defines the interface for alert persistence backends.
type AlertStore interface {
	// Store persists a single alert to the backend.
	// Returns an error if the store is unavailable or write fails.
	Store(ctx context.Context, alert types.Alert) error

	// StoreBatch persists multiple alerts efficiently.
	// Returns an error if the batch cannot be written.
	StoreBatch(ctx context.Context, alerts []types.Alert) error

	// Query retrieves alerts matching the given filters.
	// Results are ordered by timestamp descending (newest first).
	Query(ctx context.Context, filters QueryFilters) ([]types.Alert, error)

	// QueryByID retrieves a single alert by its unique ID.
	QueryByID(ctx context.Context, alertID string) (*types.Alert, error)

	// Count returns the total number of alerts matching the filters.
	Count(ctx context.Context, filters QueryFilters) (int64, error)

	// Delete removes alerts older than the given retention period.
	Delete(ctx context.Context, olderThan time.Duration) (int64, error)

	// Close releases all resources and closes the store connection.
	Close() error

	// Healthy returns true if the store connection is healthy.
	Healthy(ctx context.Context) bool
}

// QueryFilters defines filters for alert queries.
type QueryFilters struct {
	// Since filters alerts created after this time (inclusive).
	Since time.Time
	// Until filters alerts created before this time (inclusive).
	Until time.Time
	// PIDs filters by process ID (empty = all PIDs).
	PIDs []uint32
	// Severity filters by severity level (empty = all severities).
	Severity []types.Severity
	// RuleIDs filters by rule ID (empty = all rules).
	RuleIDs []string
	// PodName filters by Kubernetes pod name (empty = all pods).
	PodName string
	// Namespace filters by Kubernetes namespace (empty = all namespaces).
	Namespace string
	// Limit limits the number of results (0 = no limit).
	Limit int
	// Offset skips the first N results (for pagination).
	Offset int
}

// ProfileStore defines the interface for behavioral profile persistence.
type ProfileStore interface {
	// Store persists a process profile to disk.
	Store(ctx context.Context, profile *types.ProcessProfile) error

	// Load retrieves a profile by its unique key (e.g., "comm:namespace").
	Load(ctx context.Context, key string) (*types.ProcessProfile, error)

	// LoadAll retrieves all stored profiles.
	LoadAll(ctx context.Context) ([]*types.ProcessProfile, error)

	// Delete removes a profile from storage.
	Delete(ctx context.Context, key string) error

	// Close releases all resources.
	Close() error
}

// Config defines common configuration for all store backends.
type Config struct {
	// Backend specifies the storage backend type: "sqlite", "opensearch", "memory".
	Backend string
	// SQLite specific configuration.
	SQLite SQLiteConfig
	// OpenSearch specific configuration.
	OpenSearch OpenSearchConfig
	// RetentionPeriod defines how long to keep alerts before deletion.
	RetentionPeriod time.Duration
	// FlushInterval defines how often to flush profiles to disk.
	FlushInterval time.Duration
}

// SQLiteConfig defines SQLite-specific configuration.
type SQLiteConfig struct {
	// Path to the SQLite database file.
	Path string
	// MaxOpenConns limits the number of open connections.
	MaxOpenConns int
	// MaxIdleConns limits the number of idle connections.
	MaxIdleConns int
}

// OpenSearchConfig defines OpenSearch-specific configuration.
type OpenSearchConfig struct {
	// Addresses is a list of OpenSearch node URLs.
	Addresses []string
	// Username for basic authentication.
	Username string
	// Password for basic authentication.
	Password string
	// IndexPrefix is prepended to all index names.
	IndexPrefix string
	// InsecureSkipVerify disables TLS certificate verification.
	InsecureSkipVerify bool
}

// New creates a new AlertStore based on the configuration.
func New(cfg Config) (AlertStore, error) {
	switch cfg.Backend {
	case "sqlite":
		store, err := NewSQLiteStore(cfg.SQLite)
		if err != nil {
			return nil, fmt.Errorf("sqlite store: %w", err)
		}
		return store, nil
	case "opensearch":
		return NewOpenSearchStore(cfg.OpenSearch)
	case "memory":
		return NewMemoryStore(), nil
	default:
		return nil, fmt.Errorf("unknown store backend: %s", cfg.Backend)
	}
}

// NewProfileStore creates a new ProfileStore based on the configuration.
func NewProfileStore(cfg Config) (ProfileStore, error) {
	switch cfg.Backend {
	case "sqlite":
		store, err := NewSQLiteProfileStore(cfg.SQLite)
		if err != nil {
			return nil, fmt.Errorf("sqlite profile store: %w", err)
		}
		return store, nil
	case "memory":
		return NewMemoryProfileStore(), nil
	default:
		return nil, fmt.Errorf("unknown profile store backend: %s", cfg.Backend)
	}
}
