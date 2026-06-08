// Package store provides pluggable storage backends for alerts and profiles.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
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

	// Flush ensures all buffered or pending writes are durably committed.
	// For backends that write synchronously (memory, OpenSearch) this is a no-op.
	// For SQLite, it triggers a WAL checkpoint so data is in the main DB file.
	Flush(ctx context.Context) error

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
	// Namespaces filters by a set of Kubernetes namespaces (OR logic).
	// When non-empty, takes precedence over the single Namespace field.
	Namespaces []string
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
	// MaxAlerts is the maximum number of alerts to retain; oldest excess rows
	// are pruned each VacuumInterval. Zero disables pruning.
	MaxAlerts int64
	// VacuumInterval controls how often WAL checkpoint and row pruning run.
	// Zero disables the background maintenance goroutine.
	VacuumInterval time.Duration
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

// InstrumentedStore wraps an AlertStore with Prometheus metrics.
type InstrumentedStore struct {
	inner        AlertStore
	alertsTotal  prometheus.Counter   // ebpf_guard_store_alerts_total
	latency      prometheus.Histogram // ebpf_guard_store_latency_seconds
}

// NewInstrumentedStore wraps an AlertStore with Sprint 34.0 metrics.
func NewInstrumentedStore(inner AlertStore) *InstrumentedStore {
	return &InstrumentedStore{
		inner: inner,
		alertsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "ebpf_guard_store_alerts_total",
			Help: "Total number of alerts persisted to the store.",
		}),
		latency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "ebpf_guard_store_latency_seconds",
			Help:    "Latency of alert store write operations.",
			Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0},
		}),
	}
}

// RegisterMetrics registers the store metrics with the given Prometheus registerer.
func (s *InstrumentedStore) RegisterMetrics(reg prometheus.Registerer) error {
	for _, c := range []prometheus.Collector{s.alertsTotal, s.latency} {
		if err := reg.Register(c); err != nil {
			return err
		}
	}
	return nil
}

// Store persists a single alert and records metrics.
func (s *InstrumentedStore) Store(ctx context.Context, alert types.Alert) error {
	start := time.Now()
	err := s.inner.Store(ctx, alert)
	s.latency.Observe(time.Since(start).Seconds())
	if err == nil {
		s.alertsTotal.Add(1)
	}
	return err
}

// StoreBatch persists multiple alerts and records metrics.
func (s *InstrumentedStore) StoreBatch(ctx context.Context, alerts []types.Alert) error {
	start := time.Now()
	err := s.inner.StoreBatch(ctx, alerts)
	s.latency.Observe(time.Since(start).Seconds())
	if err == nil {
		s.alertsTotal.Add(float64(len(alerts)))
	}
	return err
}

func (s *InstrumentedStore) Query(ctx context.Context, filters QueryFilters) ([]types.Alert, error) {
	return s.inner.Query(ctx, filters)
}

func (s *InstrumentedStore) QueryByID(ctx context.Context, alertID string) (*types.Alert, error) {
	return s.inner.QueryByID(ctx, alertID)
}

func (s *InstrumentedStore) Count(ctx context.Context, filters QueryFilters) (int64, error) {
	return s.inner.Count(ctx, filters)
}

func (s *InstrumentedStore) Delete(ctx context.Context, olderThan time.Duration) (int64, error) {
	return s.inner.Delete(ctx, olderThan)
}

func (s *InstrumentedStore) Flush(ctx context.Context) error { return s.inner.Flush(ctx) }

func (s *InstrumentedStore) Close() error { return s.inner.Close() }

func (s *InstrumentedStore) Healthy(ctx context.Context) bool { return s.inner.Healthy(ctx) }

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
