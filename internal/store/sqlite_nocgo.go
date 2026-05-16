//go:build !cgo
// +build !cgo

// Package store provides stub SQLite implementation for non-CGO builds.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/ebpf-guard/ebpf-guard/pkg/types"
)

// ErrNoCGO is returned when SQLite is requested but CGO is disabled.
var ErrNoCGO = errors.New("SQLite support requires CGO enabled")

// SQLiteStore is a placeholder type for non-CGO builds.
type SQLiteStore struct{}

// Store is a stub method.
func (s *SQLiteStore) Store(ctx context.Context, alert types.Alert) error { return ErrNoCGO }

// StoreBatch is a stub method.
func (s *SQLiteStore) StoreBatch(ctx context.Context, alerts []types.Alert) error { return ErrNoCGO }

// Query is a stub method.
func (s *SQLiteStore) Query(ctx context.Context, filters QueryFilters) ([]types.Alert, error) { return nil, ErrNoCGO }

// QueryByID is a stub method.
func (s *SQLiteStore) QueryByID(ctx context.Context, alertID string) (*types.Alert, error) { return nil, ErrNoCGO }

// Count is a stub method.
func (s *SQLiteStore) Count(ctx context.Context, filters QueryFilters) (int64, error) { return 0, ErrNoCGO }

// Delete is a stub method.
func (s *SQLiteStore) Delete(ctx context.Context, olderThan time.Duration) (int64, error) { return 0, ErrNoCGO }

// Close is a stub method.
func (s *SQLiteStore) Close() error { return nil }

// Healthy is a stub method.
func (s *SQLiteStore) Healthy(ctx context.Context) bool { return false }

// SQLiteProfileStore is a placeholder type for non-CGO builds.
type SQLiteProfileStore struct{}

// Store is a stub method.
func (s *SQLiteProfileStore) Store(ctx context.Context, profile *types.ProcessProfile) error { return ErrNoCGO }

// Load is a stub method.
func (s *SQLiteProfileStore) Load(ctx context.Context, key string) (*types.ProcessProfile, error) { return nil, ErrNoCGO }

// LoadAll is a stub method.
func (s *SQLiteProfileStore) LoadAll(ctx context.Context) ([]*types.ProcessProfile, error) { return nil, ErrNoCGO }

// Delete is a stub method.
func (s *SQLiteProfileStore) Delete(ctx context.Context, key string) error { return ErrNoCGO }

// Close is a stub method.
func (s *SQLiteProfileStore) Close() error { return nil }

// NewSQLiteStore returns an error since SQLite requires CGO.
func NewSQLiteStore(cfg SQLiteConfig) (*SQLiteStore, error) {
	return nil, ErrNoCGO
}

// NewSQLiteProfileStore returns an error since SQLite requires CGO.
func NewSQLiteProfileStore(cfg SQLiteConfig) (*SQLiteProfileStore, error) {
	return nil, ErrNoCGO
}
