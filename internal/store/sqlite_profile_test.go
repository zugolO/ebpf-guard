//go:build cgo
// +build cgo

// Package store provides storage backends for alerts and profiles.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestProfile(comm, ns string) *types.ProcessProfile {
	now := time.Now()
	return &types.ProcessProfile{
		Comm:          comm,
		Namespace:     ns,
		CreatedAt:     now,
		UpdatedAt:     now,
		SyscallCounts: map[int]float64{0: 10, 1: 5},
		AnomalyScore:  0.42,
		SampleCount:   3,
	}
}

func TestSQLiteProfileStore_Lifecycle(t *testing.T) {
	ctx := context.Background()
	s, err := NewSQLiteProfileStore(SQLiteConfig{Path: ":memory:"})
	require.NoError(t, err)
	defer s.Close()

	p := newTestProfile("nginx", "prod")
	require.NoError(t, s.Store(ctx, p))

	// Load round-trips the JSON blob back into a profile.
	loaded, err := s.Load(ctx, profileKey(p))
	require.NoError(t, err)
	assert.Equal(t, "nginx", loaded.Comm)
	assert.Equal(t, "prod", loaded.Namespace)
	assert.InDelta(t, 0.42, loaded.AnomalyScore, 1e-9)
	assert.Equal(t, float64(10), loaded.SyscallCounts[0])

	// Upsert: storing the same key again updates rather than duplicating.
	p.AnomalyScore = 0.99
	require.NoError(t, s.Store(ctx, p))

	all, err := s.LoadAll(ctx)
	require.NoError(t, err)
	require.Len(t, all, 1)
	assert.InDelta(t, 0.99, all[0].AnomalyScore, 1e-9)

	// Delete removes the row.
	require.NoError(t, s.Delete(ctx, profileKey(p)))
	_, err = s.Load(ctx, profileKey(p))
	require.Error(t, err)
}

func TestSQLiteProfileStore_LoadMissing(t *testing.T) {
	ctx := context.Background()
	s, err := NewSQLiteProfileStore(SQLiteConfig{Path: ":memory:"})
	require.NoError(t, err)
	defer s.Close()

	_, err = s.Load(ctx, "does:not-exist")
	require.Error(t, err)
}

func TestSQLiteProfileStore_DeleteOlderThan(t *testing.T) {
	ctx := context.Background()
	s, err := NewSQLiteProfileStore(SQLiteConfig{Path: ":memory:"})
	require.NoError(t, err)
	defer s.Close()

	require.NoError(t, s.Store(ctx, newTestProfile("old", "ns")))
	require.NoError(t, s.Store(ctx, newTestProfile("new", "ns")))

	// updated_at is set to time.Now() inside Store, so a future cutoff deletes all.
	deleted, err := s.DeleteOlderThan(ctx, time.Now().Add(time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(2), deleted)

	all, err := s.LoadAll(ctx)
	require.NoError(t, err)
	assert.Empty(t, all)
}

func TestNewProfileStore_SQLite(t *testing.T) {
	ps, err := NewProfileStore(Config{
		Backend: "sqlite",
		SQLite:  SQLiteConfig{Path: ":memory:"},
	})
	require.NoError(t, err)
	require.NotNil(t, ps)
	require.NoError(t, ps.Close())
}

func TestNew_SQLiteBackend(t *testing.T) {
	s, err := New(Config{
		Backend: "sqlite",
		SQLite:  SQLiteConfig{Path: ":memory:"},
	})
	require.NoError(t, err)
	require.NotNil(t, s)
	require.NoError(t, s.Close())
}
