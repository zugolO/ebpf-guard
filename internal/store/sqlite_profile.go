//go:build cgo
// +build cgo

// Package store provides SQLite storage for behavioral profiles.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	_ "github.com/mattn/go-sqlite3"
)

// SQLiteProfileStore implements ProfileStore using SQLite.
type SQLiteProfileStore struct {
	db *sql.DB
}

// NewSQLiteProfileStore creates a new SQLite profile store.
func NewSQLiteProfileStore(cfg SQLiteConfig) (*SQLiteProfileStore, error) {
	if cfg.Path == "" {
		cfg.Path = ":memory:"
	}

	db, err := sql.Open("sqlite3", cfg.Path+"?_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	if err := applySQLitePragmas(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply sqlite pragmas: %w", err)
	}

	store := &SQLiteProfileStore{db: db}
	if err := store.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}

	return store, nil
}

// initSchema creates the profiles table if it doesn't exist.
func (s *SQLiteProfileStore) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS profiles (
		profile_key TEXT PRIMARY KEY,
		comm TEXT NOT NULL,
		namespace TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
		data BLOB NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_profiles_comm ON profiles(comm);
	CREATE INDEX IF NOT EXISTS idx_profiles_namespace ON profiles(namespace);
	CREATE INDEX IF NOT EXISTS idx_profiles_updated ON profiles(updated_at);
	`

	_, err := s.db.Exec(schema)
	return err
}

// Store persists a process profile.
func (s *SQLiteProfileStore) Store(ctx context.Context, profile *types.ProcessProfile) error {
	key := profileKey(profile)
	data, err := json.Marshal(profile)
	if err != nil {
		return fmt.Errorf("marshal profile: %w", err)
	}

	now := time.Now()
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO profiles (profile_key, comm, namespace, created_at, updated_at, data)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(profile_key) DO UPDATE SET
			updated_at = excluded.updated_at,
			data = excluded.data
	`, key, profile.Comm, profile.Namespace, now, now, data)

	if err != nil {
		return fmt.Errorf("store profile: %w", err)
	}
	return nil
}

// Load retrieves a profile by key.
func (s *SQLiteProfileStore) Load(ctx context.Context, key string) (*types.ProcessProfile, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT data FROM profiles WHERE profile_key = ?
	`, key)

	var data []byte
	err := row.Scan(&data)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("profile not found: %s", key)
	}
	if err != nil {
		return nil, fmt.Errorf("load profile: %w", err)
	}

	var profile types.ProcessProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("unmarshal profile: %w", err)
	}

	return &profile, nil
}

// LoadAll retrieves all stored profiles.
func (s *SQLiteProfileStore) LoadAll(ctx context.Context) ([]*types.ProcessProfile, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM profiles`)
	if err != nil {
		return nil, fmt.Errorf("query profiles: %w", err)
	}
	defer rows.Close()

	var profiles []*types.ProcessProfile
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, fmt.Errorf("scan profile: %w", err)
		}

		var profile types.ProcessProfile
		if err := json.Unmarshal(data, &profile); err != nil {
			return nil, fmt.Errorf("unmarshal profile: %w", err)
		}
		profiles = append(profiles, &profile)
	}

	return profiles, rows.Err()
}

// Delete removes a profile.
func (s *SQLiteProfileStore) Delete(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM profiles WHERE profile_key = ?`, key)
	return err
}

// Close closes the database connection.
func (s *SQLiteProfileStore) Close() error {
	return s.db.Close()
}

// DeleteOlderThan removes profiles not updated since the given time.
func (s *SQLiteProfileStore) DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx, `DELETE FROM profiles WHERE updated_at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("delete old profiles: %w", err)
	}
	return result.RowsAffected()
}
