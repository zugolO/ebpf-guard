//go:build cgo
// +build cgo

// Package store provides SQLite storage backend for alerts and profiles.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/zugolO/ebpf-guard/pkg/types"
	_ "github.com/mattn/go-sqlite3"
)

// SQLiteStore implements AlertStore using SQLite.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore creates a new SQLite alert store.
func NewSQLiteStore(cfg SQLiteConfig) (*SQLiteStore, error) {
	if cfg.Path == "" {
		cfg.Path = ":memory:"
	}
	if cfg.MaxOpenConns == 0 {
		cfg.MaxOpenConns = 10
	}
	if cfg.MaxIdleConns == 0 {
		cfg.MaxIdleConns = 5
	}

	db, err := sql.Open("sqlite3", cfg.Path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(time.Hour)

	store := &SQLiteStore{db: db}
	if err := store.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}

	return store, nil
}

// initSchema creates the alerts table if it doesn't exist.
func (s *SQLiteStore) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS alerts (
		id TEXT PRIMARY KEY,
		timestamp DATETIME NOT NULL,
		rule_id TEXT NOT NULL,
		severity TEXT NOT NULL,
		pid INTEGER NOT NULL,
		comm TEXT NOT NULL,
		message TEXT NOT NULL,
		details TEXT,
		trace_id TEXT,
		pod_name TEXT,
		namespace TEXT,
		container_id TEXT,
		labels TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
	CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id);
	CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
	CREATE INDEX IF NOT EXISTS idx_alerts_pid ON alerts(pid);
	CREATE INDEX IF NOT EXISTS idx_alerts_namespace ON alerts(namespace);
	CREATE INDEX IF NOT EXISTS idx_alerts_timestamp_rule ON alerts(timestamp, rule_id);
	`

	_, err := s.db.Exec(schema)
	return err
}

// Store persists a single alert.
func (s *SQLiteStore) Store(ctx context.Context, alert types.Alert) error {
	labelsJSON, err := json.Marshal(alert.Enrichment.Labels)
	if err != nil {
		return fmt.Errorf("marshal labels: %w", err)
	}

	detailsJSON, err := json.Marshal(alert.Details)
	if err != nil {
		return fmt.Errorf("marshal details: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO alerts (id, timestamp, rule_id, severity, pid, comm, message, details, trace_id, pod_name, namespace, container_id, labels)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, alert.ID, alert.Timestamp, alert.RuleID, string(alert.Severity), alert.PID, alert.Comm,
		alert.Message, detailsJSON, alert.TraceID, alert.Enrichment.PodName,
		alert.Enrichment.Namespace, alert.Enrichment.ContainerID, labelsJSON)

	if err != nil {
		return fmt.Errorf("insert alert: %w", err)
	}
	return nil
}

// StoreBatch persists multiple alerts in a transaction.
func (s *SQLiteStore) StoreBatch(ctx context.Context, alerts []types.Alert) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO alerts (id, timestamp, rule_id, severity, pid, comm, message, details, trace_id, pod_name, namespace, container_id, labels)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, alert := range alerts {
		labelsJSON, err := json.Marshal(alert.Enrichment.Labels)
		if err != nil {
			return fmt.Errorf("marshal labels for alert %s: %w", alert.ID, err)
		}
		detailsJSON, err := json.Marshal(alert.Details)
		if err != nil {
			return fmt.Errorf("marshal details for alert %s: %w", alert.ID, err)
		}

		if _, err = stmt.ExecContext(ctx, alert.ID, alert.Timestamp, alert.RuleID,
			string(alert.Severity), alert.PID, alert.Comm, alert.Message,
			detailsJSON, alert.TraceID, alert.Enrichment.PodName,
			alert.Enrichment.Namespace, alert.Enrichment.ContainerID, labelsJSON); err != nil {
			return fmt.Errorf("insert alert: %w", err)
		}
	}

	return tx.Commit()
}

// Query retrieves alerts matching the filters.
func (s *SQLiteStore) Query(ctx context.Context, filters QueryFilters) ([]types.Alert, error) {
	query, args := s.buildQuery(filters)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query alerts: %w", err)
	}
	defer rows.Close()

	return s.scanAlerts(rows)
}

// buildQuery constructs the SQL query and arguments from filters.
func (s *SQLiteStore) buildQuery(filters QueryFilters) (string, []interface{}) {
	var whereClauses []string
	var args []interface{}

	if !filters.Since.IsZero() {
		whereClauses = append(whereClauses, "timestamp >= ?")
		args = append(args, filters.Since)
	}
	if !filters.Until.IsZero() {
		whereClauses = append(whereClauses, "timestamp <= ?")
		args = append(args, filters.Until)
	}
	if len(filters.PIDs) > 0 {
		placeholders := make([]string, len(filters.PIDs))
		for i := range filters.PIDs {
			placeholders[i] = "?"
			args = append(args, filters.PIDs[i])
		}
		whereClauses = append(whereClauses, fmt.Sprintf("pid IN (%s)", strings.Join(placeholders, ",")))
	}
	if len(filters.Severity) > 0 {
		placeholders := make([]string, len(filters.Severity))
		for i, sev := range filters.Severity {
			placeholders[i] = "?"
			args = append(args, string(sev))
		}
		whereClauses = append(whereClauses, fmt.Sprintf("severity IN (%s)", strings.Join(placeholders, ",")))
	}
	if len(filters.RuleIDs) > 0 {
		placeholders := make([]string, len(filters.RuleIDs))
		for i := range filters.RuleIDs {
			placeholders[i] = "?"
			args = append(args, filters.RuleIDs[i])
		}
		whereClauses = append(whereClauses, fmt.Sprintf("rule_id IN (%s)", strings.Join(placeholders, ",")))
	}
	if filters.PodName != "" {
		whereClauses = append(whereClauses, "pod_name = ?")
		args = append(args, filters.PodName)
	}
	if filters.Namespace != "" {
		whereClauses = append(whereClauses, "namespace = ?")
		args = append(args, filters.Namespace)
	}

	query := "SELECT id, timestamp, rule_id, severity, pid, comm, message, details, trace_id, pod_name, namespace, container_id, labels FROM alerts"
	if len(whereClauses) > 0 {
		query += " WHERE " + strings.Join(whereClauses, " AND ")
	}
	query += " ORDER BY timestamp DESC"

	if filters.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", filters.Limit)
	}
	if filters.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", filters.Offset)
	}

	return query, args
}

// scanAlerts scans SQL rows into Alert structs.
func (s *SQLiteStore) scanAlerts(rows *sql.Rows) ([]types.Alert, error) {
	var alerts []types.Alert

	for rows.Next() {
		var alert types.Alert
		var severityStr string
		var detailsJSON, labelsJSON []byte

		err := rows.Scan(
			&alert.ID, &alert.Timestamp, &alert.RuleID, &severityStr,
			&alert.PID, &alert.Comm, &alert.Message, &detailsJSON,
			&alert.TraceID, &alert.Enrichment.PodName, &alert.Enrichment.Namespace,
			&alert.Enrichment.ContainerID, &labelsJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("scan alert: %w", err)
		}

		alert.Severity = types.Severity(severityStr)
		json.Unmarshal(detailsJSON, &alert.Details)
		json.Unmarshal(labelsJSON, &alert.Enrichment.Labels)

		alerts = append(alerts, alert)
	}

	return alerts, rows.Err()
}

// QueryByID retrieves a single alert by ID.
func (s *SQLiteStore) QueryByID(ctx context.Context, alertID string) (*types.Alert, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, timestamp, rule_id, severity, pid, comm, message, details, trace_id, pod_name, namespace, container_id, labels
		FROM alerts WHERE id = ?
	`, alertID)

	var alert types.Alert
	var severityStr string
	var detailsJSON, labelsJSON []byte

	err := row.Scan(
		&alert.ID, &alert.Timestamp, &alert.RuleID, &severityStr,
		&alert.PID, &alert.Comm, &alert.Message, &detailsJSON,
		&alert.TraceID, &alert.Enrichment.PodName, &alert.Enrichment.Namespace,
		&alert.Enrichment.ContainerID, &labelsJSON,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("alert not found: %s", alertID)
	}
	if err != nil {
		return nil, fmt.Errorf("scan alert: %w", err)
	}

	alert.Severity = types.Severity(severityStr)
	json.Unmarshal(detailsJSON, &alert.Details)
	json.Unmarshal(labelsJSON, &alert.Enrichment.Labels)

	return &alert, nil
}

// Count returns the number of matching alerts.
func (s *SQLiteStore) Count(ctx context.Context, filters QueryFilters) (int64, error) {
	query := "SELECT COUNT(*) FROM alerts"
	var whereClauses []string
	var args []interface{}

	if !filters.Since.IsZero() {
		whereClauses = append(whereClauses, "timestamp >= ?")
		args = append(args, filters.Since)
	}
	if !filters.Until.IsZero() {
		whereClauses = append(whereClauses, "timestamp <= ?")
		args = append(args, filters.Until)
	}
	if len(filters.PIDs) > 0 {
		placeholders := make([]string, len(filters.PIDs))
		for i := range filters.PIDs {
			placeholders[i] = "?"
			args = append(args, filters.PIDs[i])
		}
		whereClauses = append(whereClauses, fmt.Sprintf("pid IN (%s)", strings.Join(placeholders, ",")))
	}
	if len(filters.Severity) > 0 {
		placeholders := make([]string, len(filters.Severity))
		for i, sev := range filters.Severity {
			placeholders[i] = "?"
			args = append(args, string(sev))
		}
		whereClauses = append(whereClauses, fmt.Sprintf("severity IN (%s)", strings.Join(placeholders, ",")))
	}
	if len(filters.RuleIDs) > 0 {
		placeholders := make([]string, len(filters.RuleIDs))
		for i := range filters.RuleIDs {
			placeholders[i] = "?"
			args = append(args, filters.RuleIDs[i])
		}
		whereClauses = append(whereClauses, fmt.Sprintf("rule_id IN (%s)", strings.Join(placeholders, ",")))
	}

	if len(whereClauses) > 0 {
		query += " WHERE " + strings.Join(whereClauses, " AND ")
	}

	var count int64
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count alerts: %w", err)
	}
	return count, nil
}

// Delete removes alerts older than the given duration.
func (s *SQLiteStore) Delete(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan)
	result, err := s.db.ExecContext(ctx, "DELETE FROM alerts WHERE timestamp < ?", cutoff)
	if err != nil {
		return 0, fmt.Errorf("delete alerts: %w", err)
	}
	return result.RowsAffected()
}

// Close closes the database connection.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// Healthy checks if the database connection is alive.
func (s *SQLiteStore) Healthy(ctx context.Context) bool {
	return s.db.PingContext(ctx) == nil
}
