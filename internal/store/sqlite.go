//go:build cgo
// +build cgo

// Package store provides SQLite storage backend for alerts and profiles.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

var (
	storeBackupLastSuccess = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ebpf_guard_store_backup_last_success_timestamp",
		Help: "Unix timestamp of the last successful SQLite backup.",
	})
	storeBackupDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "ebpf_guard_store_backup_duration_seconds",
		Help:    "Duration of SQLite backup operations.",
		Buckets: []float64{0.1, 0.5, 1, 5, 10, 30, 60},
	})
	storeSizeBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ebpf_guard_store_size_bytes",
		Help: "Approximate size of the SQLite alert database in bytes (page_count * page_size).",
	})
)

// SQLiteStore implements AlertStore using SQLite.
type SQLiteStore struct {
	db              *sql.DB
	maxAlerts       int64
	vacuumInterval  time.Duration
	retentionPeriod time.Duration
	backupEnabled   bool
	backupPath      string
	backupInterval  time.Duration
	cancel          context.CancelFunc
	done            chan struct{}
	backupDone      chan struct{}
	// encKey is the AES-256-GCM key used for column-level encryption of
	// sensitive fields (message, details, labels). nil means no encryption.
	encKey []byte
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

	// _journal_mode and _synchronous in the DSN ensure every connection
	// opened by the pool inherits these settings without an extra round-trip.
	db, err := sql.Open("sqlite3", cfg.Path+"?_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(time.Hour)

	if err := applySQLitePragmas(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply sqlite pragmas: %w", err)
	}

	backupInterval := cfg.BackupInterval
	if cfg.BackupEnabled && backupInterval <= 0 {
		backupInterval = time.Hour
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &SQLiteStore{
		db:              db,
		maxAlerts:       cfg.MaxAlerts,
		vacuumInterval:  cfg.VacuumInterval,
		retentionPeriod: cfg.RetentionPeriod,
		backupEnabled:   cfg.BackupEnabled,
		backupPath:      cfg.BackupPath,
		backupInterval:  backupInterval,
		cancel:          cancel,
		done:            make(chan struct{}),
		backupDone:      make(chan struct{}),
	}

	if cfg.EncryptionEnabled {
		key, err := loadEncryptionKey(cfg.EncryptionKeyEnv, cfg.EncryptionKeyFile)
		if err != nil {
			cancel()
			db.Close()
			return nil, fmt.Errorf("load encryption key: %w", err)
		}
		s.encKey = key
		slog.Info("sqlite: column-level AES-256-GCM encryption enabled",
			slog.String("path", cfg.Path))
	} else {
		slog.Warn("sqlite: encryption at rest is disabled — alert data (message, details, labels) is stored in plaintext",
			slog.String("path", cfg.Path),
			slog.String("docs", "set store.sqlite.encryption.enabled=true and configure key_env or key_file"))
	}

	if err := s.initSchema(); err != nil {
		cancel()
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}

	go s.runMaintenance(ctx)
	go s.runBackup(ctx)
	return s, nil
}

// runMaintenance is the background WAL checkpoint and row-pruning loop.
// It exits immediately when vacuumInterval is zero or the context is cancelled.
func (s *SQLiteStore) runMaintenance(ctx context.Context) {
	defer close(s.done)
	if s.vacuumInterval <= 0 {
		return
	}
	ticker := time.NewTicker(s.vacuumInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.performMaintenance(context.Background())
		}
	}
}

// performMaintenance checkpoints the WAL, prunes excess alerts, and applies
// age-based retention. It is safe to call directly in tests.
func (s *SQLiteStore) performMaintenance(ctx context.Context) {
	s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)") //nolint:errcheck
	if s.maxAlerts > 0 {
		s.pruneExcess(ctx)
	}
	if s.retentionPeriod > 0 {
		if _, err := s.Delete(ctx, s.retentionPeriod); err != nil {
			slog.Warn("sqlite: age-based retention failed", slog.Any("error", err))
		}
	}
	s.updateSizeMetric(ctx)
}

// updateSizeMetric sets storeSizeBytes from SQLite page statistics.
func (s *SQLiteStore) updateSizeMetric(ctx context.Context) {
	var pageCount, pageSize int64
	// Best-effort size metric; explicit `_ =` discards the error to satisfy both
	// errcheck and gosec G104 (a bare //nolint:errcheck leaves gosec unhappy).
	_ = s.db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pageCount)
	_ = s.db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize)
	if pageSize > 0 {
		storeSizeBytes.Set(float64(pageCount * pageSize))
	}
}

// runBackup is the background periodic-backup goroutine.
// It exits immediately if backup is disabled or the context is cancelled.
func (s *SQLiteStore) runBackup(ctx context.Context) {
	defer close(s.backupDone)
	if !s.backupEnabled || s.backupPath == "" {
		return
	}
	ticker := time.NewTicker(s.backupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.performBackup(ctx)
		}
	}
}

// performBackup creates a consistent copy of the database at backupPath using
// SQLite's VACUUM INTO statement, which produces a defragmented, WAL-free copy
// without blocking readers or writers. It is safe to call directly in tests.
func (s *SQLiteStore) performBackup(ctx context.Context) {
	if s.backupPath == "" {
		return
	}
	start := time.Now()
	_, err := s.db.ExecContext(ctx, "VACUUM INTO ?", s.backupPath)
	elapsed := time.Since(start)
	storeBackupDuration.Observe(elapsed.Seconds())
	if err != nil {
		slog.Error("sqlite: backup failed",
			slog.String("path", s.backupPath),
			slog.Duration("elapsed", elapsed),
			slog.Any("error", err))
		return
	}
	storeBackupLastSuccess.SetToCurrentTime()
	slog.Info("sqlite: backup completed",
		slog.String("path", s.backupPath),
		slog.Duration("elapsed", elapsed))
}

// pruneExcess deletes the oldest rows that exceed maxAlerts and reclaims space.
func (s *SQLiteStore) pruneExcess(ctx context.Context) {
	var count int64
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM alerts").Scan(&count); err != nil {
		return
	}
	excess := count - s.maxAlerts
	if excess <= 0 {
		return
	}
	s.db.ExecContext(ctx, //nolint:errcheck
		"DELETE FROM alerts WHERE id IN (SELECT id FROM alerts ORDER BY timestamp ASC LIMIT ?)",
		excess,
	)
	s.db.ExecContext(ctx, "VACUUM") //nolint:errcheck
}

// applySQLitePragmas sets performance-tuning PRAGMAs on an open database.
//
//   - journal_mode=WAL  — write-ahead log; readers never block writers.
//   - synchronous=NORMAL — fsync only at WAL checkpoints, not every commit;
//     safe against OS crash, sacrifices durability only on power loss.
//   - cache_size=-32000  — page cache of 32 MB (negative = kibibytes);
//     reduces I/O for bursty alert writes.
func applySQLitePragmas(db *sql.DB) error {
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA cache_size=-32000",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
	}
	return nil
}

// initSchema creates the alerts table if it doesn't exist and applies
// column migrations for databases created by older versions.
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
		count INTEGER,
		first_seen DATETIME,
		last_seen DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
	CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id);
	CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
	CREATE INDEX IF NOT EXISTS idx_alerts_pid ON alerts(pid);
	CREATE INDEX IF NOT EXISTS idx_alerts_namespace ON alerts(namespace);
	CREATE INDEX IF NOT EXISTS idx_alerts_timestamp_rule ON alerts(timestamp, rule_id);
	CREATE INDEX IF NOT EXISTS idx_alerts_severity_ts ON alerts(severity, timestamp DESC);
	`

	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	return s.migrateAggregationColumns()
}

// migrateAggregationColumns adds the alert-aggregation columns (count,
// first_seen, last_seen) to databases created before they existed. Newer
// databases already have them from CREATE TABLE, so each ADD COLUMN is guarded
// by a table_info check (SQLite has no ADD COLUMN IF NOT EXISTS).
func (s *SQLiteStore) migrateAggregationColumns() error {
	existing := map[string]bool{}
	rows, err := s.db.Query("PRAGMA table_info(alerts)")
	if err != nil {
		return fmt.Errorf("inspect alerts schema: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return fmt.Errorf("scan table_info: %w", err)
		}
		existing[name] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}

	migrations := []struct{ col, ddl string }{
		{"count", "ALTER TABLE alerts ADD COLUMN count INTEGER"},
		{"first_seen", "ALTER TABLE alerts ADD COLUMN first_seen DATETIME"},
		{"last_seen", "ALTER TABLE alerts ADD COLUMN last_seen DATETIME"},
	}
	for _, m := range migrations {
		if existing[m.col] {
			continue
		}
		if _, err := s.db.Exec(m.ddl); err != nil {
			return fmt.Errorf("migrate column %s: %w", m.col, err)
		}
	}
	return nil
}

// alertUpsertSQL inserts an alert, upserting on the id primary key. Alert
// aggregation (aggregator.Reap) re-emits the same alert ID with a final
// count/first_seen/last_seen once its window closes; a plain INSERT would fail
// the UNIQUE constraint and roll back the whole batch. ON CONFLICT applies the
// same last-write-wins upsert semantics the memory store already uses, so the
// aggregated count is persisted instead of lost.
const alertUpsertSQL = `
	INSERT INTO alerts (id, timestamp, rule_id, severity, pid, comm, message, details, trace_id, pod_name, namespace, container_id, labels, count, first_seen, last_seen)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		timestamp=excluded.timestamp,
		message=excluded.message,
		details=excluded.details,
		count=excluded.count,
		first_seen=excluded.first_seen,
		last_seen=excluded.last_seen
`

// alertSelectColumns is the column list shared by Query and QueryByID.
const alertSelectColumns = "id, timestamp, rule_id, severity, pid, comm, message, details, trace_id, pod_name, namespace, container_id, labels, count, first_seen, last_seen"

// nullTime returns a sql argument that stores t, or NULL when t is the zero
// time, so unaggregated alerts don't persist a bogus 0001-01-01 first/last_seen.
func nullTime(t time.Time) interface{} {
	if t.IsZero() {
		return nil
	}
	return t
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

	message := alert.Message
	storedDetails := string(detailsJSON)
	storedLabels := string(labelsJSON)

	if s.encKey != nil {
		if message, err = encryptColumn(s.encKey, []byte(alert.Message)); err != nil {
			return fmt.Errorf("encrypt message: %w", err)
		}
		if storedDetails, err = encryptColumn(s.encKey, detailsJSON); err != nil {
			return fmt.Errorf("encrypt details: %w", err)
		}
		if storedLabels, err = encryptColumn(s.encKey, labelsJSON); err != nil {
			return fmt.Errorf("encrypt labels: %w", err)
		}
	}

	_, err = s.db.ExecContext(ctx, alertUpsertSQL,
		alert.ID, alert.Timestamp, alert.RuleID, string(alert.Severity), alert.PID, alert.Comm,
		message, storedDetails, alert.TraceID, alert.Enrichment.PodName,
		alert.Enrichment.Namespace, alert.Enrichment.ContainerID, storedLabels,
		alert.Count, nullTime(alert.FirstSeen), nullTime(alert.LastSeen))
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

	stmt, err := tx.PrepareContext(ctx, alertUpsertSQL)
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

		message := alert.Message
		storedDetails := string(detailsJSON)
		storedLabels := string(labelsJSON)

		if s.encKey != nil {
			if message, err = encryptColumn(s.encKey, []byte(alert.Message)); err != nil {
				return fmt.Errorf("encrypt message for alert %s: %w", alert.ID, err)
			}
			if storedDetails, err = encryptColumn(s.encKey, detailsJSON); err != nil {
				return fmt.Errorf("encrypt details for alert %s: %w", alert.ID, err)
			}
			if storedLabels, err = encryptColumn(s.encKey, labelsJSON); err != nil {
				return fmt.Errorf("encrypt labels for alert %s: %w", alert.ID, err)
			}
		}

		if _, err = stmt.ExecContext(ctx, alert.ID, alert.Timestamp, alert.RuleID,
			string(alert.Severity), alert.PID, alert.Comm, message,
			storedDetails, alert.TraceID, alert.Enrichment.PodName,
			alert.Enrichment.Namespace, alert.Enrichment.ContainerID, storedLabels,
			alert.Count, nullTime(alert.FirstSeen), nullTime(alert.LastSeen)); err != nil {
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

// buildWhere constructs the WHERE clause (including the leading " WHERE ", or an
// empty string when there are no filters) and its bound arguments. Shared by
// buildQuery and Summarize so both apply identical filtering.
func (s *SQLiteStore) buildWhere(filters QueryFilters) (string, []interface{}) {
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
	if len(filters.Namespaces) > 0 {
		placeholders := make([]string, len(filters.Namespaces))
		for i := range filters.Namespaces {
			placeholders[i] = "?"
			args = append(args, filters.Namespaces[i])
		}
		whereClauses = append(whereClauses, fmt.Sprintf("namespace IN (%s)", strings.Join(placeholders, ",")))
	}

	if len(whereClauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(whereClauses, " AND "), args
}

// buildQuery constructs the SQL query and arguments from filters.
func (s *SQLiteStore) buildQuery(filters QueryFilters) (string, []interface{}) {
	where, args := s.buildWhere(filters)

	query := "SELECT " + alertSelectColumns + " FROM alerts" + where
	query += " ORDER BY timestamp DESC"

	if filters.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", filters.Limit)
	}
	if filters.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", filters.Offset)
	}

	return query, args
}

// Summarize computes the dashboard AlertSummary entirely in SQL (COUNT/GROUP
// BY) so no alert rows are materialized — total, per-severity counts, the top
// rules by volume, and an hourly timeline are each a single aggregate query.
// The Limit/Offset fields of filters are intentionally ignored: a summary
// always reflects the full matching window, never a truncated page.
func (s *SQLiteStore) Summarize(ctx context.Context, filters QueryFilters) (AlertSummary, error) {
	where, args := s.buildWhere(filters)
	summary := AlertSummary{BySeverity: map[string]int{}}

	// The three summary queries concatenate the WHERE clause built by buildWhere,
	// which uses only bound ? placeholders and constant clause fragments — no
	// caller data ever enters the SQL text — and the LIMIT is a compile-time
	// constant. gosec G202 can't prove that, hence the suppressions below.

	// Total + per-severity counts in one pass.
	sevQuery := "SELECT severity, COUNT(*) FROM alerts" + where + " GROUP BY severity" // #nosec G202 -- WHERE uses bound placeholders; only constant fragments concatenated
	sevRows, err := s.db.QueryContext(ctx, sevQuery, args...)
	if err != nil {
		return summary, fmt.Errorf("summarize severities: %w", err)
	}
	func() {
		defer func() { _ = sevRows.Close() }()
		for sevRows.Next() {
			var sev string
			var n int
			if err := sevRows.Scan(&sev, &n); err != nil {
				return
			}
			summary.BySeverity[sev] += n
			summary.Total += n
		}
	}()
	if err := sevRows.Err(); err != nil {
		return summary, fmt.Errorf("summarize severities: %w", err)
	}

	// Top rules by count, ties broken by rule_id for determinism.
	ruleGroupBy := fmt.Sprintf(" GROUP BY rule_id ORDER BY c DESC, rule_id ASC LIMIT %d", summaryTopRules)
	ruleQuery := "SELECT rule_id, COUNT(*) c FROM alerts" + where + ruleGroupBy // #nosec G202 -- WHERE uses bound placeholders; LIMIT is a constant
	ruleRows, err := s.db.QueryContext(ctx, ruleQuery, args...)
	if err != nil {
		return summary, fmt.Errorf("summarize top rules: %w", err)
	}
	func() {
		defer func() { _ = ruleRows.Close() }()
		for ruleRows.Next() {
			var rc RuleCount
			if err := ruleRows.Scan(&rc.RuleID, &rc.Count); err != nil {
				return
			}
			summary.TopRules = append(summary.TopRules, rc)
		}
	}()
	if err := ruleRows.Err(); err != nil {
		return summary, fmt.Errorf("summarize top rules: %w", err)
	}

	// Hourly timeline. strftime with the 'utc' modifier normalizes stored
	// timestamps (which may carry a zone offset) to UTC hour buckets, matching
	// the in-memory summary's Timestamp.UTC().Truncate(time.Hour).
	tlQuery := "SELECT strftime('%Y-%m-%dT%H:00:00Z', timestamp, 'utc') h, COUNT(*) FROM alerts" + where + " GROUP BY h ORDER BY h ASC" // #nosec G202 -- WHERE uses bound placeholders; only constant fragments concatenated
	tlRows, err := s.db.QueryContext(ctx, tlQuery, args...)
	if err != nil {
		return summary, fmt.Errorf("summarize timeline: %w", err)
	}
	hourCounts := make(map[time.Time]int)
	var minHour, maxHour time.Time
	var scanErr error
	func() {
		defer func() { _ = tlRows.Close() }()
		for tlRows.Next() {
			var hourStr string
			var n int
			if err := tlRows.Scan(&hourStr, &n); err != nil {
				scanErr = err
				return
			}
			hour, err := time.Parse(time.RFC3339, hourStr)
			if err != nil {
				scanErr = err
				return
			}
			hourCounts[hour] = n
			if minHour.IsZero() || hour.Before(minHour) {
				minHour = hour
			}
			if maxHour.IsZero() || hour.After(maxHour) {
				maxHour = hour
			}
		}
	}()
	if scanErr != nil {
		return summary, fmt.Errorf("summarize timeline: %w", scanErr)
	}
	if err := tlRows.Err(); err != nil {
		return summary, fmt.Errorf("summarize timeline: %w", err)
	}
	// Fill gaps between the first and last active hour so the timeline matches
	// the in-memory summary (contiguous buckets, zero-filled), capped at
	// summaryMaxBuckets.
	summary.Timeline = timelineFromCounts(hourCounts, minHour, maxHour)

	if summary.TopRules == nil {
		summary.TopRules = []RuleCount{}
	}
	return summary, nil
}

// decryptFields decrypts the sensitive columns of a scanned alert row when
// column-level encryption is active. If a column fails decryption (e.g. it was
// written before encryption was enabled) the original value is kept and a debug
// message is logged so mixed plaintext/encrypted databases degrade gracefully.
func (s *SQLiteStore) decryptFields(alertID string, message *string, detailsJSON, labelsJSON *[]byte) {
	if s.encKey == nil {
		return
	}
	if plain, err := decryptColumn(s.encKey, *message); err == nil {
		*message = string(plain)
	} else {
		slog.Debug("sqlite: message decryption failed, treating as plaintext",
			slog.String("alert_id", alertID), slog.Any("error", err))
	}
	if len(*detailsJSON) > 0 {
		if plain, err := decryptColumn(s.encKey, string(*detailsJSON)); err == nil {
			*detailsJSON = plain
		} else {
			slog.Debug("sqlite: details decryption failed, treating as plaintext",
				slog.String("alert_id", alertID), slog.Any("error", err))
		}
	}
	if len(*labelsJSON) > 0 {
		if plain, err := decryptColumn(s.encKey, string(*labelsJSON)); err == nil {
			*labelsJSON = plain
		} else {
			slog.Debug("sqlite: labels decryption failed, treating as plaintext",
				slog.String("alert_id", alertID), slog.Any("error", err))
		}
	}
}

// scanAlerts scans SQL rows into Alert structs.
func (s *SQLiteStore) scanAlerts(rows *sql.Rows) ([]types.Alert, error) {
	var alerts []types.Alert

	for rows.Next() {
		var alert types.Alert
		var severityStr string
		var detailsJSON, labelsJSON []byte
		var count sql.NullInt64
		var firstSeen, lastSeen sql.NullTime

		err := rows.Scan(
			&alert.ID, &alert.Timestamp, &alert.RuleID, &severityStr,
			&alert.PID, &alert.Comm, &alert.Message, &detailsJSON,
			&alert.TraceID, &alert.Enrichment.PodName, &alert.Enrichment.Namespace,
			&alert.Enrichment.ContainerID, &labelsJSON,
			&count, &firstSeen, &lastSeen,
		)
		if err != nil {
			return nil, fmt.Errorf("scan alert: %w", err)
		}

		if count.Valid {
			alert.Count = int(count.Int64)
		}
		if firstSeen.Valid {
			alert.FirstSeen = firstSeen.Time
		}
		if lastSeen.Valid {
			alert.LastSeen = lastSeen.Time
		}

		s.decryptFields(alert.ID, &alert.Message, &detailsJSON, &labelsJSON)

		alert.Severity = types.Severity(severityStr)
		if len(detailsJSON) > 0 {
			if err := json.Unmarshal(detailsJSON, &alert.Details); err != nil {
				slog.Warn("sqlite: failed to unmarshal alert details", slog.String("alert_id", alert.ID), slog.Any("error", err))
			}
		}
		if len(labelsJSON) > 0 {
			if err := json.Unmarshal(labelsJSON, &alert.Enrichment.Labels); err != nil {
				slog.Warn("sqlite: failed to unmarshal alert labels", slog.String("alert_id", alert.ID), slog.Any("error", err))
			}
		}

		alerts = append(alerts, alert)
	}

	return alerts, rows.Err()
}

// QueryByID retrieves a single alert by ID.
func (s *SQLiteStore) QueryByID(ctx context.Context, alertID string) (*types.Alert, error) {
	row := s.db.QueryRowContext(ctx,
		"SELECT "+alertSelectColumns+" FROM alerts WHERE id = ?", alertID)

	var alert types.Alert
	var severityStr string
	var detailsJSON, labelsJSON []byte
	var count sql.NullInt64
	var firstSeen, lastSeen sql.NullTime

	err := row.Scan(
		&alert.ID, &alert.Timestamp, &alert.RuleID, &severityStr,
		&alert.PID, &alert.Comm, &alert.Message, &detailsJSON,
		&alert.TraceID, &alert.Enrichment.PodName, &alert.Enrichment.Namespace,
		&alert.Enrichment.ContainerID, &labelsJSON,
		&count, &firstSeen, &lastSeen,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("alert not found: %s", alertID)
	}
	if err != nil {
		return nil, fmt.Errorf("scan alert: %w", err)
	}

	if count.Valid {
		alert.Count = int(count.Int64)
	}
	if firstSeen.Valid {
		alert.FirstSeen = firstSeen.Time
	}
	if lastSeen.Valid {
		alert.LastSeen = lastSeen.Time
	}

	s.decryptFields(alert.ID, &alert.Message, &detailsJSON, &labelsJSON)

	alert.Severity = types.Severity(severityStr)
	if len(detailsJSON) > 0 {
		if err := json.Unmarshal(detailsJSON, &alert.Details); err != nil {
			slog.Warn("sqlite: failed to unmarshal alert details", slog.String("alert_id", alert.ID), slog.Any("error", err))
		}
	}
	if len(labelsJSON) > 0 {
		if err := json.Unmarshal(labelsJSON, &alert.Enrichment.Labels); err != nil {
			slog.Warn("sqlite: failed to unmarshal alert labels", slog.String("alert_id", alert.ID), slog.Any("error", err))
		}
	}

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

// Flush checkpoints the SQLite WAL so all committed writes are in the main DB
// file and will survive a crash without replaying the WAL.
func (s *SQLiteStore) Flush(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	return err
}

// Close stops the background goroutines and closes the database.
func (s *SQLiteStore) Close() error {
	s.cancel()
	<-s.done
	<-s.backupDone
	return s.db.Close()
}

// Healthy checks if the database connection is alive.
func (s *SQLiteStore) Healthy(ctx context.Context) bool {
	return s.db.PingContext(ctx) == nil
}
