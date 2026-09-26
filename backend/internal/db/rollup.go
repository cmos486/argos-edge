package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Hourly rollup of log_entries (v1.3.42.0, migration 034). FillRollupHour
// writes one closed UTC hour into log_hourly and log_hourly_paths from
// the raw rows, idempotently (INSERT OR REPLACE per key inside one
// transaction), so a job may re-run any hour. Readers stitch closed
// hours from the rollup with the hour in progress from log_entries.

// RollupPathsPerHost is how many paths per host each hour keeps.
const RollupPathsPerHost = 50

// Per-hour fill statements. The grouped pass reads the hour's rows once
// through idx_log_entries_timestamp (a range on the pinned index; the
// only per-row cost is the page read, measured on the dense demo at
// 0.6 s per hour under IO pressure). host_id 0 stands for NULL.
const rollupFillMainSQL = `
INSERT OR REPLACE INTO log_hourly
  (hour, source, host_id, status_class, requests, bytes_out, dur_sum_ms, dur_max_ms,
   dur_h0, dur_h1, dur_h2, dur_h3, dur_h4, dur_h5, dur_h6, dur_h7,
   forbidden, rate_limited, errors, updated_at)
SELECT ?, source, COALESCE(host_id, 0), CASE WHEN status >= 100 THEN status / 100 ELSE 0 END,
       COUNT(*), COALESCE(SUM(size_bytes), 0), COALESCE(SUM(duration_ms), 0), COALESCE(MAX(duration_ms), 0),
       SUM(duration_ms <= 50), SUM(duration_ms > 50 AND duration_ms <= 100),
       SUM(duration_ms > 100 AND duration_ms <= 250), SUM(duration_ms > 250 AND duration_ms <= 500),
       SUM(duration_ms > 500 AND duration_ms <= 1000), SUM(duration_ms > 1000 AND duration_ms <= 2500),
       SUM(duration_ms > 2500 AND duration_ms <= 5000), SUM(duration_ms > 5000),
       SUM(status = 403), SUM(status = 429), SUM(level = 'error'), CURRENT_TIMESTAMP
FROM log_entries INDEXED BY idx_log_entries_timestamp
WHERE timestamp >= ? AND timestamp < ?
GROUP BY source, COALESCE(host_id, 0), CASE WHEN status >= 100 THEN status / 100 ELSE 0 END`

// Exact per-group percentiles for the hour's access rows: rank the
// durations inside each group and pick the ceil(p * n)-th.
const rollupFillPctSQL = `
WITH ranked AS (
  SELECT source, COALESCE(host_id, 0) AS h, CASE WHEN status >= 100 THEN status / 100 ELSE 0 END AS sc,
         duration_ms,
         ROW_NUMBER() OVER (PARTITION BY source, COALESCE(host_id, 0), CASE WHEN status >= 100 THEN status / 100 ELSE 0 END ORDER BY duration_ms) AS rn,
         COUNT(*) OVER (PARTITION BY source, COALESCE(host_id, 0), CASE WHEN status >= 100 THEN status / 100 ELSE 0 END) AS n
  FROM log_entries INDEXED BY idx_log_entries_timestamp
  WHERE timestamp >= ? AND timestamp < ? AND source = 'caddy_access'
)
UPDATE log_hourly SET
  dur_p50_ms = (SELECT duration_ms FROM ranked r WHERE r.source = log_hourly.source AND r.h = log_hourly.host_id AND r.sc = log_hourly.status_class AND r.rn = MAX(1, (r.n * 50 + 99) / 100)),
  dur_p95_ms = (SELECT duration_ms FROM ranked r WHERE r.source = log_hourly.source AND r.h = log_hourly.host_id AND r.sc = log_hourly.status_class AND r.rn = MAX(1, (r.n * 95 + 99) / 100)),
  dur_p99_ms = (SELECT duration_ms FROM ranked r WHERE r.source = log_hourly.source AND r.h = log_hourly.host_id AND r.sc = log_hourly.status_class AND r.rn = MAX(1, (r.n * 99 + 99) / 100))
WHERE hour = ? AND source = 'caddy_access'`

const rollupFillPathsSQL = `
INSERT OR REPLACE INTO log_hourly_paths (hour, host_id, path, requests, bytes_out, updated_at)
SELECT ?, h, path, c, b, CURRENT_TIMESTAMP FROM (
  SELECT COALESCE(host_id, 0) AS h, path, COUNT(*) AS c, COALESCE(SUM(size_bytes), 0) AS b,
         ROW_NUMBER() OVER (PARTITION BY COALESCE(host_id, 0) ORDER BY COUNT(*) DESC, path) AS rn
  FROM log_entries INDEXED BY idx_log_entries_timestamp
  WHERE timestamp >= ? AND timestamp < ? AND source = 'caddy_access' AND path <> ''
  GROUP BY COALESCE(host_id, 0), path
) WHERE rn <= ?`

// RollupFillResult reports one hour's fill.
type RollupFillResult struct {
	Hour     time.Time
	Rows     int64 // log_hourly rows written (groups)
	PathRows int64 // log_hourly_paths rows written
	Elapsed  time.Duration
}

// FillRollupHour aggregates [hour, hour+1h) into the rollup tables in
// one transaction. hour must be a UTC hour start. Re-filling an hour
// replaces its groups; groups that disappeared from the raw rows (a
// purge in between) are deleted first so the hour never keeps stale
// keys.
func FillRollupHour(ctx context.Context, d *sql.DB, hour time.Time) (RollupFillResult, error) {
	hour = hour.UTC().Truncate(time.Hour)
	next := hour.Add(time.Hour)
	res := RollupFillResult{Hour: hour}
	start := time.Now()
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("rollup begin: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM log_hourly WHERE hour = ?`, hour); err != nil {
		return res, fmt.Errorf("rollup clear hour: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM log_hourly_paths WHERE hour = ?`, hour); err != nil {
		return res, fmt.Errorf("rollup clear paths: %w", err)
	}
	r, err := tx.ExecContext(ctx, rollupFillMainSQL, hour, hour, next)
	if err != nil {
		return res, fmt.Errorf("rollup fill: %w", err)
	}
	res.Rows, _ = r.RowsAffected()
	if _, err := tx.ExecContext(ctx, rollupFillPctSQL, hour, next, hour); err != nil {
		return res, fmt.Errorf("rollup percentiles: %w", err)
	}
	r, err = tx.ExecContext(ctx, rollupFillPathsSQL, hour, hour, next, RollupPathsPerHost)
	if err != nil {
		return res, fmt.Errorf("rollup paths: %w", err)
	}
	res.PathRows, _ = r.RowsAffected()
	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("rollup commit: %w", err)
	}
	res.Elapsed = time.Since(start)
	return res, nil
}

// dbTimeLayouts are the text forms a TIMESTAMP column may hold: the
// driver's default (time.Time.String) for rows argos wrote, RFC 3339
// for rows written by hand, and the bare form.
var dbTimeLayouts = []string{
	"2006-01-02 15:04:05.999999999 -0700 MST",
	time.RFC3339Nano,
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05",
}

// ParseDBTime parses a TIMESTAMP column read as text.
func ParseDBTime(s string) (time.Time, error) {
	for _, l := range dbTimeLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognised timestamp %q", s)
}

func scalarTime(ctx context.Context, d *sql.DB, q string) (time.Time, bool, error) {
	var s sql.NullString
	if err := d.QueryRowContext(ctx, q).Scan(&s); err != nil {
		return time.Time{}, false, err
	}
	if !s.Valid || s.String == "" {
		return time.Time{}, false, nil
	}
	t, err := ParseDBTime(s.String)
	if err != nil {
		return time.Time{}, false, err
	}
	return t, true, nil
}

// RollupMaxHour returns the newest hour present in log_hourly.
func RollupMaxHour(ctx context.Context, d *sql.DB) (time.Time, bool, error) {
	return scalarTime(ctx, d, `SELECT MAX(hour) FROM log_hourly`)
}

// LogEntriesMinHour returns the hour of the oldest log_entries row.
func LogEntriesMinHour(ctx context.Context, d *sql.DB) (time.Time, bool, error) {
	t, ok, err := scalarTime(ctx, d, `SELECT MIN(timestamp) FROM log_entries`)
	if err != nil || !ok {
		return t, ok, err
	}
	return t.Truncate(time.Hour), true, nil
}

// RollupDriftResult compares one closed hour on both sides.
type RollupDriftResult struct {
	Hour           time.Time
	RawRows        int64
	RollupRequests int64
	RawBytes       int64
	RollupBytes    int64
	RawByClass     map[int]int64
	RollupByClass  map[int]int64
}

// Agrees is true when every compared number matches (tolerance 0).
func (r RollupDriftResult) Agrees() bool {
	if r.RawRows != r.RollupRequests || r.RawBytes != r.RollupBytes {
		return false
	}
	for c := 0; c <= 5; c++ {
		if r.RawByClass[c] != r.RollupByClass[c] {
			return false
		}
	}
	return true
}

// RollupDrift recomputes the hour's totals and per-class counts from
// log_entries and reads the rollup's; the caller decides what to do.
func RollupDrift(ctx context.Context, d *sql.DB, hour time.Time) (RollupDriftResult, error) {
	hour = hour.UTC().Truncate(time.Hour)
	next := hour.Add(time.Hour)
	res := RollupDriftResult{Hour: hour, RawByClass: map[int]int64{}, RollupByClass: map[int]int64{}}
	if err := d.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM log_entries INDEXED BY idx_log_entries_timestamp WHERE timestamp >= ? AND timestamp < ?`,
		hour, next).Scan(&res.RawRows, &res.RawBytes); err != nil {
		return res, fmt.Errorf("drift raw: %w", err)
	}
	if err := d.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(requests), 0), COALESCE(SUM(bytes_out), 0) FROM log_hourly WHERE hour = ?`,
		hour).Scan(&res.RollupRequests, &res.RollupBytes); err != nil {
		return res, fmt.Errorf("drift rollup: %w", err)
	}
	rows, err := d.QueryContext(ctx,
		`SELECT CASE WHEN status >= 100 THEN status / 100 ELSE 0 END AS c, COUNT(*) FROM log_entries INDEXED BY idx_log_entries_timestamp WHERE timestamp >= ? AND timestamp < ? GROUP BY c`,
		hour, next)
	if err != nil {
		return res, fmt.Errorf("drift raw classes: %w", err)
	}
	for rows.Next() {
		var c int
		var n int64
		if err := rows.Scan(&c, &n); err != nil {
			rows.Close()
			return res, err
		}
		res.RawByClass[c] = n
	}
	rows.Close()
	rows, err = d.QueryContext(ctx, `SELECT status_class, SUM(requests) FROM log_hourly WHERE hour = ? GROUP BY status_class`, hour)
	if err != nil {
		return res, fmt.Errorf("drift rollup classes: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var c int
		var n int64
		if err := rows.Scan(&c, &n); err != nil {
			return res, err
		}
		res.RollupByClass[c] = n
	}
	return res, rows.Err()
}

// PurgeRollup deletes rollup hours older than before.
func PurgeRollup(ctx context.Context, d *sql.DB, before time.Time) (int64, error) {
	before = before.UTC().Truncate(time.Hour)
	r, err := d.ExecContext(ctx, `DELETE FROM log_hourly WHERE hour < ?`, before)
	if err != nil {
		return 0, fmt.Errorf("purge rollup: %w", err)
	}
	n, _ := r.RowsAffected()
	if _, err := d.ExecContext(ctx, `DELETE FROM log_hourly_paths WHERE hour < ?`, before); err != nil {
		return n, fmt.Errorf("purge rollup paths: %w", err)
	}
	return n, nil
}
