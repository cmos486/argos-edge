package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/models"
)

var ErrLogNotFound = errors.New("log entry not found")

// LogFilter captures every filter /api/logs accepts so repo callers do
// not have to stringify conditions themselves. Zero values mean "no
// constraint"; empty slices and empty strings are treated identically.
type LogFilter struct {
	From       time.Time
	To         time.Time
	Sources    []models.LogSource
	HostIDs    []int64
	RuleIDs    []int64
	StatusExpr string // "200" | "4xx" | "500-504" | "200,301"
	Methods    []string
	PathExpr   string // substring, or "re:pattern" for regex
	RemoteIP   string // literal IP or CIDR
	Levels     []string
	Query      string // free text LIKE across path/user_agent/message/raw
}

const logCols = `id, timestamp, source, level, host_id, host_domain, rule_id,
    remote_ip, method, path, status, duration_ms, size_bytes,
    user_agent, upstream, message, raw`

// InsertLogEntry writes one row. Prefer InsertLogBatch for throughput.
func InsertLogEntry(ctx context.Context, d *sql.DB, e models.LogEntry) (int64, error) {
	res, err := d.ExecContext(ctx,
		`INSERT INTO log_entries
		  (timestamp, source, level, host_id, host_domain, rule_id,
		   remote_ip, method, path, status, duration_ms, size_bytes,
		   user_agent, upstream, message, raw)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.Timestamp.UTC(), string(e.Source), e.Level,
		nullableInt(e.HostID), e.HostDomain, nullableInt(e.RuleID),
		e.RemoteIP, e.Method, e.Path, e.Status, e.DurationMs, e.SizeBytes,
		e.UserAgent, e.Upstream, e.Message, e.Raw,
	)
	if err != nil {
		return 0, fmt.Errorf("insert log_entries: %w", err)
	}
	return res.LastInsertId()
}

// InsertLogBatch commits a slice in one transaction to amortize the
// fsync cost across many rows.
func InsertLogBatch(ctx context.Context, d *sql.DB, rows []models.LogEntry) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO log_entries
		  (timestamp, source, level, host_id, host_domain, rule_id,
		   remote_ip, method, path, status, duration_ms, size_bytes,
		   user_agent, upstream, message, raw)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return fmt.Errorf("prepare: %w", err)
	}
	defer stmt.Close()
	for _, e := range rows {
		if _, err := stmt.ExecContext(ctx,
			e.Timestamp.UTC(), string(e.Source), e.Level,
			nullableInt(e.HostID), e.HostDomain, nullableInt(e.RuleID),
			e.RemoteIP, e.Method, e.Path, e.Status, e.DurationMs, e.SizeBytes,
			e.UserAgent, e.Upstream, e.Message, e.Raw,
		); err != nil {
			return fmt.Errorf("exec: %w", err)
		}
	}
	return tx.Commit()
}

// GetLogEntry returns one row.
func GetLogEntry(ctx context.Context, d *sql.DB, id int64) (models.LogEntry, error) {
	row := d.QueryRowContext(ctx,
		`SELECT `+logCols+` FROM log_entries WHERE id = ?`, id)
	e, err := scanLogEntry(row)
	if errors.Is(err, sql.ErrNoRows) {
		return models.LogEntry{}, ErrLogNotFound
	}
	return e, err
}

// ListLogEntries returns filtered rows. order is "asc" or "desc"
// (default desc). limit is clamped by the caller.
func ListLogEntries(ctx context.Context, d *sql.DB, f LogFilter, order string, limit, offset int) ([]models.LogEntry, error) {
	where, args := buildLogWhere(f)
	ord := "DESC"
	if strings.ToLower(order) == "asc" {
		ord = "ASC"
	}
	q := `SELECT ` + logCols + ` FROM log_entries` + where +
		` ORDER BY timestamp ` + ord + `, id ` + ord + ` LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list logs: %w", err)
	}
	defer rows.Close()
	var out []models.LogEntry
	for rows.Next() {
		e, err := scanLogEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountLogEntries returns the match count for a filter.
func CountLogEntries(ctx context.Context, d *sql.DB, f LogFilter) (int, error) {
	where, args := buildLogWhere(f)
	var n int
	err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM log_entries`+where, args...).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count logs: %w", err)
	}
	return n, nil
}

// StreamLogEntries returns rows with id > afterID ordered ASC, useful
// for the SSE tailer to pick up freshly ingested entries.
func StreamLogEntries(ctx context.Context, d *sql.DB, f LogFilter, afterID int64, limit int) ([]models.LogEntry, error) {
	where, args := buildLogWhere(f)
	joiner := " WHERE"
	if where != "" {
		joiner = " AND"
	}
	q := `SELECT ` + logCols + ` FROM log_entries` + where +
		joiner + ` id > ? ORDER BY id ASC LIMIT ?`
	args = append(args, afterID, limit)
	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("stream logs: %w", err)
	}
	defer rows.Close()
	var out []models.LogEntry
	for rows.Next() {
		e, err := scanLogEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// LogStats is the aggregate /api/logs/stats returns.
type LogStats struct {
	Total          int            `json:"total"`
	ByStatusClass  map[string]int `json:"by_status_class"`
	BySource       map[string]int `json:"by_source"`
	AvgDurationMs  int            `json:"avg_duration_ms"`
	P95DurationMs  int            `json:"p95_duration_ms"`
	TopHosts       []Pair         `json:"top_hosts"`
	TopPaths       []Pair         `json:"top_paths"`
}

// Pair is one {label, count} entry in a top-N list.
type Pair struct {
	Label string `json:"label"`
	Count int    `json:"count"`
}

// ComputeStats runs the aggregate queries for a filter.
func ComputeStats(ctx context.Context, d *sql.DB, f LogFilter) (LogStats, error) {
	where, args := buildLogWhere(f)
	s := LogStats{
		ByStatusClass: map[string]int{},
		BySource:      map[string]int{},
	}
	if err := d.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(AVG(duration_ms),0) FROM log_entries`+where, args...,
	).Scan(&s.Total, &s.AvgDurationMs); err != nil {
		return s, fmt.Errorf("stats total: %w", err)
	}
	// P95 via a bounded offset scan; for homelab volumes this is fine.
	if s.Total > 0 {
		offset := (s.Total * 95) / 100
		var p95 sql.NullInt64
		if err := d.QueryRowContext(ctx,
			`SELECT duration_ms FROM log_entries`+where+` ORDER BY duration_ms ASC LIMIT 1 OFFSET ?`,
			append(append([]any{}, args...), offset)...,
		).Scan(&p95); err == nil && p95.Valid {
			s.P95DurationMs = int(p95.Int64)
		}
	}

	if err := aggregate(ctx, d, where, args, `CASE
		WHEN status BETWEEN 200 AND 299 THEN '2xx'
		WHEN status BETWEEN 300 AND 399 THEN '3xx'
		WHEN status BETWEEN 400 AND 499 THEN '4xx'
		WHEN status BETWEEN 500 AND 599 THEN '5xx'
		ELSE 'other' END`, s.ByStatusClass); err != nil {
		return s, err
	}
	if err := aggregate(ctx, d, where, args, `source`, s.BySource); err != nil {
		return s, err
	}
	top, err := topN(ctx, d, where, args, `host_domain`)
	if err != nil {
		return s, err
	}
	s.TopHosts = top
	top, err = topN(ctx, d, where, args, `path`)
	if err != nil {
		return s, err
	}
	s.TopPaths = top
	return s, nil
}

func aggregate(ctx context.Context, d *sql.DB, where string, args []any, expr string, out map[string]int) error {
	q := `SELECT ` + expr + ` AS k, COUNT(*) FROM log_entries` + where + ` GROUP BY k`
	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return err
		}
		out[k] = n
	}
	return rows.Err()
}

func topN(ctx context.Context, d *sql.DB, where string, args []any, col string) ([]Pair, error) {
	q := `SELECT ` + col + `, COUNT(*) AS c FROM log_entries` + where +
		` AND ` + col + ` != '' GROUP BY ` + col + ` ORDER BY c DESC LIMIT 5`
	if where == "" {
		q = `SELECT ` + col + `, COUNT(*) AS c FROM log_entries WHERE ` + col +
			` != '' GROUP BY ` + col + ` ORDER BY c DESC LIMIT 5`
	}
	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Pair
	for rows.Next() {
		var p Pair
		if err := rows.Scan(&p.Label, &p.Count); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Bucket is one point on the timeseries.
type Bucket struct {
	Timestamp time.Time `json:"timestamp"`
	Total     int       `json:"total"`
	Class2xx  int       `json:"class_2xx"`
	Class3xx  int       `json:"class_3xx"`
	Class4xx  int       `json:"class_4xx"`
	Class5xx  int       `json:"class_5xx"`
	Other     int       `json:"other"`
}

// ComputeTimeseries buckets rows by interval seconds.
func ComputeTimeseries(ctx context.Context, d *sql.DB, f LogFilter, bucketSeconds int) ([]Bucket, error) {
	where, args := buildLogWhere(f)
	if bucketSeconds <= 0 {
		bucketSeconds = 60
	}
	// SQLite: strftime + bucket math.
	q := `SELECT
		(CAST(strftime('%s', timestamp) AS INTEGER) / ?) * ? AS bucket,
		COUNT(*),
		SUM(CASE WHEN status BETWEEN 200 AND 299 THEN 1 ELSE 0 END),
		SUM(CASE WHEN status BETWEEN 300 AND 399 THEN 1 ELSE 0 END),
		SUM(CASE WHEN status BETWEEN 400 AND 499 THEN 1 ELSE 0 END),
		SUM(CASE WHEN status BETWEEN 500 AND 599 THEN 1 ELSE 0 END),
		SUM(CASE WHEN status NOT BETWEEN 100 AND 599 OR status = 0 THEN 1 ELSE 0 END)
	FROM log_entries` + where + `
	GROUP BY bucket ORDER BY bucket ASC`
	args = append([]any{bucketSeconds, bucketSeconds}, args...)
	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("timeseries: %w", err)
	}
	defer rows.Close()
	var out []Bucket
	for rows.Next() {
		var sec int64
		var b Bucket
		if err := rows.Scan(&sec, &b.Total, &b.Class2xx, &b.Class3xx, &b.Class4xx, &b.Class5xx, &b.Other); err != nil {
			return nil, err
		}
		b.Timestamp = time.Unix(sec, 0).UTC()
		out = append(out, b)
	}
	return out, rows.Err()
}

// PurgeOld removes rows older than retentionDays, then trims the total
// to maxEntries if still over. Returns the count deleted.
func PurgeOld(ctx context.Context, d *sql.DB, retentionDays, maxEntries int) (int, error) {
	var removed int
	if retentionDays > 0 {
		cutoff := time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour)
		res, err := d.ExecContext(ctx,
			`DELETE FROM log_entries WHERE timestamp < ?`, cutoff)
		if err != nil {
			return 0, fmt.Errorf("purge by age: %w", err)
		}
		n, _ := res.RowsAffected()
		removed += int(n)
	}
	if maxEntries > 0 {
		var total int
		if err := d.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM log_entries`).Scan(&total); err != nil {
			return removed, fmt.Errorf("count before cap: %w", err)
		}
		if total > maxEntries {
			over := total - maxEntries
			res, err := d.ExecContext(ctx,
				`DELETE FROM log_entries WHERE id IN
				  (SELECT id FROM log_entries ORDER BY timestamp ASC, id ASC LIMIT ?)`,
				over)
			if err != nil {
				return removed, fmt.Errorf("purge by cap: %w", err)
			}
			n, _ := res.RowsAffected()
			removed += int(n)
		}
	}
	return removed, nil
}

// Vacuum reclaims space from SQLite. Run monthly.
func Vacuum(ctx context.Context, d *sql.DB) error {
	_, err := d.ExecContext(ctx, `VACUUM`)
	return err
}

// --- filter translation ---

// buildLogWhere assembles the WHERE clause (empty if no filter) plus
// the positional args slice.
func buildLogWhere(f LogFilter) (string, []any) {
	var conds []string
	var args []any

	if !f.From.IsZero() {
		conds = append(conds, "timestamp >= ?")
		args = append(args, f.From.UTC())
	}
	if !f.To.IsZero() {
		conds = append(conds, "timestamp <= ?")
		args = append(args, f.To.UTC())
	}
	if len(f.Sources) > 0 {
		placeholders := make([]string, len(f.Sources))
		for i, s := range f.Sources {
			placeholders[i] = "?"
			args = append(args, string(s))
		}
		conds = append(conds, "source IN ("+strings.Join(placeholders, ",")+")")
	}
	if len(f.HostIDs) > 0 {
		placeholders := make([]string, len(f.HostIDs))
		for i, h := range f.HostIDs {
			placeholders[i] = "?"
			args = append(args, h)
		}
		conds = append(conds, "host_id IN ("+strings.Join(placeholders, ",")+")")
	}
	if len(f.RuleIDs) > 0 {
		placeholders := make([]string, len(f.RuleIDs))
		for i, r := range f.RuleIDs {
			placeholders[i] = "?"
			args = append(args, r)
		}
		conds = append(conds, "rule_id IN ("+strings.Join(placeholders, ",")+")")
	}
	if f.StatusExpr != "" {
		if clause, vals, ok := statusExprToSQL(f.StatusExpr); ok {
			conds = append(conds, clause)
			args = append(args, vals...)
		}
	}
	if len(f.Methods) > 0 {
		placeholders := make([]string, len(f.Methods))
		for i, m := range f.Methods {
			placeholders[i] = "?"
			args = append(args, strings.ToUpper(m))
		}
		conds = append(conds, "UPPER(method) IN ("+strings.Join(placeholders, ",")+")")
	}
	if f.PathExpr != "" {
		if strings.HasPrefix(f.PathExpr, "re:") {
			conds = append(conds, "path REGEXP ?")
			args = append(args, strings.TrimPrefix(f.PathExpr, "re:"))
		} else {
			conds = append(conds, "path LIKE ?")
			args = append(args, "%"+f.PathExpr+"%")
		}
	}
	if f.RemoteIP != "" {
		// Substring match is good enough for homelab; CIDR is evaluated
		// at the API edge by enumerating matches on the filter layer.
		conds = append(conds, "remote_ip LIKE ?")
		args = append(args, "%"+f.RemoteIP+"%")
	}
	if len(f.Levels) > 0 {
		placeholders := make([]string, len(f.Levels))
		for i, l := range f.Levels {
			placeholders[i] = "?"
			args = append(args, strings.ToLower(l))
		}
		conds = append(conds, "LOWER(level) IN ("+strings.Join(placeholders, ",")+")")
	}
	if f.Query != "" {
		q := "%" + f.Query + "%"
		conds = append(conds, "(path LIKE ? OR user_agent LIKE ? OR message LIKE ? OR raw LIKE ?)")
		args = append(args, q, q, q, q)
	}

	if len(conds) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// statusExprToSQL parses "200", "4xx", "500-504", "200,301" into a
// SQL clause + positional args. Invalid expressions are dropped.
func statusExprToSQL(expr string) (string, []any, bool) {
	var ors []string
	var args []any
	for _, tok := range strings.Split(expr, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if strings.HasSuffix(tok, "xx") && len(tok) == 3 {
			// 2xx -> 200..299
			lead := tok[0]
			if lead < '1' || lead > '5' {
				return "", nil, false
			}
			lo := int(lead-'0') * 100
			ors = append(ors, "(status BETWEEN ? AND ?)")
			args = append(args, lo, lo+99)
			continue
		}
		if strings.Contains(tok, "-") {
			parts := strings.SplitN(tok, "-", 2)
			lo, err1 := parseStatus(parts[0])
			hi, err2 := parseStatus(parts[1])
			if err1 != nil || err2 != nil || lo > hi {
				return "", nil, false
			}
			ors = append(ors, "(status BETWEEN ? AND ?)")
			args = append(args, lo, hi)
			continue
		}
		n, err := parseStatus(tok)
		if err != nil {
			return "", nil, false
		}
		ors = append(ors, "status = ?")
		args = append(args, n)
	}
	if len(ors) == 0 {
		return "", nil, false
	}
	return "(" + strings.Join(ors, " OR ") + ")", args, true
}

func parseStatus(s string) (int, error) {
	s = strings.TrimSpace(s)
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, err
	}
	if n < 100 || n > 599 {
		return 0, fmt.Errorf("status %d out of range", n)
	}
	return n, nil
}

func scanLogEntry(s scanner) (models.LogEntry, error) {
	var (
		e          models.LogEntry
		src        string
		hostID     sql.NullInt64
		ruleID     sql.NullInt64
	)
	if err := s.Scan(
		&e.ID, &e.Timestamp, &src, &e.Level, &hostID, &e.HostDomain,
		&ruleID, &e.RemoteIP, &e.Method, &e.Path, &e.Status, &e.DurationMs,
		&e.SizeBytes, &e.UserAgent, &e.Upstream, &e.Message, &e.Raw,
	); err != nil {
		return models.LogEntry{}, err
	}
	e.Source = models.LogSource(src)
	if hostID.Valid {
		id := hostID.Int64
		e.HostID = &id
	}
	if ruleID.Valid {
		id := ruleID.Int64
		e.RuleID = &id
	}
	return e, nil
}

func nullableInt(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}
