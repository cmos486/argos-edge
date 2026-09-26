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
//
// HostDomainsOR is an OR extension of HostIDs: any row whose host_id is
// in HostIDs OR whose host_domain is in HostDomainsOR matches. The API
// layer populates it by resolving each requested host_id to its
// current domain, so caddy_error rows from Coraza -- which cannot be
// linked to a host_id at ingest time but do carry host_domain -- are
// included when the operator clicks "View logs" on a specific host.
type LogFilter struct {
	From          time.Time
	To            time.Time
	Sources       []models.LogSource
	HostIDs       []int64
	HostDomainsOR []string
	RuleIDs       []int64
	StatusExpr    string // "200" | "4xx" | "500-504" | "200,301"
	Methods       []string
	PathExpr      string // substring, or "re:pattern" for regex
	RemoteIP      string // literal IP or CIDR
	Levels        []string
	Query         string   // free text LIKE across path/user_agent/message/raw
	WAFRuleIDs    []int    // match waf_rule_id exactly
	WAFSeverity   []string // match waf_severity (uppercase like CRITICAL)
}

const logCols = `id, timestamp, source, level, host_id, host_domain, rule_id,
    remote_ip, method, path, status, duration_ms, size_bytes,
    user_agent, upstream, message, raw,
    waf_rule_id, waf_rule_message, waf_severity, waf_anomaly_score`

const insertLogSQL = `INSERT INTO log_entries
  (timestamp, source, level, host_id, host_domain, rule_id,
   remote_ip, method, path, status, duration_ms, size_bytes,
   user_agent, upstream, message, raw,
   waf_rule_id, waf_rule_message, waf_severity, waf_anomaly_score)
 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

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
	stmt, err := tx.PrepareContext(ctx, insertLogSQL)
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
			e.WAFRuleID, e.WAFRuleMessage, e.WAFSeverity, e.WAFAnomalyScore,
		); err != nil {
			return fmt.Errorf("exec: %w", err)
		}
	}
	return tx.Commit()
}

// ListLogEntriesAfter returns the next page of the match set in
// (timestamp, id) order after the cursor, for exports that walk a
// large filter without OFFSET (which re-reads every earlier row on
// each page). The cursor bounds are range terms, like the strip
// cursor (strike 14): with the lower bound inside an OR the planner
// used only the upper bound. The first page passes the zero time.
func ListLogEntriesAfter(ctx context.Context, d *sql.DB, f LogFilter, afterTS time.Time, afterID int64, limit int) ([]models.LogEntry, error) {
	where, args := buildLogWhere(f)
	if where == "" {
		where = " WHERE"
	} else {
		where += " AND"
	}
	q := `SELECT ` + logCols + ` FROM log_entries` + where +
		` timestamp >= ? AND NOT (timestamp = ? AND id <= ?)` +
		` ORDER BY timestamp ASC, id ASC LIMIT ?`
	args = append(args, afterTS.UTC(), afterTS.UTC(), afterID, limit)
	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list logs after: %w", err)
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
	Total         int            `json:"total"`
	ByStatusClass map[string]int `json:"by_status_class"`
	BySource      map[string]int `json:"by_source"`
	AvgDurationMs int            `json:"avg_duration_ms"`
	P95DurationMs int            `json:"p95_duration_ms"`
	TopHosts      []Pair         `json:"top_hosts"`
	TopPaths      []Pair         `json:"top_paths"`
	// v1.3.38.4, long time-only windows: avg/p95 come from the newest
	// SampleN rows and top_paths from the newest DetailWindow; total,
	// status classes, sources and top_hosts cover the whole window.
	// Both zero when every figure covers the whole filter.
	SampleN      int    `json:"sample_n,omitempty"`
	DetailWindow string `json:"detail_window,omitempty"`
}

// Long time-only windows (v1.3.38.4): the covering-index path. See
// statsFastPathEligible for the exact conditions; everything else
// keeps the row-visiting queries (a filter on q / path / ip / status
// needs the rows anyway). Bridge until the v1.3.40 hourly rollup.
const (
	statsLongThreshold = 24 * time.Hour
	statsDetailWindow  = 24 * time.Hour
	statsSampleN       = 20000
)

// statsFastPathEligible: only From/To and an optional source list
// limited to caddy_access are set, and the window is longer than
// statsLongThreshold (or unbounded).
func statsFastPathEligible(f LogFilter) bool {
	if len(f.HostIDs) > 0 || len(f.HostDomainsOR) > 0 || len(f.RuleIDs) > 0 || f.StatusExpr != "" ||
		len(f.Methods) > 0 || f.PathExpr != "" || f.RemoteIP != "" || len(f.Levels) > 0 ||
		f.Query != "" || len(f.WAFRuleIDs) > 0 || len(f.WAFSeverity) > 0 {
		return false
	}
	for _, src := range f.Sources {
		if src != models.LogCaddyAccess {
			return false
		}
	}
	if f.From.IsZero() {
		return true
	}
	to := f.To
	if to.IsZero() {
		to = time.Now().UTC()
	}
	return to.Sub(f.From) > statsLongThreshold
}

// statsWindow returns the [from, to] the fast path counts over; an
// unbounded From becomes the epoch, an empty To becomes now.
func statsWindow(f LogFilter) (time.Time, time.Time) {
	from, to := f.From, f.To
	if from.IsZero() {
		from = time.Unix(0, 0).UTC()
	}
	if to.IsZero() {
		to = time.Now().UTC()
	}
	return from, to
}

// Planner-pinned shapes (INDEXED BY): see the dashboard package's
// TestLongRangePlans for why the shape matters; TestStatsLongPlans
// here guards these.
const (
	statsClassCountSQL = `SELECT COUNT(*) FROM log_entries INDEXED BY idx_log_entries_status_ts
		WHERE status BETWEEN ? AND ? AND timestamp BETWEEN ? AND ?`
	statsSourceCountSQL = `SELECT COUNT(*) FROM log_entries INDEXED BY idx_log_entries_source_ts
		WHERE source = ? AND timestamp BETWEEN ? AND ?`
	statsTotalSQL = `SELECT COUNT(*) FROM log_entries INDEXED BY idx_log_entries_timestamp
		WHERE timestamp BETWEEN ? AND ?`
	statsTopHostsSQL = `SELECT host_id, COUNT(*) FROM log_entries INDEXED BY idx_log_entries_host_ts
		WHERE host_id IS NOT NULL AND timestamp BETWEEN ? AND ?
		GROUP BY host_id ORDER BY 2 DESC LIMIT 5`
	statsClassSeriesSQL = `SELECT substr(timestamp, 1, 13) AS h, COUNT(*)
		FROM log_entries INDEXED BY idx_log_entries_status_ts
		WHERE status BETWEEN ? AND ? AND timestamp BETWEEN ? AND ?
		GROUP BY h`
	statsTotalSeriesSQL = `SELECT substr(timestamp, 1, 13) AS h, COUNT(*)
		FROM log_entries INDEXED BY idx_log_entries_timestamp
		WHERE timestamp BETWEEN ? AND ?
		GROUP BY h`
)

var statusClasses = []struct {
	key    string
	lo, hi int
}{{"2xx", 200, 299}, {"3xx", 300, 399}, {"4xx", 400, 499}, {"5xx", 500, 599}}

// computeStatsLong is ComputeStats for statsFastPathEligible filters.
func computeStatsLong(ctx context.Context, d *sql.DB, f LogFilter) (LogStats, error) {
	from, to := statsWindow(f)
	s := LogStats{ByStatusClass: map[string]int{}, BySource: map[string]int{}, DetailWindow: statsDetailWindow.String()}
	accessOnly := len(f.Sources) > 0

	// Total: covering count on (source,ts) when limited to access rows,
	// on (ts) otherwise.
	if accessOnly {
		if err := d.QueryRowContext(ctx, statsSourceCountSQL, string(models.LogCaddyAccess), from, to).Scan(&s.Total); err != nil {
			return s, fmt.Errorf("stats total: %w", err)
		}
	} else if err := d.QueryRowContext(ctx, statsTotalSQL, from, to).Scan(&s.Total); err != nil {
		return s, fmt.Errorf("stats total: %w", err)
	}
	// Status classes: one covering range per class. status >= 100
	// implies caddy_access (only access rows carry an HTTP status).
	classed := 0
	for _, c := range statusClasses {
		var n int
		if err := d.QueryRowContext(ctx, statsClassCountSQL, c.lo, c.hi, from, to).Scan(&n); err != nil {
			return s, fmt.Errorf("stats class %s: %w", c.key, err)
		}
		s.ByStatusClass[c.key] = n
		classed += n
	}
	if other := s.Total - classed; other > 0 {
		s.ByStatusClass["other"] = other
	}
	// Sources: one covering range per known source.
	sources := []models.LogSource{models.LogCaddyAccess}
	if !accessOnly {
		sources = []models.LogSource{models.LogCaddyAccess, models.LogCaddyError, models.LogAudit, models.LogWAFAudit}
	}
	for _, src := range sources {
		var n int
		if err := d.QueryRowContext(ctx, statsSourceCountSQL, string(src), from, to).Scan(&n); err != nil {
			return s, fmt.Errorf("stats source %s: %w", src, err)
		}
		if n > 0 {
			s.BySource[string(src)] = n
		}
	}
	// avg / p95 over a bounded sample of the newest rows (rows must be
	// visited for duration_ms; the sample keeps that to statsSampleN).
	sampleWhere := `WHERE timestamp BETWEEN ? AND ?`
	sampleArgs := []any{from, to}
	if accessOnly {
		sampleWhere += ` AND source = ?`
		sampleArgs = append(sampleArgs, string(models.LogCaddyAccess))
	}
	sampleSQL := `SELECT duration_ms FROM log_entries ` + sampleWhere + ` ORDER BY timestamp DESC LIMIT ?`
	sampleArgs = append(sampleArgs, statsSampleN)
	var avgMs float64
	if err := d.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(AVG(duration_ms),0) FROM (`+sampleSQL+`)`, sampleArgs...).Scan(&s.SampleN, &avgMs); err != nil {
		return s, fmt.Errorf("stats sample: %w", err)
	}
	s.AvgDurationMs = int(avgMs)
	if s.SampleN > 0 {
		offset := (s.SampleN * 95) / 100
		var p95 sql.NullInt64
		if err := d.QueryRowContext(ctx, `SELECT duration_ms FROM (`+sampleSQL+`) ORDER BY duration_ms ASC LIMIT 1 OFFSET ?`,
			append(append([]any{}, sampleArgs...), offset)...).Scan(&p95); err == nil && p95.Valid {
			s.P95DurationMs = int(p95.Int64)
		}
	}
	// Top hosts over the whole window, by host_id, mapped to domains.
	hRows, err := d.QueryContext(ctx, statsTopHostsSQL, from, to)
	if err != nil {
		return s, fmt.Errorf("stats top hosts: %w", err)
	}
	type hc struct {
		id int64
		n  int
	}
	var counts []hc
	for hRows.Next() {
		var c hc
		if err := hRows.Scan(&c.id, &c.n); err != nil {
			hRows.Close()
			return s, err
		}
		counts = append(counts, c)
	}
	hRows.Close()
	if len(counts) > 0 {
		names := map[int64]string{}
		nRows, err := d.QueryContext(ctx, `SELECT id, domain FROM hosts`)
		if err != nil {
			return s, fmt.Errorf("stats host names: %w", err)
		}
		for nRows.Next() {
			var id int64
			var dom string
			if err := nRows.Scan(&id, &dom); err != nil {
				nRows.Close()
				return s, err
			}
			names[id] = dom
		}
		nRows.Close()
		for _, c := range counts {
			if dom, ok := names[c.id]; ok {
				s.TopHosts = append(s.TopHosts, Pair{Label: dom, Count: c.n})
			}
		}
	}
	// Top paths over the newest detail window only.
	detail := f
	detail.From = to.Add(-statsDetailWindow)
	if detail.From.Before(from) {
		detail.From = from
	}
	detail.To = to
	where, args := buildLogWhere(detail)
	top, err := topN(ctx, d, where, args, `path`)
	if err != nil {
		return s, err
	}
	s.TopPaths = top
	return s, nil
}

// computeTimeseriesLong is ComputeTimeseries for eligible filters at
// hourly buckets: per-class hourly counts from the status index, the
// hourly total from the timestamp index (or the source index when
// limited to access rows), other = total - classes.
func computeTimeseriesLong(ctx context.Context, d *sql.DB, f LogFilter) ([]Bucket, error) {
	from, to := statsWindow(f)
	buckets := map[int64]*Bucket{}
	get := func(h string) *Bucket {
		ts, err := time.Parse("2006-01-02 15", h)
		if err != nil {
			return nil
		}
		key := ts.Unix()
		b, ok := buckets[key]
		if !ok {
			b = &Bucket{Timestamp: time.Unix(key, 0).UTC()}
			buckets[key] = b
		}
		return b
	}
	for _, c := range statusClasses {
		rows, err := d.QueryContext(ctx, statsClassSeriesSQL, c.lo, c.hi, from, to)
		if err != nil {
			return nil, fmt.Errorf("timeseries class %s: %w", c.key, err)
		}
		for rows.Next() {
			var h string
			var n int
			if err := rows.Scan(&h, &n); err != nil {
				rows.Close()
				return nil, err
			}
			b := get(h)
			if b == nil {
				continue
			}
			switch c.key {
			case "2xx":
				b.Class2xx += n
			case "3xx":
				b.Class3xx += n
			case "4xx":
				b.Class4xx += n
			case "5xx":
				b.Class5xx += n
			}
		}
		rows.Close()
	}
	totalSQL, totalArgs := statsTotalSeriesSQL, []any{from, to}
	if len(f.Sources) > 0 {
		totalSQL = `SELECT substr(timestamp, 1, 13) AS h, COUNT(*)
			FROM log_entries INDEXED BY idx_log_entries_source_ts
			WHERE source = ? AND timestamp BETWEEN ? AND ? GROUP BY h`
		totalArgs = []any{string(models.LogCaddyAccess), from, to}
	}
	rows, err := d.QueryContext(ctx, totalSQL, totalArgs...)
	if err != nil {
		return nil, fmt.Errorf("timeseries total: %w", err)
	}
	for rows.Next() {
		var h string
		var n int
		if err := rows.Scan(&h, &n); err != nil {
			rows.Close()
			return nil, err
		}
		if b := get(h); b != nil {
			b.Total = n
		}
	}
	rows.Close()
	out := make([]Bucket, 0, len(buckets))
	for _, b := range buckets {
		b.Other = b.Total - b.Class2xx - b.Class3xx - b.Class4xx - b.Class5xx
		if b.Other < 0 {
			b.Other = 0
		}
		out = append(out, *b)
	}
	sortBuckets(out)
	return out, nil
}

// Pair is one {label, count} entry in a top-N list.
type Pair struct {
	Label string `json:"label"`
	Count int    `json:"count"`
}

// ComputeStats runs the aggregate queries for a filter. Long time-only
// windows take the covering-index path (computeStatsLong).
func ComputeStats(ctx context.Context, d *sql.DB, f LogFilter) (LogStats, error) {
	if statsFastPathEligible(f) {
		return computeStatsLong(ctx, d, f)
	}
	where, args := buildLogWhere(f)
	s := LogStats{
		ByStatusClass: map[string]int{},
		BySource:      map[string]int{},
	}
	var avgMs float64
	if err := d.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(AVG(duration_ms),0) FROM log_entries`+where, args...,
	).Scan(&s.Total, &avgMs); err != nil {
		return s, fmt.Errorf("stats total: %w", err)
	}
	s.AvgDurationMs = int(avgMs)
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
//
// The aggregation runs in Go rather than SQL because SQLite's strftime
// does not parse the "2006-01-02 15:04:05.999999999 +0000 UTC" shape
// modernc.org/sqlite serialises time.Time into. Homelab volumes stay
// below ~100k rows per window, so the in-memory pass is cheap enough
// and keeps the TIMESTAMP column compatible with future schema needs.
func ComputeTimeseries(ctx context.Context, d *sql.DB, f LogFilter, bucketSeconds int) ([]Bucket, error) {
	if bucketSeconds <= 0 {
		bucketSeconds = 60
	}
	if bucketSeconds == 3600 && statsFastPathEligible(f) {
		return computeTimeseriesLong(ctx, d, f)
	}
	where, args := buildLogWhere(f)
	rows, err := d.QueryContext(ctx,
		`SELECT timestamp, status FROM log_entries`+where+` ORDER BY timestamp ASC`,
		args...,
	)
	if err != nil {
		return nil, fmt.Errorf("timeseries query: %w", err)
	}
	defer rows.Close()

	buckets := map[int64]*Bucket{}
	for rows.Next() {
		var ts time.Time
		var status int
		if err := rows.Scan(&ts, &status); err != nil {
			return nil, err
		}
		key := (ts.UTC().Unix() / int64(bucketSeconds)) * int64(bucketSeconds)
		b, ok := buckets[key]
		if !ok {
			b = &Bucket{Timestamp: time.Unix(key, 0).UTC()}
			buckets[key] = b
		}
		b.Total++
		switch {
		case status >= 200 && status < 300:
			b.Class2xx++
		case status >= 300 && status < 400:
			b.Class3xx++
		case status >= 400 && status < 500:
			b.Class4xx++
		case status >= 500 && status < 600:
			b.Class5xx++
		default:
			b.Other++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]Bucket, 0, len(buckets))
	for _, b := range buckets {
		out = append(out, *b)
	}
	// Sort ascending by timestamp; keeps the client sparkline oriented.
	sortBuckets(out)
	return out, nil
}

func sortBuckets(bs []Bucket) {
	// Insertion sort; len is tiny (<= span/bucket_seconds).
	for i := 1; i < len(bs); i++ {
		for j := i; j > 0 && bs[j].Timestamp.Before(bs[j-1].Timestamp); j-- {
			bs[j], bs[j-1] = bs[j-1], bs[j]
		}
	}
}

// Purge batching defaults (v1.3.38.3). The panel has a single SQLite
// connection: one DELETE of N rows holds it for the whole statement,
// so a large purge stalls every request and the log ingestor behind
// it. Deleting in batches with a pause between them bounds the hold
// time per statement; the pause lets queued readers and the ingestor
// flush in between.
const (
	PurgeBatchSize  = 5000
	PurgeBatchPause = 100 * time.Millisecond
)

// PurgeOld removes rows older than retentionDays, then trims the total
// to maxEntries if still over, in batches of PurgeBatchSize with
// PurgeBatchPause between batches. Returns the count deleted.
func PurgeOld(ctx context.Context, d *sql.DB, retentionDays, maxEntries int) (int, error) {
	return PurgeOldBatched(ctx, d, retentionDays, maxEntries, PurgeBatchSize, PurgeBatchPause)
}

// PurgeOldBatched is PurgeOld with explicit batch size and pause
// (tests use small values). batchSize <= 0 means one statement. One
// retention for every source; see PurgeWithPolicy for the v1.3.40
// per-source shape this delegates to.
func PurgeOldBatched(ctx context.Context, d *sql.DB, retentionDays, maxEntries, batchSize int, pause time.Duration) (int, error) {
	res, err := PurgeWithPolicy(ctx, d, PurgePolicy{DefaultDays: retentionDays, MaxEntries: maxEntries}, batchSize, pause)
	return res.Removed, err
}

// PurgePolicy is what one retention run applies (v1.3.40.0).
//
//   - SourceDays: rows of that source older than N days go; sources
//     not listed use DefaultDays (0 = keep forever).
//   - MaxEntries: after the age purge, the oldest rows over the cap
//     go. The cap check is bounded first: ids are monotonic and the
//     purges always delete the oldest rows, so MAX(id)-MIN(id)+1 is
//     the exact count unless rows were deleted from the middle (the
//     operator's manual purge can do that). When that bound is at or
//     under the cap the table is certainly under it and no COUNT(*)
//     runs; only when the bound exceeds the cap does the exact
//     COUNT(*) decide, so a gap can never make the cap delete too
//     much or too little.
//   - RawSource / RawAfter / RawWatermark: rows of RawSource older
//     than RawAfter lose their raw JSON (raw emptied: the column is
//     NOT NULL with an empty default; v1.3.40.0 wrote NULL and the whole purge
//     run failed on prod). v1.3.40.2: the strip walks the
//     (timestamp, id) order on idx_log_entries_source_ts in batches
//     of RawStripBatch ids, updates exactly those ids, and reports
//     the batch's last timestamp through OnRawProgress so the caller
//     persists the watermark as it goes. v1.3.40.1 selected
//     the not-yet-empty rows from the watermark on every batch, so batch k
//     re-read the k-1 batches already emptied: quadratic row visits
//     on the single connection, /api/hosts waited up to 59 s on
//     prod. Only rows with timestamp >= RawWatermark are visited, so
//     each run touches the rows that aged since the previous one.
type PurgePolicy struct {
	SourceDays   map[string]int
	DefaultDays  int
	MaxEntries   int
	RawSource    string
	RawAfter     time.Duration
	RawWatermark time.Time
	// OnRawProgress, when set, receives the watermark after every
	// strip batch so a restart resumes where the previous run
	// stopped instead of at the previous run's start.
	OnRawProgress func(watermark time.Time)
}

// RawStripBatch is the number of rows one strip batch updates. Each
// row rewritten is about 1.4 KB; measured on prod (v1.3.40.2, 80,653
// rows in 109 s) a 1,000-row batch held the single connection for
// about 180 ms (/api/hosts p50 178 ms, p99 465 ms during the strip),
// so the batch is 200 rows: about 40 ms held, then the 100 ms pause.
const RawStripBatch = 200

// PurgeResult reports what a policy run did.
type PurgeResult struct {
	Removed      int
	RawStripped  int
	CapBound     int  // MAX(id)-MIN(id)+1 at the cap check
	CapCounted   bool // the exact COUNT(*) ran (bound exceeded the cap)
	RawWatermark time.Time
}

// PurgeWithPolicy runs the age purge per source, the bounded cap
// purge and the raw strip, all batched.
func PurgeWithPolicy(ctx context.Context, d *sql.DB, p PurgePolicy, batchSize int, pause time.Duration) (PurgeResult, error) {
	res := PurgeResult{RawWatermark: p.RawWatermark}
	now := time.Now().UTC()
	listed := make([]string, 0, len(p.SourceDays))
	for source, days := range p.SourceDays {
		listed = append(listed, source)
		if days <= 0 {
			continue
		}
		n, err := deleteInBatches(ctx, d, batchSize, pause, -1,
			`DELETE FROM log_entries WHERE id IN
			  (SELECT id FROM log_entries WHERE source = ? AND timestamp < ? ORDER BY timestamp ASC, id ASC LIMIT ?)`,
			source, now.Add(-time.Duration(days)*24*time.Hour))
		if err != nil {
			return res, fmt.Errorf("purge %s by age: %w", source, err)
		}
		res.Removed += n
	}
	if p.DefaultDays > 0 {
		cutoff := now.Add(-time.Duration(p.DefaultDays) * 24 * time.Hour)
		stmt := `DELETE FROM log_entries WHERE id IN
			  (SELECT id FROM log_entries WHERE timestamp < ?`
		args := []any{cutoff}
		if len(listed) > 0 {
			stmt += ` AND source NOT IN (` + strings.TrimSuffix(strings.Repeat("?,", len(listed)), ",") + `)`
			for _, s := range listed {
				args = append(args, s)
			}
		}
		stmt += ` ORDER BY timestamp ASC, id ASC LIMIT ?)`
		n, err := deleteInBatches(ctx, d, batchSize, pause, -1, stmt, args...)
		if err != nil {
			return res, fmt.Errorf("purge by age: %w", err)
		}
		res.Removed += n
	}
	if p.MaxEntries > 0 {
		bound, err := RowCountBound(ctx, d)
		if err != nil {
			return res, fmt.Errorf("count bound: %w", err)
		}
		res.CapBound = bound
		if bound > p.MaxEntries {
			var total int
			if err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM log_entries`).Scan(&total); err != nil {
				return res, fmt.Errorf("count before cap: %w", err)
			}
			res.CapCounted = true
			if total > p.MaxEntries {
				n, err := deleteInBatches(ctx, d, batchSize, pause, total-p.MaxEntries,
					`DELETE FROM log_entries WHERE id IN
					  (SELECT id FROM log_entries ORDER BY timestamp ASC, id ASC LIMIT ?)`)
				if err != nil {
					return res, fmt.Errorf("purge by cap: %w", err)
				}
				res.Removed += n
			}
		}
	}
	if p.RawSource != "" && p.RawAfter > 0 {
		cutoff := now.Add(-p.RawAfter)
		if cutoff.After(p.RawWatermark) {
			n, wm, err := stripRawByCursor(ctx, d, p.RawSource, p.RawWatermark, cutoff, RawStripBatch, pause, p.OnRawProgress)
			res.RawStripped = n
			if !wm.IsZero() {
				res.RawWatermark = wm
			}
			if err != nil {
				return res, fmt.Errorf("raw strip: %w", err)
			}
			res.RawWatermark = cutoff
			if p.OnRawProgress != nil {
				p.OnRawProgress(cutoff)
			}
		}
	}
	return res, nil
}

// StripCursorSQL selects the next strip batch after the (timestamp,
// id) cursor. Both bounds are plain range terms on purpose: with the
// lower bound inside an OR, as in
// timestamp < cutoff AND (timestamp > cur OR (timestamp = cur AND id > id)),
// the planner used only timestamp < cutoff on idx_log_entries_source_ts
// and every batch walked the index from the oldest row (100-150 ms of
// CPU per 200-row batch at 400k rows, strike 14). TestStripCursorPlan
// pins the plan through the driver; the sqlite3 CLI picks both bounds
// for the OR form and hides the difference.
const StripCursorSQL = `SELECT id, timestamp FROM log_entries
  WHERE source = ? AND timestamp >= ? AND timestamp < ?
    AND NOT (timestamp = ? AND id <= ?)
  ORDER BY timestamp ASC, id ASC LIMIT ?`

// stripRawByCursor empties raw on source rows in [from, cutoff),
// walking (timestamp, id) through the source/timestamp index in
// batches of batchSize ids: one covering SELECT for the ids, one
// UPDATE on exactly those ids (rows already empty are skipped by the
// not-empty predicate on the id set, never re-scanned). Returns the
// rows updated and the last timestamp handed to progress; on a
// cancelled context the watermark is the last completed batch, so
// the next run resumes there.
func stripRawByCursor(ctx context.Context, d *sql.DB, source string, from, cutoff time.Time, batchSize int, pause time.Duration, progress func(time.Time)) (int, time.Time, error) {
	if batchSize <= 0 {
		batchSize = RawStripBatch
	}
	stripped := 0
	cursorTS, cursorID := from, int64(0)
	var last time.Time
	for {
		rows, err := d.QueryContext(ctx, StripCursorSQL,
			source, cursorTS, cutoff, cursorTS, cursorID, batchSize)
		if err != nil {
			return stripped, last, err
		}
		ids := make([]any, 0, batchSize)
		var lastTS time.Time
		var lastID int64
		for rows.Next() {
			var id int64
			var ts time.Time
			if err := rows.Scan(&id, &ts); err != nil {
				rows.Close()
				return stripped, last, err
			}
			ids = append(ids, id)
			lastTS, lastID = ts, id
		}
		rows.Close()
		if len(ids) == 0 {
			return stripped, last, nil
		}
		res, err := d.ExecContext(ctx,
			`UPDATE log_entries SET raw = '' WHERE raw <> '' AND id IN (`+strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")+`)`, ids...)
		if err != nil {
			return stripped, last, err
		}
		n, _ := res.RowsAffected()
		stripped += int(n)
		cursorTS, cursorID, last = lastTS.UTC(), lastID, lastTS.UTC()
		if progress != nil {
			progress(last)
		}
		if len(ids) < batchSize {
			return stripped, last, nil
		}
		if pause > 0 {
			select {
			case <-ctx.Done():
				return stripped, last, ctx.Err()
			case <-time.After(pause):
			}
		}
	}
}

// RowCountBound returns MAX(id)-MIN(id)+1: the exact row count of
// log_entries when nothing was ever deleted from the middle, an upper
// bound otherwise. Two primary-key lookups.
func RowCountBound(ctx context.Context, d *sql.DB) (int, error) {
	var bound int
	err := d.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(id) - MIN(id) + 1, 0) FROM log_entries`).Scan(&bound)
	return bound, err
}

// deleteInBatches runs stmt (whose LAST placeholder is the LIMIT)
// repeatedly with LIMIT=batchSize until it affects fewer rows than
// the batch, or until want rows were removed (want < 0 = no limit).
// Sleeps pause between batches; honours ctx.
func deleteInBatches(ctx context.Context, d *sql.DB, batchSize int, pause time.Duration, want int, stmt string, args ...any) (int, error) {
	if batchSize <= 0 {
		batchSize = 1 << 30
	}
	removed := 0
	for {
		limit := batchSize
		if want >= 0 && want-removed < limit {
			limit = want - removed
		}
		if limit <= 0 {
			return removed, nil
		}
		res, err := d.ExecContext(ctx, stmt, append(append([]any{}, args...), limit)...)
		if err != nil {
			return removed, err
		}
		n, _ := res.RowsAffected()
		removed += int(n)
		if int(n) < limit {
			return removed, nil
		}
		if pause > 0 {
			select {
			case <-ctx.Done():
				return removed, ctx.Err()
			case <-time.After(pause):
			}
		}
	}
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
	if len(f.HostIDs) > 0 || len(f.HostDomainsOR) > 0 {
		// OR the two legs so rows the ingestor could not link (host_id
		// IS NULL but host_domain matches) come through too.
		var parts []string
		if len(f.HostIDs) > 0 {
			placeholders := make([]string, len(f.HostIDs))
			for i, h := range f.HostIDs {
				placeholders[i] = "?"
				args = append(args, h)
			}
			parts = append(parts, "host_id IN ("+strings.Join(placeholders, ",")+")")
		}
		if len(f.HostDomainsOR) > 0 {
			placeholders := make([]string, len(f.HostDomainsOR))
			for i, d := range f.HostDomainsOR {
				placeholders[i] = "?"
				args = append(args, d)
			}
			parts = append(parts, "host_domain IN ("+strings.Join(placeholders, ",")+")")
		}
		conds = append(conds, "("+strings.Join(parts, " OR ")+")")
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
	if len(f.WAFRuleIDs) > 0 {
		placeholders := make([]string, len(f.WAFRuleIDs))
		for i, id := range f.WAFRuleIDs {
			placeholders[i] = "?"
			args = append(args, id)
		}
		conds = append(conds, "waf_rule_id IN ("+strings.Join(placeholders, ",")+")")
	}
	if len(f.WAFSeverity) > 0 {
		placeholders := make([]string, len(f.WAFSeverity))
		for i, s := range f.WAFSeverity {
			placeholders[i] = "?"
			args = append(args, strings.ToUpper(s))
		}
		conds = append(conds, "waf_severity IN ("+strings.Join(placeholders, ",")+")")
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
		e      models.LogEntry
		src    string
		hostID sql.NullInt64
		ruleID sql.NullInt64
	)
	if err := s.Scan(
		&e.ID, &e.Timestamp, &src, &e.Level, &hostID, &e.HostDomain,
		&ruleID, &e.RemoteIP, &e.Method, &e.Path, &e.Status, &e.DurationMs,
		&e.SizeBytes, &e.UserAgent, &e.Upstream, &e.Message, &e.Raw,
		&e.WAFRuleID, &e.WAFRuleMessage, &e.WAFSeverity, &e.WAFAnomalyScore,
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
