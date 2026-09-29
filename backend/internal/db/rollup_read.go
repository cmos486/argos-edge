package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Readers of the hourly rollup (v1.3.42.3). A window [From, To] is
// split into three spans: the head edge before the first closed hour
// the rollup holds, the closed hours themselves, and the live tail
// after the newest rollup hour. The closed span is served from
// log_hourly / log_hourly_paths, the two edges from log_entries with
// the existing row statements bounded to the edge (at most two hours
// of rows when the fill job keeps up). Every count, byte and sum is
// exact; percentiles over closed hours come from the 8-bucket
// duration histogram (see Hist).

// HistEdgesMs are the upper edges of the duration histogram buckets
// dur_h0..dur_h6 of log_hourly; dur_h7 holds everything above the
// last edge and reports the merged maximum instead of an edge.
var HistEdgesMs = [7]int{50, 100, 250, 500, 1000, 2500, 5000}

// RollupSpan is the split of one window.
type RollupSpan struct {
	From, To             time.Time
	ClosedFrom, ClosedTo time.Time // [ClosedFrom, ClosedTo) served by the rollup; empty when ClosedFrom >= ClosedTo
}

// HasClosed is true when at least one closed hour is served by the
// rollup; without it the caller keeps its row path.
func (s RollupSpan) HasClosed() bool { return s.ClosedFrom.Before(s.ClosedTo) }

// HasHead is true when rows before the first closed hour are needed.
func (s RollupSpan) HasHead() bool { return s.From.Before(s.ClosedFrom) }

// HasLive is true when rows after the newest closed hour are needed.
func (s RollupSpan) HasLive() bool { return s.ClosedTo.Before(s.To) }

// LiveFrom is the start of the live tail (the end of the closed span).
func (s RollupSpan) LiveFrom() time.Time { return s.ClosedTo }

// HeadTo is the end of the head edge (the start of the closed span).
func (s RollupSpan) HeadTo() time.Time { return s.ClosedFrom }

// Edge is one raw-row span of a stitched window: the head edge ends
// before the first closed hour (Inclusive false, "<"), the live tail
// ends at the window end (Inclusive true, "<=").
type Edge struct {
	From, To  time.Time
	Inclusive bool
}

// UpperOp is the SQL comparison for the edge's upper bound.
func (e Edge) UpperOp() string {
	if e.Inclusive {
		return "timestamp <="
	}
	return "timestamp <"
}

// Edges lists the raw-row spans of the window in time order.
func (s RollupSpan) Edges() []Edge {
	var out []Edge
	if s.HasHead() {
		out = append(out, Edge{From: s.From, To: s.ClosedFrom})
	}
	if s.HasLive() {
		out = append(out, Edge{From: s.ClosedTo, To: s.To, Inclusive: true})
	}
	return out
}

func ceilHour(t time.Time) time.Time {
	tr := t.UTC().Truncate(time.Hour)
	if tr.Equal(t.UTC()) {
		return tr
	}
	return tr.Add(time.Hour)
}

// RollupSpanFor splits [from, to] against what log_hourly holds now:
// closed hours are those from ceil(from) up to min(floor(to), newest
// rollup hour + 1 h), and never before the oldest rollup hour. With no
// rollup rows the closed span is empty and the caller takes its row
// path unchanged.
func RollupSpanFor(ctx context.Context, d *sql.DB, from, to time.Time) (RollupSpan, error) {
	from, to = from.UTC(), to.UTC()
	s := RollupSpan{From: from, To: to, ClosedFrom: from, ClosedTo: from}
	maxHour, ok, err := RollupMaxHour(ctx, d)
	if err != nil {
		return s, fmt.Errorf("rollup span max: %w", err)
	}
	if !ok {
		return s, nil
	}
	minHour, ok, err := scalarTime(ctx, d, `SELECT MIN(hour) FROM log_hourly`)
	if err != nil {
		return s, fmt.Errorf("rollup span min: %w", err)
	}
	if !ok {
		return s, nil
	}
	cf := ceilHour(from)
	if cf.Before(minHour) {
		cf = minHour
	}
	ct := to.Truncate(time.Hour)
	if newest := maxHour.Add(time.Hour); newest.Before(ct) {
		ct = newest
	}
	if ct.After(to) {
		ct = to
	}
	if !cf.Before(ct) {
		// nothing closed inside the window
		s.ClosedFrom, s.ClosedTo = from, from
		return s, nil
	}
	s.ClosedFrom, s.ClosedTo = cf, ct
	return s, nil
}

// RollupHourRow is one log_hourly row.
type RollupHourRow struct {
	Hour        time.Time
	Source      string
	HostID      int64
	StatusClass int
	Requests    int64
	BytesOut    int64
	DurSumMs    int64
	DurMaxMs    int64
	P50, P95    sql.NullInt64
	P99         sql.NullInt64
	Hist        [8]int64
	Forbidden   int64
	RateLimited int64
	Errors      int64
}

// Planner-pinned shapes (TestRollupReadPlans): the source-filtered read
// walks idx_log_hourly_source_hour, the unfiltered one the primary key
// on (hour, ...); the paths read walks idx_log_hourly_paths_hour.
const (
	rollupReadSQL = `SELECT hour, source, host_id, status_class, requests, bytes_out, dur_sum_ms, dur_max_ms,
		dur_p50_ms, dur_p95_ms, dur_p99_ms, dur_h0, dur_h1, dur_h2, dur_h3, dur_h4, dur_h5, dur_h6, dur_h7,
		forbidden, rate_limited, errors
		FROM log_hourly WHERE hour >= ? AND hour < ?`
	rollupReadBySourceSQL = `SELECT hour, source, host_id, status_class, requests, bytes_out, dur_sum_ms, dur_max_ms,
		dur_p50_ms, dur_p95_ms, dur_p99_ms, dur_h0, dur_h1, dur_h2, dur_h3, dur_h4, dur_h5, dur_h6, dur_h7,
		forbidden, rate_limited, errors
		FROM log_hourly INDEXED BY idx_log_hourly_source_hour WHERE source = ? AND hour >= ? AND hour < ?`
	rollupReadPathsSQL = `SELECT host_id, path, SUM(requests), SUM(bytes_out)
		FROM log_hourly_paths INDEXED BY idx_log_hourly_paths_hour WHERE hour >= ? AND hour < ?`
)

// ReadRollupHours returns the rollup rows of [from, to), optionally
// limited to one source and one host (0 = any host).
func ReadRollupHours(ctx context.Context, d *sql.DB, from, to time.Time, source string, hostID int64) ([]RollupHourRow, error) {
	q, args := rollupReadSQL, []any{from.UTC(), to.UTC()}
	if source != "" {
		q, args = rollupReadBySourceSQL, []any{source, from.UTC(), to.UTC()}
	}
	if hostID > 0 {
		q += ` AND host_id = ?`
		args = append(args, hostID)
	}
	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("rollup read: %w", err)
	}
	defer rows.Close()
	var out []RollupHourRow
	for rows.Next() {
		var r RollupHourRow
		var hour string
		if err := rows.Scan(&hour, &r.Source, &r.HostID, &r.StatusClass, &r.Requests, &r.BytesOut, &r.DurSumMs, &r.DurMaxMs,
			&r.P50, &r.P95, &r.P99, &r.Hist[0], &r.Hist[1], &r.Hist[2], &r.Hist[3], &r.Hist[4], &r.Hist[5], &r.Hist[6], &r.Hist[7],
			&r.Forbidden, &r.RateLimited, &r.Errors); err != nil {
			return nil, fmt.Errorf("rollup read scan: %w", err)
		}
		if r.Hour, err = ParseDBTime(hour); err != nil {
			return nil, fmt.Errorf("rollup read hour: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RollupPathRow is one (host, path) total over a span.
type RollupPathRow struct {
	HostID   int64
	Path     string
	Requests int64
	BytesOut int64
}

// ReadRollupPaths sums log_hourly_paths over [from, to) per (host,
// path), optionally for one host. The caller merges the live edges and
// takes its top N; a path can only be missing from a range top N if it
// never made an hourly top RollupPathsPerHost for its host.
func ReadRollupPaths(ctx context.Context, d *sql.DB, from, to time.Time, hostID int64) ([]RollupPathRow, error) {
	q, args := rollupReadPathsSQL, []any{from.UTC(), to.UTC()}
	if hostID > 0 {
		q += ` AND host_id = ?`
		args = append(args, hostID)
	}
	q += ` GROUP BY host_id, path`
	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("rollup paths read: %w", err)
	}
	defer rows.Close()
	var out []RollupPathRow
	for rows.Next() {
		var r RollupPathRow
		if err := rows.Scan(&r.HostID, &r.Path, &r.Requests, &r.BytesOut); err != nil {
			return nil, fmt.Errorf("rollup paths scan: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Hist is the merged duration histogram of any number of rollup rows
// and live rows. Percentiles are nearest-rank (ceil(p * n / 100), the
// rank the fill job uses for its exact per-group values) resolved to
// the upper edge of the bucket that holds that rank; the open bucket
// (above 5,000 ms) resolves to 5,000, read as "5,000 ms or more". It
// never reports the merged maximum: on prod that is the lifetime of a
// long-lived connection (a websocket row of 5.3 days, v1.3.42.3.1).
type Hist struct {
	N   int64
	B   [8]int64
	Sum int64
	Max int64
}

// AddRow merges one rollup row.
func (h *Hist) AddRow(r RollupHourRow) {
	h.N += r.Requests
	h.Sum += r.DurSumMs
	for i := range h.B {
		h.B[i] += r.Hist[i]
	}
	if r.DurMaxMs > h.Max {
		h.Max = r.DurMaxMs
	}
}

// AddDuration merges one live row.
func (h *Hist) AddDuration(ms int) {
	h.N++
	h.Sum += int64(ms)
	if int64(ms) > h.Max {
		h.Max = int64(ms)
	}
	for i, edge := range HistEdgesMs {
		if ms <= edge {
			h.B[i]++
			return
		}
	}
	h.B[7]++
}

// Percentile returns the p-th percentile (0-100) as described on Hist;
// 0 when the histogram is empty.
func (h Hist) Percentile(p int) int {
	if h.N <= 0 {
		return 0
	}
	rank := (h.N*int64(p) + 99) / 100
	if rank < 1 {
		rank = 1
	}
	var seen int64
	for i := 0; i < 7; i++ {
		seen += h.B[i]
		if seen >= rank {
			return HistEdgesMs[i]
		}
	}
	return HistEdgesMs[6]
}

// Avg is the mean duration, 0 when empty.
func (h Hist) Avg() int {
	if h.N <= 0 {
		return 0
	}
	return int(h.Sum / h.N)
}
