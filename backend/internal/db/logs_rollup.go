package db

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/models"
)

// logs/stats and logs/timeseries on the hourly rollup (v1.3.42.3).
// The closed hours of a time-only filter come from log_hourly and
// log_hourly_paths; the head edge and the live tail come from the
// rows through the covering statements below, bounded to the edge.
// Rows without a host link never count in top_hosts on this path
// (the rollup groups by host_id), and top_paths counts access rows
// only (the rollup keeps access paths), as api.md says.

// Edge statements, planner-pinned in TestStatsRollupPlans. Each takes
// the lower bound, then the upper bound; the comparison for the upper
// bound is the edge's (< for the head, <= for the live tail).
func edgeTotalSQL(e Edge) string {
	return `SELECT COUNT(*) FROM log_entries INDEXED BY idx_log_entries_timestamp WHERE timestamp >= ? AND ` + e.UpperOp() + ` ?`
}

func edgeSourceCountSQL(e Edge) string {
	return `SELECT COUNT(*) FROM log_entries INDEXED BY idx_log_entries_source_ts WHERE source = ? AND timestamp >= ? AND ` + e.UpperOp() + ` ?`
}

func edgeClassCountSQL(e Edge) string {
	return `SELECT COUNT(*) FROM log_entries INDEXED BY idx_log_entries_status_ts WHERE status BETWEEN ? AND ? AND timestamp >= ? AND ` + e.UpperOp() + ` ?`
}

func edgeHostsSQL(e Edge, accessOnly bool) string {
	if accessOnly {
		return `SELECT COALESCE(host_id, 0), COUNT(*) FROM log_entries INDEXED BY idx_log_entries_source_ts WHERE source = 'caddy_access' AND timestamp >= ? AND ` + e.UpperOp() + ` ? GROUP BY 1`
	}
	return `SELECT host_id, COUNT(*) FROM log_entries INDEXED BY idx_log_entries_host_ts WHERE host_id IS NOT NULL AND timestamp >= ? AND ` + e.UpperOp() + ` ? GROUP BY host_id`
}

func edgeDurationsSQL(e Edge, accessOnly bool) string {
	if accessOnly {
		return `SELECT duration_ms FROM log_entries INDEXED BY idx_log_entries_source_ts WHERE source = 'caddy_access' AND timestamp >= ? AND ` + e.UpperOp() + ` ?`
	}
	return `SELECT duration_ms FROM log_entries INDEXED BY idx_log_entries_timestamp WHERE timestamp >= ? AND ` + e.UpperOp() + ` ?`
}

func edgePathsSQL(e Edge) string {
	return `SELECT path, COUNT(*) FROM log_entries INDEXED BY idx_log_entries_source_ts WHERE source = 'caddy_access' AND path <> '' AND timestamp >= ? AND ` + e.UpperOp() + ` ? GROUP BY path`
}

func edgeClassSeriesSQL(e Edge) string {
	return `SELECT substr(timestamp, 1, 13) AS h, COUNT(*) FROM log_entries INDEXED BY idx_log_entries_status_ts WHERE status BETWEEN ? AND ? AND timestamp >= ? AND ` + e.UpperOp() + ` ? GROUP BY h`
}

func edgeTotalSeriesSQL(e Edge, accessOnly bool) string {
	if accessOnly {
		return `SELECT substr(timestamp, 1, 13) AS h, COUNT(*) FROM log_entries INDEXED BY idx_log_entries_source_ts WHERE source = 'caddy_access' AND timestamp >= ? AND ` + e.UpperOp() + ` ? GROUP BY h`
	}
	return `SELECT substr(timestamp, 1, 13) AS h, COUNT(*) FROM log_entries INDEXED BY idx_log_entries_timestamp WHERE timestamp >= ? AND ` + e.UpperOp() + ` ? GROUP BY h`
}

func rollupSourceFilter(f LogFilter) (string, bool) {
	if len(f.Sources) > 0 {
		return string(models.LogCaddyAccess), true
	}
	return "", false
}

func computeStatsRollup(ctx context.Context, d *sql.DB, f LogFilter, span RollupSpan) (LogStats, error) {
	s := LogStats{ByStatusClass: map[string]int{}, BySource: map[string]int{}, PercentileMethod: PercentileHistogram, Path: PathRollup}
	source, accessOnly := rollupSourceFilter(f)
	classes := map[int]int{}
	byHost := map[int64]int64{}
	byPath := map[string]int64{}
	var hist Hist

	rows, err := ReadRollupHours(ctx, d, span.ClosedFrom, span.ClosedTo, source, 0)
	if err != nil {
		return s, err
	}
	for _, r := range rows {
		s.Total += int(r.Requests)
		classes[r.StatusClass] += int(r.Requests)
		s.BySource[r.Source] += int(r.Requests)
		if r.HostID > 0 {
			byHost[r.HostID] += r.Requests
		}
		hist.AddRow(r)
	}
	paths, err := ReadRollupPaths(ctx, d, span.ClosedFrom, span.ClosedTo, 0)
	if err != nil {
		return s, err
	}
	for _, p := range paths {
		byPath[p.Path] += p.Requests
	}

	sources := []models.LogSource{models.LogCaddyAccess}
	if !accessOnly {
		sources = []models.LogSource{models.LogCaddyAccess, models.LogCaddyError, models.LogAudit, models.LogWAFAudit}
	}
	for _, e := range span.Edges() {
		if accessOnly {
			var n int
			if err := d.QueryRowContext(ctx, edgeSourceCountSQL(e), string(models.LogCaddyAccess), e.From, e.To).Scan(&n); err != nil {
				return s, fmt.Errorf("stats edge total: %w", err)
			}
			s.Total += n
		} else {
			var n int
			if err := d.QueryRowContext(ctx, edgeTotalSQL(e), e.From, e.To).Scan(&n); err != nil {
				return s, fmt.Errorf("stats edge total: %w", err)
			}
			s.Total += n
		}
		for _, c := range statusClasses {
			var n int
			if err := d.QueryRowContext(ctx, edgeClassCountSQL(e), c.lo, c.hi, e.From, e.To).Scan(&n); err != nil {
				return s, fmt.Errorf("stats edge class %s: %w", c.key, err)
			}
			classes[c.lo/100] += n
		}
		for _, src := range sources {
			var n int
			if err := d.QueryRowContext(ctx, edgeSourceCountSQL(e), string(src), e.From, e.To).Scan(&n); err != nil {
				return s, fmt.Errorf("stats edge source %s: %w", src, err)
			}
			s.BySource[string(src)] += n
		}
		if err := scanPairsInt64(ctx, d, edgeHostsSQL(e, accessOnly), []any{e.From, e.To}, func(id, n int64) {
			if id > 0 {
				byHost[id] += n
			}
		}); err != nil {
			return s, fmt.Errorf("stats edge hosts: %w", err)
		}
		dRows, err := d.QueryContext(ctx, edgeDurationsSQL(e, accessOnly), e.From, e.To)
		if err != nil {
			return s, fmt.Errorf("stats edge durations: %w", err)
		}
		for dRows.Next() {
			var ms int
			if err := dRows.Scan(&ms); err != nil {
				dRows.Close()
				return s, err
			}
			hist.AddDuration(ms)
		}
		dRows.Close()
		if err := scanPairsStr(ctx, d, edgePathsSQL(e), []any{e.From, e.To}, func(p string, n int64) { byPath[p] += n }); err != nil {
			return s, fmt.Errorf("stats edge paths: %w", err)
		}
	}

	classed := 0
	for _, c := range statusClasses {
		if n := classes[c.lo/100]; n > 0 {
			s.ByStatusClass[c.key] = n
			classed += n
		}
	}
	if other := s.Total - classed; other > 0 {
		s.ByStatusClass["other"] = other
	}
	for k, n := range s.BySource {
		if n == 0 {
			delete(s.BySource, k)
		}
	}
	s.AvgDurationMs = hist.Avg()
	s.P95DurationMs = hist.Percentile(95)

	names := map[int64]string{}
	if len(byHost) > 0 {
		if err := scanPairsIDStr(ctx, d, `SELECT id, domain FROM hosts`, func(id int64, dom string) { names[id] = dom }); err != nil {
			return s, fmt.Errorf("stats host names: %w", err)
		}
	}
	type hc struct {
		id int64
		n  int64
	}
	var hosts []hc
	for id, n := range byHost {
		hosts = append(hosts, hc{id, n})
	}
	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i].n != hosts[j].n {
			return hosts[i].n > hosts[j].n
		}
		return hosts[i].id < hosts[j].id
	})
	for _, h := range hosts {
		if dom, ok := names[h.id]; ok {
			s.TopHosts = append(s.TopHosts, Pair{Label: dom, Count: int(h.n)})
		}
		if len(s.TopHosts) == 5 {
			break
		}
	}
	type pc struct {
		p string
		n int64
	}
	var pcs []pc
	for p, n := range byPath {
		pcs = append(pcs, pc{p, n})
	}
	sort.Slice(pcs, func(i, j int) bool {
		if pcs[i].n != pcs[j].n {
			return pcs[i].n > pcs[j].n
		}
		return pcs[i].p < pcs[j].p
	})
	for i, p := range pcs {
		if i == 5 {
			break
		}
		s.TopPaths = append(s.TopPaths, Pair{Label: p.p, Count: int(p.n)})
	}
	return s, nil
}

func computeTimeseriesRollup(ctx context.Context, d *sql.DB, f LogFilter, span RollupSpan) ([]Bucket, error) {
	source, accessOnly := rollupSourceFilter(f)
	buckets := map[int64]*Bucket{}
	get := func(t time.Time) *Bucket {
		key := t.Unix()
		b, ok := buckets[key]
		if !ok {
			b = &Bucket{Timestamp: time.Unix(key, 0).UTC()}
			buckets[key] = b
		}
		return b
	}
	rows, err := ReadRollupHours(ctx, d, span.ClosedFrom, span.ClosedTo, source, 0)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		b := get(r.Hour)
		b.Total += int(r.Requests)
		switch r.StatusClass {
		case 2:
			b.Class2xx += int(r.Requests)
		case 3:
			b.Class3xx += int(r.Requests)
		case 4:
			b.Class4xx += int(r.Requests)
		case 5:
			b.Class5xx += int(r.Requests)
		}
	}
	hourOf := func(h string) (time.Time, bool) {
		ts, err := time.Parse("2006-01-02 15", h)
		return ts, err == nil
	}
	for _, e := range span.Edges() {
		for _, c := range statusClasses {
			if err := scanPairsStr(ctx, d, edgeClassSeriesSQL(e), []any{c.lo, c.hi, e.From, e.To}, func(h string, n int64) {
				ts, ok := hourOf(h)
				if !ok {
					return
				}
				b := get(ts)
				switch c.key {
				case "2xx":
					b.Class2xx += int(n)
				case "3xx":
					b.Class3xx += int(n)
				case "4xx":
					b.Class4xx += int(n)
				case "5xx":
					b.Class5xx += int(n)
				}
			}); err != nil {
				return nil, fmt.Errorf("timeseries edge class %s: %w", c.key, err)
			}
		}
		if err := scanPairsStr(ctx, d, edgeTotalSeriesSQL(e, accessOnly), []any{e.From, e.To}, func(h string, n int64) {
			if ts, ok := hourOf(h); ok {
				get(ts).Total += int(n)
			}
		}); err != nil {
			return nil, fmt.Errorf("timeseries edge total: %w", err)
		}
	}
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

func scanPairsInt64(ctx context.Context, d *sql.DB, q string, args []any, fn func(a, b int64)) error {
	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var a, b int64
		if err := rows.Scan(&a, &b); err != nil {
			return err
		}
		fn(a, b)
	}
	return rows.Err()
}

func scanPairsStr(ctx context.Context, d *sql.DB, q string, args []any, fn func(s string, n int64)) error {
	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		var n int64
		if err := rows.Scan(&s, &n); err != nil {
			return err
		}
		fn(s, n)
	}
	return rows.Err()
}

func scanPairsIDStr(ctx context.Context, d *sql.DB, q string, fn func(id int64, s string)) error {
	rows, err := d.QueryContext(ctx, q)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var s string
		if err := rows.Scan(&id, &s); err != nil {
			return err
		}
		fn(id, s)
	}
	return rows.Err()
}
