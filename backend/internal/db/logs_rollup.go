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

// Edge statements, planner-pinned in TestStatsRollupPlans. One row pass
// per edge (at most about two hours of rows when the fill job keeps
// up) aggregates everything in Go; that is cheaper than one covering
// statement per figure on a span this short (the status and host
// indexes seek once per status value and per host). Each takes the
// lower bound, then the upper bound; the comparison for the upper
// bound is the edge's (< for the head, <= for the live tail).
func edgeStatsRowsSQL(e Edge, accessOnly bool) string {
	if accessOnly {
		return `SELECT source, status, duration_ms, COALESCE(host_id, 0), path FROM log_entries INDEXED BY idx_log_entries_source_ts WHERE source = 'caddy_access' AND timestamp >= ? AND ` + e.UpperOp() + ` ?`
	}
	return `SELECT source, status, duration_ms, COALESCE(host_id, 0), path FROM log_entries INDEXED BY idx_log_entries_timestamp WHERE timestamp >= ? AND ` + e.UpperOp() + ` ?`
}

func edgeSeriesRowsSQL(e Edge, accessOnly bool) string {
	if accessOnly {
		return `SELECT timestamp, status FROM log_entries INDEXED BY idx_log_entries_source_ts WHERE source = 'caddy_access' AND timestamp >= ? AND ` + e.UpperOp() + ` ?`
	}
	return `SELECT timestamp, status FROM log_entries INDEXED BY idx_log_entries_timestamp WHERE timestamp >= ? AND ` + e.UpperOp() + ` ?`
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

	for _, e := range span.Edges() {
		rows, err := d.QueryContext(ctx, edgeStatsRowsSQL(e, accessOnly), e.From, e.To)
		if err != nil {
			return s, fmt.Errorf("stats edge rows: %w", err)
		}
		for rows.Next() {
			var source, path string
			var status, dur int
			var host int64
			if err := rows.Scan(&source, &status, &dur, &host, &path); err != nil {
				rows.Close()
				return s, err
			}
			s.Total++
			if status >= 100 {
				classes[status/100]++
			} else {
				classes[0]++
			}
			s.BySource[source]++
			if host > 0 {
				byHost[host]++
			}
			hist.AddDuration(dur)
			if source == string(models.LogCaddyAccess) && path != "" {
				byPath[path]++
			}
		}
		rows.Close()
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
	for _, e := range span.Edges() {
		rows, err := d.QueryContext(ctx, edgeSeriesRowsSQL(e, accessOnly), e.From, e.To)
		if err != nil {
			return nil, fmt.Errorf("timeseries edge rows: %w", err)
		}
		for rows.Next() {
			var ts time.Time
			var status int
			if err := rows.Scan(&ts, &status); err != nil {
				rows.Close()
				return nil, err
			}
			b := get(ts.UTC().Truncate(time.Hour))
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
			}
		}
		rows.Close()
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
