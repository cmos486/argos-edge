package dashboard

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// longRangeDB mirrors the log_entries columns the traffic queries touch
// and, crucially, the six indexes of migration 009 by their real
// names: the long-range path pins them with INDEXED BY and the planner
// test below asserts on their use.
func longRangeDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	d.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = d.Close() })
	stmts := []string{
		`CREATE TABLE hosts (id INTEGER PRIMARY KEY, domain TEXT NOT NULL)`,
		`CREATE TABLE log_entries (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TIMESTAMP NOT NULL,
			source TEXT NOT NULL,
			host_id INTEGER,
			host_domain TEXT NOT NULL DEFAULT '',
			rule_id INTEGER,
			status INTEGER NOT NULL DEFAULT 0,
			duration_ms INTEGER NOT NULL DEFAULT 0,
			size_bytes INTEGER NOT NULL DEFAULT 0,
			path TEXT NOT NULL DEFAULT '',
			waf_rule_id INTEGER NOT NULL DEFAULT 0)`,
		`CREATE INDEX idx_log_entries_timestamp ON log_entries(timestamp DESC)`,
		`CREATE INDEX idx_log_entries_source_ts ON log_entries(source, timestamp DESC)`,
		`CREATE INDEX idx_log_entries_host_ts ON log_entries(host_id, timestamp DESC)`,
		`CREATE INDEX idx_log_entries_rule_ts ON log_entries(rule_id, timestamp DESC)`,
		`CREATE INDEX idx_log_entries_status_ts ON log_entries(status, timestamp DESC)`,
		`CREATE INDEX idx_log_entries_waf_rule_ts ON log_entries(waf_rule_id, timestamp DESC)`,
	}
	for _, st := range stmts {
		if _, err := d.Exec(st); err != nil {
			t.Fatalf("%s: %v", st[:40], err)
		}
	}
	return d
}

func insertAccess(t *testing.T, d *sql.DB, ts time.Time, hostID int64, domain string, status, durMs, size int, path string) {
	t.Helper()
	if _, err := d.Exec(`INSERT INTO log_entries (timestamp, source, host_id, host_domain, status, duration_ms, size_bytes, path)
		VALUES (?, 'caddy_access', ?, ?, ?, ?, ?, ?)`, ts.UTC(), hostID, domain, status, durMs, size, path); err != nil {
		t.Fatal(err)
	}
}

// TestLongRangePlans is the planner regression guard the operator
// asked for: the class series and top-hosts queries must be answered
// from a covering index. A query-shape change that makes SQLite fall
// back to idx_log_entries_timestamp + row visits (7 s instead of 0.2 s
// on 480k rows) breaks here, not in prod.
func TestLongRangePlans(t *testing.T) {
	d := longRangeDB(t)
	from, to := time.Now().Add(-7*24*time.Hour), time.Now()
	cases := []struct {
		name  string
		sql   string
		args  []any
		index string
	}{
		{"class 2xx", classSeriesSQL, []any{200, 299, from, to}, "idx_log_entries_status_ts"},
		{"class 3xx", classSeriesSQL, []any{300, 399, from, to}, "idx_log_entries_status_ts"},
		{"class 4xx", classSeriesSQL, []any{400, 499, from, to}, "idx_log_entries_status_ts"},
		{"class 5xx", classSeriesSQL, []any{500, 599, from, to}, "idx_log_entries_status_ts"},
		{"top hosts", topHostsByIDSQL, []any{from, to}, "idx_log_entries_host_ts"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rows, err := d.Query("EXPLAIN QUERY PLAN "+c.sql, c.args...)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			var plan []string
			for rows.Next() {
				var id, parent, notused int
				var detail string
				if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
					t.Fatal(err)
				}
				plan = append(plan, detail)
			}
			joined := strings.Join(plan, " | ")
			if !strings.Contains(joined, "COVERING INDEX "+c.index) {
				t.Fatalf("plan must use COVERING INDEX %s, got: %s", c.index, joined)
			}
			for _, p := range plan {
				if strings.HasPrefix(p, "SCAN") {
					t.Fatalf("plan must not SCAN the table, got: %s", joined)
				}
			}
		})
	}
}

func TestTrafficLongRangeCountsAndDetailWindow(t *testing.T) {
	d := longRangeDB(t)
	if _, err := d.Exec(`INSERT INTO hosts (id, domain) VALUES (1, 'a.example.com'), (2, 'b.example.com')`); err != nil {
		t.Fatal(err)
	}
	to := time.Now().UTC().Truncate(time.Hour)
	from := to.Add(-7 * 24 * time.Hour)
	// Six days ago: 3x 200 and 1x 500 on host 1 (outside the detail window).
	old := to.Add(-6 * 24 * time.Hour).Add(30 * time.Minute)
	for i := 0; i < 3; i++ {
		insertAccess(t, d, old, 1, "a.example.com", 200, 1000, 10, "/old")
	}
	insertAccess(t, d, old, 1, "a.example.com", 500, 1000, 10, "/old")
	// Two hours ago: 2x 200 on host 2 and 1x 404 on host 1 (inside the detail window).
	recent := to.Add(-2 * time.Hour).Add(15 * time.Minute)
	insertAccess(t, d, recent, 2, "b.example.com", 200, 50, 100, "/api")
	insertAccess(t, d, recent, 2, "b.example.com", 200, 70, 100, "/api")
	insertAccess(t, d, recent, 1, "a.example.com", 404, 20, 5, "/missing")

	q := &Queries{DB: d}
	tm, err := q.Traffic(context.Background(), from, to, time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !tm.SeriesCoversRange || tm.DetailWindow != "24h0m0s" || tm.DetailFrom.IsZero() {
		t.Fatalf("long-range markers wrong: covers=%v window=%q from=%v", tm.SeriesCoversRange, tm.DetailWindow, tm.DetailFrom)
	}
	if len(tm.Timeseries) != 7*24+1 {
		t.Fatalf("want %d hourly buckets, got %d", 7*24+1, len(tm.Timeseries))
	}
	var c2, c4, c5 int
	for _, b := range tm.Timeseries {
		c2 += b.C2xx
		c4 += b.C4xx
		c5 += b.C5xx
	}
	if c2 != 5 || c4 != 1 || c5 != 1 {
		t.Fatalf("series must cover the whole range: 2xx=%d 4xx=%d 5xx=%d", c2, c4, c5)
	}
	// The old rows land in their own hour bucket, the recent ones in theirs.
	oldKey := old.Truncate(time.Hour)
	found := false
	for _, b := range tm.Timeseries {
		if b.Time.Equal(oldKey) {
			found = true
			if b.C2xx != 3 || b.C5xx != 1 {
				t.Fatalf("old bucket: want 3x2xx 1x5xx, got %+v", b)
			}
		}
	}
	if !found {
		t.Fatalf("old bucket %v missing", oldKey)
	}
	// Top hosts over the whole range: host 1 has 5 rows, host 2 has 2.
	if len(tm.TopHosts) != 2 || tm.TopHosts[0].HostDomain != "a.example.com" || tm.TopHosts[0].Count != 5 || tm.TopHosts[1].Count != 2 {
		t.Fatalf("top hosts: %+v", tm.TopHosts)
	}
	// Detail sections only see the newest 24 h: bandwidth 205, paths /api + /missing.
	if tm.BandwidthOut != 205 {
		t.Fatalf("bandwidth must be detail-window only (205), got %d", tm.BandwidthOut)
	}
	paths := map[string]int64{}
	for _, p := range tm.TopPaths {
		paths[p.Path] = p.Count
	}
	if paths["/api"] != 2 || paths["/missing"] != 1 || paths["/old"] != 0 {
		t.Fatalf("top paths must be detail-window only: %+v", tm.TopPaths)
	}
	if len(tm.ResponseTimes) != 24+1 {
		t.Fatalf("response times must cover the 24 h detail window: %d buckets", len(tm.ResponseTimes))
	}
}

func TestTrafficLongRangeWithHostIsBoundedToDetailWindow(t *testing.T) {
	d := longRangeDB(t)
	to := time.Now().UTC().Truncate(time.Hour)
	from := to.Add(-7 * 24 * time.Hour)
	insertAccess(t, d, to.Add(-5*24*time.Hour), 1, "a.example.com", 200, 10, 1, "/")
	insertAccess(t, d, to.Add(-3*time.Hour), 1, "a.example.com", 200, 10, 1, "/")
	q := &Queries{DB: d}
	tm, err := q.Traffic(context.Background(), from, to, time.Hour, 1)
	if err != nil {
		t.Fatal(err)
	}
	if tm.SeriesCoversRange || tm.DetailWindow == "" {
		t.Fatalf("host-filtered long range must be bounded and say so: %+v", tm)
	}
	total := 0
	for _, b := range tm.Timeseries {
		total += b.C2xx
	}
	if total != 1 || len(tm.Timeseries) != 24+1 {
		t.Fatalf("series must be the newest 24 h only: total=%d buckets=%d", total, len(tm.Timeseries))
	}
}

func TestTrafficShortRangeUnchanged(t *testing.T) {
	d := longRangeDB(t)
	to := time.Now().UTC().Truncate(15 * time.Minute)
	from := to.Add(-24 * time.Hour)
	insertAccess(t, d, to.Add(-time.Hour), 1, "a.example.com", 200, 10, 7, "/x")
	q := &Queries{DB: d}
	tm, err := q.Traffic(context.Background(), from, to, 15*time.Minute, 0)
	if err != nil {
		t.Fatal(err)
	}
	if tm.DetailWindow != "" || !tm.SeriesCoversRange || tm.BandwidthOut != 7 {
		t.Fatalf("short range must not carry detail markers: %+v", tm)
	}
}
