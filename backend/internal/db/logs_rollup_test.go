package db_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/db/dbtest"
	"github.com/cmos486/argos-edge/backend/internal/models"
)

func hostPtr(id int64) *int64 {
	if id == 0 {
		return nil
	}
	return &id
}

// seedLogHours writes deterministic rows of every source for each hour
// in [start, end): access rows on two hosts and one without a host,
// one error row, one audit row, one waf_audit row with a path.
func seedLogHours(t *testing.T, d *sql.DB, h1, h2 int64, start, end time.Time) {
	t.Helper()
	i := 0
	for h := start; h.Before(end); h = h.Add(time.Hour) {
		i++
		mk := func(off time.Duration, host int64, dom string, status, dur, size int, path string) models.LogEntry {
			return models.LogEntry{Timestamp: h.Add(off), Source: models.LogCaddyAccess, HostID: hostPtr(host), HostDomain: dom,
				Method: "GET", Path: path, Status: status, DurationMs: dur, SizeBytes: size, Level: "info"}
		}
		rows := []models.LogEntry{
			mk(3*time.Minute, h1, "one.example.com", 200, 10+i%40, 100, "/a"),
			mk(17*time.Minute, h1, "one.example.com", 200, 120, 100, "/a"),
			mk(22*time.Minute, h1, "one.example.com", 301, 30, 10, "/r"),
			mk(31*time.Minute, h1, "one.example.com", 403, 45, 50, "/x"),
			mk(44*time.Minute, h1, "one.example.com", 429, 2600+i, 10, "/y"),
			mk(47*time.Minute, h2, "two.example.com", 200, 60, 1000, "/c"),
			mk(52*time.Minute, h2, "two.example.com", 500, 700, 0, "/c"),
			mk(58*time.Minute, h2, "two.example.com", 200, 6000, 20, "/slow"),
			mk(59*time.Minute, 0, "", 200, 5, 1, "/nohost"),
			{Timestamp: h.Add(9 * time.Minute), Source: models.LogCaddyError, HostID: hostPtr(h1), HostDomain: "one.example.com", Level: "error", Message: "upstream"},
			{Timestamp: h.Add(11 * time.Minute), Source: models.LogAudit, Level: "info", Message: "login"},
		}
		if err := db.InsertLogBatch(context.Background(), d, rows); err != nil {
			t.Fatal(err)
		}
	}
}

// rawStats is the reference computed from the rows with plain SQL.
type rawStats struct {
	total   int
	classes map[string]int
	sources map[string]int
	hosts   map[string]int
	paths   map[string]int
	hist    db.Hist
}

func rawStatsFor(t *testing.T, d *sql.DB, from, to time.Time, accessOnly bool) rawStats {
	t.Helper()
	r := rawStats{classes: map[string]int{}, sources: map[string]int{}, hosts: map[string]int{}, paths: map[string]int{}}
	where := ` WHERE timestamp >= ? AND timestamp <= ?`
	if accessOnly {
		where += ` AND source = 'caddy_access'`
	}
	// One connection in dbtest: read the host names before opening the
	// row cursor, or the second query waits for the first forever.
	names := map[int64]string{}
	nr, err := d.Query(`SELECT id, domain FROM hosts`)
	if err != nil {
		t.Fatal(err)
	}
	for nr.Next() {
		var id int64
		var dom string
		if err := nr.Scan(&id, &dom); err != nil {
			t.Fatal(err)
		}
		names[id] = dom
	}
	nr.Close()
	rows, err := d.Query(`SELECT source, status, duration_ms, COALESCE(host_id, 0), path FROM log_entries`+where, from, to)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var source, path string
		var status, dur int
		var host int64
		if err := rows.Scan(&source, &status, &dur, &host, &path); err != nil {
			t.Fatal(err)
		}
		r.total++
		switch {
		case status >= 200 && status < 300:
			r.classes["2xx"]++
		case status >= 300 && status < 400:
			r.classes["3xx"]++
		case status >= 400 && status < 500:
			r.classes["4xx"]++
		case status >= 500 && status < 600:
			r.classes["5xx"]++
		default:
			r.classes["other"]++
		}
		r.sources[source]++
		if host > 0 {
			r.hosts[names[host]]++
		}
		if source == "caddy_access" && path != "" {
			r.paths[path]++
		}
		r.hist.AddDuration(dur)
	}
	return r
}

// TestStatsRollupEqualsRows: with and without the access-only source
// filter, for 6 h, 24 h and 7 d windows, the stitched stats equal the
// row computation for total, classes, sources, top hosts and top
// paths (tolerance 0) and the histogram avg / p95.
func TestStatsRollupEqualsRows(t *testing.T) {
	d := dbtest.Open(t)
	ctx := context.Background()
	h1 := dbtest.InsertHost(t, d, "one.example.com")
	h2 := dbtest.InsertHost(t, d, "two.example.com")
	now := time.Date(2026, 9, 27, 10, 37, 0, 0, time.UTC)
	floor := now.Truncate(time.Hour)
	seedLogHours(t, d, h1, h2, floor.Add(-8*24*time.Hour), floor.Add(time.Hour))
	for h := floor.Add(-8 * 24 * time.Hour); h.Before(floor); h = h.Add(time.Hour) {
		if _, err := db.FillRollupHour(ctx, d, h); err != nil {
			t.Fatal(err)
		}
	}
	for _, window := range []time.Duration{6 * time.Hour, 24 * time.Hour, 7 * 24 * time.Hour} {
		for _, accessOnly := range []bool{false, true} {
			f := db.LogFilter{From: now.Add(-window), To: now}
			if accessOnly {
				f.Sources = []models.LogSource{models.LogCaddyAccess}
			}
			s, err := db.ComputeStats(ctx, d, f)
			if err != nil {
				t.Fatal(err)
			}
			if s.Path != db.PathRollup || s.PercentileMethod != db.PercentileHistogram {
				t.Fatalf("%v access=%v: path=%s method=%s", window, accessOnly, s.Path, s.PercentileMethod)
			}
			ref := rawStatsFor(t, d, f.From, f.To, accessOnly)
			if s.Total != ref.total {
				t.Fatalf("%v access=%v: total %d, rows %d", window, accessOnly, s.Total, ref.total)
			}
			for k, n := range ref.classes {
				if s.ByStatusClass[k] != n {
					t.Fatalf("%v access=%v: class %s = %d, rows %d", window, accessOnly, k, s.ByStatusClass[k], n)
				}
			}
			if len(s.ByStatusClass) != len(ref.classes) {
				t.Fatalf("%v access=%v: classes %v vs %v", window, accessOnly, s.ByStatusClass, ref.classes)
			}
			for k, n := range ref.sources {
				if s.BySource[k] != n {
					t.Fatalf("%v access=%v: source %s = %d, rows %d", window, accessOnly, k, s.BySource[k], n)
				}
			}
			if len(s.BySource) != len(ref.sources) {
				t.Fatalf("%v access=%v: sources %v vs %v", window, accessOnly, s.BySource, ref.sources)
			}
			if len(s.TopHosts) != len(ref.hosts) {
				t.Fatalf("%v access=%v: top hosts %v vs %v", window, accessOnly, s.TopHosts, ref.hosts)
			}
			for _, p := range s.TopHosts {
				if ref.hosts[p.Label] != p.Count {
					t.Fatalf("%v access=%v: host %s = %d, rows %d", window, accessOnly, p.Label, p.Count, ref.hosts[p.Label])
				}
			}
			if len(s.TopPaths) != 5 {
				t.Fatalf("%v access=%v: top paths %v", window, accessOnly, s.TopPaths)
			}
			for _, p := range s.TopPaths {
				if ref.paths[p.Label] != p.Count {
					t.Fatalf("%v access=%v: path %s = %d, rows %d", window, accessOnly, p.Label, p.Count, ref.paths[p.Label])
				}
			}
			if s.AvgDurationMs != ref.hist.Avg() || s.P95DurationMs != ref.hist.Percentile(95) {
				t.Fatalf("%v access=%v: avg/p95 %d/%d, rows %d/%d", window, accessOnly, s.AvgDurationMs, s.P95DurationMs, ref.hist.Avg(), ref.hist.Percentile(95))
			}
		}
	}
	// Inside the hour in progress: the exact row path.
	s, err := db.ComputeStats(ctx, d, db.LogFilter{From: now.Add(-15 * time.Minute), To: now})
	if err != nil {
		t.Fatal(err)
	}
	if s.Path != db.PathRows || s.PercentileMethod != db.PercentileExact {
		t.Fatalf("15 m: path=%s method=%s", s.Path, s.PercentileMethod)
	}
}

// TestTimeseriesRollupEqualsRows: hourly buckets stitched from the
// rollup and the edges equal the per-hour row counts.
func TestTimeseriesRollupEqualsRows(t *testing.T) {
	d := dbtest.Open(t)
	ctx := context.Background()
	h1 := dbtest.InsertHost(t, d, "one.example.com")
	h2 := dbtest.InsertHost(t, d, "two.example.com")
	now := time.Date(2026, 9, 27, 10, 37, 0, 0, time.UTC)
	floor := now.Truncate(time.Hour)
	seedLogHours(t, d, h1, h2, floor.Add(-3*24*time.Hour), floor.Add(time.Hour))
	for h := floor.Add(-3 * 24 * time.Hour); h.Before(floor); h = h.Add(time.Hour) {
		if _, err := db.FillRollupHour(ctx, d, h); err != nil {
			t.Fatal(err)
		}
	}
	for _, accessOnly := range []bool{false, true} {
		f := db.LogFilter{From: now.Add(-48*time.Hour - 20*time.Minute), To: now}
		if accessOnly {
			f.Sources = []models.LogSource{models.LogCaddyAccess}
		}
		pts, path, err := db.ComputeTimeseriesPath(ctx, d, f, 3600)
		if err != nil {
			t.Fatal(err)
		}
		if path != db.PathRollup {
			t.Fatalf("path = %s", path)
		}
		where := `timestamp >= ? AND timestamp <= ?`
		if accessOnly {
			where += ` AND source = 'caddy_access'`
		}
		rows, err := d.Query(`SELECT substr(timestamp, 1, 13), COUNT(*), SUM(status BETWEEN 200 AND 299), SUM(status BETWEEN 500 AND 599) FROM log_entries WHERE `+where+` GROUP BY 1`, f.From, f.To)
		if err != nil {
			t.Fatal(err)
		}
		type ref struct{ total, c2, c5 int }
		want := map[string]ref{}
		for rows.Next() {
			var h string
			var r ref
			if err := rows.Scan(&h, &r.total, &r.c2, &r.c5); err != nil {
				t.Fatal(err)
			}
			want[h] = r
		}
		rows.Close()
		if len(pts) != len(want) {
			t.Fatalf("access=%v: %d buckets, rows %d", accessOnly, len(pts), len(want))
		}
		for _, b := range pts {
			r, ok := want[b.Timestamp.Format("2006-01-02 15")]
			if !ok || b.Total != r.total || b.Class2xx != r.c2 || b.Class5xx != r.c5 {
				t.Fatalf("access=%v: bucket %s = %+v, rows %+v", accessOnly, b.Timestamp, b, r)
			}
			if b.Other != b.Total-b.Class2xx-b.Class3xx-b.Class4xx-b.Class5xx {
				t.Fatalf("other mismatch %+v", b)
			}
		}
	}
}

// TestStatsRollupPlans pins the edge statements through the driver on
// the real schema: index searches, no table scan.
func TestStatsRollupPlans(t *testing.T) {
	d := dbtest.Open(t)
	from, to := time.Now().Add(-2*time.Hour), time.Now()
	head := db.Edge{From: from, To: to}
	live := db.Edge{From: from, To: to, Inclusive: true}
	cases := []struct {
		name  string
		sql   string
		args  []any
		index string
	}{
		{"stats rows all", db.EdgeSQLForTest("stats rows", head, false), []any{from, to}, "idx_log_entries_timestamp"},
		{"stats rows access", db.EdgeSQLForTest("stats rows", live, true), []any{from, to}, "idx_log_entries_source_ts"},
		{"series rows all", db.EdgeSQLForTest("series rows", live, false), []any{from, to}, "idx_log_entries_timestamp"},
		{"series rows access", db.EdgeSQLForTest("series rows", head, true), []any{from, to}, "idx_log_entries_source_ts"},
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
			if !strings.Contains(joined, "INDEX "+c.index) {
				t.Fatalf("plan must use %s, got: %s", c.index, joined)
			}
			for _, p := range plan {
				if strings.HasPrefix(p, "SCAN") {
					t.Fatalf("plan must not SCAN, got: %s", joined)
				}
			}
		})
	}
}

// The three v1.3.38.4 cases, on the real schema: with no rollup hour
// the long window takes the covering-index fallback, the short window
// the exact rows.
func TestComputeStatsLongWindowFallback(t *testing.T) {
	d := dbtest.Open(t)
	ctx := context.Background()
	h1 := dbtest.InsertHost(t, d, "a.example.com")
	h2 := dbtest.InsertHost(t, d, "b.example.com")
	now := time.Now().UTC()
	old := now.Add(-5 * 24 * time.Hour)
	recent := now.Add(-2 * time.Hour)
	mk := func(ts time.Time, host int64, dom string, status, dur int, path string) models.LogEntry {
		return models.LogEntry{Timestamp: ts, Source: models.LogCaddyAccess, HostID: hostPtr(host), HostDomain: dom, Status: status, DurationMs: dur, Path: path}
	}
	if err := db.InsertLogBatch(ctx, d, []models.LogEntry{
		mk(old, h1, "a.example.com", 200, 100, "/old"), mk(old, h1, "a.example.com", 200, 100, "/old"),
		mk(old, h1, "a.example.com", 404, 100, "/old"), mk(old, h1, "a.example.com", 503, 100, "/old"),
		{Timestamp: old, Source: models.LogCaddyError, Level: "error"},
		mk(recent, h2, "b.example.com", 200, 10, "/new"), mk(recent, h2, "b.example.com", 302, 30, "/new"),
	}); err != nil {
		t.Fatal(err)
	}
	s, err := db.ComputeStats(ctx, d, db.LogFilter{From: now.Add(-7 * 24 * time.Hour), To: now})
	if err != nil {
		t.Fatal(err)
	}
	if s.Path != db.PathRows || s.PercentileMethod != db.PercentileSample || s.Total != 7 || s.ByStatusClass["2xx"] != 3 || s.ByStatusClass["other"] != 1 {
		t.Fatalf("fallback: %+v", s)
	}
	s, err = db.ComputeStats(ctx, d, db.LogFilter{From: now.Add(-3 * time.Hour), To: now})
	if err != nil {
		t.Fatal(err)
	}
	if s.Path != db.PathRows || s.PercentileMethod != db.PercentileExact || s.Total != 2 {
		t.Fatalf("short window: %+v", s)
	}
	pts, path, err := db.ComputeTimeseriesPath(ctx, d, db.LogFilter{From: now.Add(-7 * 24 * time.Hour), To: now}, 3600)
	if err != nil {
		t.Fatal(err)
	}
	if path != db.PathRows || len(pts) != 2 || pts[0].Total != 5 || pts[0].Other != 1 || pts[1].Total != 2 {
		t.Fatalf("timeseries fallback: path=%s %+v", path, pts)
	}
}
