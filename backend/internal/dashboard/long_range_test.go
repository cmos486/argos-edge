package dashboard

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/db/dbtest"
)

// The dashboard tests run on the real schema through dbtest
// (v1.3.42.3; the hand-made table of v1.3.38.4 was a strike-12 shape).

func insertAccess(t *testing.T, d *sql.DB, ts time.Time, hostID int64, domain string, status, durMs, size int, path string) {
	t.Helper()
	var host any = hostID
	if hostID == 0 {
		host = nil
	}
	if _, err := d.Exec(`INSERT INTO log_entries (timestamp, source, host_id, host_domain, status, duration_ms, size_bytes, path)
		VALUES (?, 'caddy_access', ?, ?, ?, ?, ?, ?)`, ts.UTC(), host, domain, status, durMs, size, path); err != nil {
		t.Fatal(err)
	}
}

// seedTraffic writes deterministic access rows for every hour in
// [start, end): two hosts, one no-host row, five status classes,
// durations across the histogram buckets. Returns the raw row count.
func seedTraffic(t *testing.T, d *sql.DB, h1, h2 int64, start, end time.Time) int {
	t.Helper()
	n := 0
	i := 0
	for h := start; h.Before(end); h = h.Add(time.Hour) {
		i++
		rows := []struct {
			off    time.Duration
			host   int64
			dom    string
			status int
			dur    int
			size   int
			path   string
		}{
			{3 * time.Minute, h1, "one.example.com", 200, 10 + i%40, 100, "/a"},
			{17 * time.Minute, h1, "one.example.com", 200, 120, 100, "/a"},
			{22 * time.Minute, h1, "one.example.com", 301, 30, 10, "/r"},
			{31 * time.Minute, h1, "one.example.com", 403, 45, 50, "/x"},
			{44 * time.Minute, h1, "one.example.com", 429, 2600 + i, 10, "/y"},
			{47 * time.Minute, h2, "two.example.com", 200, 60, 1000, "/c"},
			{52 * time.Minute, h2, "two.example.com", 500, 700, 0, "/c"},
			{58 * time.Minute, h2, "two.example.com", 200, 6000, 20, "/slow"},
			{59 * time.Minute, 0, "", 200, 5, 1, "/nohost"},
		}
		for _, r := range rows {
			insertAccess(t, d, h.Add(r.off), r.host, r.dom, r.status, r.dur, r.size, r.path)
			n++
		}
	}
	return n
}

func fillHours(t *testing.T, d *sql.DB, start, end time.Time) {
	t.Helper()
	for h := start; h.Before(end); h = h.Add(time.Hour) {
		if _, err := db.FillRollupHour(context.Background(), d, h); err != nil {
			t.Fatal(err)
		}
	}
}

// rawHists rebuilds the per-bucket duration histogram from the rows,
// the reference for the stitched response times.
func rawHists(t *testing.T, d *sql.DB, from, to time.Time, g time.Duration, hostID int64) map[int64]*db.Hist {
	t.Helper()
	q := `SELECT timestamp, duration_ms FROM log_entries WHERE source = 'caddy_access' AND timestamp BETWEEN ? AND ?`
	args := []any{from, to}
	if hostID > 0 {
		q += ` AND host_id = ?`
		args = append(args, hostID)
	}
	rows, err := d.Query(q, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[int64]*db.Hist{}
	for rows.Next() {
		var ts time.Time
		var dur int
		if err := rows.Scan(&ts, &dur); err != nil {
			t.Fatal(err)
		}
		k := ts.Truncate(g).Unix()
		if out[k] == nil {
			out[k] = &db.Hist{}
		}
		out[k].AddDuration(dur)
	}
	return out
}

// TestLongRangePlans pins the planner through the Go driver on the
// real schema (strike-14 rule): the 15 min class series must be a
// covering scan of the status index, the edge rows a search of the
// source index; neither may scan the table.
func TestLongRangePlans(t *testing.T) {
	d := dbtest.Open(t)
	from, to := time.Now().Add(-24*time.Hour), time.Now()
	cases := []struct {
		name  string
		sql   string
		args  []any
		want  string
		cover bool
	}{
		{"class times 2xx", classTimesSQL, []any{200, 299, from, to}, "COVERING INDEX idx_log_entries_status_ts", true},
		{"class times 5xx", classTimesSQL, []any{500, 599, from, to}, "COVERING INDEX idx_log_entries_status_ts", true},
		{"edge rows", edgeRowsSQL + `timestamp < ?`, []any{from, to}, "USING INDEX idx_log_entries_source_ts", false},
		{"edge rows with host", edgeRowsSQL + `timestamp <= ? AND host_id = ?`, []any{from, to, 1}, "USING INDEX idx_log_entries_source_ts", false},
		{"top hosts index-only", topHostsByIDSQL, []any{from, to}, "COVERING INDEX idx_log_entries_host_ts", true},
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
			if !strings.Contains(joined, c.want) {
				t.Fatalf("plan must contain %q, got: %s", c.want, joined)
			}
			for _, p := range plan {
				if strings.HasPrefix(p, "SCAN") {
					t.Fatalf("plan must not SCAN the table, got: %s", joined)
				}
			}
		})
	}
}

// TestTrafficStitchedEqualsRows: for 24 h, 7 d and 30 d, with and
// without a host filter, the stitched result (rollup for the closed
// hours, rows for the edges) equals the row computation over the same
// window for every count, byte and sum (tolerance 0), and the
// histogram percentiles equal the ones rebuilt from the raw durations.
func TestTrafficStitchedEqualsRows(t *testing.T) {
	d := dbtest.Open(t)
	h1 := dbtest.InsertHost(t, d, "one.example.com")
	h2 := dbtest.InsertHost(t, d, "two.example.com")
	now := time.Date(2026, 9, 27, 10, 37, 0, 0, time.UTC)
	floor := now.Truncate(time.Hour)
	start := floor.Add(-8 * 24 * time.Hour)
	seedTraffic(t, d, h1, h2, start, floor.Add(time.Hour)) // includes the hour in progress
	fillHours(t, d, start, floor)                          // every closed hour; the live hour stays raw
	q := &Queries{DB: d}

	cases := []struct {
		name   string
		window time.Duration
		g      time.Duration
		host   int64
	}{
		{"24h all hosts", 24 * time.Hour, 15 * time.Minute, 0},
		{"24h host 1", 24 * time.Hour, 15 * time.Minute, h1},
		{"7d all hosts", 7 * 24 * time.Hour, time.Hour, 0},
		{"7d host 2", 7 * 24 * time.Hour, time.Hour, h2},
		{"30d all hosts", 30 * 24 * time.Hour, 6 * time.Hour, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			from := now.Add(-c.window).Truncate(c.g)
			got, err := q.Traffic(context.Background(), from, now, c.g, c.host)
			if err != nil {
				t.Fatal(err)
			}
			if got.SourcePath() != PathRollup || got.PercentileMethod != PercentileHistogram {
				t.Fatalf("path=%s method=%s, want rollup / histogram", got.SourcePath(), got.PercentileMethod)
			}
			want, err := q.trafficRows(context.Background(), from, now, c.g, c.host, from, now)
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Timeseries) != len(want.Timeseries) {
				t.Fatalf("series length %d, want %d", len(got.Timeseries), len(want.Timeseries))
			}
			for i := range want.Timeseries {
				if got.Timeseries[i] != want.Timeseries[i] {
					t.Fatalf("bucket %d: got %+v, want %+v", i, got.Timeseries[i], want.Timeseries[i])
				}
			}
			if got.BandwidthOut != want.BandwidthOut {
				t.Fatalf("bandwidth %d, want %d", got.BandwidthOut, want.BandwidthOut)
			}
			if len(got.TopHosts) != len(want.TopHosts) {
				t.Fatalf("top hosts %+v, want %+v", got.TopHosts, want.TopHosts)
			}
			for i := range want.TopHosts {
				if got.TopHosts[i] != want.TopHosts[i] {
					t.Fatalf("top host %d: %+v, want %+v", i, got.TopHosts[i], want.TopHosts[i])
				}
			}
			wantPaths := map[string]int64{}
			for _, p := range want.TopPaths {
				wantPaths[p.HostDomain+" "+p.Path] = p.Count
			}
			gotPaths := map[string]int64{}
			for _, p := range got.TopPaths {
				gotPaths[p.HostDomain+" "+p.Path] = p.Count
			}
			if len(gotPaths) != len(wantPaths) {
				t.Fatalf("top paths %v, want %v", gotPaths, wantPaths)
			}
			for k, n := range wantPaths {
				if gotPaths[k] != n {
					t.Fatalf("top path %s = %d, want %d", k, gotPaths[k], n)
				}
			}
			gRT := c.g
			if gRT < time.Hour {
				gRT = time.Hour
			}
			ref := rawHists(t, d, from, now, gRT, c.host)
			if len(got.ResponseTimes) != len(bucketTimes(from, now, gRT)) {
				t.Fatalf("response-time buckets %d", len(got.ResponseTimes))
			}
			for _, b := range got.ResponseTimes {
				h := ref[b.Time.Unix()]
				if h == nil {
					if b.N != 0 {
						t.Fatalf("bucket %s has %d rows, reference none", b.Time, b.N)
					}
					continue
				}
				if int64(b.N) != h.N || b.P50 != h.Percentile(50) || b.P95 != h.Percentile(95) || b.P99 != h.Percentile(99) {
					t.Fatalf("bucket %s: got n=%d p50=%d p95=%d p99=%d, want n=%d %d %d %d", b.Time, b.N, b.P50, b.P95, b.P99, h.N, h.Percentile(50), h.Percentile(95), h.Percentile(99))
				}
			}
		})
	}

	// A window inside the hour in progress stays on the rows and says so.
	got, err := q.Traffic(context.Background(), now.Add(-time.Hour).Truncate(time.Minute), now, time.Minute, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.SourcePath() != PathRows || got.PercentileMethod != PercentileExact {
		t.Fatalf("1 h: path=%s method=%s, want rows / exact", got.SourcePath(), got.PercentileMethod)
	}
}

// TestTrafficFallsBackWithoutRollup: no rollup hours (fresh install)
// means the row path, marked as such.
func TestTrafficFallsBackWithoutRollup(t *testing.T) {
	d := dbtest.Open(t)
	h1 := dbtest.InsertHost(t, d, "one.example.com")
	now := time.Now().UTC()
	insertAccess(t, d, now.Add(-3*time.Hour), h1, "one.example.com", 200, 10, 5, "/")
	q := &Queries{DB: d}
	// 24 h: the rows, every section.
	got, err := q.Traffic(context.Background(), now.Add(-24*time.Hour).Truncate(15*time.Minute), now, 15*time.Minute, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.SourcePath() != PathRows || got.PercentileMethod != PercentileExact || got.BandwidthOut != 5 || got.Note != "" {
		t.Fatalf("24h fallback: path=%s method=%s bandwidth=%d note=%q", got.SourcePath(), got.PercentileMethod, got.BandwidthOut, got.Note)
	}
	// 7 d: index-only series and top hosts, the rest empty with a note.
	got, err = q.Traffic(context.Background(), now.Add(-7*24*time.Hour).Truncate(time.Hour), now, time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	sum := 0
	for _, b := range got.Timeseries {
		sum += b.C2xx
	}
	if got.SourcePath() != PathRows || got.Note == "" || sum != 1 || len(got.TopHosts) != 1 || got.TopHosts[0].Count != 1 || got.BandwidthOut != 0 || len(got.TopPaths) != 0 {
		t.Fatalf("7d fallback: %+v", got)
	}
	if len(got.ResponseTimes) != len(got.Timeseries) {
		t.Fatalf("7d fallback response-time buckets %d vs %d", len(got.ResponseTimes), len(got.Timeseries))
	}
}

// TestOverviewStitchedEqualsRows: the 24 h counters from the rollup
// plus the live hour equal the row counts.
func TestOverviewStitchedEqualsRows(t *testing.T) {
	d := dbtest.Open(t)
	h1 := dbtest.InsertHost(t, d, "one.example.com")
	h2 := dbtest.InsertHost(t, d, "two.example.com")
	now := time.Now().UTC()
	floor := now.Truncate(time.Hour)
	seedTraffic(t, d, h1, h2, floor.Add(-30*time.Hour), floor.Add(time.Hour))
	fillHours(t, d, floor.Add(-30*time.Hour), floor)
	// The live hour's rows may sit after "now" (seeded at fixed minutes):
	// they count on both sides only when before now, so the reference
	// uses the same clock a moment later; rows at minute 59 are excluded
	// on both sides unless the test runs in the last minute of an hour.
	q := &Queries{DB: d}
	o, err := q.Overview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var total, errs, blocked int64
	if err := d.QueryRow(`SELECT COUNT(*), SUM(status >= 500), SUM(status = 403 OR status = 429) FROM log_entries
		WHERE source = 'caddy_access' AND timestamp >= ? AND timestamp <= ?`, now.Add(-24*time.Hour), time.Now().UTC()).Scan(&total, &errs, &blocked); err != nil {
		t.Fatal(err)
	}
	if o.TotalRequests24h != total || o.ErrorRequests24h != errs || o.BlockedRequests24h != blocked {
		t.Fatalf("overview total=%d errors=%d blocked=%d, rows say %d %d %d", o.TotalRequests24h, o.ErrorRequests24h, o.BlockedRequests24h, total, errs, blocked)
	}
	if o.SourcePath() != PathRollup {
		t.Fatalf("path = %s, want rollup", o.SourcePath())
	}
}
