package db_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/db/dbtest"
	"github.com/cmos486/argos-edge/backend/internal/models"
)

// TestRollupSpanFor pins the window split against what the rollup
// holds (v1.3.42.3).
func TestRollupSpanFor(t *testing.T) {
	d := dbtest.Open(t)
	ctx := context.Background()
	h1 := dbtest.InsertHost(t, d, "one.example.com")
	base := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)

	// No rollup rows: the closed span is empty, everything is live.
	s, err := db.RollupSpanFor(ctx, d, base.Add(-3*time.Hour), base.Add(30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if s.HasClosed() || s.HasHead() || !s.HasLive() {
		t.Fatalf("empty rollup: span = %+v", s)
	}

	// Rows in hours 07, 08, 09 (closed) and 10 (in progress); fill 07-09.
	for h := -3; h <= 0; h++ {
		if err := db.InsertLogBatch(ctx, d, rowsFor(base.Add(time.Duration(h)*time.Hour), h1, h1)); err != nil {
			t.Fatal(err)
		}
	}
	for h := -3; h < 0; h++ {
		if _, err := db.FillRollupHour(ctx, d, base.Add(time.Duration(h)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name       string
		from, to   time.Time
		closedFrom time.Time
		closedTo   time.Time
		head, live bool
	}{
		{"whole window inside the rollup", base.Add(-3 * time.Hour), base.Add(-1 * time.Hour), base.Add(-3 * time.Hour), base.Add(-1 * time.Hour), false, false},
		{"head edge, closed, live tail", base.Add(-2*time.Hour - 20*time.Minute), base.Add(25 * time.Minute), base.Add(-2 * time.Hour), base, true, true},
		{"window before the rollup starts", base.Add(-6 * time.Hour), base.Add(-1 * time.Hour), base.Add(-3 * time.Hour), base.Add(-1 * time.Hour), true, false},
		{"window inside the hour in progress", base.Add(5 * time.Minute), base.Add(25 * time.Minute), time.Time{}, time.Time{}, false, true},
		{"window ending inside a closed hour", base.Add(-3 * time.Hour), base.Add(-90 * time.Minute), base.Add(-3 * time.Hour), base.Add(-2 * time.Hour), false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := db.RollupSpanFor(ctx, d, c.from, c.to)
			if err != nil {
				t.Fatal(err)
			}
			if c.closedFrom.IsZero() {
				if s.HasClosed() {
					t.Fatalf("expected no closed span, got %+v", s)
				}
			} else if !s.ClosedFrom.Equal(c.closedFrom) || !s.ClosedTo.Equal(c.closedTo) {
				t.Fatalf("closed = [%s, %s), want [%s, %s)", s.ClosedFrom, s.ClosedTo, c.closedFrom, c.closedTo)
			}
			if s.HasHead() != c.head || s.HasLive() != c.live {
				t.Fatalf("head=%v live=%v, want %v %v (%+v)", s.HasHead(), s.HasLive(), c.head, c.live, s)
			}
		})
	}
}

// TestReadRollupHoursAndPaths: the reader returns what the fill wrote,
// with the source and host filters, and the merged histogram gives
// the documented percentiles.
func TestReadRollupHoursAndPaths(t *testing.T) {
	d := dbtest.Open(t)
	ctx := context.Background()
	h1 := dbtest.InsertHost(t, d, "one.example.com")
	h2 := dbtest.InsertHost(t, d, "two.example.com")
	hour := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)
	for h := 0; h < 2; h++ {
		if err := db.InsertLogBatch(ctx, d, rowsFor(hour.Add(time.Duration(h)*time.Hour), h1, h2)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.FillRollupHour(ctx, d, hour.Add(time.Duration(h)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	all, err := db.ReadRollupHours(ctx, d, hour, hour.Add(2*time.Hour), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	var req, bytes int64
	for _, r := range all {
		req += r.Requests
		bytes += r.BytesOut
	}
	if len(all) != 12 || req != 18 || bytes != 2*1361 {
		t.Fatalf("all rows: n=%d requests=%d bytes=%d, want 12 / 18 / 2722", len(all), req, bytes)
	}
	access, err := db.ReadRollupHours(ctx, d, hour, hour.Add(2*time.Hour), string(models.LogCaddyAccess), 0)
	if err != nil {
		t.Fatal(err)
	}
	var hist db.Hist
	req = 0
	for _, r := range access {
		if r.Source != string(models.LogCaddyAccess) {
			t.Fatalf("source filter leaked %s", r.Source)
		}
		req += r.Requests
		hist.AddRow(r)
	}
	if req != 16 {
		t.Fatalf("access requests = %d, want 16", req)
	}
	// 16 durations: 10,20,30,40,2000,60,700,5 twice. Sorted: 5,5,10,10,20,20,30,30,40,40,60,60,700,700,2000,2000.
	// p50 rank 8 -> 30 -> edge 50; p95 rank 16 -> 2000 -> edge 2500; avg = 2865*2/16 = 358.
	if got := hist.Percentile(50); got != 50 {
		t.Fatalf("p50 = %d, want 50", got)
	}
	if got := hist.Percentile(95); got != 2500 {
		t.Fatalf("p95 = %d, want 2500", got)
	}
	if got := hist.Avg(); got != 358 {
		t.Fatalf("avg = %d, want 358", got)
	}
	if hist.N != 16 || hist.Max != 2000 {
		t.Fatalf("hist n=%d max=%d", hist.N, hist.Max)
	}
	// Live rows merge into the same histogram: one 9,000 ms row moves p99
	// into the open bucket, reported as the 5,000 edge, never the max.
	hist.AddDuration(9000)
	if got := hist.Percentile(99); got != 5000 {
		t.Fatalf("p99 with a live 9000 ms row = %d, want 5000 (the open bucket edge)", got)
	}
	if hist.Max != 9000 {
		t.Fatalf("max = %d, want 9000 (tracked, not reported)", hist.Max)
	}
	// Host filter.
	host2, err := db.ReadRollupHours(ctx, d, hour, hour.Add(2*time.Hour), string(models.LogCaddyAccess), h2)
	if err != nil {
		t.Fatal(err)
	}
	req = 0
	for _, r := range host2 {
		req += r.Requests
	}
	if req != 4 {
		t.Fatalf("host 2 requests = %d, want 4", req)
	}
	// Paths summed over both hours.
	paths, err := db.ReadRollupPaths(ctx, d, hour, hour.Add(2*time.Hour), 0)
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]int64{}
	for _, p := range paths {
		byPath[p.Path] += p.Requests
	}
	if byPath["/a"] != 4 || byPath["/c"] != 4 || byPath["/nohost"] != 2 {
		t.Fatalf("paths = %v", byPath)
	}
	paths, err = db.ReadRollupPaths(ctx, d, hour, hour.Add(2*time.Hour), h1)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		if p.HostID != h1 {
			t.Fatalf("host filter leaked host %d", p.HostID)
		}
	}
}

// TestRollupReadPlans pins the planner through the Go driver on the
// real schema (strike-14 rule): the reads must search the rollup
// indexes, never scan the tables.
func TestRollupReadPlans(t *testing.T) {
	d := dbtest.Open(t)
	from, to := time.Now().Add(-7*24*time.Hour), time.Now()
	cases := []struct {
		name, sql string
		args      []any
		index     string
	}{
		{"hours by source", db.RollupReadBySourceSQLForTest(), []any{"caddy_access", from, to}, "USING INDEX idx_log_hourly_source_hour"},
		{"hours all sources", db.RollupReadSQLForTest(), []any{from, to}, "USING INDEX sqlite_autoindex_log_hourly_1"},
		{"paths", db.RollupReadPathsSQLForTest() + ` GROUP BY host_id, path`, []any{from, to}, "USING INDEX idx_log_hourly_paths_hour"},
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
			if !strings.Contains(joined, c.index) {
				t.Fatalf("plan must contain %q, got: %s", c.index, joined)
			}
			for _, p := range plan {
				if strings.HasPrefix(p, "SCAN") {
					t.Fatalf("plan must not SCAN, got: %s", joined)
				}
			}
		})
	}
}

// TestHistOpenBucketEdge pins v1.3.42.3.1: a rank that falls in the
// open bucket above 5,000 ms reports the 5,000 edge, whatever the
// merged maximum is. On prod the maximum was a websocket row of
// 457,244,622 ms (5.3 days) and ten 7d p99 points carried it.
func TestHistOpenBucketEdge(t *testing.T) {
	// 100 rows: 97 at 100 ms, 3 above 5 s. p95 rank 95 -> 100 ms bucket;
	// p99 rank 99 -> open bucket.
	var h db.Hist
	for i := 0; i < 97; i++ {
		h.AddDuration(100)
	}
	h.AddDuration(6000)
	h.AddDuration(70000)
	h.AddDuration(457244622)
	if h.N != 100 || h.Max != 457244622 || h.B[7] != 3 {
		t.Fatalf("n=%d max=%d open=%d", h.N, h.Max, h.B[7])
	}
	if got := h.Percentile(95); got != 100 {
		t.Fatalf("p95 = %d, want 100", got)
	}
	if got := h.Percentile(99); got != 5000 {
		t.Fatalf("p99 = %d, want 5000 (open bucket edge), max must not leak", got)
	}
	// Every rank in the open bucket: all three percentiles are the edge.
	var all db.Hist
	for i := 0; i < 10; i++ {
		all.AddDuration(457244622)
	}
	for _, p := range []int{50, 95, 99} {
		if got := all.Percentile(p); got != 5000 {
			t.Fatalf("p%d with every row above 5 s = %d, want 5000", p, got)
		}
	}
	// A rollup row whose only requests sit in the open bucket behaves the same.
	var row db.Hist
	row.AddRow(db.RollupHourRow{Requests: 4, DurSumMs: 4 * 457244622, DurMaxMs: 457244622, Hist: [8]int64{0, 0, 0, 0, 0, 0, 0, 4}})
	if got := row.Percentile(99); got != 5000 || row.Max != 457244622 {
		t.Fatalf("rollup-only open bucket: p99 = %d max = %d, want 5000 and 457244622", got, row.Max)
	}
}
