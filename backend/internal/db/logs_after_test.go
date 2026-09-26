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

// TestListLogEntriesAfterWalksEveryRowOnce: keyset pages cover the
// match set exactly once in (timestamp, id) order, including rows
// that share a timestamp, and the filter still applies.
func TestListLogEntriesAfterWalksEveryRowOnce(t *testing.T) {
	d := dbtest.Open(t)
	ctx := context.Background()
	base := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	var rows []models.LogEntry
	for i := 0; i < 25; i++ {
		src := models.LogCaddyAccess
		if i%5 == 0 {
			src = models.LogCaddyError
		}
		// four rows per second so timestamps repeat
		rows = append(rows, models.LogEntry{Timestamp: base.Add(time.Duration(i/4) * time.Second), Source: src, Path: "/p"})
	}
	if err := db.InsertLogBatch(ctx, d, rows); err != nil {
		t.Fatal(err)
	}
	f := db.LogFilter{From: base, Sources: []models.LogSource{models.LogCaddyAccess}}
	var got []int64
	var afterTS time.Time
	var afterID int64
	for {
		page, err := db.ListLogEntriesAfter(ctx, d, f, afterTS, afterID, 3)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		for _, e := range page {
			got = append(got, e.ID)
		}
		last := page[len(page)-1]
		afterTS, afterID = last.Timestamp, last.ID
	}
	want := dbtest.Count(t, d, "log_entries", "source = 'caddy_access'")
	if len(got) != want {
		t.Fatalf("walked %d rows, want %d", len(got), want)
	}
	seen := map[int64]bool{}
	for i, id := range got {
		if seen[id] {
			t.Fatalf("row %d visited twice", id)
		}
		seen[id] = true
		if i > 0 && id <= got[i-1] {
			t.Fatalf("ids not ascending at %d: %v", i, got)
		}
	}
}

// TestListLogEntriesAfterPlan: the cursor is a range on the timestamp
// index (both bounds), not a scan from the oldest row.
func TestListLogEntriesAfterPlan(t *testing.T) {
	d := dbtest.Open(t)
	q := `EXPLAIN QUERY PLAN SELECT id FROM log_entries WHERE timestamp >= ? AND source IN (?) AND timestamp >= ? AND NOT (timestamp = ? AND id <= ?) ORDER BY timestamp ASC, id ASC LIMIT ?`
	cur := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	rows, err := d.Query(q, cur, "caddy_access", cur, cur, int64(0), 2000)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var a, b, c int
		var s string
		_ = rows.Scan(&a, &b, &c, &s)
		plan = append(plan, s)
	}
	p := strings.Join(plan, " | ")
	if !strings.Contains(p, "idx_log_entries_source_ts") || !strings.Contains(p, "timestamp>?") {
		t.Fatalf("plan is not a range on idx_log_entries_source_ts: %s", p)
	}
}
