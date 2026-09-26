package db

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func openPurgePolicyDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	d.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = d.Close() })
	if _, err := d.Exec(`CREATE TABLE log_entries (
		id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TIMESTAMP NOT NULL, source TEXT NOT NULL,
		raw TEXT, message TEXT)`); err != nil {
		t.Fatal(err)
	}
	return d
}

func insertPurgeRow(t *testing.T, d *sql.DB, ts time.Time, source, raw string) {
	t.Helper()
	if _, err := d.Exec(`INSERT INTO log_entries (timestamp, source, raw) VALUES (?,?,?)`, ts.UTC(), source, raw); err != nil {
		t.Fatal(err)
	}
}

func countPurgeRows(t *testing.T, d *sql.DB, where string, args ...any) int {
	t.Helper()
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM log_entries WHERE `+where, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPurgeWithPolicyPerSourceDays(t *testing.T) {
	d := openPurgePolicyDB(t)
	now := time.Now().UTC()
	insertPurgeRow(t, d, now.Add(-8*24*time.Hour), "caddy_access", "{}") // access older than 7 d: goes
	insertPurgeRow(t, d, now.Add(-6*24*time.Hour), "caddy_access", "{}") // stays
	insertPurgeRow(t, d, now.Add(-20*24*time.Hour), "caddy_error", "{}") // error 20 d: stays (30 d)
	insertPurgeRow(t, d, now.Add(-40*24*time.Hour), "caddy_error", "{}") // goes
	insertPurgeRow(t, d, now.Add(-80*24*time.Hour), "audit", "{}")       // audit 80 d: stays (90 d)
	insertPurgeRow(t, d, now.Add(-45*24*time.Hour), "other", "{}")       // unlisted: default 30 d -> goes
	insertPurgeRow(t, d, now.Add(-10*24*time.Hour), "other", "{}")       // stays
	res, err := PurgeWithPolicy(context.Background(), d, PurgePolicy{
		SourceDays:  map[string]int{"caddy_access": 7, "caddy_error": 30, "audit": 90},
		DefaultDays: 30,
	}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Removed != 3 {
		t.Fatalf("removed %d, want 3", res.Removed)
	}
	if countPurgeRows(t, d, "1=1") != 4 || countPurgeRows(t, d, "source='audit'") != 1 || countPurgeRows(t, d, "source='other'") != 1 {
		t.Fatalf("survivors wrong")
	}
}

func TestPurgeWithPolicyRawStripWatermark(t *testing.T) {
	d := openPurgePolicyDB(t)
	now := time.Now().UTC()
	insertPurgeRow(t, d, now.Add(-30*time.Hour), "caddy_access", "{\"old\":1}")
	insertPurgeRow(t, d, now.Add(-2*time.Hour), "caddy_access", "{\"new\":1}")
	insertPurgeRow(t, d, now.Add(-30*time.Hour), "caddy_error", "{\"err\":1}") // other source untouched
	p := PurgePolicy{RawSource: "caddy_access", RawAfter: 24 * time.Hour}
	res, err := PurgeWithPolicy(context.Background(), d, p, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.RawStripped != 1 || res.RawWatermark.IsZero() {
		t.Fatalf("strip: %+v", res)
	}
	if countPurgeRows(t, d, "source='caddy_access' AND raw IS NULL") != 1 || countPurgeRows(t, d, "raw IS NOT NULL") != 2 {
		t.Fatalf("raw state wrong")
	}
	// Second run with the watermark: nothing older than the watermark is
	// visited, nothing new aged past 24 h -> 0 stripped, watermark moves.
	p.RawWatermark = res.RawWatermark
	res2, err := PurgeWithPolicy(context.Background(), d, p, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res2.RawStripped != 0 || !res2.RawWatermark.After(p.RawWatermark.Add(-time.Second)) {
		t.Fatalf("second run: %+v", res2)
	}
}

// TestPurgeCapBoundWithManualGaps: the cap check trusts MAX-MIN+1
// only to say "under the cap". Rows deleted from the middle (the
// operator's manual purge) make the bound overestimate; then the
// exact COUNT(*) decides and the cap never removes too much.
func TestPurgeCapBoundWithManualGaps(t *testing.T) {
	d := openPurgePolicyDB(t)
	now := time.Now().UTC()
	for i := 0; i < 10; i++ {
		insertPurgeRow(t, d, now.Add(time.Duration(i)*time.Minute), "caddy_access", "{}")
	}
	// Manual deletion in the middle: ids 3..7 gone -> 5 rows left, bound 10.
	if _, err := d.Exec(`DELETE FROM log_entries WHERE id BETWEEN 3 AND 7`); err != nil {
		t.Fatal(err)
	}
	bound, err := RowCountBound(context.Background(), d)
	if err != nil || bound != 10 {
		t.Fatalf("bound=%d err=%v", bound, err)
	}
	// Cap 6: the bound (10) exceeds it, the exact count (5) does not:
	// nothing may be deleted.
	res, err := PurgeWithPolicy(context.Background(), d, PurgePolicy{MaxEntries: 6}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Removed != 0 || !res.CapCounted || res.CapBound != 10 || countPurgeRows(t, d, "1=1") != 5 {
		t.Fatalf("gap case: %+v rows=%d", res, countPurgeRows(t, d, "1=1"))
	}
	// Cap 3: the exact count (5) exceeds it -> exactly 2 oldest go.
	res, err = PurgeWithPolicy(context.Background(), d, PurgePolicy{MaxEntries: 3}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Removed != 2 || countPurgeRows(t, d, "1=1") != 3 || countPurgeRows(t, d, "id IN (1,2)") != 0 {
		t.Fatalf("over-cap with gaps: %+v", res)
	}
	// Under the bound: no COUNT(*) at all.
	res, err = PurgeWithPolicy(context.Background(), d, PurgePolicy{MaxEntries: 100}, 0, 0)
	if err != nil || res.CapCounted {
		t.Fatalf("bound under the cap must skip COUNT(*): %+v err=%v", res, err)
	}
}
