package db_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/db/dbtest"
)

// The real schema (migrations 001-033) through dbtest: log_entries.raw
// is NOT NULL with an empty default and source is CHECKed, which the hand-made
// table of v1.3.40.0 did not know (strike 12).
func openPurgePolicyDB(t *testing.T) *sql.DB {
	t.Helper()
	return dbtest.Open(t)
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
	insertPurgeRow(t, d, now.Add(-45*24*time.Hour), "waf_audit", "{}")   // unlisted: default 30 d -> goes
	insertPurgeRow(t, d, now.Add(-10*24*time.Hour), "waf_audit", "{}")   // stays
	res, err := db.PurgeWithPolicy(context.Background(), d, db.PurgePolicy{
		SourceDays:  map[string]int{"caddy_access": 7, "caddy_error": 30, "audit": 90},
		DefaultDays: 30,
	}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Removed != 3 {
		t.Fatalf("removed %d, want 3", res.Removed)
	}
	if countPurgeRows(t, d, "1=1") != 4 || countPurgeRows(t, d, "source='audit'") != 1 || countPurgeRows(t, d, "source='waf_audit'") != 1 {
		t.Fatalf("survivors wrong")
	}
}

func TestPurgeWithPolicyRawStripWatermark(t *testing.T) {
	d := openPurgePolicyDB(t)
	now := time.Now().UTC()
	insertPurgeRow(t, d, now.Add(-30*time.Hour), "caddy_access", "{\"old\":1}")
	insertPurgeRow(t, d, now.Add(-2*time.Hour), "caddy_access", "{\"new\":1}")
	insertPurgeRow(t, d, now.Add(-30*time.Hour), "caddy_error", "{\"err\":1}") // other source untouched
	p := db.PurgePolicy{RawSource: "caddy_access", RawAfter: 24 * time.Hour}
	res, err := db.PurgeWithPolicy(context.Background(), d, p, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.RawStripped != 1 || res.RawWatermark.IsZero() {
		t.Fatalf("strip: %+v", res)
	}
	// The column is NOT NULL DEFAULT '' on the real schema (v1.3.40.0
	// wrote NULL and failed on prod): stripped means empty.
	if countPurgeRows(t, d, "source='caddy_access' AND raw = ''") != 1 || countPurgeRows(t, d, "raw <> ''") != 2 || countPurgeRows(t, d, "raw IS NULL") != 0 {
		t.Fatalf("raw state wrong")
	}
	// Second run with the watermark: nothing older than the watermark is
	// visited, nothing new aged past 24 h -> 0 stripped, watermark moves.
	p.RawWatermark = res.RawWatermark
	res2, err := db.PurgeWithPolicy(context.Background(), d, p, 0, 0)
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
	bound, err := db.RowCountBound(context.Background(), d)
	if err != nil || bound != 10 {
		t.Fatalf("bound=%d err=%v", bound, err)
	}
	// Cap 6: the bound (10) exceeds it, the exact count (5) does not:
	// nothing may be deleted.
	res, err := db.PurgeWithPolicy(context.Background(), d, db.PurgePolicy{MaxEntries: 6}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Removed != 0 || !res.CapCounted || res.CapBound != 10 || countPurgeRows(t, d, "1=1") != 5 {
		t.Fatalf("gap case: %+v rows=%d", res, countPurgeRows(t, d, "1=1"))
	}
	// Cap 3: the exact count (5) exceeds it -> exactly 2 oldest go.
	res, err = db.PurgeWithPolicy(context.Background(), d, db.PurgePolicy{MaxEntries: 3}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Removed != 2 || countPurgeRows(t, d, "1=1") != 3 || countPurgeRows(t, d, "id IN (1,2)") != 0 {
		t.Fatalf("over-cap with gaps: %+v", res)
	}
	// Under the bound: no COUNT(*) at all.
	res, err = db.PurgeWithPolicy(context.Background(), d, db.PurgePolicy{MaxEntries: 100}, 0, 0)
	if err != nil || res.CapCounted {
		t.Fatalf("bound under the cap must skip COUNT(*): %+v err=%v", res, err)
	}
}

// TestRawStripCursorResumesAndSkipsEmptied: the strip walks
// (timestamp, id) in batches, reports progress after each batch, does
// not re-touch rows already emptied, resumes from the watermark after
// a cancelled context, and never touches rows at or past the cutoff.
func TestRawStripCursorResumesAndSkipsEmptied(t *testing.T) {
	d := openPurgePolicyDB(t)
	now := time.Now().UTC()
	// 3,500 old access rows one second apart (older than 24 h), 5 fresh ones.
	for i := 0; i < 3500; i++ {
		insertPurgeRow(t, d, now.Add(-48*time.Hour+time.Duration(i)*time.Second), "caddy_access", "{\"i\":1}")
	}
	for i := 0; i < 5; i++ {
		insertPurgeRow(t, d, now.Add(-time.Hour+time.Duration(i)*time.Second), "caddy_access", "{\"fresh\":1}")
	}
	var marks []time.Time
	p := db.PurgePolicy{RawSource: "caddy_access", RawAfter: 24 * time.Hour, OnRawProgress: func(wm time.Time) { marks = append(marks, wm) }}
	res, err := db.PurgeWithPolicy(context.Background(), d, p, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.RawStripped != 3500 || countPurgeRows(t, d, "raw = ''") != 3500 || countPurgeRows(t, d, "raw <> ''") != 5 {
		t.Fatalf("strip: %+v empty=%d full=%d", res, countPurgeRows(t, d, "raw = ''"), countPurgeRows(t, d, "raw <> ''"))
	}
	// 3,500 / RawStripBatch batches plus the final cutoff mark, increasing.
	if len(marks) < 3500/db.RawStripBatch+1 {
		t.Fatalf("progress marks: %d", len(marks))
	}
	for i := 1; i < len(marks); i++ {
		if marks[i].Before(marks[i-1]) {
			t.Fatalf("watermark went backwards: %v -> %v", marks[i-1], marks[i])
		}
	}
	// A second run from the returned watermark touches nothing.
	p.RawWatermark, p.OnRawProgress = res.RawWatermark, nil
	res2, err := db.PurgeWithPolicy(context.Background(), d, p, 0, 0)
	if err != nil || res2.RawStripped != 0 {
		t.Fatalf("second run: %+v err=%v", res2, err)
	}
}

func TestRawStripCancelledContextKeepsProgress(t *testing.T) {
	d := openPurgePolicyDB(t)
	now := time.Now().UTC()
	for i := 0; i < 2500; i++ {
		insertPurgeRow(t, d, now.Add(-48*time.Hour+time.Duration(i)*time.Second), "caddy_access", "{}")
	}
	ctx, cancel := context.WithCancel(context.Background())
	var last time.Time
	p := db.PurgePolicy{RawSource: "caddy_access", RawAfter: 24 * time.Hour, OnRawProgress: func(wm time.Time) {
		last = wm
		cancel() // cancel after the first batch
	}}
	res, err := db.PurgeWithPolicy(ctx, d, p, 0, time.Millisecond)
	if err == nil || res.RawStripped != db.RawStripBatch || res.RawWatermark.IsZero() || !res.RawWatermark.Equal(last) {
		t.Fatalf("cancelled strip: %+v err=%v last=%v", res, err, last)
	}
	// Resume: the remaining rows, nothing re-touched.
	p.RawWatermark, p.OnRawProgress = res.RawWatermark, nil
	res2, err := db.PurgeWithPolicy(context.Background(), d, p, 0, 0)
	if err != nil || res2.RawStripped != 2500-db.RawStripBatch || countPurgeRows(t, d, "raw <> ''") != 0 {
		t.Fatalf("resume: %+v err=%v left=%d", res2, err, countPurgeRows(t, d, "raw <> ''"))
	}
}
