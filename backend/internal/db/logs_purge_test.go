package db_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/db/dbtest"
)

// purgeDB is the real schema through dbtest (v1.3.40.1; the hand-made
// two-column table is gone).
func purgeDB(t *testing.T) *sql.DB {
	t.Helper()
	return dbtest.Open(t)
}

func seedRows(t *testing.T, d *sql.DB, n int, from time.Time, step time.Duration) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := d.Exec(`INSERT INTO log_entries (timestamp, source) VALUES (?, 'caddy_access')`, from.Add(time.Duration(i)*step).UTC()); err != nil {
			t.Fatal(err)
		}
	}
}

func count(t *testing.T, d *sql.DB) int {
	t.Helper()
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM log_entries`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPurgeOldBatchedByCapRemovesOldestInBatches(t *testing.T) {
	d := purgeDB(t)
	now := time.Now().UTC()
	seedRows(t, d, 23, now.Add(-23*time.Minute), time.Minute)                // ids 1..23, oldest first
	removed, err := db.PurgeOldBatched(context.Background(), d, 0, 10, 4, 0) // over by 13, batches of 4
	if err != nil {
		t.Fatal(err)
	}
	if removed != 13 || count(t, d) != 10 {
		t.Fatalf("want 13 removed / 10 left, got %d / %d", removed, count(t, d))
	}
	var minID int
	if err := d.QueryRow(`SELECT MIN(id) FROM log_entries`).Scan(&minID); err != nil {
		t.Fatal(err)
	}
	if minID != 14 {
		t.Fatalf("oldest rows must go first: want min id 14, got %d", minID)
	}
}

func TestPurgeOldBatchedByAgeThenCap(t *testing.T) {
	d := purgeDB(t)
	now := time.Now().UTC()
	seedRows(t, d, 5, now.Add(-40*24*time.Hour), time.Minute) // older than 30 d
	seedRows(t, d, 12, now.Add(-time.Hour), time.Minute)      // recent
	removed, err := db.PurgeOldBatched(context.Background(), d, 30, 10, 3, 0)
	if err != nil {
		t.Fatal(err)
	}
	// 5 by age, then 12 > 10 -> 2 more by cap.
	if removed != 7 || count(t, d) != 10 {
		t.Fatalf("want 7 removed / 10 left, got %d / %d", removed, count(t, d))
	}
}

func TestPurgeOldBatchedNothingToDo(t *testing.T) {
	d := purgeDB(t)
	seedRows(t, d, 3, time.Now().UTC().Add(-time.Hour), time.Minute)
	removed, err := db.PurgeOldBatched(context.Background(), d, 30, 10, 2, 0)
	if err != nil || removed != 0 || count(t, d) != 3 {
		t.Fatalf("want nothing removed, got removed=%d err=%v left=%d", removed, err, count(t, d))
	}
}

func TestPurgeOldBatchedHonoursCancelledContext(t *testing.T) {
	d := purgeDB(t)
	seedRows(t, d, 30, time.Now().UTC().Add(-30*time.Minute), time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// A cancelled context stops the purge before it deletes anything;
	// the pause between batches selects on the same ctx.
	removed, err := db.PurgeOldBatched(ctx, d, 0, 1, 5, 50*time.Millisecond)
	if err == nil || removed != 0 || count(t, d) != 30 {
		t.Fatalf("want ctx error and no deletions, got removed=%d err=%v left=%d", removed, err, count(t, d))
	}
}
