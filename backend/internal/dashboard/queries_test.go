package dashboard

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db/dbtest"
)

// recentErrorsDB is the real schema through dbtest (v1.3.40.1): the
// (source, timestamp DESC) index the production query is shaped for
// is the one migration 008 creates.
func recentErrorsDB(t *testing.T) *sql.DB {
	t.Helper()
	return dbtest.Open(t)
}

func insertRow(t *testing.T, d *sql.DB, ts time.Time, source, level string, status int, msg string) {
	t.Helper()
	if _, err := d.Exec(`INSERT INTO log_entries (timestamp, source, level, status, message) VALUES (?,?,?,?,?)`,
		ts.UTC(), source, level, status, msg); err != nil {
		t.Fatal(err)
	}
}

func TestRecentErrorsBoundedAndOrdered(t *testing.T) {
	d := recentErrorsDB(t)
	now := time.Now().UTC()

	insertRow(t, d, now.Add(-10*time.Minute), "caddy_error", "error", 0, "e-10m")
	insertRow(t, d, now.Add(-5*time.Minute), "caddy_access", "", 502, "a-5m")
	insertRow(t, d, now.Add(-20*time.Minute), "caddy_error", "warn", 0, "e-20m")
	// Noise that must never appear: info-level error log, 4xx access,
	// and real errors older than 24 h.
	insertRow(t, d, now.Add(-1*time.Minute), "caddy_error", "info", 0, "e-info")
	insertRow(t, d, now.Add(-1*time.Minute), "caddy_access", "", 404, "a-404")
	insertRow(t, d, now.Add(-30*time.Hour), "caddy_error", "error", 0, "e-old")
	insertRow(t, d, now.Add(-30*time.Hour), "caddy_access", "", 500, "a-old")

	q := &Queries{DB: d}
	got, err := q.RecentErrors(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a-5m", "e-10m", "e-20m"}
	if len(got) != len(want) {
		t.Fatalf("want %d rows %v, got %d: %+v", len(want), want, len(got), got)
	}
	for i, w := range want {
		if got[i].Message != w {
			t.Errorf("row %d: want %q, got %q", i, w, got[i].Message)
		}
	}
	if got[0].Source != "caddy_access" || got[1].Level != "error" {
		t.Errorf("source/level not carried through: %+v", got[:2])
	}
}

func TestRecentErrorsLimitAcrossBothSources(t *testing.T) {
	d := recentErrorsDB(t)
	now := time.Now().UTC()
	// 6 access 5xx newer than 6 error-log rows: LIMIT 3 must return the
	// three newest overall, all from the access branch.
	for i := 0; i < 6; i++ {
		insertRow(t, d, now.Add(-time.Duration(i+1)*time.Minute), "caddy_access", "", 500, "a")
		insertRow(t, d, now.Add(-time.Duration(i+10)*time.Minute), "caddy_error", "error", 0, "e")
	}
	q := &Queries{DB: d}
	got, err := q.RecentErrors(context.Background(), 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 rows, got %d", len(got))
	}
	for _, r := range got {
		if r.Message != "a" {
			t.Errorf("want newest access rows only, got %+v", got)
			break
		}
	}
	for i := 1; i < len(got); i++ {
		if got[i].Timestamp.After(got[i-1].Timestamp) {
			t.Errorf("not ordered newest first: %+v", got)
		}
	}
}
