package api

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// wafStatsDB stands up an in-memory SQLite with only the log_entries
// columns wafAuditStatsByHost touches, writing timestamps the way the
// ingestor does (time.Time bound by the modernc driver into a TEXT
// column declared TIMESTAMP).
func wafStatsDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	d.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = d.Close() })
	if _, err := d.Exec(`
		CREATE TABLE log_entries (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TIMESTAMP NOT NULL,
			source TEXT NOT NULL,
			host_id INTEGER,
			waf_severity TEXT NOT NULL DEFAULT ''
		)`); err != nil {
		t.Fatal(err)
	}
	return d
}

func insertWAF(t *testing.T, d *sql.DB, ts time.Time, source string, hostID any, sev string) {
	t.Helper()
	if _, err := d.Exec(`INSERT INTO log_entries (timestamp, source, host_id, waf_severity) VALUES (?,?,?,?)`,
		ts.UTC(), source, hostID, sev); err != nil {
		t.Fatal(err)
	}
}

func TestWafAuditStatsByHost(t *testing.T) {
	d := wafStatsDB(t)
	now := time.Now().UTC()
	cutoff := now.Add(-24 * time.Hour)

	// host 1: two CRITICAL inside 24h, one WARNING inside 24h (not
	// counted), one CRITICAL outside 24h (not counted, but it is not
	// the newest so it does not affect last_triggered either).
	insertWAF(t, d, now.Add(-1*time.Hour), "waf_audit", 1, "CRITICAL")
	insertWAF(t, d, now.Add(-2*time.Hour), "waf_audit", 1, "ERROR")
	insertWAF(t, d, now.Add(-3*time.Hour), "waf_audit", 1, "WARNING")
	insertWAF(t, d, now.Add(-48*time.Hour), "waf_audit", 1, "CRITICAL")
	// host 2: only an old row -> counted 0, last_triggered = that row.
	insertWAF(t, d, now.Add(-30*time.Hour), "waf_audit", 2, "CRITICAL")
	// host 3: only non-waf rows -> absent from the map.
	insertWAF(t, d, now.Add(-1*time.Hour), "caddy_access", 3, "")
	// NULL host_id waf rows are ignored.
	insertWAF(t, d, now.Add(-1*time.Hour), "waf_audit", nil, "CRITICAL")

	got, err := wafAuditStatsByHost(context.Background(), d, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want stats for 2 hosts, got %d: %+v", len(got), got)
	}
	h1 := got[1]
	if h1.blocked24h != 2 {
		t.Errorf("host 1 blocked24h: want 2, got %d", h1.blocked24h)
	}
	if h1.lastTriggered.IsZero() || now.Sub(h1.lastTriggered) > 61*time.Minute || now.Sub(h1.lastTriggered) < 59*time.Minute {
		t.Errorf("host 1 lastTriggered: want ~1h ago, got %v (now %v)", h1.lastTriggered, now)
	}
	h2 := got[2]
	if h2.blocked24h != 0 {
		t.Errorf("host 2 blocked24h: want 0, got %d", h2.blocked24h)
	}
	if h2.lastTriggered.IsZero() {
		t.Errorf("host 2 lastTriggered: want the 30h-old row, got zero")
	}
	if _, ok := got[3]; ok {
		t.Errorf("host 3 must be absent (no waf_audit rows)")
	}
}

func TestSqliteTimeAny(t *testing.T) {
	ref := time.Date(2026, 9, 25, 18, 3, 43, 418462514, time.UTC)
	cases := []struct {
		name string
		in   any
		want time.Time
	}{
		{"time.Time", ref, ref},
		{"modernc text", "2026-09-25 18:03:43.418462514 +0000 UTC", ref},
		{"bytes", []byte("2026-09-25 18:03:43.418462514 +0000 UTC"), ref},
		{"rfc3339", "2026-09-25T18:03:43Z", ref.Truncate(time.Second)},
		{"nil", nil, time.Time{}},
		{"garbage", "yesterday", time.Time{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sqliteTimeAny(c.in); !got.Equal(c.want) {
				t.Errorf("want %v, got %v", c.want, got)
			}
		})
	}
}
