package logs

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// openRetentionTestDB builds the minimum schema runPurge touches:
// log_entries (the primary retention target), login_attempts
// (auxiliary 24h purge), totp_attempts (wired in the recent Fix #4),
// and settings (retention_days / max_entries lookups).
func openRetentionTestDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	// log_entries carries the full column surface db.PurgeOld references.
	// Only id + timestamp are functionally relevant here; the others are
	// NULLable so the test inserts can keep the payload tiny.
	if _, err := d.Exec(`
		CREATE TABLE log_entries (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TIMESTAMP NOT NULL,
			source TEXT NOT NULL DEFAULT '',
			level TEXT NOT NULL DEFAULT '',
			host_id INTEGER,
			host_domain TEXT DEFAULT '',
			rule_id INTEGER,
			remote_ip TEXT DEFAULT '',
			method TEXT DEFAULT '',
			path TEXT DEFAULT '',
			status INTEGER DEFAULT 0,
			duration_ms INTEGER DEFAULT 0,
			size_bytes INTEGER DEFAULT 0,
			user_agent TEXT DEFAULT '',
			upstream TEXT DEFAULT '',
			message TEXT DEFAULT '',
			raw TEXT DEFAULT '',
			waf_rule_id INTEGER DEFAULT 0,
			waf_rule_message TEXT DEFAULT '',
			waf_severity TEXT DEFAULT '',
			waf_anomaly_score INTEGER DEFAULT 0
		);
		CREATE TABLE login_attempts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			remote_ip TEXT NOT NULL,
			username TEXT NOT NULL,
			success INTEGER NOT NULL DEFAULT 0,
			timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE totp_attempts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			ip TEXT NOT NULL,
			success INTEGER NOT NULL DEFAULT 0,
			attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`); err != nil {
		t.Fatal(err)
	}
	return d
}

// countRows is a terse helper used across every assertion below.
func countRows(t *testing.T, d *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// TestRunPurgeDropsLogEntriesPastRetention seeds 4 entries at various
// ages and asserts runPurge honours the retention_days setting: rows
// older than the cutoff go, rows within stay.
func TestRunPurgeDropsLogEntriesPastRetention(t *testing.T) {
	d := openRetentionTestDB(t)
	ctx := context.Background()
	if _, err := d.Exec(`INSERT INTO settings(key, value) VALUES('logs.retention_days','7')`); err != nil {
		t.Fatal(err)
	}
	// Ages: 30d (drop), 14d (drop), 3d (keep), now (keep).
	now := time.Now().UTC()
	stamps := []time.Time{
		now.AddDate(0, 0, -30),
		now.AddDate(0, 0, -14),
		now.AddDate(0, 0, -3),
		now,
	}
	for _, ts := range stamps {
		if _, err := d.Exec(`INSERT INTO log_entries (timestamp, source) VALUES (?, 'caddy')`, ts); err != nil {
			t.Fatal(err)
		}
	}

	n, err := RunPurgeOnce(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("expected 2 deletes, got %d", n)
	}
	if remaining := countRows(t, d, "log_entries"); remaining != 2 {
		t.Fatalf("expected 2 rows remaining, got %d", remaining)
	}
}

// TestRunPurgeCapEnforced seeds more rows than the max_entries cap
// with retention_days off so only the cap rule runs. The oldest rows
// must go; the newest remain.
func TestRunPurgeCapEnforced(t *testing.T) {
	d := openRetentionTestDB(t)
	ctx := context.Background()
	if _, err := d.Exec(`INSERT INTO settings(key, value) VALUES
		('logs.retention_days','0'),
		('logs.max_entries','3')`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i := 0; i < 6; i++ {
		if _, err := d.Exec(
			`INSERT INTO log_entries (timestamp, source) VALUES (?, 'caddy')`,
			now.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}

	n, err := RunPurgeOnce(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("expected 3 over-cap deletes, got %d", n)
	}
	// The 3 oldest rows are gone; the 3 newest stay. Pick the surviving
	// timestamps and assert they are the last 3 inserted.
	rows, err := d.Query(`SELECT timestamp FROM log_entries ORDER BY timestamp ASC`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var first time.Time
	rows.Next()
	if err := rows.Scan(&first); err != nil {
		t.Fatal(err)
	}
	if first.Before(now.Add(3 * time.Minute)) {
		t.Fatalf("oldest survivor is too old: %v, expected >= %v", first, now.Add(3*time.Minute))
	}
}

// TestRunPurgeDropsStaleLoginAttempts covers the phase-9b in-SQL
// DELETE on login_attempts. The cutoff is hardcoded to 24h in the
// retention loop, so back-date rows to land on either side of it.
func TestRunPurgeDropsStaleLoginAttempts(t *testing.T) {
	d := openRetentionTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	// 2 stale (48h + 25h) and 1 fresh (1h).
	if _, err := d.Exec(
		`INSERT INTO login_attempts (remote_ip, username, success, timestamp) VALUES
			('1.2.3.4','a',0,?), ('1.2.3.4','a',0,?), ('1.2.3.4','a',0,?)`,
		now.Add(-48*time.Hour),
		now.Add(-25*time.Hour),
		now.Add(-1*time.Hour),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := RunPurgeOnce(ctx, d); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, d, "login_attempts"); got != 1 {
		t.Fatalf("stale login_attempts not purged: %d remain, want 1", got)
	}
}

// TestRunPurgeDropsStaleTOTPAttempts verifies Fix #4 wiring:
// PurgeTOTPAttempts is actually called by runPurge. Without the
// wiring this table would grow unbounded.
func TestRunPurgeDropsStaleTOTPAttempts(t *testing.T) {
	d := openRetentionTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := d.Exec(
		`INSERT INTO totp_attempts (user_id, ip, success, attempted_at) VALUES
			(1,'1.2.3.4',0,?), (1,'1.2.3.4',0,?), (1,'1.2.3.4',0,?)`,
		now.Add(-48*time.Hour),
		now.Add(-25*time.Hour),
		now.Add(-30*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := RunPurgeOnce(ctx, d); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, d, "totp_attempts"); got != 1 {
		t.Fatalf("stale totp_attempts not purged: %d remain, want 1", got)
	}
}

// TestRunPurgeDefaultsWhenSettingsMissing: with no settings rows the
// retention loop must not error and should fall back to the 30d /
// 500k defaults encoded in retention.go. Exercise by inserting one
// very old log entry (past the default 30d window) and confirming
// it is swept.
func TestRunPurgeDefaultsWhenSettingsMissing(t *testing.T) {
	d := openRetentionTestDB(t)
	ctx := context.Background()
	old := time.Now().UTC().AddDate(0, 0, -90)
	if _, err := d.Exec(
		`INSERT INTO log_entries (timestamp, source) VALUES (?, 'caddy')`, old,
	); err != nil {
		t.Fatal(err)
	}
	n, err := RunPurgeOnce(ctx, d)
	if err != nil {
		t.Fatalf("purge with empty settings: %v", err)
	}
	if n != 1 {
		t.Fatalf("default 30d retention did not drop a 90d row: deleted %d", n)
	}
}
