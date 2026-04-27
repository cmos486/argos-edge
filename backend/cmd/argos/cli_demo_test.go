package main

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// newDemoTestDB stands up an in-memory SQLite with the minimal subset
// of the production schema the seed/clear paths touch. Mirrors the
// shape from migrations 002 (hosts), 008 (logs+settings), 010
// (notifications), 028 (whitelist), 029 (country_ban_expansions),
// plus the column ALTERs through migration 028.
func newDemoTestDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	d.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = d.Close() })
	schema := `
		CREATE TABLE target_groups (
		    id INTEGER PRIMARY KEY AUTOINCREMENT,
		    name TEXT NOT NULL UNIQUE,
		    protocol TEXT NOT NULL DEFAULT 'http',
		    verify_tls INTEGER NOT NULL DEFAULT 1,
		    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE targets (
		    id INTEGER PRIMARY KEY AUTOINCREMENT,
		    target_group_id INTEGER NOT NULL REFERENCES target_groups(id) ON DELETE CASCADE,
		    host TEXT NOT NULL,
		    port INTEGER NOT NULL,
		    weight INTEGER NOT NULL DEFAULT 1,
		    enabled INTEGER NOT NULL DEFAULT 1,
		    UNIQUE(target_group_id, host, port)
		);
		CREATE TABLE hosts (
		    id INTEGER PRIMARY KEY AUTOINCREMENT,
		    domain TEXT NOT NULL UNIQUE,
		    target_group_id INTEGER NOT NULL REFERENCES target_groups(id) ON DELETE RESTRICT,
		    tls_mode TEXT NOT NULL DEFAULT 'auto',
		    tls_email TEXT NOT NULL DEFAULT '',
		    enabled INTEGER NOT NULL DEFAULT 1,
		    tls_challenge TEXT NOT NULL DEFAULT 'dns',
		    tls_dns_provider TEXT NOT NULL DEFAULT 'cloudflare',
		    lan_only INTEGER NOT NULL DEFAULT 0,
		    true_detect_mode INTEGER NOT NULL DEFAULT 0,
		    auth_required INTEGER NOT NULL DEFAULT 0,
		    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE security_whitelist (
		    id INTEGER PRIMARY KEY AUTOINCREMENT,
		    scope TEXT NOT NULL,
		    value TEXT NOT NULL,
		    reason TEXT NOT NULL DEFAULT '',
		    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		    UNIQUE(scope, value)
		);
		CREATE TABLE country_ban_expansions (
		    id INTEGER PRIMARY KEY AUTOINCREMENT,
		    country_code TEXT NOT NULL UNIQUE,
		    decision_ids TEXT NOT NULL,
		    cidr_count INTEGER NOT NULL,
		    reason TEXT NOT NULL DEFAULT '',
		    duration TEXT NOT NULL,
		    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		    created_by TEXT NOT NULL,
		    mmdb_version_at_creation TEXT NOT NULL
		);
		CREATE TABLE log_entries (
		    id INTEGER PRIMARY KEY AUTOINCREMENT,
		    timestamp TIMESTAMP NOT NULL,
		    source TEXT NOT NULL,
		    level TEXT NOT NULL DEFAULT '',
		    message TEXT NOT NULL DEFAULT '',
		    raw TEXT NOT NULL DEFAULT ''
		);
		CREATE TABLE settings (
		    key TEXT PRIMARY KEY,
		    value TEXT NOT NULL DEFAULT '',
		    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE notification_channels (
		    id INTEGER PRIMARY KEY AUTOINCREMENT,
		    name TEXT NOT NULL UNIQUE,
		    type TEXT NOT NULL,
		    enabled INTEGER NOT NULL DEFAULT 1,
		    config TEXT NOT NULL DEFAULT '{}',
		    template TEXT NOT NULL DEFAULT '',
		    rate_limit_per_minute INTEGER NOT NULL DEFAULT 10,
		    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`
	if _, err := d.Exec(schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	return d
}

// rowCount is a tiny helper for assertions.
func rowCount(t *testing.T, d *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := d.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatalf("count(%s): %v", table, err)
	}
	return n
}

// --- Safety-gate tests ---

func TestGateDemoRefusesWithoutYes(t *testing.T) {
	t.Setenv("ARGOS_DEMO_SEED", "1")
	t.Setenv("ARGOS_DB_PATH", "/data/argos-demo.db")
	_, err := gateDemo(&demoOpts{Yes: false, DBPath: "/data/argos-demo.db"})
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("expected --yes refusal, got: %v", err)
	}
}

func TestGateDemoRefusesWithoutEnvVar(t *testing.T) {
	t.Setenv("ARGOS_DEMO_SEED", "")
	_, err := gateDemo(&demoOpts{Yes: true, DBPath: "/data/argos-demo.db"})
	if err == nil || !strings.Contains(err.Error(), "ARGOS_DEMO_SEED") {
		t.Errorf("expected env-var refusal, got: %v", err)
	}
}

func TestGateDemoRefusesProdPath(t *testing.T) {
	t.Setenv("ARGOS_DEMO_SEED", "1")
	cases := []string{
		"/home/anyone/argos-prod/data/argos.db",
		"/srv/argos-prod/argos.db",
	}
	for _, p := range cases {
		_, err := gateDemo(&demoOpts{Yes: true, DBPath: p})
		if err == nil || !strings.Contains(err.Error(), "argos-prod") {
			t.Errorf("path=%q: expected refusal, got: %v", p, err)
		}
	}
}

func TestGateDemoRefusesEmptyDBPath(t *testing.T) {
	t.Setenv("ARGOS_DEMO_SEED", "1")
	t.Setenv("ARGOS_DB_PATH", "")
	_, err := gateDemo(&demoOpts{Yes: true, DBPath: ""})
	if err == nil || !strings.Contains(err.Error(), "ARGOS_DB_PATH") {
		t.Errorf("expected empty-path refusal, got: %v", err)
	}
}

func TestGateDemoAcceptsDemoPath(t *testing.T) {
	t.Setenv("ARGOS_DEMO_SEED", "1")
	t.Setenv("ARGOS_DB_PATH", "")
	got, err := gateDemo(&demoOpts{Yes: true, DBPath: "/data/argos-demo.db"})
	if err != nil {
		t.Errorf("expected pass, got error: %v", err)
	}
	if got != "/data/argos-demo.db" {
		t.Errorf("expected returned path, got: %q", got)
	}
}

// --- Seed effect tests ---

func TestSeedDemoDBPopulatesAllSurfaces(t *testing.T) {
	d := newDemoTestDB(t)
	out := &bytes.Buffer{}
	if err := seedDemoDB(context.Background(), d, out); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if rowCount(t, d, "hosts") != 8 {
		t.Errorf("hosts: want 8, got %d", rowCount(t, d, "hosts"))
	}
	if rowCount(t, d, "country_ban_expansions") != 5 {
		t.Errorf("country: want 5, got %d", rowCount(t, d, "country_ban_expansions"))
	}
	if rowCount(t, d, "security_whitelist") != 4 {
		t.Errorf("whitelist: want 4, got %d", rowCount(t, d, "security_whitelist"))
	}
	if rowCount(t, d, "log_entries") != 15 {
		t.Errorf("activity: want 15, got %d", rowCount(t, d, "log_entries"))
	}
	if rowCount(t, d, "notification_channels") != 3 {
		t.Errorf("channels: want 3, got %d", rowCount(t, d, "notification_channels"))
	}
	// settings: 6 keys touched (3 tuning + 1 disabled-scenarios + 2 drift_state)
	if rowCount(t, d, "settings") != 6 {
		t.Errorf("settings: want 6, got %d", rowCount(t, d, "settings"))
	}
	if !strings.Contains(out.String(), "demo seed complete") {
		t.Errorf("output missing summary: %q", out.String())
	}
}

func TestSeedDemoDBIsIdempotent(t *testing.T) {
	d := newDemoTestDB(t)
	for i := 0; i < 3; i++ {
		if err := seedDemoDB(context.Background(), d, &bytes.Buffer{}); err != nil {
			t.Fatalf("seed pass %d: %v", i, err)
		}
	}
	// Hosts/country/whitelist/channels are INSERT OR IGNORE so still
	// at the original counts.
	if rowCount(t, d, "hosts") != 8 {
		t.Errorf("hosts after 3 seeds: want 8, got %d", rowCount(t, d, "hosts"))
	}
	if rowCount(t, d, "country_ban_expansions") != 5 {
		t.Errorf("country: want 5, got %d", rowCount(t, d, "country_ban_expansions"))
	}
	if rowCount(t, d, "notification_channels") != 3 {
		t.Errorf("channels: want 3, got %d", rowCount(t, d, "notification_channels"))
	}
	// log_entries has no UNIQUE so each seed adds 15. Document the
	// behaviour explicitly so a future change doesn't break this
	// assertion silently: activity is the one surface the demo CLI
	// is *not* idempotent on, by design (multiple runs simulate more
	// activity on screen).
	if rowCount(t, d, "log_entries") != 45 {
		t.Errorf("activity after 3 seeds: want 45, got %d", rowCount(t, d, "log_entries"))
	}
}

// --- Clear effect tests ---

func TestClearDemoDBRemovesAllDemoRows(t *testing.T) {
	d := newDemoTestDB(t)
	if err := seedDemoDB(context.Background(), d, &bytes.Buffer{}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := clearDemoDB(context.Background(), d, &bytes.Buffer{}); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if rowCount(t, d, "hosts") != 0 {
		t.Errorf("hosts after clear: want 0, got %d", rowCount(t, d, "hosts"))
	}
	if rowCount(t, d, "country_ban_expansions") != 0 {
		t.Errorf("country after clear: want 0, got %d", rowCount(t, d, "country_ban_expansions"))
	}
	if rowCount(t, d, "security_whitelist") != 0 {
		t.Errorf("whitelist after clear: want 0, got %d", rowCount(t, d, "security_whitelist"))
	}
	if rowCount(t, d, "log_entries") != 0 {
		t.Errorf("activity after clear: want 0, got %d", rowCount(t, d, "log_entries"))
	}
	if rowCount(t, d, "notification_channels") != 0 {
		t.Errorf("channels after clear: want 0, got %d", rowCount(t, d, "notification_channels"))
	}
	// Settings rows are deliberately NOT cleared.
	if rowCount(t, d, "settings") != 6 {
		t.Errorf("settings should be untouched: want 6, got %d", rowCount(t, d, "settings"))
	}
}

// TestClearDemoDBLeavesNonDemoRowsAlone covers the safety guarantee:
// a real-looking host (NOT under example.{com,org,net}), a manually-
// added whitelist entry without "demo:" reason, an audit log entry
// without "demo:" prefix, a non-demo country expansion, and a
// non-demo notification channel must all survive a clear.
func TestClearDemoDBLeavesNonDemoRowsAlone(t *testing.T) {
	d := newDemoTestDB(t)
	if err := seedDemoDB(context.Background(), d, &bytes.Buffer{}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Inject non-demo rows alongside the demo ones. Real production
	// host needs its own (non-demo:) target_group + target since the
	// hosts FK requires it.
	mustExec(t, d, `INSERT INTO target_groups (name) VALUES ('real-tg')`)
	var realTGID int64
	if err := d.QueryRow(`SELECT id FROM target_groups WHERE name = 'real-tg'`).Scan(&realTGID); err != nil {
		t.Fatalf("lookup real-tg: %v", err)
	}
	mustExec(t, d, `INSERT INTO targets (target_group_id, host, port) VALUES (?, '192.0.2.99', 80)`, realTGID)
	mustExec(t, d, `INSERT INTO hosts (domain, target_group_id) VALUES ('real.production.org', ?)`, realTGID)
	mustExec(t, d, `INSERT INTO security_whitelist (scope, value, reason) VALUES ('ip', '198.51.100.99', 'real ops note')`)
	mustExec(t, d, `INSERT INTO country_ban_expansions (country_code, decision_ids, cidr_count, duration, created_by, mmdb_version_at_creation) VALUES ('JP', '[]', 0, '168h', 'admin', '2026.04')`)
	mustExec(t, d, `INSERT INTO log_entries (timestamp, source, message, raw) VALUES (CURRENT_TIMESTAMP, 'audit', 'real audit event', '{}')`)
	mustExec(t, d, `INSERT INTO notification_channels (name, type, config) VALUES ('Real channel', 'webhook', '{}')`)

	if err := clearDemoDB(context.Background(), d, &bytes.Buffer{}); err != nil {
		t.Fatalf("clear: %v", err)
	}

	// Non-demo rows must survive.
	if rowCount(t, d, "hosts") != 1 {
		t.Errorf("hosts: real.production.org should survive, got count=%d", rowCount(t, d, "hosts"))
	}
	if rowCount(t, d, "security_whitelist") != 1 {
		t.Errorf("whitelist: 'real ops note' row should survive, got count=%d", rowCount(t, d, "security_whitelist"))
	}
	if rowCount(t, d, "country_ban_expansions") != 1 {
		t.Errorf("country: JP (created_by=admin) should survive, got count=%d", rowCount(t, d, "country_ban_expansions"))
	}
	if rowCount(t, d, "log_entries") != 1 {
		t.Errorf("activity: real audit row should survive, got count=%d", rowCount(t, d, "log_entries"))
	}
	if rowCount(t, d, "notification_channels") != 1 {
		t.Errorf("channels: 'Real channel' should survive, got count=%d", rowCount(t, d, "notification_channels"))
	}
}

func mustExec(t *testing.T, d *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := d.Exec(q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

// --- Sanitization spot-checks (every seeded value must be RFC5737 /
// example.* / fake) ---

func TestSeedSanitizationNoOperatorData(t *testing.T) {
	d := newDemoTestDB(t)
	if err := seedDemoDB(context.Background(), d, &bytes.Buffer{}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Pull every text-y column we wrote and assert it's either:
	//   - in RFC5737 IP space (192.0.2., 198.51.100., 203.0.113.),
	//   - under example.{com,org,net},
	//   - a "demo:"-prefixed marker, or
	//   - a known-safe constant (cloudflare, dns, etc.).
	rows, err := d.Query(`
		SELECT 'host' AS table_name,
		       hosts.domain || ' / ' || targets.host || ':' || targets.port AS body
		  FROM hosts JOIN targets ON targets.target_group_id = hosts.target_group_id
		UNION ALL
		SELECT 'wl', value || ' / ' || reason FROM security_whitelist
		UNION ALL
		SELECT 'channel', config FROM notification_channels
	`)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	defer rows.Close()
	suspicious := []string{
		"argos-prod", "argos-edge", ".local",
	}
	for rows.Next() {
		var which, body string
		if err := rows.Scan(&which, &body); err != nil {
			t.Fatalf("scan: %v", err)
		}
		for _, s := range suspicious {
			if strings.Contains(body, s) {
				t.Errorf("[%s] body contains suspicious substring %q: %s", which, s, body)
			}
		}
	}
}

// helper: ensure go test in this package never tries to read
// $ARGOS_DB_PATH from the developer's actual env.
func TestMain(m *testing.M) {
	_ = os.Unsetenv("ARGOS_DB_PATH")
	_ = os.Unsetenv("ARGOS_DEMO_SEED")
	os.Exit(m.Run())
}
