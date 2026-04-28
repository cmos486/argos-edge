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
		    mmdb_version_at_creation TEXT NOT NULL,
		    state TEXT NOT NULL DEFAULT 'active'
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
		CREATE TABLE notification_rules (
		    id INTEGER PRIMARY KEY AUTOINCREMENT,
		    name TEXT NOT NULL,
		    channel_id INTEGER NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
		    event_type TEXT NOT NULL,
		    filter_host_ids TEXT NOT NULL DEFAULT '',
		    filter_severities TEXT NOT NULL DEFAULT '',
		    enabled INTEGER NOT NULL DEFAULT 1,
		    throttle_window_seconds INTEGER NOT NULL DEFAULT 0,
		    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE notification_deliveries (
		    id INTEGER PRIMARY KEY AUTOINCREMENT,
		    rule_id INTEGER REFERENCES notification_rules(id) ON DELETE SET NULL,
		    channel_id INTEGER REFERENCES notification_channels(id) ON DELETE SET NULL,
		    event_type TEXT NOT NULL DEFAULT '',
		    event_payload TEXT NOT NULL DEFAULT '',
		    rendered_payload TEXT NOT NULL DEFAULT '',
		    status TEXT NOT NULL,
		    error_message TEXT NOT NULL DEFAULT '',
		    attempts INTEGER NOT NULL DEFAULT 0,
		    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		    sent_at TIMESTAMP
		);
		CREATE TABLE backups (
		    id INTEGER PRIMARY KEY AUTOINCREMENT,
		    filename TEXT NOT NULL UNIQUE,
		    size_bytes INTEGER NOT NULL,
		    sha256 TEXT NOT NULL,
		    kind TEXT NOT NULL,
		    trigger_user_id INTEGER,
		    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		    note TEXT NOT NULL DEFAULT ''
		);
		CREATE TABLE login_attempts (
		    id INTEGER PRIMARY KEY AUTOINCREMENT,
		    remote_ip TEXT NOT NULL,
		    username TEXT NOT NULL,
		    success INTEGER NOT NULL DEFAULT 0,
		    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE country_expansion_jobs (
		    id INTEGER PRIMARY KEY AUTOINCREMENT,
		    country_code TEXT NOT NULL,
		    state TEXT NOT NULL DEFAULT 'pending',
		    chunks_total INTEGER NOT NULL DEFAULT 0,
		    chunks_done INTEGER NOT NULL DEFAULT 0,
		    chunks_failed INTEGER NOT NULL DEFAULT 0,
		    cidr_committed INTEGER NOT NULL DEFAULT 0,
		    requested_count INTEGER NOT NULL DEFAULT 0,
		    duration TEXT NOT NULL DEFAULT '',
		    reason TEXT NOT NULL DEFAULT '',
		    error_message TEXT NOT NULL DEFAULT '',
		    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		    started_at TIMESTAMP,
		    completed_at TIMESTAMP,
		    created_by TEXT NOT NULL DEFAULT ''
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
	opts := &demoOpts{Stdout: out}
	if err := seedDemoDB(context.Background(), d, opts); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if rowCount(t, d, "hosts") != 14 {
		t.Errorf("hosts: want 14, got %d", rowCount(t, d, "hosts"))
	}
	if rowCount(t, d, "country_ban_expansions") != 8 {
		t.Errorf("country: want 8, got %d", rowCount(t, d, "country_ban_expansions"))
	}
	if rowCount(t, d, "country_expansion_jobs") != 10 {
		t.Errorf("country jobs: want 10, got %d", rowCount(t, d, "country_expansion_jobs"))
	}
	if rowCount(t, d, "security_whitelist") != 8 {
		t.Errorf("whitelist: want 8, got %d", rowCount(t, d, "security_whitelist"))
	}
	if rowCount(t, d, "log_entries") != 100 {
		t.Errorf("activity: want 100, got %d", rowCount(t, d, "log_entries"))
	}
	if rowCount(t, d, "notification_channels") != 5 {
		t.Errorf("channels: want 5, got %d", rowCount(t, d, "notification_channels"))
	}
	if rowCount(t, d, "notification_rules") != 6 {
		t.Errorf("rules: want 6, got %d", rowCount(t, d, "notification_rules"))
	}
	if rowCount(t, d, "notification_deliveries") != 250 {
		t.Errorf("deliveries: want 250, got %d", rowCount(t, d, "notification_deliveries"))
	}
	if rowCount(t, d, "backups") != 7 {
		t.Errorf("backups: want 7, got %d", rowCount(t, d, "backups"))
	}
	if rowCount(t, d, "login_attempts") != 40 {
		t.Errorf("login_attempts: want 40, got %d", rowCount(t, d, "login_attempts"))
	}
	// settings: 6 keys touched (3 tuning + 1 disabled-scenarios + 2 drift_state)
	if rowCount(t, d, "settings") != 6 {
		t.Errorf("settings: want 6, got %d", rowCount(t, d, "settings"))
	}
	if !strings.Contains(out.String(), "demo seed complete") {
		t.Errorf("output missing summary: %q", out.String())
	}
}

// TestSeedDemoDBProducesDriftedCountry asserts at least one country
// row has state='drifted' so the demo's country reconciler surface
// renders the drift indicator.
func TestSeedDemoDBProducesDriftedCountry(t *testing.T) {
	d := newDemoTestDB(t)
	if err := seedDemoDB(context.Background(), d, &demoOpts{Stdout: &bytes.Buffer{}}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM country_ban_expansions WHERE state = 'drifted'`).Scan(&n); err != nil {
		t.Fatalf("count drifted: %v", err)
	}
	if n < 1 {
		t.Errorf("expected at least 1 drifted country, got %d", n)
	}
}

// TestSeedDemoDBProducesDriftedAppSec asserts the appsec.tuning.drift_state
// settings row has drift_detected:true so the demo UI shows the
// drift banner on both Scenarios and AppSec tabs.
func TestSeedDemoDBProducesDriftedAppSec(t *testing.T) {
	d := newDemoTestDB(t)
	if err := seedDemoDB(context.Background(), d, &demoOpts{Stdout: &bytes.Buffer{}}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	var v string
	if err := d.QueryRow(`SELECT value FROM settings WHERE key = 'appsec.tuning.drift_state'`).Scan(&v); err != nil {
		t.Fatalf("get drift state: %v", err)
	}
	if !strings.Contains(v, `"drift_detected":true`) {
		t.Errorf("expected drift_detected:true, got: %s", v)
	}
}

// TestSeedDemoDBProducesMultipleDeliveryStatuses asserts the seeded
// notification_deliveries table has a realistic mix of sent / failed /
// rate_limited / throttled rows.
func TestSeedDemoDBProducesMultipleDeliveryStatuses(t *testing.T) {
	d := newDemoTestDB(t)
	if err := seedDemoDB(context.Background(), d, &demoOpts{Stdout: &bytes.Buffer{}}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rows, err := d.Query(`SELECT status, COUNT(*) FROM notification_deliveries GROUP BY status`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	statuses := map[string]int{}
	for rows.Next() {
		var s string
		var n int
		if err := rows.Scan(&s, &n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		statuses[s] = n
	}
	if statuses["sent"] < 100 {
		t.Errorf("expected >100 sent deliveries, got %d", statuses["sent"])
	}
	if statuses["failed"] < 1 {
		t.Errorf("expected >= 1 failed delivery, got %d", statuses["failed"])
	}
}

// TestSeedDemoDBIsIdempotent — re-running seed produces stable
// counts. v1.3.35.2 made activity log idempotent too via DELETE+INSERT
// scoped on demo: prefix; older "append-only activity" semantics
// retired because the production-density seed (100 rows) made the
// growth-on-every-run behaviour confusing.
func TestSeedDemoDBIsIdempotent(t *testing.T) {
	d := newDemoTestDB(t)
	for i := 0; i < 3; i++ {
		if err := seedDemoDB(context.Background(), d, &demoOpts{Stdout: &bytes.Buffer{}}); err != nil {
			t.Fatalf("seed pass %d: %v", i, err)
		}
	}
	// Every surface should match its single-run count exactly.
	checks := map[string]int{
		"hosts":                   14,
		"country_ban_expansions":  8,
		"country_expansion_jobs":  10,
		"security_whitelist":      8,
		"log_entries":             100,
		"notification_channels":   5,
		"notification_rules":      6,
		"notification_deliveries": 250,
		"backups":                 7,
		"login_attempts":          40,
	}
	for table, want := range checks {
		got := rowCount(t, d, table)
		if got != want {
			t.Errorf("%s after 3 seeds: want %d, got %d", table, want, got)
		}
	}
}

// --- Clear effect tests ---

func TestClearDemoDBRemovesAllDemoRows(t *testing.T) {
	d := newDemoTestDB(t)
	if err := seedDemoDB(context.Background(), d, &demoOpts{Stdout: &bytes.Buffer{}}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := clearDemoDB(context.Background(), d, &bytes.Buffer{}); err != nil {
		t.Fatalf("clear: %v", err)
	}
	zeroChecks := []string{
		"hosts", "country_ban_expansions", "country_expansion_jobs",
		"security_whitelist", "log_entries", "notification_channels",
		"notification_rules", "notification_deliveries", "backups",
		"login_attempts",
	}
	for _, table := range zeroChecks {
		if got := rowCount(t, d, table); got != 0 {
			t.Errorf("%s after clear: want 0, got %d", table, got)
		}
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
	if err := seedDemoDB(context.Background(), d, &demoOpts{Stdout: &bytes.Buffer{}}); err != nil {
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
	if err := seedDemoDB(context.Background(), d, &demoOpts{Stdout: &bytes.Buffer{}}); err != nil {
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
