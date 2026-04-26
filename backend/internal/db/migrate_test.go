package db

import (
	"context"
	"database/sql"
	"embed"
	"io/fs"
	"testing"

	_ "modernc.org/sqlite"

	argosmigrations "github.com/cmos486/argos-edge/backend/migrations"
)

// migrationFS returns the real argos migration set. Tests want real
// fixtures here: a synthetic one-file FS exercises the loop but misses
// the cross-migration ordering bugs (e.g. a later .up.sql depending on
// a column a Go hook created).
func migrationFS(t *testing.T) fs.FS {
	t.Helper()
	return argosmigrations.FS
}

func openSchemaDB(t *testing.T) *sql.DB {
	t.Helper()
	// Use Open rather than sql.Open directly so the REGEXP function is
	// registered -- some migrations reference regexp at INSERT time via
	// triggers, and opening bare sqlite would silently drop them.
	d, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

// hooksFor returns the up-hooks as a db.Hook map (adapting the local
// HookFunc type defined in the migrations package so it matches).
func hooksFor() map[string]Hook {
	m := make(map[string]Hook, len(argosmigrations.UpHooks))
	for k, v := range argosmigrations.UpHooks {
		v := v
		m[k] = func(ctx context.Context, d *sql.DB) error { return v(ctx, d) }
	}
	return m
}

// TestMigrateAppliesFullChain verifies the real embedded migration set
// runs clean on a fresh DB. Worth pinning: a new .up.sql that
// references a column added two versions later or that uses SQLite
// syntax only present in modernc's driver would blow up here on the
// next `go test`.
func TestMigrateAppliesFullChain(t *testing.T) {
	d := openSchemaDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, d, migrationFS(t), hooksFor()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Tables touched by the core panel paths must all exist.
	for _, table := range []string{"users", "sessions", "login_attempts", "totp_attempts", "settings", "log_entries"} {
		var name string
		err := d.QueryRow(
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table,
		).Scan(&name)
		if err != nil {
			t.Fatalf("table %q missing after Migrate: %v", table, err)
		}
	}
	// schema_migrations must be populated: count >= number of .up.sql
	// files in the embedded FS.
	var applied int
	if err := d.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied < 15 {
		t.Fatalf("schema_migrations has %d rows, expected >= 15", applied)
	}
}

// TestMigrateIsIdempotent runs the full chain twice. Each migration
// version must only INSERT one schema_migrations row; running the
// chain a second time must be a pure no-op -- the runner uses the
// applied table to skip.
func TestMigrateIsIdempotent(t *testing.T) {
	d := openSchemaDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, d, migrationFS(t), hooksFor()); err != nil {
		t.Fatal(err)
	}
	var first int
	_ = d.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&first)

	if err := Migrate(ctx, d, migrationFS(t), hooksFor()); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	var second int
	_ = d.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&second)
	if first != second {
		t.Fatalf("second Migrate added rows: %d -> %d", first, second)
	}
}

// TestRollbackLastMigration applies the full chain and rolls back
// the three most recent migrations one step at a time:
//
//	025 -> 024 -> 023
//
// Each Rollback call must shrink schema_migrations by one and undo
// its specific schema change. The test originally only covered 023
// (the Go-hook writable_schema trick for tls_mode); it now also
// covers the v1.3 pair (024 = dns_providers table, 025 = hosts.
// tls_dns_provider column) so a regression in either down-migration
// surfaces here.
func TestRollbackLastMigration(t *testing.T) {
	d := openSchemaDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, d, migrationFS(t), hooksFor()); err != nil {
		t.Fatal(err)
	}

	// Sanity checks on the forward direction.
	if !tableExists(t, d, "host_manual_certs") {
		t.Fatalf("expected 023 to have created host_manual_certs")
	}
	if !tableExists(t, d, "dns_providers") {
		t.Fatalf("expected 024 to have created dns_providers")
	}
	if !hostsHasColumn(t, d, "tls_dns_provider") {
		t.Fatalf("expected 025 to have added hosts.tls_dns_provider")
	}
	// 023 extended tls_mode CHECK so 'manual' is accepted.
	if _, err := d.Exec(
		`INSERT INTO target_groups (name, protocol, algorithm) VALUES ('t', 'http', 'round_robin')`,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(
		`INSERT INTO hosts (domain, target_group_id, tls_mode, tls_email) VALUES (?, 1, 'manual', '')`,
		"example.com",
	); err != nil {
		t.Fatalf("expected tls_mode='manual' to be accepted post-023: %v", err)
	}
	if _, err := d.Exec(`DELETE FROM hosts WHERE domain=?`, "example.com"); err != nil {
		t.Fatal(err)
	}

	before := countMigrations(t, d)

	// Roll back 032 first (introduced v1.3.31): drop the
	// country_expansion_jobs table.
	if err := Rollback(ctx, d, migrationFS(t), hooksForDown()); err != nil {
		t.Fatalf("rollback 032: %v", err)
	}
	if tableExists(t, d, "country_expansion_jobs") {
		t.Fatalf("032 down did not drop country_expansion_jobs")
	}
	before--

	// Roll back 031 (introduced v1.3.27): data-migration that
	// dropped two settings rows; the .down is a no-op SELECT 1. We
	// assert only that the rollback path runs cleanly and shrinks
	// schema_migrations by one. There is no schema effect to check.
	if err := Rollback(ctx, d, migrationFS(t), hooksForDown()); err != nil {
		t.Fatalf("rollback 031: %v", err)
	}
	before--

	// Roll back 030 (introduced v1.3.23): drop
	// sessions.client_ip + sessions.xff_chain. The rollback chain
	// peels back the most recent migration and asserts the schema
	// reverted before peeling the next one.
	if err := Rollback(ctx, d, migrationFS(t), hooksForDown()); err != nil {
		t.Fatalf("rollback 030: %v", err)
	}
	if tableHasColumn(t, d, "sessions", "client_ip") {
		t.Fatalf("030 down did not drop sessions.client_ip")
	}
	if tableHasColumn(t, d, "sessions", "xff_chain") {
		t.Fatalf("030 down did not drop sessions.xff_chain")
	}
	before--

	// Roll back 029 (introduced v1.3.21): drop
	// country_ban_expansions table.
	if err := Rollback(ctx, d, migrationFS(t), hooksForDown()); err != nil {
		t.Fatalf("rollback 029: %v", err)
	}
	if tableExists(t, d, "country_ban_expansions") {
		t.Fatalf("029 down did not drop country_ban_expansions")
	}
	before--

	// Roll back 028 (introduced v1.3.19): drop
	// hosts.true_detect_mode + security_whitelist table.
	if err := Rollback(ctx, d, migrationFS(t), hooksForDown()); err != nil {
		t.Fatalf("rollback 028: %v", err)
	}
	if hostsHasColumn(t, d, "true_detect_mode") {
		t.Fatalf("028 down did not drop hosts.true_detect_mode")
	}
	before--

	// Roll back 027 (introduced v1.3.18): drop hosts.lan_only.
	// After this rollback the column should be gone; later
	// assertions operate against a stack where 026 is the latest
	// applied migration.
	if err := Rollback(ctx, d, migrationFS(t), hooksForDown()); err != nil {
		t.Fatalf("rollback 027: %v", err)
	}
	if hostsHasColumn(t, d, "lan_only") {
		t.Fatalf("027 down did not drop hosts.lan_only")
	}
	before--

	// Roll back 026 (introduced v1.3.16): drop
	// target_groups.preserve_host. After this rollback the column
	// should be gone but the table itself still present; the rest
	// of the assertions below operate against a stack where 025 is
	// the latest applied migration (the original invariant of this
	// test pre-v1.3.16).
	if err := Rollback(ctx, d, migrationFS(t), hooksForDown()); err != nil {
		t.Fatalf("rollback 026: %v", err)
	}
	if targetGroupsHasColumn(t, d, "preserve_host") {
		t.Fatalf("026 down did not drop target_groups.preserve_host")
	}
	before--

	// Roll back 025.
	if err := Rollback(ctx, d, migrationFS(t), hooksForDown()); err != nil {
		t.Fatalf("rollback 025: %v", err)
	}
	if hostsHasColumn(t, d, "tls_dns_provider") {
		t.Fatalf("025 down did not drop hosts.tls_dns_provider")
	}

	// Roll back 024.
	if err := Rollback(ctx, d, migrationFS(t), hooksForDown()); err != nil {
		t.Fatalf("rollback 024: %v", err)
	}
	if tableExists(t, d, "dns_providers") {
		t.Fatalf("024 down did not drop dns_providers")
	}

	// Roll back 023.
	if err := Rollback(ctx, d, migrationFS(t), hooksForDown()); err != nil {
		t.Fatalf("rollback 023: %v", err)
	}
	if tableExists(t, d, "host_manual_certs") {
		t.Fatalf("023 down did not drop host_manual_certs")
	}
	// CHECK reverted: writing 'manual' should now fail.
	if _, err := d.Exec(
		`INSERT INTO hosts (domain, target_group_id, tls_mode, tls_email) VALUES (?, 1, 'manual', '')`,
		"post-rollback.example.com",
	); err == nil {
		t.Fatalf("expected tls_mode='manual' to be rejected after rollback")
	}

	after := countMigrations(t, d)
	if after != before-3 {
		t.Fatalf("three rollbacks should drop three rows, went %d -> %d", before, after)
	}
}

// TestMigration030SessionsClientIP: forward-shape pin for the
// v1.3.23 schema add. The rollback path is exercised in
// TestRollbackLastMigration; this test locks the columns + their
// nullability so a future "make client_ip NOT NULL" refactor
// fails here rather than at runtime against legacy session rows.
func TestMigration030SessionsClientIP(t *testing.T) {
	d := openSchemaDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, d, migrationFS(t), hooksFor()); err != nil {
		t.Fatal(err)
	}
	if !tableHasColumn(t, d, "sessions", "client_ip") {
		t.Fatalf("030 did not add sessions.client_ip")
	}
	if !tableHasColumn(t, d, "sessions", "xff_chain") {
		t.Fatalf("030 did not add sessions.xff_chain")
	}
	// Both columns must accept NULL so legacy rows from pre-v1.3.23
	// logins survive the migration.
	rows, err := d.Query(`PRAGMA table_info(sessions)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid     int
			name    string
			ctype   string
			notnull int
			dflt    any
			pk      int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		if (name == "client_ip" || name == "xff_chain") && notnull != 0 {
			t.Fatalf("sessions.%s must be NULL-allowed for legacy-row degradation", name)
		}
	}
}

// TestMigration029CountryBanExpansions: forward-only assertions on
// the v1.3.21 schema. The rollback path is exercised by
// TestRollbackLastMigration above; this test pins the table shape so
// later refactors of the country-expansion writer cannot drift away
// from what the migration creates.
func TestMigration029CountryBanExpansions(t *testing.T) {
	d := openSchemaDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, d, migrationFS(t), hooksFor()); err != nil {
		t.Fatal(err)
	}
	if !tableExists(t, d, "country_ban_expansions") {
		t.Fatalf("029 did not create country_ban_expansions")
	}
	for _, col := range []string{
		"id", "country_code", "decision_ids", "cidr_count",
		"reason", "duration", "created_at", "created_by",
		"mmdb_version_at_creation",
	} {
		if !tableHasColumn(t, d, "country_ban_expansions", col) {
			t.Fatalf("country_ban_expansions missing column %q", col)
		}
	}
	// UNIQUE(country_code) -- second insert with the same code must
	// fail. Avoids a future "double-expand" bug where the operator
	// hits "ban BR" twice and ends up with two stacked expansions.
	if _, err := d.Exec(`
		INSERT INTO country_ban_expansions
			(country_code, decision_ids, cidr_count, duration, created_by, mmdb_version_at_creation)
		VALUES ('XX', '[]', 0, '4h', 'admin', '2026-04')
	`); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if _, err := d.Exec(`
		INSERT INTO country_ban_expansions
			(country_code, decision_ids, cidr_count, duration, created_by, mmdb_version_at_creation)
		VALUES ('XX', '[]', 0, '4h', 'admin', '2026-04')
	`); err == nil {
		t.Fatalf("UNIQUE(country_code) did not reject duplicate insert")
	}
}

func tableExists(t *testing.T, d *sql.DB, name string) bool {
	t.Helper()
	var n int
	if err := d.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name,
	).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

// hostsHasColumn probes PRAGMA table_info(hosts) for the named column.
func hostsHasColumn(t *testing.T, d *sql.DB, name string) bool {
	return tableHasColumn(t, d, "hosts", name)
}

func targetGroupsHasColumn(t *testing.T, d *sql.DB, name string) bool {
	return tableHasColumn(t, d, "target_groups", name)
}

func tableHasColumn(t *testing.T, d *sql.DB, table, name string) bool {
	t.Helper()
	rows, err := d.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid     int
			colName string
			colType string
			notnull int
			dflt    any
			pk      int
		)
		if err := rows.Scan(&cid, &colName, &colType, &notnull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		if colName == name {
			return true
		}
	}
	return false
}

// TestRollbackEmptyErrors: the runner returns an explicit error when
// there is nothing to undo, so the CLI can surface a clear message.
func TestRollbackEmptyErrors(t *testing.T) {
	d := openSchemaDB(t)
	// create just the schema_migrations table to isolate the "empty" path
	if _, err := d.Exec(`CREATE TABLE schema_migrations (
		version TEXT PRIMARY KEY, applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatal(err)
	}
	if err := Rollback(context.Background(), d, emptyFS{}, nil); err == nil {
		t.Fatal("Rollback on empty schema_migrations should error")
	}
}

// TestMigratePartialApply simulates a panel that was up-to-v19 when
// the v20 feature shipped. Pre-seed the first N rows as applied, run
// Migrate, and confirm only the new ones land.
func TestMigratePartialApply(t *testing.T) {
	d := openSchemaDB(t)
	ctx := context.Background()
	// Apply everything through 019 normally.
	if err := Migrate(ctx, d, migrationFS(t), hooksFor()); err != nil {
		t.Fatal(err)
	}
	// Pretend we never applied 020: delete its schema_migrations row
	// and its downstream effect (the seeded setting).
	if _, err := d.Exec(`DELETE FROM schema_migrations WHERE version LIKE '020%'`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`DELETE FROM settings WHERE key='oidc.require_email_verified'`); err != nil {
		t.Fatal(err)
	}
	// Re-run Migrate. Only 020 should be applied; everything else skipped.
	if err := Migrate(ctx, d, migrationFS(t), hooksFor()); err != nil {
		t.Fatalf("partial re-apply: %v", err)
	}
	var n int
	_ = d.QueryRow(`SELECT COUNT(*) FROM settings WHERE key='oidc.require_email_verified'`).Scan(&n)
	if n != 1 {
		t.Fatalf("020 not re-applied: settings count=%d", n)
	}
}

// --- helpers ---

func countMigrations(t *testing.T, d *sql.DB) int {
	t.Helper()
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func hooksForDown() map[string]Hook {
	m := make(map[string]Hook, len(argosmigrations.DownHooks))
	for k, v := range argosmigrations.DownHooks {
		v := v
		m[k] = func(ctx context.Context, d *sql.DB) error { return v(ctx, d) }
	}
	return m
}

// emptyFS satisfies fs.FS with no files so Rollback's "look up the
// down.sql" path trivially returns nothing. The Rollback-on-empty
// case returns early before it reads any file anyway.
type emptyFS struct{}

// Implementing embed.FS's surface via a tiny adapter would be a lot
// of boilerplate; reuse an empty subdirectory of the embedded FS.
func (emptyFS) Open(name string) (fs.File, error) { return nil, fs.ErrNotExist }

// Keep embed referenced even if the compiler decides this file does
// not otherwise use it -- guards against a "unused import" refactor.
var _ embed.FS
