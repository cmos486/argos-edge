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

// TestRollbackLastMigration applies the full chain, rolls back the
// most recent version, and confirms schema_migrations shrinks by one
// and the rollback actually ran. The latest version is 023 (creates
// host_manual_certs + extends hosts.tls_mode CHECK); rolling it back
// drops the table and reverts the CHECK to the two-value form.
func TestRollbackLastMigration(t *testing.T) {
	d := openSchemaDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, d, migrationFS(t), hooksFor()); err != nil {
		t.Fatal(err)
	}
	// Sanity: 023 created host_manual_certs.
	if !tableExists(t, d, "host_manual_certs") {
		t.Fatalf("expected 023 to have created host_manual_certs")
	}
	// Sanity: 023 extended the tls_mode CHECK so 'manual' is accepted.
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
	if err := Rollback(ctx, d, migrationFS(t), hooksForDown()); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	after := countMigrations(t, d)
	if after != before-1 {
		t.Fatalf("rollback should drop one row, went %d -> %d", before, after)
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
	t.Helper()
	rows, err := d.Query(`PRAGMA table_info(hosts)`)
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
