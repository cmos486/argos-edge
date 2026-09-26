// Package dbtest opens an in-memory SQLite with the REAL migration set
// (backend/migrations, 001 onwards) applied by the same runner main
// uses: db.Open (pragmas, REGEXP) + db.Migrate + the Go up-hooks.
//
// Every test that touches a table of the schema uses this instead of
// a hand-written CREATE TABLE: v1.3.40.0 shipped a raw strip that
// wrote NULL into a NOT NULL column because its test table had been
// invented (strike 12 of the upstream-behaviour pattern; see
// CLAUDE.md). A hand-made schema in a test is a strike.
package dbtest

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/migrations"
)

// Open returns a migrated in-memory database, closed at test cleanup.
// db.Open pins the pool to one connection, so ":memory:" is one
// database for the whole test.
func Open(t testing.TB) *sql.DB {
	t.Helper()
	d, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("dbtest: open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	hooks := make(map[string]db.Hook, len(migrations.UpHooks))
	for v, h := range migrations.UpHooks {
		h := h
		hooks[v] = func(ctx context.Context, d *sql.DB) error { return h(ctx, d) }
	}
	if err := db.Migrate(context.Background(), d, migrations.FS, hooks); err != nil {
		t.Fatalf("dbtest: migrate: %v", err)
	}
	return d
}

// InsertHost creates a target group and a host for domain (foreign
// keys are on) and returns the host id.
func InsertHost(t testing.TB, d *sql.DB, domain string) int64 {
	t.Helper()
	res, err := d.Exec(`INSERT INTO target_groups (name) VALUES (?)`, "tg-"+domain)
	if err != nil {
		t.Fatalf("dbtest: insert target group: %v", err)
	}
	tg, _ := res.LastInsertId()
	res, err = d.Exec(`INSERT INTO hosts (domain, target_group_id) VALUES (?, ?)`, domain, tg)
	if err != nil {
		t.Fatalf("dbtest: insert host %s: %v", domain, err)
	}
	id, _ := res.LastInsertId()
	return id
}

// InsertUser creates a user (password hash is a placeholder; only the
// row and its id matter to callers) and returns the id.
func InsertUser(t testing.TB, d *sql.DB, username string) int64 {
	t.Helper()
	res, err := d.Exec(`INSERT INTO users (username, password_hash) VALUES (?, ?)`, username, "x")
	if err != nil {
		t.Fatalf("dbtest: insert user %s: %v", username, err)
	}
	id, _ := res.LastInsertId()
	return id
}

// Count is the terse row counter tests keep rewriting.
func Count(t testing.TB, d *sql.DB, table, where string, args ...any) int {
	t.Helper()
	q := "SELECT COUNT(*) FROM " + table
	if where != "" {
		q += " WHERE " + where
	}
	var n int
	if err := d.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("dbtest: count %s: %v", table, err)
	}
	return n
}

var _ = fmt.Sprintf
