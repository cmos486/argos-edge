package db_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/cmos486/argos-edge/backend/internal/db"
)

// TestOpenReadOnly: the read handle sees the writer's commits, refuses
// writes, and its reads are not blocked by an open write transaction.
func TestOpenReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "argos.db")
	w, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Exec(`INSERT INTO t (v) VALUES ('a')`); err != nil {
		t.Fatal(err)
	}
	r, err := db.OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var n int
	if err := r.QueryRow(`SELECT COUNT(*) FROM t`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("read after write: n=%d err=%v", n, err)
	}
	if _, err := r.Exec(`INSERT INTO t (v) VALUES ('b')`); err == nil {
		t.Fatal("write through the read-only handle succeeded")
	}
	// A write transaction held open by the writer must not block the
	// reader (WAL): the read returns the last committed state.
	ctx := context.Background()
	tx, err := w.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO t (v) VALUES ('c')`); err != nil {
		t.Fatal(err)
	}
	if err := r.QueryRow(`SELECT COUNT(*) FROM t`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("read during open write tx: n=%d err=%v", n, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := r.QueryRow(`SELECT COUNT(*) FROM t`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("read after commit: n=%d err=%v", n, err)
	}
}
