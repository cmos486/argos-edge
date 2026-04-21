package migrations

import (
	"context"
	"database/sql"
	"fmt"
)

// up023HostManualCerts extends hosts.tls_mode to accept 'manual' and
// creates the host_manual_certs table that backs Feature 5.
//
// The CHECK constraint extension uses SQLite's writable_schema trick:
// sqlite_master row for 'hosts' is edited in place to append 'manual'
// to the IN-list. This is the documented workaround for SQLite's lack
// of ALTER TABLE CHECK support and is safer than the full-table
// rebuild dance (which would need PRAGMA foreign_keys=OFF coordinated
// across child tables). writable_schema is scoped to the one pinned
// connection and reset before return.
func up023HostManualCerts(ctx context.Context, d *sql.DB) error {
	conn, err := d.Conn(ctx)
	if err != nil {
		return fmt.Errorf("pin conn: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, `PRAGMA writable_schema = ON`); err != nil {
		return fmt.Errorf("writable_schema on: %w", err)
	}
	defer func() {
		_, _ = conn.ExecContext(context.Background(), `PRAGMA writable_schema = RESET`)
	}()

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Rewrite the hosts CHECK clause literally. A RowsAffected of 0
	// means the stored DDL no longer matches the expected text (e.g.
	// an earlier migration changed it) and we want to fail loudly
	// instead of silently emitting a no-op.
	res, err := tx.ExecContext(ctx, `
		UPDATE sqlite_master
		   SET sql = replace(sql,
		             'CHECK (tls_mode IN (''auto'', ''none''))',
		             'CHECK (tls_mode IN (''auto'', ''none'', ''manual''))')
		 WHERE type = 'table' AND name = 'hosts'
	`)
	if err != nil {
		return fmt.Errorf("rewrite hosts CHECK: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rewrite hosts CHECK rows: %w", err)
	}
	if n != 1 {
		return fmt.Errorf("hosts CHECK rewrite affected %d rows, expected 1 (DDL drifted?)", n)
	}

	if _, err := tx.ExecContext(ctx, `
		CREATE TABLE host_manual_certs (
			id                 INTEGER PRIMARY KEY AUTOINCREMENT,
			host_id            INTEGER NOT NULL UNIQUE,
			cert_pem           TEXT NOT NULL,
			key_pem_encrypted  BLOB NOT NULL,
			chain_pem          TEXT NOT NULL DEFAULT '',
			not_after          DATETIME NOT NULL,
			not_before         DATETIME NOT NULL,
			sans               TEXT NOT NULL,
			fingerprint_sha256 TEXT NOT NULL,
			uploaded_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			uploaded_by        INTEGER NOT NULL,
			FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
			FOREIGN KEY (uploaded_by) REFERENCES users(id)
		)`); err != nil {
		return fmt.Errorf("create host_manual_certs: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		CREATE INDEX idx_host_manual_certs_not_after ON host_manual_certs(not_after)
	`); err != nil {
		return fmt.Errorf("create index: %w", err)
	}

	return tx.Commit()
}

// down023HostManualCerts reverses up023. DROP TABLE must come first so
// the hosts FK from host_manual_certs.host_id is gone; THEN the CHECK
// rewrite reverts to the two-value form. Running the down path while
// any host row has tls_mode='manual' intentionally fails at the
// sqlite_master rewrite (the rewrite itself succeeds, but subsequent
// writes against that row would fail the narrowed CHECK) -- the caller
// is expected to delete 'manual' rows first.
func down023HostManualCerts(ctx context.Context, d *sql.DB) error {
	conn, err := d.Conn(ctx)
	if err != nil {
		return fmt.Errorf("pin conn: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, `PRAGMA writable_schema = ON`); err != nil {
		return fmt.Errorf("writable_schema on: %w", err)
	}
	defer func() {
		_, _ = conn.ExecContext(context.Background(), `PRAGMA writable_schema = RESET`)
	}()

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DROP TABLE IF EXISTS host_manual_certs`); err != nil {
		return fmt.Errorf("drop host_manual_certs: %w", err)
	}

	res, err := tx.ExecContext(ctx, `
		UPDATE sqlite_master
		   SET sql = replace(sql,
		             'CHECK (tls_mode IN (''auto'', ''none'', ''manual''))',
		             'CHECK (tls_mode IN (''auto'', ''none''))')
		 WHERE type = 'table' AND name = 'hosts'
	`)
	if err != nil {
		return fmt.Errorf("rewrite hosts CHECK back: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rewrite rows: %w", err)
	}
	if n != 1 {
		return fmt.Errorf("hosts CHECK revert affected %d rows, expected 1", n)
	}

	return tx.Commit()
}
