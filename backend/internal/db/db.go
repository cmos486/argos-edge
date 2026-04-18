// Package db opens the SQLite database used by the panel and runs migrations.
package db

import (
	"database/sql"
	"fmt"
	"net/url"

	_ "modernc.org/sqlite"
)

// Open returns a *sql.DB pointing at path with WAL and sane pragmas set.
// The caller owns the returned handle and must Close it.
func Open(path string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?%s", path, url.Values{
		"_pragma": []string{
			"journal_mode(WAL)",
			"foreign_keys(1)",
			"busy_timeout(5000)",
			"synchronous(NORMAL)",
		},
	}.Encode())

	d, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// SQLite is a single writer; keep the pool small to avoid
	// "database is locked" under contention.
	d.SetMaxOpenConns(1)

	if err := d.Ping(); err != nil {
		d.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	return d, nil
}
