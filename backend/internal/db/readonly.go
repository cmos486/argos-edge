package db

import (
	"database/sql"
	"fmt"
	"net/url"
)

// ReadPoolSize is how many read-only connections OpenReadOnly keeps.
// Two: one for the request that is running, one for the next, so a
// long GET (CSV export) does not queue every other GET behind it. A
// third would only add memory (each connection has its own page
// cache) on a 2-vCPU host.
const ReadPoolSize = 2

// OpenReadOnly returns a second handle on the same file opened with
// mode=ro, for GET handlers only. SQLite WAL lets readers run while
// the single writer (Open) holds its lock, so a purge or a pinned
// dashboard refresh no longer blocks reads. Reads see every commit
// that finished before the statement started (each statement is its
// own snapshot); nothing here caches across statements.
//
// The handle rejects writes at the SQLite level (attempt to write a
// readonly database), so a handler that slips a write through it
// fails loudly instead of racing the writer.
func OpenReadOnly(path string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?%s", path, url.Values{
		"mode": []string{"ro"},
		"_pragma": []string{
			"busy_timeout(5000)",
			"query_only(1)",
		},
	}.Encode())
	d, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite read-only: %w", err)
	}
	d.SetMaxOpenConns(ReadPoolSize)
	d.SetMaxIdleConns(ReadPoolSize)
	if err := d.Ping(); err != nil {
		d.Close()
		return nil, fmt.Errorf("ping sqlite read-only: %w", err)
	}
	return d, nil
}
