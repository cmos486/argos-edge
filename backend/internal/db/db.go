// Package db opens the SQLite database used by the panel and runs migrations.
package db

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"sync"

	sqlite "modernc.org/sqlite"
)

var regexpRegisterOnce sync.Once

// registerRegexp adds a REGEXP scalar function to the modernc.org/sqlite
// driver so SELECT ... WHERE path REGEXP ? works. Go's stdlib regexp is
// used; invalid patterns evaluate to false.
func registerRegexp() {
	regexpRegisterOnce.Do(func() {
		err := sqlite.RegisterScalarFunction("regexp", 2,
			func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
				pattern, _ := args[0].(string)
				value, _ := args[1].(string)
				re, err := regexp.Compile(pattern)
				if err != nil {
					return int64(0), nil
				}
				if re.MatchString(value) {
					return int64(1), nil
				}
				return int64(0), nil
			})
		if err != nil {
			slog.Warn("register REGEXP function", "error", err)
		}
	})
}

// Open returns a *sql.DB pointing at path with WAL and sane pragmas set.
// The caller owns the returned handle and must Close it.
func Open(path string) (*sql.DB, error) {
	registerRegexp()
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
