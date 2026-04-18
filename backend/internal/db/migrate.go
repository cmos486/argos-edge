package db

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strings"
)

// Hook is an optional Go-side migration step keyed by version (matches
// the .up.sql basename). When present the SQL file for that version is
// skipped; the hook owns opening its own transaction, running DDL, and
// rewriting data. Hooks exist for migrations that need logic the SQL
// engine cannot express (e.g. URL parsing in 005).
type Hook func(ctx context.Context, d *sql.DB) error

// Migrate applies any *.up.sql entry in fsys that has not been recorded
// in schema_migrations, plus any Go hook in hooks that lacks a recorded
// row. Files and hooks are applied together in lexical version order.
func Migrate(ctx context.Context, d *sql.DB, fsys fs.FS, hooks map[string]Hook) error {
	if _, err := d.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    TEXT PRIMARY KEY,
			applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
	`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	versions := collectVersions(fsys, hooks)

	for _, v := range versions {
		applied, err := isApplied(ctx, d, v.version)
		if err != nil {
			return err
		}
		if applied {
			continue
		}
		if v.hook != nil {
			if err := v.hook(ctx, d); err != nil {
				return fmt.Errorf("apply %s (go hook): %w", v.version, err)
			}
			if err := recordApplied(ctx, d, v.version); err != nil {
				return err
			}
		} else {
			if err := applyMigration(ctx, d, fsys, v.version+".up.sql", v.version); err != nil {
				return fmt.Errorf("apply %s: %w", v.version, err)
			}
		}
		slog.Info("applied migration", "version", v.version)
	}
	return nil
}

type versionEntry struct {
	version string
	hook    Hook
}

func collectVersions(fsys fs.FS, hooks map[string]Hook) []versionEntry {
	set := map[string]Hook{}

	if fsys != nil {
		if entries, err := fs.ReadDir(fsys, "."); err == nil {
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".up.sql") {
					continue
				}
				v := strings.TrimSuffix(e.Name(), ".up.sql")
				set[v] = nil
			}
		}
	}
	for v, h := range hooks {
		set[v] = h
	}

	out := make([]versionEntry, 0, len(set))
	for v, h := range set {
		out = append(out, versionEntry{version: v, hook: h})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out
}

func isApplied(ctx context.Context, d *sql.DB, version string) (bool, error) {
	var n int
	err := d.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM schema_migrations WHERE version = ?", version,
	).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("check migration %s: %w", version, err)
	}
	return n > 0, nil
}

func recordApplied(ctx context.Context, d *sql.DB, version string) error {
	if _, err := d.ExecContext(ctx,
		"INSERT INTO schema_migrations(version) VALUES (?)", version,
	); err != nil {
		return fmt.Errorf("record migration %s: %w", version, err)
	}
	return nil
}

func applyMigration(ctx context.Context, d *sql.DB, fsys fs.FS, filename, version string) error {
	sqlBytes, err := fs.ReadFile(fsys, filename)
	if err != nil {
		return fmt.Errorf("read %s: %w", filename, err)
	}

	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, string(sqlBytes)); err != nil {
		return fmt.Errorf("exec sql: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO schema_migrations(version) VALUES (?)", version,
	); err != nil {
		return fmt.Errorf("record migration: %w", err)
	}
	return tx.Commit()
}

// Rollback reverts the most recent applied migration. If a Go down hook
// is registered for that version it runs; otherwise the matching
// .down.sql is executed. The schema_migrations row is removed either way.
// Used only by the `argos migrate rollback` subcommand for sandboxed
// down-migration testing; production never calls this.
func Rollback(ctx context.Context, d *sql.DB, fsys fs.FS, downHooks map[string]Hook) error {
	var version string
	err := d.QueryRowContext(ctx,
		"SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1",
	).Scan(&version)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("nothing to roll back")
		}
		return fmt.Errorf("fetch latest version: %w", err)
	}

	if hook, ok := downHooks[version]; ok && hook != nil {
		if err := hook(ctx, d); err != nil {
			return fmt.Errorf("rollback %s (go hook): %w", version, err)
		}
	} else {
		if err := applyDown(ctx, d, fsys, version+".down.sql"); err != nil {
			return fmt.Errorf("rollback %s: %w", version, err)
		}
	}

	if _, err := d.ExecContext(ctx,
		"DELETE FROM schema_migrations WHERE version = ?", version,
	); err != nil {
		return fmt.Errorf("unrecord migration %s: %w", version, err)
	}
	slog.Info("rolled back migration", "version", version)
	return nil
}

func applyDown(ctx context.Context, d *sql.DB, fsys fs.FS, filename string) error {
	sqlBytes, err := fs.ReadFile(fsys, filename)
	if err != nil {
		return fmt.Errorf("read %s: %w", filename, err)
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, string(sqlBytes)); err != nil {
		return fmt.Errorf("exec sql: %w", err)
	}
	return tx.Commit()
}
