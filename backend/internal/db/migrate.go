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

// Migrate applies any *.up.sql entry in fsys that has not been recorded in
// schema_migrations. Files are applied in lexical order of their filename.
// The caller owns fsys; typically this is migrations.FS from the companion
// migrations package.
func Migrate(ctx context.Context, d *sql.DB, fsys fs.FS) error {
	if _, err := d.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    TEXT PRIMARY KEY,
			applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
	`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}

	var upFiles []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(e.Name(), ".up.sql") {
			upFiles = append(upFiles, e.Name())
		}
	}
	sort.Strings(upFiles)

	for _, name := range upFiles {
		version := strings.TrimSuffix(name, ".up.sql")
		applied, err := isApplied(ctx, d, version)
		if err != nil {
			return err
		}
		if applied {
			continue
		}
		if err := applyMigration(ctx, d, fsys, name, version); err != nil {
			return fmt.Errorf("apply %s: %w", name, err)
		}
		slog.Info("applied migration", "version", version)
	}
	return nil
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
