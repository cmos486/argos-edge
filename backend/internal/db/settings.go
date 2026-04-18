package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/cmos486/argos-edge/backend/internal/models"
)

var ErrSettingNotFound = errors.New("setting not found")

// GetSetting returns one setting by key.
func GetSetting(ctx context.Context, d *sql.DB, key string) (models.Setting, error) {
	row := d.QueryRowContext(ctx,
		`SELECT key, value, updated_at FROM settings WHERE key = ?`, key)
	var s models.Setting
	if err := row.Scan(&s.Key, &s.Value, &s.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.Setting{}, ErrSettingNotFound
		}
		return models.Setting{}, err
	}
	return s, nil
}

// GetSettingValue is a convenience for consumers that only need the
// value string; returns fallback on miss.
func GetSettingValue(ctx context.Context, d *sql.DB, key, fallback string) string {
	s, err := GetSetting(ctx, d, key)
	if err != nil {
		return fallback
	}
	return s.Value
}

// ListSettingsByPrefix returns every setting whose key starts with prefix.
// prefix="" returns everything.
func ListSettingsByPrefix(ctx context.Context, d *sql.DB, prefix string) ([]models.Setting, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT key, value, updated_at FROM settings WHERE key LIKE ? ORDER BY key ASC`,
		prefix+"%")
	if err != nil {
		return nil, fmt.Errorf("list settings: %w", err)
	}
	defer rows.Close()
	var out []models.Setting
	for rows.Next() {
		var s models.Setting
		if err := rows.Scan(&s.Key, &s.Value, &s.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// UpsertSetting sets or updates a key. Does not validate the key (the
// API layer enforces the whitelist of acceptable keys).
func UpsertSetting(ctx context.Context, d *sql.DB, key, value string) error {
	_, err := d.ExecContext(ctx,
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value,
		                                updated_at = CURRENT_TIMESTAMP`,
		key, value)
	if err != nil {
		return fmt.Errorf("upsert setting %s: %w", key, err)
	}
	return nil
}
