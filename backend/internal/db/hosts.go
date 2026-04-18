package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/cmos486/argos-edge/backend/internal/models"
)

// ErrNotFound is returned when a host lookup targets a missing row.
var ErrNotFound = errors.New("host not found")

// ErrDomainTaken wraps the SQLite unique-constraint failure so callers can
// translate it to a 409 without sniffing driver error messages.
var ErrDomainTaken = errors.New("domain already registered")

// ListHosts returns every host ordered by domain ascending.
func ListHosts(ctx context.Context, d *sql.DB) ([]models.Host, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT id, domain, upstream_url, tls_mode, tls_email, enabled,
		        created_at, updated_at
		 FROM hosts
		 ORDER BY domain ASC`)
	if err != nil {
		return nil, fmt.Errorf("query hosts: %w", err)
	}
	defer rows.Close()

	var out []models.Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ListEnabledHosts is the input the reconciler needs at startup.
func ListEnabledHosts(ctx context.Context, d *sql.DB) ([]models.Host, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT id, domain, upstream_url, tls_mode, tls_email, enabled,
		        created_at, updated_at
		 FROM hosts
		 WHERE enabled = 1
		 ORDER BY domain ASC`)
	if err != nil {
		return nil, fmt.Errorf("query enabled hosts: %w", err)
	}
	defer rows.Close()

	var out []models.Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// GetHost returns the host with the given id.
func GetHost(ctx context.Context, d *sql.DB, id int64) (models.Host, error) {
	row := d.QueryRowContext(ctx,
		`SELECT id, domain, upstream_url, tls_mode, tls_email, enabled,
		        created_at, updated_at
		 FROM hosts
		 WHERE id = ?`, id)
	h, err := scanHost(row)
	if errors.Is(err, sql.ErrNoRows) {
		return models.Host{}, ErrNotFound
	}
	if err != nil {
		return models.Host{}, err
	}
	return h, nil
}

// CreateHost inserts and returns the persisted row (with id + timestamps).
func CreateHost(ctx context.Context, d *sql.DB, h models.Host) (models.Host, error) {
	res, err := d.ExecContext(ctx,
		`INSERT INTO hosts (domain, upstream_url, tls_mode, tls_email, enabled)
		 VALUES (?, ?, ?, ?, ?)`,
		h.Domain, h.UpstreamURL, string(h.TLSMode), h.TLSEmail, boolToInt(h.Enabled),
	)
	if err != nil {
		if isUniqueConstraint(err) {
			return models.Host{}, ErrDomainTaken
		}
		return models.Host{}, fmt.Errorf("insert host: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return models.Host{}, fmt.Errorf("last insert id: %w", err)
	}
	return GetHost(ctx, d, id)
}

// UpdateHost overwrites the mutable fields on an existing row.
func UpdateHost(ctx context.Context, d *sql.DB, h models.Host) (models.Host, error) {
	res, err := d.ExecContext(ctx,
		`UPDATE hosts
		    SET domain = ?, upstream_url = ?, tls_mode = ?, tls_email = ?,
		        enabled = ?, updated_at = CURRENT_TIMESTAMP
		  WHERE id = ?`,
		h.Domain, h.UpstreamURL, string(h.TLSMode), h.TLSEmail,
		boolToInt(h.Enabled), h.ID,
	)
	if err != nil {
		if isUniqueConstraint(err) {
			return models.Host{}, ErrDomainTaken
		}
		return models.Host{}, fmt.Errorf("update host: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return models.Host{}, fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return models.Host{}, ErrNotFound
	}
	return GetHost(ctx, d, h.ID)
}

// DeleteHost removes a row by id.
func DeleteHost(ctx context.Context, d *sql.DB, id int64) error {
	res, err := d.ExecContext(ctx, `DELETE FROM hosts WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete host: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ToggleHost flips the enabled flag and returns the resulting row.
func ToggleHost(ctx context.Context, d *sql.DB, id int64) (models.Host, error) {
	res, err := d.ExecContext(ctx,
		`UPDATE hosts
		    SET enabled = CASE enabled WHEN 1 THEN 0 ELSE 1 END,
		        updated_at = CURRENT_TIMESTAMP
		  WHERE id = ?`, id)
	if err != nil {
		return models.Host{}, fmt.Errorf("toggle host: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return models.Host{}, fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return models.Host{}, ErrNotFound
	}
	return GetHost(ctx, d, id)
}

// scanner lets GetHost reuse the same code path for QueryRow and Query rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanHost(s scanner) (models.Host, error) {
	var (
		h       models.Host
		enabled int
		tlsMode string
	)
	if err := s.Scan(
		&h.ID, &h.Domain, &h.UpstreamURL, &tlsMode, &h.TLSEmail, &enabled,
		&h.CreatedAt, &h.UpdatedAt,
	); err != nil {
		return models.Host{}, err
	}
	h.TLSMode = models.TLSMode(tlsMode)
	h.Enabled = enabled == 1
	return h, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func isUniqueConstraint(err error) bool {
	// modernc.org/sqlite wraps the raw errno+msg; sniffing the substring is
	// good enough for the single UNIQUE index we have. Worst case this
	// misses and the caller sees a 500 instead of a 409: recoverable.
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "hosts.domain") &&
		(strings.Contains(msg, "UNIQUE") || strings.Contains(msg, "constraint failed"))
}
