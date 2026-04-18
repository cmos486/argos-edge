package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/cmos486/argos-edge/backend/internal/models"
)

var (
	ErrHostSecurityNotFound = errors.New("host_security row missing")
	ErrExclusionNotFound    = errors.New("waf exclusion not found")
	ErrExclusionDuplicate   = errors.New("exclusion already exists for this host+rule+path")
	ErrCustomRuleNotFound   = errors.New("waf custom rule not found")
)

const hostSecurityCols = `host_id, waf_enabled, waf_mode, waf_paranoia,
    waf_block_status, waf_block_body, rate_limit_enabled,
    rate_limit_requests, rate_limit_window_seconds, rate_limit_key,
    rate_limit_header_name, rate_limit_status, updated_at`

// GetHostSecurity returns the per-host security config. If the row is
// missing (host pre-dates phase 4 and backfill did not fire for some
// reason) a fresh default is returned without touching the DB.
func GetHostSecurity(ctx context.Context, d *sql.DB, hostID int64) (models.HostSecurity, error) {
	row := d.QueryRowContext(ctx,
		`SELECT `+hostSecurityCols+` FROM host_security WHERE host_id = ?`, hostID)
	s, err := scanHostSecurity(row)
	if errors.Is(err, sql.ErrNoRows) {
		return defaultHostSecurity(hostID), nil
	}
	return s, err
}

// UpdateHostSecurity upserts the row. The handler validates values
// before calling here.
func UpdateHostSecurity(ctx context.Context, d *sql.DB, s models.HostSecurity) (models.HostSecurity, error) {
	_, err := d.ExecContext(ctx,
		`INSERT INTO host_security
		    (host_id, waf_enabled, waf_mode, waf_paranoia,
		     waf_block_status, waf_block_body, rate_limit_enabled,
		     rate_limit_requests, rate_limit_window_seconds, rate_limit_key,
		     rate_limit_header_name, rate_limit_status)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(host_id) DO UPDATE SET
		    waf_enabled = excluded.waf_enabled,
		    waf_mode = excluded.waf_mode,
		    waf_paranoia = excluded.waf_paranoia,
		    waf_block_status = excluded.waf_block_status,
		    waf_block_body = excluded.waf_block_body,
		    rate_limit_enabled = excluded.rate_limit_enabled,
		    rate_limit_requests = excluded.rate_limit_requests,
		    rate_limit_window_seconds = excluded.rate_limit_window_seconds,
		    rate_limit_key = excluded.rate_limit_key,
		    rate_limit_header_name = excluded.rate_limit_header_name,
		    rate_limit_status = excluded.rate_limit_status,
		    updated_at = CURRENT_TIMESTAMP`,
		s.HostID, boolToInt(s.WAFEnabled), string(s.WAFMode), s.WAFParanoia,
		s.WAFBlockStatus, s.WAFBlockBody,
		boolToInt(s.RateLimitEnabled), s.RateLimitRequests, s.RateLimitWindowSeconds,
		string(s.RateLimitKey), s.RateLimitHeaderName, s.RateLimitStatus,
	)
	if err != nil {
		return models.HostSecurity{}, fmt.Errorf("upsert host_security: %w", err)
	}
	return GetHostSecurity(ctx, d, s.HostID)
}

// LoadHostSecurityBundle fetches host_security + exclusions + custom
// rules for one host.
func LoadHostSecurityBundle(ctx context.Context, d *sql.DB, hostID int64) (models.HostSecurityBundle, error) {
	core, err := GetHostSecurity(ctx, d, hostID)
	if err != nil {
		return models.HostSecurityBundle{}, err
	}
	ex, err := ListExclusions(ctx, d, hostID)
	if err != nil {
		return models.HostSecurityBundle{}, err
	}
	cr, err := ListCustomRules(ctx, d, hostID)
	if err != nil {
		return models.HostSecurityBundle{}, err
	}
	return models.HostSecurityBundle{
		HostSecurity: core,
		Exclusions:   ex,
		CustomRules:  cr,
	}, nil
}

// --- exclusions ---

const exclusionCols = `id, host_id, crs_rule_id, path_pattern, reason,
    enabled, created_at, updated_at`

func ListExclusions(ctx context.Context, d *sql.DB, hostID int64) ([]models.WAFExclusion, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT `+exclusionCols+`
		   FROM waf_exclusions WHERE host_id = ?
		   ORDER BY crs_rule_id ASC, id ASC`, hostID)
	if err != nil {
		return nil, fmt.Errorf("list exclusions: %w", err)
	}
	defer rows.Close()
	var out []models.WAFExclusion
	for rows.Next() {
		e, err := scanExclusion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func GetExclusion(ctx context.Context, d *sql.DB, hostID, id int64) (models.WAFExclusion, error) {
	row := d.QueryRowContext(ctx,
		`SELECT `+exclusionCols+` FROM waf_exclusions WHERE id = ? AND host_id = ?`,
		id, hostID)
	e, err := scanExclusion(row)
	if errors.Is(err, sql.ErrNoRows) {
		return models.WAFExclusion{}, ErrExclusionNotFound
	}
	return e, err
}

func CreateExclusion(ctx context.Context, d *sql.DB, e models.WAFExclusion) (models.WAFExclusion, error) {
	res, err := d.ExecContext(ctx,
		`INSERT INTO waf_exclusions
		    (host_id, crs_rule_id, path_pattern, reason, enabled)
		 VALUES (?, ?, ?, ?, ?)`,
		e.HostID, e.CRSRuleID, e.PathPattern, e.Reason, boolToInt(e.Enabled),
	)
	if err != nil {
		if isExclusionUnique(err) {
			return models.WAFExclusion{}, ErrExclusionDuplicate
		}
		return models.WAFExclusion{}, fmt.Errorf("insert exclusion: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return models.WAFExclusion{}, err
	}
	return GetExclusion(ctx, d, e.HostID, id)
}

func UpdateExclusion(ctx context.Context, d *sql.DB, e models.WAFExclusion) (models.WAFExclusion, error) {
	res, err := d.ExecContext(ctx,
		`UPDATE waf_exclusions
		    SET crs_rule_id = ?, path_pattern = ?, reason = ?, enabled = ?,
		        updated_at = CURRENT_TIMESTAMP
		  WHERE id = ? AND host_id = ?`,
		e.CRSRuleID, e.PathPattern, e.Reason, boolToInt(e.Enabled),
		e.ID, e.HostID,
	)
	if err != nil {
		if isExclusionUnique(err) {
			return models.WAFExclusion{}, ErrExclusionDuplicate
		}
		return models.WAFExclusion{}, fmt.Errorf("update exclusion: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return models.WAFExclusion{}, ErrExclusionNotFound
	}
	return GetExclusion(ctx, d, e.HostID, e.ID)
}

func DeleteExclusion(ctx context.Context, d *sql.DB, hostID, id int64) error {
	res, err := d.ExecContext(ctx,
		`DELETE FROM waf_exclusions WHERE id = ? AND host_id = ?`, id, hostID)
	if err != nil {
		return fmt.Errorf("delete exclusion: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrExclusionNotFound
	}
	return nil
}

func ToggleExclusion(ctx context.Context, d *sql.DB, hostID, id int64) (models.WAFExclusion, error) {
	res, err := d.ExecContext(ctx,
		`UPDATE waf_exclusions
		    SET enabled = CASE enabled WHEN 1 THEN 0 ELSE 1 END,
		        updated_at = CURRENT_TIMESTAMP
		  WHERE id = ? AND host_id = ?`, id, hostID)
	if err != nil {
		return models.WAFExclusion{}, fmt.Errorf("toggle exclusion: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return models.WAFExclusion{}, ErrExclusionNotFound
	}
	return GetExclusion(ctx, d, hostID, id)
}

// --- custom rules ---

const customRuleCols = `id, host_id, name, secrule, enabled, created_at, updated_at`

func ListCustomRules(ctx context.Context, d *sql.DB, hostID int64) ([]models.WAFCustomRule, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT `+customRuleCols+` FROM waf_custom_rules WHERE host_id = ? ORDER BY id ASC`,
		hostID)
	if err != nil {
		return nil, fmt.Errorf("list custom rules: %w", err)
	}
	defer rows.Close()
	var out []models.WAFCustomRule
	for rows.Next() {
		r, err := scanCustomRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func GetCustomRule(ctx context.Context, d *sql.DB, hostID, id int64) (models.WAFCustomRule, error) {
	row := d.QueryRowContext(ctx,
		`SELECT `+customRuleCols+` FROM waf_custom_rules WHERE id = ? AND host_id = ?`,
		id, hostID)
	r, err := scanCustomRule(row)
	if errors.Is(err, sql.ErrNoRows) {
		return models.WAFCustomRule{}, ErrCustomRuleNotFound
	}
	return r, err
}

func CreateCustomRule(ctx context.Context, d *sql.DB, r models.WAFCustomRule) (models.WAFCustomRule, error) {
	res, err := d.ExecContext(ctx,
		`INSERT INTO waf_custom_rules (host_id, name, secrule, enabled)
		 VALUES (?, ?, ?, ?)`,
		r.HostID, r.Name, r.SecRule, boolToInt(r.Enabled),
	)
	if err != nil {
		return models.WAFCustomRule{}, fmt.Errorf("insert custom rule: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return models.WAFCustomRule{}, err
	}
	return GetCustomRule(ctx, d, r.HostID, id)
}

func UpdateCustomRule(ctx context.Context, d *sql.DB, r models.WAFCustomRule) (models.WAFCustomRule, error) {
	res, err := d.ExecContext(ctx,
		`UPDATE waf_custom_rules
		    SET name = ?, secrule = ?, enabled = ?,
		        updated_at = CURRENT_TIMESTAMP
		  WHERE id = ? AND host_id = ?`,
		r.Name, r.SecRule, boolToInt(r.Enabled), r.ID, r.HostID,
	)
	if err != nil {
		return models.WAFCustomRule{}, fmt.Errorf("update custom rule: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return models.WAFCustomRule{}, ErrCustomRuleNotFound
	}
	return GetCustomRule(ctx, d, r.HostID, r.ID)
}

func DeleteCustomRule(ctx context.Context, d *sql.DB, hostID, id int64) error {
	res, err := d.ExecContext(ctx,
		`DELETE FROM waf_custom_rules WHERE id = ? AND host_id = ?`, id, hostID)
	if err != nil {
		return fmt.Errorf("delete custom rule: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrCustomRuleNotFound
	}
	return nil
}

func ToggleCustomRule(ctx context.Context, d *sql.DB, hostID, id int64) (models.WAFCustomRule, error) {
	res, err := d.ExecContext(ctx,
		`UPDATE waf_custom_rules
		    SET enabled = CASE enabled WHEN 1 THEN 0 ELSE 1 END,
		        updated_at = CURRENT_TIMESTAMP
		  WHERE id = ? AND host_id = ?`, id, hostID)
	if err != nil {
		return models.WAFCustomRule{}, fmt.Errorf("toggle custom rule: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return models.WAFCustomRule{}, ErrCustomRuleNotFound
	}
	return GetCustomRule(ctx, d, hostID, id)
}

// --- scanners ---

func scanHostSecurity(s scanner) (models.HostSecurity, error) {
	var (
		h                models.HostSecurity
		wafEnabled       int
		rateLimitEnabled int
		mode             string
		rlKey            string
	)
	if err := s.Scan(
		&h.HostID, &wafEnabled, &mode, &h.WAFParanoia,
		&h.WAFBlockStatus, &h.WAFBlockBody,
		&rateLimitEnabled, &h.RateLimitRequests, &h.RateLimitWindowSeconds,
		&rlKey, &h.RateLimitHeaderName, &h.RateLimitStatus, &h.UpdatedAt,
	); err != nil {
		return models.HostSecurity{}, err
	}
	h.WAFEnabled = wafEnabled == 1
	h.WAFMode = models.WAFMode(mode)
	h.RateLimitEnabled = rateLimitEnabled == 1
	h.RateLimitKey = models.RateLimitKey(rlKey)
	return h, nil
}

func scanExclusion(s scanner) (models.WAFExclusion, error) {
	var (
		e       models.WAFExclusion
		enabled int
	)
	if err := s.Scan(
		&e.ID, &e.HostID, &e.CRSRuleID, &e.PathPattern, &e.Reason,
		&enabled, &e.CreatedAt, &e.UpdatedAt,
	); err != nil {
		return models.WAFExclusion{}, err
	}
	e.Enabled = enabled == 1
	return e, nil
}

func scanCustomRule(s scanner) (models.WAFCustomRule, error) {
	var (
		r       models.WAFCustomRule
		enabled int
	)
	if err := s.Scan(
		&r.ID, &r.HostID, &r.Name, &r.SecRule, &enabled, &r.CreatedAt, &r.UpdatedAt,
	); err != nil {
		return models.WAFCustomRule{}, err
	}
	r.Enabled = enabled == 1
	return r, nil
}

func defaultHostSecurity(hostID int64) models.HostSecurity {
	return models.HostSecurity{
		HostID:          hostID,
		WAFMode:         models.WAFModeDetect,
		WAFParanoia:     1,
		WAFBlockStatus:  403,
		RateLimitKey:    models.RateLimitKeyIP,
		RateLimitStatus: 429,
	}
}

func isExclusionUnique(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "waf_exclusions") &&
		(strings.Contains(msg, "UNIQUE") || strings.Contains(msg, "constraint failed"))
}
