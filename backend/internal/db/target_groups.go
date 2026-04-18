package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/cmos486/argos-edge/backend/internal/models"
)

// Target-group sentinel errors. Callers translate these into the
// appropriate HTTP status codes.
var (
	ErrTargetGroupNotFound  = errors.New("target group not found")
	ErrTargetGroupNameTaken = errors.New("target group name already taken")
	ErrTargetGroupInUse     = errors.New("target group has associated hosts")
	ErrTargetNotFound       = errors.New("target not found")
	ErrTargetDuplicate      = errors.New("target with same host+port already in group")
)

const tgColumns = `id, name, protocol, verify_tls, algorithm,
    health_check_enabled, health_check_path, health_check_method,
    health_check_expect_status, health_check_interval_seconds,
    health_check_timeout_seconds, health_check_fails_to_unhealthy,
    health_check_passes_to_healthy, created_at, updated_at`

// ListTargetGroups returns every target group. When withTargets is
// true, each row's Targets slice is populated; otherwise only counts.
func ListTargetGroups(ctx context.Context, d *sql.DB, withTargets bool) ([]models.TargetGroup, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT `+tgColumns+`,
		        (SELECT COUNT(*) FROM targets WHERE target_group_id = target_groups.id) AS cnt,
		        (SELECT COUNT(*) FROM targets WHERE target_group_id = target_groups.id AND enabled = 1) AS enabled_cnt
		   FROM target_groups
		   ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("query target_groups: %w", err)
	}
	defer rows.Close()

	var out []models.TargetGroup
	for rows.Next() {
		tg, err := scanTargetGroupWithCounts(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, tg)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if withTargets {
		for i := range out {
			ts, err := listTargetsForGroup(ctx, d, out[i].ID)
			if err != nil {
				return nil, err
			}
			out[i].Targets = ts
		}
	}
	return out, nil
}

// GetTargetGroup returns one target group with its targets hydrated.
func GetTargetGroup(ctx context.Context, d *sql.DB, id int64) (models.TargetGroup, error) {
	row := d.QueryRowContext(ctx,
		`SELECT `+tgColumns+`,
		        (SELECT COUNT(*) FROM targets WHERE target_group_id = target_groups.id) AS cnt,
		        (SELECT COUNT(*) FROM targets WHERE target_group_id = target_groups.id AND enabled = 1) AS enabled_cnt
		   FROM target_groups
		  WHERE id = ?`, id)
	tg, err := scanTargetGroupWithCounts(row)
	if errors.Is(err, sql.ErrNoRows) {
		return models.TargetGroup{}, ErrTargetGroupNotFound
	}
	if err != nil {
		return models.TargetGroup{}, err
	}
	ts, err := listTargetsForGroup(ctx, d, tg.ID)
	if err != nil {
		return models.TargetGroup{}, err
	}
	tg.Targets = ts
	return tg, nil
}

// CreateTargetGroup inserts a TG plus any initial targets in one tx.
func CreateTargetGroup(ctx context.Context, d *sql.DB, tg models.TargetGroup, initial []models.Target) (models.TargetGroup, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return models.TargetGroup{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	id, err := insertTargetGroupTx(ctx, tx, tg)
	if err != nil {
		return models.TargetGroup{}, err
	}
	for _, t := range initial {
		t.TargetGroupID = id
		if _, err := insertTargetTx(ctx, tx, t); err != nil {
			return models.TargetGroup{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return models.TargetGroup{}, fmt.Errorf("commit: %w", err)
	}
	return GetTargetGroup(ctx, d, id)
}

func insertTargetGroupTx(ctx context.Context, tx *sql.Tx, tg models.TargetGroup) (int64, error) {
	res, err := tx.ExecContext(ctx,
		`INSERT INTO target_groups
		    (name, protocol, verify_tls, algorithm,
		     health_check_enabled, health_check_path, health_check_method,
		     health_check_expect_status, health_check_interval_seconds,
		     health_check_timeout_seconds, health_check_fails_to_unhealthy,
		     health_check_passes_to_healthy)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		tg.Name, string(tg.Protocol), boolToInt(tg.VerifyTLS), string(tg.Algorithm),
		boolToInt(tg.HealthCheckEnabled), tg.HealthCheckPath, string(tg.HealthCheckMethod),
		tg.HealthCheckExpectStatus, tg.HealthCheckIntervalSeconds,
		tg.HealthCheckTimeoutSeconds, tg.HealthCheckFailsToUnhealthy,
		tg.HealthCheckPassesToHealthy,
	)
	if err != nil {
		if isTGNameUnique(err) {
			return 0, ErrTargetGroupNameTaken
		}
		return 0, fmt.Errorf("insert target_group: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("last insert id: %w", err)
	}
	return id, nil
}

// UpdateTargetGroup overwrites the config fields of a TG; targets
// management happens through the dedicated helpers.
func UpdateTargetGroup(ctx context.Context, d *sql.DB, tg models.TargetGroup) (models.TargetGroup, error) {
	res, err := d.ExecContext(ctx,
		`UPDATE target_groups
		    SET name = ?, protocol = ?, verify_tls = ?, algorithm = ?,
		        health_check_enabled = ?, health_check_path = ?, health_check_method = ?,
		        health_check_expect_status = ?, health_check_interval_seconds = ?,
		        health_check_timeout_seconds = ?, health_check_fails_to_unhealthy = ?,
		        health_check_passes_to_healthy = ?,
		        updated_at = CURRENT_TIMESTAMP
		  WHERE id = ?`,
		tg.Name, string(tg.Protocol), boolToInt(tg.VerifyTLS), string(tg.Algorithm),
		boolToInt(tg.HealthCheckEnabled), tg.HealthCheckPath, string(tg.HealthCheckMethod),
		tg.HealthCheckExpectStatus, tg.HealthCheckIntervalSeconds,
		tg.HealthCheckTimeoutSeconds, tg.HealthCheckFailsToUnhealthy,
		tg.HealthCheckPassesToHealthy, tg.ID,
	)
	if err != nil {
		if isTGNameUnique(err) {
			return models.TargetGroup{}, ErrTargetGroupNameTaken
		}
		return models.TargetGroup{}, fmt.Errorf("update target_group: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return models.TargetGroup{}, err
	}
	if n == 0 {
		return models.TargetGroup{}, ErrTargetGroupNotFound
	}
	return GetTargetGroup(ctx, d, tg.ID)
}

// DeleteTargetGroup removes a TG if it is not referenced by any host.
// ErrTargetGroupInUse leaves the row intact.
func DeleteTargetGroup(ctx context.Context, d *sql.DB, id int64) error {
	n, err := CountHostsUsingTargetGroup(ctx, d, id)
	if err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("%w: %d hosts reference it", ErrTargetGroupInUse, n)
	}
	res, err := d.ExecContext(ctx, `DELETE FROM target_groups WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete target_group: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrTargetGroupNotFound
	}
	return nil
}

// CountHostsUsingTargetGroup is handy both for DeleteTargetGroup and
// for surfacing the "in use by N hosts" message in the API layer.
func CountHostsUsingTargetGroup(ctx context.Context, d *sql.DB, id int64) (int, error) {
	var n int
	if err := d.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM hosts WHERE target_group_id = ?`, id,
	).Scan(&n); err != nil {
		return 0, fmt.Errorf("count hosts: %w", err)
	}
	return n, nil
}

// --- targets ---

func listTargetsForGroup(ctx context.Context, d *sql.DB, tgID int64) ([]models.Target, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT id, target_group_id, host, port, weight, enabled, created_at, updated_at
		   FROM targets
		  WHERE target_group_id = ?
		  ORDER BY id ASC`, tgID)
	if err != nil {
		return nil, fmt.Errorf("query targets: %w", err)
	}
	defer rows.Close()
	var out []models.Target
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetTarget returns a target by id.
func GetTarget(ctx context.Context, d *sql.DB, id int64) (models.Target, error) {
	row := d.QueryRowContext(ctx,
		`SELECT id, target_group_id, host, port, weight, enabled, created_at, updated_at
		   FROM targets WHERE id = ?`, id)
	t, err := scanTarget(row)
	if errors.Is(err, sql.ErrNoRows) {
		return models.Target{}, ErrTargetNotFound
	}
	if err != nil {
		return models.Target{}, err
	}
	return t, nil
}

// AddTarget inserts a target into an existing target group.
func AddTarget(ctx context.Context, d *sql.DB, t models.Target) (models.Target, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return models.Target{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	id, err := insertTargetTx(ctx, tx, t)
	if err != nil {
		return models.Target{}, err
	}
	if err := tx.Commit(); err != nil {
		return models.Target{}, fmt.Errorf("commit: %w", err)
	}
	return GetTarget(ctx, d, id)
}

func insertTargetTx(ctx context.Context, tx *sql.Tx, t models.Target) (int64, error) {
	// Verify the target group exists so we return a clean 404 rather than
	// a confusing FK violation from SQLite.
	var exists int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM target_groups WHERE id = ?`, t.TargetGroupID,
	).Scan(&exists); err != nil {
		return 0, fmt.Errorf("check target_group exists: %w", err)
	}
	if exists == 0 {
		return 0, ErrTargetGroupNotFound
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO targets (target_group_id, host, port, weight, enabled)
		 VALUES (?, ?, ?, ?, ?)`,
		t.TargetGroupID, t.Host, t.Port, t.Weight, boolToInt(t.Enabled),
	)
	if err != nil {
		if isTargetUnique(err) {
			return 0, ErrTargetDuplicate
		}
		return 0, fmt.Errorf("insert target: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("last insert id: %w", err)
	}
	return id, nil
}

// UpdateTarget overwrites host/port/weight/enabled by id.
func UpdateTarget(ctx context.Context, d *sql.DB, t models.Target) (models.Target, error) {
	res, err := d.ExecContext(ctx,
		`UPDATE targets
		    SET host = ?, port = ?, weight = ?, enabled = ?,
		        updated_at = CURRENT_TIMESTAMP
		  WHERE id = ?`,
		t.Host, t.Port, t.Weight, boolToInt(t.Enabled), t.ID,
	)
	if err != nil {
		if isTargetUnique(err) {
			return models.Target{}, ErrTargetDuplicate
		}
		return models.Target{}, fmt.Errorf("update target: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return models.Target{}, err
	}
	if n == 0 {
		return models.Target{}, ErrTargetNotFound
	}
	return GetTarget(ctx, d, t.ID)
}

// DeleteTarget removes one target.
func DeleteTarget(ctx context.Context, d *sql.DB, id int64) error {
	res, err := d.ExecContext(ctx, `DELETE FROM targets WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete target: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrTargetNotFound
	}
	return nil
}

// ToggleTarget flips enabled.
func ToggleTarget(ctx context.Context, d *sql.DB, id int64) (models.Target, error) {
	res, err := d.ExecContext(ctx,
		`UPDATE targets
		    SET enabled = CASE enabled WHEN 1 THEN 0 ELSE 1 END,
		        updated_at = CURRENT_TIMESTAMP
		  WHERE id = ?`, id)
	if err != nil {
		return models.Target{}, fmt.Errorf("toggle target: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return models.Target{}, err
	}
	if n == 0 {
		return models.Target{}, ErrTargetNotFound
	}
	return GetTarget(ctx, d, id)
}

// --- scanners ---

func scanTargetGroupWithCounts(s scanner) (models.TargetGroup, error) {
	var (
		tg                models.TargetGroup
		protocol          string
		algorithm         string
		method            string
		verifyTLS         int
		hcEnabled         int
		total             int
		enabledCnt        int
	)
	if err := s.Scan(
		&tg.ID, &tg.Name, &protocol, &verifyTLS, &algorithm,
		&hcEnabled, &tg.HealthCheckPath, &method,
		&tg.HealthCheckExpectStatus, &tg.HealthCheckIntervalSeconds,
		&tg.HealthCheckTimeoutSeconds, &tg.HealthCheckFailsToUnhealthy,
		&tg.HealthCheckPassesToHealthy, &tg.CreatedAt, &tg.UpdatedAt,
		&total, &enabledCnt,
	); err != nil {
		return models.TargetGroup{}, err
	}
	tg.Protocol = models.Protocol(protocol)
	tg.Algorithm = models.Algorithm(algorithm)
	tg.HealthCheckMethod = models.HealthCheckMethod(method)
	tg.VerifyTLS = verifyTLS == 1
	tg.HealthCheckEnabled = hcEnabled == 1
	tg.TargetsCount = total
	tg.TargetsEnabledCount = enabledCnt
	return tg, nil
}

func scanTarget(s scanner) (models.Target, error) {
	var (
		t       models.Target
		enabled int
	)
	if err := s.Scan(
		&t.ID, &t.TargetGroupID, &t.Host, &t.Port, &t.Weight, &enabled,
		&t.CreatedAt, &t.UpdatedAt,
	); err != nil {
		return models.Target{}, err
	}
	t.Enabled = enabled == 1
	return t, nil
}

// --- constraint sniffing ---

func isTGNameUnique(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "target_groups.name") &&
		(strings.Contains(msg, "UNIQUE") || strings.Contains(msg, "constraint failed"))
}

func isTargetUnique(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "targets") && strings.Contains(msg, "host") &&
		strings.Contains(msg, "port") &&
		(strings.Contains(msg, "UNIQUE") || strings.Contains(msg, "constraint failed"))
}
