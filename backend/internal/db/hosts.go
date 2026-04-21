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

// ErrTargetGroupRequired is returned when a host row needs a TG but
// the reference is missing (should not happen now that the column is
// NOT NULL, but the repo still guards against it defensively).
var ErrTargetGroupRequired = errors.New("host must reference a target group")

// hostColumns selects the full host row plus the embedded target
// group summary (id, name, protocol, algorithm, counts) in a single
// query so the hosts endpoint avoids an N+1.
const hostColumns = `h.id, h.domain, h.target_group_id, h.tls_mode, h.tls_email,
    h.enabled, h.auth_required, h.tls_acme_ca_url, h.tls_challenge,
    h.tls_dns_provider,
    h.created_at, h.updated_at,
    tg.name, tg.protocol, tg.algorithm,
    (SELECT COUNT(*) FROM targets WHERE target_group_id = tg.id) AS tg_cnt,
    (SELECT COUNT(*) FROM targets WHERE target_group_id = tg.id AND enabled = 1) AS tg_enabled_cnt`

// ListHosts returns every host with its target group summary embedded
// and RulesCount populated via a single batched query.
func ListHosts(ctx context.Context, d *sql.DB) ([]models.Host, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT `+hostColumns+`
		 FROM hosts h
		 JOIN target_groups tg ON tg.id = h.target_group_id
		 ORDER BY h.domain ASC`)
	if err != nil {
		return nil, fmt.Errorf("query hosts: %w", err)
	}
	defer rows.Close()

	var out []models.Host
	var ids []int64
	for rows.Next() {
		h, err := scanHostWithTG(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
		ids = append(ids, h.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	counts, err := CountRulesByHostBatch(ctx, d, ids)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].RulesCount = counts[out[i].ID]
	}
	return out, nil
}

// ListEnabledHosts is the input the reconciler needs at startup.
// Disabled hosts are skipped; hosts whose target group has no enabled
// targets are left for the caddycfg layer to warn about (they still
// belong in state, they just contribute no upstreams).
func ListEnabledHosts(ctx context.Context, d *sql.DB) ([]models.Host, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT `+hostColumns+`
		 FROM hosts h
		 JOIN target_groups tg ON tg.id = h.target_group_id
		 WHERE h.enabled = 1
		 ORDER BY h.domain ASC`)
	if err != nil {
		return nil, fmt.Errorf("query enabled hosts: %w", err)
	}
	defer rows.Close()

	var out []models.Host
	for rows.Next() {
		h, err := scanHostWithTG(rows)
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
		`SELECT `+hostColumns+`
		 FROM hosts h
		 JOIN target_groups tg ON tg.id = h.target_group_id
		 WHERE h.id = ?`, id)
	h, err := scanHostWithTG(row)
	if errors.Is(err, sql.ErrNoRows) {
		return models.Host{}, ErrNotFound
	}
	if err != nil {
		return models.Host{}, err
	}
	count, err := CountRulesByHost(ctx, d, h.ID)
	if err != nil {
		return models.Host{}, err
	}
	h.RulesCount = count
	return h, nil
}

// CreateHost inserts a new host bound to an existing target group.
// A default host_security row is created in the same transaction so the
// Security page has something to render without a second call.
func CreateHost(ctx context.Context, d *sql.DB, h models.Host) (models.Host, error) {
	if h.TargetGroupID <= 0 {
		return models.Host{}, ErrTargetGroupRequired
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return models.Host{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx,
		`INSERT INTO hosts (domain, target_group_id, tls_mode, tls_email, enabled, auth_required, tls_acme_ca_url, tls_challenge, tls_dns_provider)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		h.Domain, h.TargetGroupID, string(h.TLSMode), h.TLSEmail, boolToInt(h.Enabled), boolToInt(h.AuthRequired),
		h.TLSACMECAURL, string(tlsChallengeOrDefault(h)), tlsDNSProviderOrDefault(h),
	)
	if err != nil {
		if isHostDomainUnique(err) {
			return models.Host{}, ErrDomainTaken
		}
		return models.Host{}, fmt.Errorf("insert host: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return models.Host{}, fmt.Errorf("last insert id: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO host_security (host_id) VALUES (?)`, id,
	); err != nil {
		return models.Host{}, fmt.Errorf("seed host_security: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return models.Host{}, fmt.Errorf("commit: %w", err)
	}
	return GetHost(ctx, d, id)
}

// CreateHostWithTargetGroup builds a target group (plus targets) and
// the host in a single transaction, so the inline-TG path in POST
// /api/hosts rolls back cleanly if any step fails.
func CreateHostWithTargetGroup(
	ctx context.Context,
	d *sql.DB,
	tg models.TargetGroup,
	targets []models.Target,
	host models.Host,
) (models.Host, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return models.Host{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	tgID, err := insertTargetGroupTx(ctx, tx, tg)
	if err != nil {
		return models.Host{}, err
	}
	for _, t := range targets {
		t.TargetGroupID = tgID
		if _, err := insertTargetTx(ctx, tx, t); err != nil {
			return models.Host{}, err
		}
	}

	res, err := tx.ExecContext(ctx,
		`INSERT INTO hosts (domain, target_group_id, tls_mode, tls_email, enabled, auth_required, tls_acme_ca_url, tls_challenge, tls_dns_provider)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		host.Domain, tgID, string(host.TLSMode), host.TLSEmail, boolToInt(host.Enabled), boolToInt(host.AuthRequired),
		host.TLSACMECAURL, string(tlsChallengeOrDefault(host)), tlsDNSProviderOrDefault(host),
	)
	if err != nil {
		if isHostDomainUnique(err) {
			return models.Host{}, ErrDomainTaken
		}
		return models.Host{}, fmt.Errorf("insert host: %w", err)
	}
	hostID, err := res.LastInsertId()
	if err != nil {
		return models.Host{}, fmt.Errorf("last insert id: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO host_security (host_id) VALUES (?)`, hostID,
	); err != nil {
		return models.Host{}, fmt.Errorf("seed host_security: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return models.Host{}, fmt.Errorf("commit: %w", err)
	}
	return GetHost(ctx, d, hostID)
}

// UpdateHost overwrites the mutable fields on an existing row.
func UpdateHost(ctx context.Context, d *sql.DB, h models.Host) (models.Host, error) {
	if h.TargetGroupID <= 0 {
		return models.Host{}, ErrTargetGroupRequired
	}
	res, err := d.ExecContext(ctx,
		`UPDATE hosts
		    SET domain = ?, target_group_id = ?, tls_mode = ?, tls_email = ?,
		        enabled = ?, auth_required = ?, tls_acme_ca_url = ?,
		        tls_challenge = ?, tls_dns_provider = ?,
		        updated_at = CURRENT_TIMESTAMP
		  WHERE id = ?`,
		h.Domain, h.TargetGroupID, string(h.TLSMode), h.TLSEmail,
		boolToInt(h.Enabled), boolToInt(h.AuthRequired), h.TLSACMECAURL,
		string(tlsChallengeOrDefault(h)), tlsDNSProviderOrDefault(h), h.ID,
	)
	if err != nil {
		if isHostDomainUnique(err) {
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

func scanHostWithTG(s scanner) (models.Host, error) {
	var (
		h         models.Host
		enabled   int
		authReq   int
		tlsMode   string
		tgName    string
		tgProto   string
		tgAlgo    string
		tgCount   int
		tgEnabled int
	)
	var tlsChallenge string
	var tlsDNSProvider string
	if err := s.Scan(
		&h.ID, &h.Domain, &h.TargetGroupID, &tlsMode, &h.TLSEmail, &enabled, &authReq,
		&h.TLSACMECAURL, &tlsChallenge, &tlsDNSProvider,
		&h.CreatedAt, &h.UpdatedAt,
		&tgName, &tgProto, &tgAlgo, &tgCount, &tgEnabled,
	); err != nil {
		return models.Host{}, err
	}
	h.TLSMode = models.TLSMode(tlsMode)
	h.TLSChallenge = models.TLSChallenge(tlsChallenge)
	h.TLSDNSProvider = tlsDNSProvider
	h.Enabled = enabled == 1
	h.AuthRequired = authReq == 1
	h.TargetGroup = &models.TargetGroupSummary{
		ID:                  h.TargetGroupID,
		Name:                tgName,
		Protocol:            models.Protocol(tgProto),
		Algorithm:           models.Algorithm(tgAlgo),
		TargetsCount:        tgCount,
		TargetsEnabledCount: tgEnabled,
	}
	return h, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// tlsChallengeOrDefault normalises TLSChallenge for writes: an empty
// value (zero-value struct, or an out-of-band write that skipped the
// field) falls back to "dns" so the CHECK constraint does not reject
// the row. The API layer is the real validator; this guard keeps a
// bad caller from breaking the row-insert.
func tlsChallengeOrDefault(h models.Host) models.TLSChallenge {
	switch h.TLSChallenge {
	case models.TLSChallengeDNS, models.TLSChallengeHTTP, models.TLSChallengeTLSALPN:
		return h.TLSChallenge
	}
	return models.TLSChallengeDNS
}

// tlsDNSProviderOrDefault mirrors tlsChallengeOrDefault for the v1.3
// provider column: empty falls back to cloudflare so the NOT NULL +
// DEFAULT constraint in migration 025 is never violated by a caller
// that forgot to populate the field. The catalogue + API layer do
// the actual validation against enabled providers; this just
// protects the row-level write.
func tlsDNSProviderOrDefault(h models.Host) string {
	if h.TLSDNSProvider == "" {
		return "cloudflare"
	}
	return h.TLSDNSProvider
}

func isHostDomainUnique(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "hosts.domain") &&
		(strings.Contains(msg, "UNIQUE") || strings.Contains(msg, "constraint failed"))
}
