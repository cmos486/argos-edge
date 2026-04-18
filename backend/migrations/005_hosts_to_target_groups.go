package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
)

// up005HostsToTargetGroups migrates every phase-1 host row (domain +
// upstream_url + upstream_verify_tls) into an auto-generated target
// group with exactly one target, then rewrites the hosts table to drop
// the upstream columns and make target_group_id NOT NULL.
//
// The whole operation runs in a single transaction. Any failure — a
// row we can't parse, a collision we can't resolve, a host that ends
// up without a target_group_id — aborts and rolls back, leaving the
// database in its phase-1 state so the operator can fix the offending
// row and retry.
func up005HostsToTargetGroups(ctx context.Context, d *sql.DB) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Step 1: add the nullable FK column; we backfill next and only
	// then rewrite the table to make it NOT NULL.
	if _, err := tx.ExecContext(ctx,
		`ALTER TABLE hosts ADD COLUMN target_group_id INTEGER
		 REFERENCES target_groups(id) ON DELETE RESTRICT`,
	); err != nil {
		return fmt.Errorf("add target_group_id: %w", err)
	}

	rows, err := tx.QueryContext(ctx,
		`SELECT id, domain, upstream_url, upstream_verify_tls
		 FROM hosts
		 ORDER BY id`,
	)
	if err != nil {
		return fmt.Errorf("select hosts: %w", err)
	}

	type hostRow struct {
		id        int64
		domain    string
		upstream  string
		verifyTLS int
	}
	var hosts []hostRow
	for rows.Next() {
		var h hostRow
		if err := rows.Scan(&h.id, &h.domain, &h.upstream, &h.verifyTLS); err != nil {
			rows.Close()
			return fmt.Errorf("scan host row: %w", err)
		}
		hosts = append(hosts, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iter hosts: %w", err)
	}

	// Step 2: for every host with a non-empty upstream_url, create a
	// dedicated target group and target, then wire the host to it.
	for _, h := range hosts {
		if h.upstream == "" {
			return fmt.Errorf("host id=%d domain=%q has empty upstream_url; cannot migrate",
				h.id, h.domain)
		}
		scheme, host, port, err := parseUpstream(h.upstream)
		if err != nil {
			return fmt.Errorf("host id=%d domain=%q upstream=%q: %w",
				h.id, h.domain, h.upstream, err)
		}

		tgName, err := uniqueTGName(ctx, tx, h.domain, h.id)
		if err != nil {
			return err
		}
		var tgID int64
		err = tx.QueryRowContext(ctx,
			`INSERT INTO target_groups
			     (name, protocol, verify_tls, algorithm, health_check_enabled)
			 VALUES (?, ?, ?, 'round_robin', 0)
			 RETURNING id`,
			tgName, scheme, h.verifyTLS,
		).Scan(&tgID)
		if err != nil {
			return fmt.Errorf("insert target_group for host %d: %w", h.id, err)
		}

		if _, err := tx.ExecContext(ctx,
			`INSERT INTO targets (target_group_id, host, port, weight, enabled)
			 VALUES (?, ?, ?, 1, 1)`,
			tgID, host, port,
		); err != nil {
			return fmt.Errorf("insert target for host %d: %w", h.id, err)
		}

		if _, err := tx.ExecContext(ctx,
			`UPDATE hosts SET target_group_id = ? WHERE id = ?`, tgID, h.id,
		); err != nil {
			return fmt.Errorf("link host %d to tg %d: %w", h.id, tgID, err)
		}

		slog.Info("migrated host to target group",
			"host_id", h.id, "domain", h.domain, "target_group_id", tgID,
			"target", fmt.Sprintf("%s://%s:%d", scheme, host, port))
	}

	// Step 3: safety net — every host must now be linked.
	var unlinked int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM hosts WHERE target_group_id IS NULL`,
	).Scan(&unlinked); err != nil {
		return fmt.Errorf("count unlinked hosts: %w", err)
	}
	if unlinked != 0 {
		return fmt.Errorf("%d hosts still without target_group_id after migration; aborting",
			unlinked)
	}

	// Step 4: rebuild the hosts table without the upstream columns and
	// with target_group_id NOT NULL. SQLite does not support ALTER
	// COLUMN, so we recreate and swap.
	stmts := []string{
		`CREATE TABLE hosts_new (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			domain          TEXT NOT NULL UNIQUE,
			target_group_id INTEGER NOT NULL REFERENCES target_groups(id) ON DELETE RESTRICT,
			tls_mode        TEXT NOT NULL DEFAULT 'auto'
				CHECK (tls_mode IN ('auto', 'none')),
			tls_email       TEXT NOT NULL DEFAULT '',
			enabled         INTEGER NOT NULL DEFAULT 1,
			created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`INSERT INTO hosts_new
		     (id, domain, target_group_id, tls_mode, tls_email, enabled, created_at, updated_at)
		 SELECT id, domain, target_group_id, tls_mode, tls_email, enabled, created_at, updated_at
		 FROM hosts`,
		`DROP INDEX IF EXISTS idx_hosts_enabled`,
		`DROP TABLE hosts`,
		`ALTER TABLE hosts_new RENAME TO hosts`,
		`CREATE INDEX idx_hosts_enabled ON hosts(enabled)`,
		`CREATE INDEX idx_hosts_target_group_id ON hosts(target_group_id)`,
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("rebuild hosts table: %w\nstmt: %s", err, s)
		}
	}

	return tx.Commit()
}

// parseUpstream is a migration-local parser: we cannot depend on the
// panel's caddycfg package here (import cycle via db). It mirrors the
// http/https + optional port logic used in phase 1.
func parseUpstream(raw string) (scheme, host string, port int, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", 0, fmt.Errorf("parse upstream: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", "", 0, fmt.Errorf("scheme must be http or https, got %q", u.Scheme)
	}
	host = u.Hostname()
	if host == "" {
		return "", "", 0, fmt.Errorf("upstream missing host")
	}
	portStr := u.Port()
	if portStr == "" {
		if u.Scheme == "https" {
			port = 443
		} else {
			port = 80
		}
		return u.Scheme, host, port, nil
	}
	port, err = strconv.Atoi(portStr)
	if err != nil {
		return "", "", 0, fmt.Errorf("parse port: %w", err)
	}
	if port < 1 || port > 65535 {
		return "", "", 0, fmt.Errorf("port %d out of range", port)
	}
	return u.Scheme, host, port, nil
}

// uniqueTGName returns an available target group name built from the
// host's domain. Collisions (a pre-existing TG that happens to share
// the auto name, or two hosts that would otherwise clash) fall back to
// embedding the host id.
func uniqueTGName(ctx context.Context, tx *sql.Tx, domain string, hostID int64) (string, error) {
	candidate := "auto-" + domain
	var n int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM target_groups WHERE name = ?`, candidate,
	).Scan(&n); err != nil {
		return "", fmt.Errorf("check tg name: %w", err)
	}
	if n == 0 {
		return candidate, nil
	}
	fallback := fmt.Sprintf("auto-%d-%s", hostID, domain)
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM target_groups WHERE name = ?`, fallback,
	).Scan(&n); err != nil {
		return "", fmt.Errorf("check fallback tg name: %w", err)
	}
	if n != 0 {
		return "", fmt.Errorf("cannot find unique target_group name for host %d / domain %q",
			hostID, domain)
	}
	return fallback, nil
}
