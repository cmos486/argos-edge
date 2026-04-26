// Package security owns the panel-managed CrowdSec configuration
// files that persist across panel restarts via the shared volume
// (mounted at /data/shared in the panel and /shared in the
// crowdsec container). The files this package writes are picked up
// by setup-appsec.sh on its next run, which transforms them into
// the actual /etc/crowdsec/profiles.yaml and
// /etc/crowdsec/parsers/s02-enrich/argos-whitelist.yaml that
// CrowdSec reads.
//
// CrowdSec does NOT hot-reload profiles or parser changes; the
// operator must run `docker compose exec crowdsec /setup-appsec.sh`
// (or restart the crowdsec container) for new entries to take
// effect. The panel's Edit Host modal + the self-block banner
// surface this requirement.
//
// The shared-volume indirection avoids needing the docker socket
// inside the panel container or extending the container image
// with cscli. v1.3.20+ may revisit if a tighter reload mechanism
// becomes worthwhile.
package security

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cmos486/argos-edge/backend/internal/db"
)

// SharedDir is the in-panel mount point for the volume that
// crowdsec sees as /shared. v1.3.5 introduced it for the machine-
// credentials handoff; v1.3.19 reuses it for the
// true-detect-hosts and whitelist sentinels.
const SharedDir = "/data/shared"

const (
	trueDetectFile         = "argos-true-detect-hosts.txt"
	whitelistFile          = "argos-whitelist-entries.txt"
	disabledScenariosFile  = "argos-disabled-scenarios.txt"
	appsecTuningFile       = "argos-appsec-tuning.txt"
)

// WriteTrueDetectHosts dumps the set of host domains that have
// true_detect_mode=true to /data/shared/argos-true-detect-hosts.txt,
// one domain per line. setup-appsec.sh consumes this on its next
// run to construct the argos-managed entry in profiles.yaml.
//
// Empty file (zero matching hosts) is written explicitly so a
// stale file from a previous toggle gets cleared.
func WriteTrueDetectHosts(ctx context.Context, d *sql.DB) error {
	if _, err := os.Stat(SharedDir); err != nil {
		// Shared volume not mounted (e.g. dev panel running outside
		// docker). Nothing to do; not an error.
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat shared dir: %w", err)
	}

	rows, err := d.QueryContext(ctx,
		`SELECT domain FROM hosts WHERE true_detect_mode = 1 AND enabled = 1 ORDER BY domain ASC`)
	if err != nil {
		return fmt.Errorf("query hosts: %w", err)
	}
	defer rows.Close()
	var domains []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return fmt.Errorf("scan: %w", err)
		}
		domains = append(domains, d)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	body := "# argos-managed: true_detect_mode hosts.\n" +
		"# One hostname per line; consumed by setup-appsec.sh on\n" +
		"# its next run to construct the argos-managed entry of\n" +
		"# /etc/crowdsec/profiles.yaml.\n" +
		"# Operator edits here are overwritten on the next panel\n" +
		"# reconcile -- toggle hosts via the panel UI.\n"
	if len(domains) > 0 {
		body += strings.Join(domains, "\n") + "\n"
	}
	return atomicWrite(filepath.Join(SharedDir, trueDetectFile), body)
}

// WriteWhitelistEntries dumps the manual whitelist rows from the
// security_whitelist table to /data/shared/argos-whitelist-entries.txt
// in `<scope> <value>` format. setup-appsec.sh transforms this into
// /etc/crowdsec/parsers/s02-enrich/argos-whitelist.yaml on its next
// run.
//
// System ranges (RFC 1918 / loopback / ULA) are NOT included here
// -- the script emits those unconditionally.
func WriteWhitelistEntries(ctx context.Context, d *sql.DB) error {
	if _, err := os.Stat(SharedDir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat shared dir: %w", err)
	}

	rows, err := d.QueryContext(ctx,
		`SELECT scope, value FROM security_whitelist ORDER BY id ASC`)
	if err != nil {
		return fmt.Errorf("query whitelist: %w", err)
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var scope, value string
		if err := rows.Scan(&scope, &value); err != nil {
			return fmt.Errorf("scan: %w", err)
		}
		lines = append(lines, fmt.Sprintf("%s %s", scope, value))
	}
	if err := rows.Err(); err != nil {
		return err
	}

	body := "# argos-managed: whitelist entries.\n" +
		"# Format: <scope> <value>  (scope = ip | range)\n" +
		"# Consumed by setup-appsec.sh on its next run; merged with\n" +
		"# the unconditional RFC 1918 / loopback / ULA system entries\n" +
		"# into /etc/crowdsec/parsers/s02-enrich/argos-whitelist.yaml.\n" +
		"# Operator edits here are overwritten on the next panel write.\n"
	if len(lines) > 0 {
		body += strings.Join(lines, "\n") + "\n"
	}
	return atomicWrite(filepath.Join(SharedDir, whitelistFile), body)
}

// AddManualWhitelist inserts a row into security_whitelist and
// rewrites the shared-volume sentinel. Returns ErrDuplicate when
// the (scope, value) pair already exists -- the API layer maps
// that to a 409.
func AddManualWhitelist(ctx context.Context, d *sql.DB, scope, value, reason string) error {
	scope = strings.TrimSpace(scope)
	value = strings.TrimSpace(value)
	if scope != "ip" && scope != "range" {
		return fmt.Errorf("scope must be 'ip' or 'range'")
	}
	if value == "" {
		return fmt.Errorf("value required")
	}
	_, err := d.ExecContext(ctx,
		`INSERT INTO security_whitelist (scope, value, reason) VALUES (?, ?, ?)`,
		scope, value, reason)
	if err != nil {
		// modernc/sqlite returns "UNIQUE constraint failed:..." on
		// duplicate. Surface as a sentinel the API layer can match.
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			return ErrDuplicate
		}
		return fmt.Errorf("insert whitelist: %w", err)
	}
	return WriteWhitelistEntries(ctx, d)
}

// ErrDuplicate is returned by AddManualWhitelist when the (scope,
// value) pair already exists.
var ErrDuplicate = fmt.Errorf("whitelist entry already exists")

// WriteDisabledScenarios materialises the operator's disabled-
// scenario set (CSV stored in settings under
// appsec.disabled_scenarios) into the panel-managed sentinel at
// /data/shared/argos-disabled-scenarios.txt -- one canonical name
// per line, blank lines + #-prefixed comments tolerated.
// setup-appsec.sh reads this on its next run and `cscli scenarios
// remove --force`s each entry.
//
// Empty CSV writes an empty file (header-only) explicitly so a
// stale sentinel from a previous toggle gets cleared. The two
// v1.3.19 hardcoded scenarios (appsec-native, appsec-generic-test)
// stay hardcoded in the script -- this file is for operator-
// managed additions only.
func WriteDisabledScenarios(csv string) error {
	if _, err := os.Stat(SharedDir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat shared dir: %w", err)
	}
	body := "# argos-managed: operator-disabled scenarios.\n" +
		"# One canonical scenario name per line.\n" +
		"# Consumed by setup-appsec.sh: each line gets\n" +
		"# `cscli scenarios remove --force` on the next script run.\n" +
		"# Operator edits here are overwritten on the next panel write.\n"
	for _, raw := range strings.Split(csv, ",") {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		body += s + "\n"
	}
	return atomicWrite(filepath.Join(SharedDir, disabledScenariosFile), body)
}

// AppSecTuning is the panel-side shape of the threshold settings
// the v1.3.25 AppSec tab edits. Mirrors the two SecAction lines
// in argos-tuning.yaml.
type AppSecTuning struct {
	InboundThreshold  int
	OutboundThreshold int
}

// WriteAppSecTuning materialises the operator-tuned thresholds
// into /data/shared/argos-appsec-tuning.txt as a key=value file.
// setup-appsec.sh reads this and regenerates argos-tuning.yaml
// in /etc/crowdsec/appsec-rules/ before the SIGHUP reload.
//
// Empty / zero values are NOT written -- the script falls back
// to the v1.3.19 defaults (inbound 15, outbound 4). This keeps
// the sentinel file optional: an operator who never visits the
// AppSec tab gets the v1.3.19 defaults forever.
func WriteAppSecTuning(t AppSecTuning) error {
	if _, err := os.Stat(SharedDir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat shared dir: %w", err)
	}
	body := "# argos-managed: AppSec tuning thresholds.\n" +
		"# Consumed by setup-appsec.sh to regenerate\n" +
		"# /etc/crowdsec/appsec-rules/argos-tuning.yaml. Empty\n" +
		"# values fall back to the v1.3.19 defaults\n" +
		"# (inbound=15 outbound=4). Operator edits here are\n" +
		"# overwritten on the next panel PATCH.\n"
	if t.InboundThreshold > 0 {
		body += fmt.Sprintf("inbound_threshold=%d\n", t.InboundThreshold)
	}
	if t.OutboundThreshold > 0 {
		body += fmt.Sprintf("outbound_threshold=%d\n", t.OutboundThreshold)
	}
	return atomicWrite(filepath.Join(SharedDir, appsecTuningFile), body)
}

// WhitelistEntry mirrors a security_whitelist row for the API
// layer to render. CreatedAt is the timestamp the panel persisted
// the entry; the matching argos-whitelist.yaml line lands in
// CrowdSec on the next setup-appsec.sh run.
type WhitelistEntry struct {
	ID        int64  `json:"id"`
	Scope     string `json:"scope"`
	Value     string `json:"value"`
	Reason    string `json:"reason"`
	CreatedAt string `json:"created_at"`
}

// ListWhitelist returns every row from security_whitelist for the
// v1.3.23 GET /api/security/whitelist endpoint. Empty list when
// the table is empty; the API maps that to a [].
func ListWhitelist(ctx context.Context, d *sql.DB) ([]WhitelistEntry, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT id, scope, value, reason, created_at FROM security_whitelist
		 ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("query whitelist: %w", err)
	}
	defer rows.Close()
	var out []WhitelistEntry
	for rows.Next() {
		var e WhitelistEntry
		if err := rows.Scan(&e.ID, &e.Scope, &e.Value, &e.Reason, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// DeleteWhitelistByID removes one row by id and rewrites the
// shared sentinel so setup-appsec.sh's next run drops the
// corresponding YAML entry. Returns true if a row was deleted,
// false if the id didn't exist (idempotent).
func DeleteWhitelistByID(ctx context.Context, d *sql.DB, id int64) (bool, error) {
	res, err := d.ExecContext(ctx,
		`DELETE FROM security_whitelist WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("delete whitelist: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return false, nil
	}
	if err := WriteWhitelistEntries(ctx, d); err != nil {
		// The DB delete succeeded -- failing to rewrite the
		// sentinel just means the operator needs to re-run
		// setup-appsec.sh manually. Surface, don't roll back.
		return true, fmt.Errorf("rewrite sentinel: %w", err)
	}
	return true, nil
}

// atomicWrite stages the file via a sibling tempfile then renames
// over the destination. On crash mid-write the operator sees either
// the old contents or the new ones, never a half-written file.
func atomicWrite(path, body string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".argos-tmp-*")
	if err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.WriteString(body); err != nil {
		tmp.Close()
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename tmp: %w", err)
	}
	return nil
}

// PreserveDBImport keeps the db package referenced even if the
// helpers here grow callers that don't import it directly. Avoids
// a stray "imported and not used" failure in a future refactor.
var _ = db.GetSettingValue
