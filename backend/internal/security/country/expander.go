// Package country implements panel-side expansion of operator-issued
// country bans into the equivalent list of scope=Range LAPI
// decisions, which the upstream caddy-crowdsec-bouncer plugin
// handles natively (it does NOT handle scope=Country in either
// stream or live mode -- see project memory entry
// project_caddy_bouncer_stream_mode.md for the upstream-source
// citation).
//
// One country expansion = one row in the country_ban_expansions
// table + N LAPI decisions tagged origin=argos-country-XX. Revoke
// drops them via a single DELETE /v1/decisions?origins=...
package country

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/crowdsec"
)

// CIDRSource resolves a country code into the list of CIDR blocks
// that map to that country in the panel's GeoIP database. The
// production implementation iterates the embedded country.mmdb;
// tests inject a fake to avoid bundling test fixtures.
type CIDRSource interface {
	// ListCIDRs returns the CIDR strings (IPv4 + IPv6) for the
	// given ISO 3166-1 alpha-2 country code, plus the GeoIP DB
	// version string at lookup time. Order is implementation-
	// defined; the Expander does not depend on any particular
	// order.
	ListCIDRs(countryCode string) (cidrs []string, version string, err error)
}

// LAPIWriter is the subset of crowdsec.Client the expander needs.
// Declared as an interface here so tests can stub it without
// spinning up a real LAPI; production callers pass *crowdsec.Client.
//
// AddRangeDecisions takes the full slice and emits one /v1/alerts
// POST -- v1.3.22 collapsed N sequential roundtrips into one batch
// because the per-roundtrip latency was the actual root cause of
// the country-expansion stuck-UI bug, not the count itself.
type LAPIWriter interface {
	AddRangeDecisions(ctx context.Context, ins []crowdsec.AddRangeDecisionInput) error
	DeleteDecisionsByOrigin(ctx context.Context, origin string) (int, error)
}

// Expander binds a CIDR source, an LAPI writer, and the panel DB.
// All three are required; New() does not validate them so callers
// who omit one will get nil-deref at first use rather than a quiet
// no-op.
type Expander struct {
	DB     *sql.DB
	LAPI   LAPIWriter
	Source CIDRSource
}

// BanResult is the public summary of a successful Ban call. Useful
// for the API layer to render in the response body without re-
// querying the table.
type BanResult struct {
	CountryCode  string `json:"country_code"`
	CIDRCount    int    `json:"cidr_count"`
	MMDBVersion  string `json:"mmdb_version"`
	ExpansionID  int64  `json:"expansion_id"`
	OriginTag    string `json:"origin_tag"`
	ReplacedRows int    `json:"replaced_rows,omitempty"`
}

// Expansion is the read-shape returned by List. Mirrors the table
// row 1:1 except the JSON-array column is decoded into a Go slice.
type Expansion struct {
	ID                    int64     `json:"id"`
	CountryCode           string    `json:"country_code"`
	CIDRs                 []string  `json:"cidrs"`
	CIDRCount             int       `json:"cidr_count"`
	Reason                string    `json:"reason"`
	Duration              string    `json:"duration"`
	CreatedAt             time.Time `json:"created_at"`
	CreatedBy             string    `json:"created_by"`
	MMDBVersionAtCreation string    `json:"mmdb_version_at_creation"`
}

// ErrCountryNotFound means the GeoIP DB returned zero CIDRs for the
// supplied code. Either the code is wrong (should be ISO 3166-1
// alpha-2 like "BR", "DE") or the DB shipped without that country.
// Surfaced as 404 by the API layer.
var ErrCountryNotFound = errors.New("country not found in geoip database")

// originPrefix is the LAPI decision origin that tags every Range
// decision the expander emits. Revocation matches on this prefix
// so a single DELETE /v1/decisions?origins=... clears the country.
const originPrefix = "argos-country-"

// originFor builds the per-country origin tag. Always upper-cases
// the code so "br" and "BR" land in the same expansion row.
func originFor(code string) string {
	return originPrefix + strings.ToUpper(code)
}

// Ban expands the country code, pushes one Range decision per CIDR
// to LAPI, and persists the tracking row. Idempotent on country_code:
// if a row already exists, its decisions are revoked first and the
// row is replaced -- the new MMDB version is recorded.
//
// durationGoString must parse as a Go time.Duration (e.g. "4h",
// "168h", "8760h"). LAPI wants integer hours; the conversion lives
// here so the API layer can pass through the operator's literal.
func (e *Expander) Ban(
	ctx context.Context,
	countryCode string,
	durationGoString string,
	reason string,
	createdBy string,
) (*BanResult, error) {
	code := strings.ToUpper(strings.TrimSpace(countryCode))
	if !isValidISOCode(code) {
		return nil, fmt.Errorf("country_code must be ISO 3166-1 alpha-2 (got %q)", countryCode)
	}
	dur, err := time.ParseDuration(durationGoString)
	if err != nil {
		return nil, fmt.Errorf("duration: %w", err)
	}
	hours := int(dur.Hours())
	if hours <= 0 {
		return nil, fmt.Errorf("duration must be at least 1h (got %q)", durationGoString)
	}

	cidrs, mmdbVersion, err := e.Source.ListCIDRs(code)
	if err != nil {
		return nil, fmt.Errorf("source: %w", err)
	}
	if len(cidrs) == 0 {
		return nil, ErrCountryNotFound
	}

	// Idempotency: if there is an existing expansion for this code,
	// revoke its LAPI decisions first so we don't double-stack. The
	// row itself is replaced by the INSERT OR REPLACE below.
	var existing int
	_ = e.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM country_ban_expansions WHERE country_code = ?`, code,
	).Scan(&existing)
	if existing > 0 {
		if _, derr := e.LAPI.DeleteDecisionsByOrigin(ctx, originFor(code)); derr != nil {
			return nil, fmt.Errorf("revoke previous expansion: %w", derr)
		}
	}

	// Push every CIDR in ONE /v1/alerts batch (v1.3.22). LAPI
	// processes the batch atomically: either the full N decisions
	// land, or LAPI rejects the whole array. No partial-state to
	// clean up on success -- but we still call DeleteDecisionsByOrigin
	// on error as a defence against any LAPI build that processes
	// partials anyway.
	tagged := originFor(code)
	batch := make([]crowdsec.AddRangeDecisionInput, 0, len(cidrs))
	for _, cidr := range cidrs {
		batch = append(batch, crowdsec.AddRangeDecisionInput{
			CIDR:          cidr,
			Reason:        fmt.Sprintf("country=%s [auto-expanded] %s", code, reason),
			Origin:        tagged,
			DurationHours: hours,
		})
	}
	if err := e.LAPI.AddRangeDecisions(ctx, batch); err != nil {
		_, _ = e.LAPI.DeleteDecisionsByOrigin(ctx, tagged)
		return nil, fmt.Errorf("push %d decisions: %w", len(cidrs), err)
	}

	// Persist the tracking row. INSERT OR REPLACE replaces any
	// pre-existing row for this country_code (UNIQUE constraint
	// on country_code makes the conflict deterministic).
	cidrJSON, err := json.Marshal(cidrs)
	if err != nil {
		return nil, fmt.Errorf("marshal cidrs: %w", err)
	}
	res, err := e.DB.ExecContext(ctx, `
		INSERT INTO country_ban_expansions
			(country_code, decision_ids, cidr_count, reason, duration,
			 created_by, mmdb_version_at_creation)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(country_code) DO UPDATE SET
			decision_ids = excluded.decision_ids,
			cidr_count = excluded.cidr_count,
			reason = excluded.reason,
			duration = excluded.duration,
			created_at = CURRENT_TIMESTAMP,
			created_by = excluded.created_by,
			mmdb_version_at_creation = excluded.mmdb_version_at_creation
	`, code, string(cidrJSON), len(cidrs), reason, durationGoString, createdBy, mmdbVersion)
	if err != nil {
		// Roll back the LAPI side too -- otherwise we leak decisions
		// the panel doesn't track.
		_, _ = e.LAPI.DeleteDecisionsByOrigin(ctx, tagged)
		return nil, fmt.Errorf("persist tracking row: %w", err)
	}
	id, _ := res.LastInsertId()

	out := &BanResult{
		CountryCode:  code,
		CIDRCount:    len(cidrs),
		MMDBVersion:  mmdbVersion,
		ExpansionID:  id,
		OriginTag:    tagged,
		ReplacedRows: existing,
	}
	return out, nil
}

// Revoke drops every LAPI decision tagged with the country's origin
// and removes the tracking row. Idempotent: missing row returns nil
// (the operator already cleaned up; complaining adds noise to the UI).
func (e *Expander) Revoke(ctx context.Context, countryCode string) (removed int, err error) {
	code := strings.ToUpper(strings.TrimSpace(countryCode))
	if !isValidISOCode(code) {
		return 0, fmt.Errorf("country_code must be ISO 3166-1 alpha-2 (got %q)", countryCode)
	}
	tagged := originFor(code)
	removed, err = e.LAPI.DeleteDecisionsByOrigin(ctx, tagged)
	if err != nil {
		return 0, fmt.Errorf("delete decisions: %w", err)
	}
	if _, err := e.DB.ExecContext(ctx,
		`DELETE FROM country_ban_expansions WHERE country_code = ?`, code,
	); err != nil {
		return removed, fmt.Errorf("delete tracking row: %w", err)
	}
	return removed, nil
}

// List returns every active expansion row for the UI. The CIDR
// list is decoded into Go strings so the front-end can render
// counts / sample addresses without re-parsing JSON.
func (e *Expander) List(ctx context.Context) ([]Expansion, error) {
	rows, err := e.DB.QueryContext(ctx, `
		SELECT id, country_code, decision_ids, cidr_count, reason,
		       duration, created_at, created_by, mmdb_version_at_creation
		  FROM country_ban_expansions
		 ORDER BY country_code ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()
	var out []Expansion
	for rows.Next() {
		var e Expansion
		var cidrJSON string
		if err := rows.Scan(
			&e.ID, &e.CountryCode, &cidrJSON, &e.CIDRCount,
			&e.Reason, &e.Duration, &e.CreatedAt, &e.CreatedBy,
			&e.MMDBVersionAtCreation,
		); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		_ = json.Unmarshal([]byte(cidrJSON), &e.CIDRs)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// isValidISOCode is permissive on purpose: the GeoIP DB will reject
// unknown codes by returning zero CIDRs (which surfaces as
// ErrCountryNotFound). The check here just keeps obvious garbage
// (lowercase, numbers, three-letter codes) from reaching the DB.
func isValidISOCode(s string) bool {
	if len(s) != 2 {
		return false
	}
	for _, r := range s {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}

// preserveStrconv keeps strconv referenced if a future change wants
// to parse integer hour overrides directly. Today the duration
// arrives as a Go duration string and gets parsed via time.Parse,
// so strconv is unused -- but the import line costs nothing and
// removes a future-friction edit.
var _ = strconv.Itoa
