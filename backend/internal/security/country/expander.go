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
	"log/slog"
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

// DefaultChunkSize is the per-/v1/alerts-POST batch size used by
// Ban. v1.3.22 introduced chunking after the empirical finding
// that LAPI's batch insert is NOT atomic at scale: a 21k-alert
// single POST committed ~6.6k alerts before timing out, with no
// rollback. Smaller chunks keep individual LAPI transactions
// short (~12s each at the measured ~40 alerts/sec) and bound the
// blast radius of any single chunk failure.
const DefaultChunkSize = 500

// Expander binds a CIDR source, an LAPI writer, and the panel DB.
// All three are required; New() does not validate them so callers
// who omit one will get nil-deref at first use rather than a quiet
// no-op.
//
// ChunkSize controls how many alerts go into each /v1/alerts POST
// during Ban. Zero falls back to DefaultChunkSize; tests can
// override to exercise multi-chunk behaviour without committing
// a 1000-CIDR fixture.
type Expander struct {
	DB        *sql.DB
	LAPI      LAPIWriter
	Source    CIDRSource
	ChunkSize int
}

// BanResult is the public summary of a Ban call. CIDRCount counts
// only the chunks that LAPI accepted; FailedChunks counts the
// chunks that errored (each ~ChunkSize CIDRs not committed).
// RequestedCount is the full MMDB-derived count for the country
// so the operator can see partial-success ratios at a glance.
type BanResult struct {
	CountryCode    string `json:"country_code"`
	CIDRCount      int    `json:"cidr_count"`
	RequestedCount int    `json:"requested_count"`
	FailedChunks   int    `json:"failed_chunks,omitempty"`
	MMDBVersion    string `json:"mmdb_version"`
	ExpansionID    int64  `json:"expansion_id"`
	OriginTag      string `json:"origin_tag"`
	ReplacedRows   int    `json:"replaced_rows,omitempty"`
}

// Expansion is the read-shape returned by List. Mirrors the table
// row 1:1 except the JSON-array column is decoded into a Go slice.
//
// v1.3.33 added State -- the reconciler health-check verdict.
// 'active' = panel cidr_count matches LAPI count within 1%.
// 'drifted' = LAPI count diverged (operator should re-emit).
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
	State                 string    `json:"state"`
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

// ProgressFn reports per-chunk progress to the caller. It is
// invoked AFTER each chunk's LAPI call completes (success or
// fail). chunkIdx is 0-based; totalChunks is precomputed.
// cidrCommitted is the running total of LAPI-accepted CIDRs.
// Failed chunks count toward chunkIdx but not cidrCommitted.
//
// Used by v1.3.31's async JobRunner to push chunk-by-chunk
// progress into the country_expansion_jobs row so the polling
// frontend can render a live progress bar.
type ProgressFn func(chunkIdx, totalChunks, cidrCommitted, chunksFailed int)

// BanRequest is the input to BanWithProgress. The synchronous
// Ban() shim keeps the historical positional shape; new callers
// (the v1.3.31 JobRunner) use the struct so optional fields can
// land without breaking the existing call sites.
type BanRequest struct {
	CountryCode string
	Duration    string
	Reason      string
	CreatedBy   string
	// Progress, when non-nil, is invoked after every chunk.
	// Implementations should be quick (no blocking I/O) -- the
	// expansion stalls between chunks while the callback runs.
	Progress ProgressFn
}

// Ban is the synchronous expansion path kept for the v1.3.21
// caller shape. v1.3.31 added BanWithProgress; this is now a
// thin wrapper for callers that don't need progress.
func (e *Expander) Ban(
	ctx context.Context,
	countryCode string,
	durationGoString string,
	reason string,
	createdBy string,
) (*BanResult, error) {
	return e.BanWithProgress(ctx, BanRequest{
		CountryCode: countryCode,
		Duration:    durationGoString,
		Reason:      reason,
		CreatedBy:   createdBy,
	})
}

// BanWithProgress is the same as Ban but accepts a progress
// callback fired after each chunk. v1.3.31 JobRunner uses this
// to push live chunks_done into the country_expansion_jobs row.
func (e *Expander) BanWithProgress(ctx context.Context, req BanRequest) (*BanResult, error) {
	countryCode := req.CountryCode
	durationGoString := req.Duration
	reason := req.Reason
	createdBy := req.CreatedBy
	progress := req.Progress
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

	// Push CIDRs in chunks of ChunkSize (v1.3.22 chunked batch).
	// Empirical finding from prod Apr 25 2026: LAPI's /v1/alerts
	// batch is NOT atomic at scale -- a 21k-alert single POST
	// committed ~6.6k before timing out, leaving partial state.
	// Smaller chunks each behave better atomically (LAPI commits
	// per /v1/alerts call, and small per-call transactions are
	// short enough to fit comfortably).
	//
	// Continue-on-error semantics: a failed chunk is logged + the
	// loop moves on. This trades atomicity for progress -- if 5
	// chunks of a 22-chunk run fail, the operator gets 17 chunks
	// committed plus a clear FailedChunks count and can choose to
	// retry. v1.3.23 (async background job) will revisit.
	chunkSize := e.ChunkSize
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	tagged := originFor(code)
	committed := make([]string, 0, len(cidrs))
	failedChunks := 0
	var lastErr error
	totalChunks := (len(cidrs) + chunkSize - 1) / chunkSize
	for i := 0; i < len(cidrs); i += chunkSize {
		end := i + chunkSize
		if end > len(cidrs) {
			end = len(cidrs)
		}
		chunk := cidrs[i:end]
		batch := make([]crowdsec.AddRangeDecisionInput, 0, len(chunk))
		for _, cidr := range chunk {
			batch = append(batch, crowdsec.AddRangeDecisionInput{
				CIDR:          cidr,
				Reason:        fmt.Sprintf("country=%s [auto-expanded] %s", code, reason),
				Origin:        tagged,
				DurationHours: hours,
			})
		}
		chunkIdx := i / chunkSize
		if cerr := e.LAPI.AddRangeDecisions(ctx, batch); cerr != nil {
			failedChunks++
			lastErr = cerr
			slog.Warn("country: chunk failed",
				"country", code,
				"chunk_index", chunkIdx,
				"chunk_size", len(chunk),
				"error", cerr)
			if progress != nil {
				progress(chunkIdx+1, totalChunks, len(committed), failedChunks)
			}
			continue
		}
		committed = append(committed, chunk...)
		if progress != nil {
			progress(chunkIdx+1, totalChunks, len(committed), failedChunks)
		}
	}

	// All chunks failed: roll back any partial state via origin-
	// tag delete (defence in depth -- the loop above shouldn't
	// have inserted anything if every call errored, but small
	// chunks may have committed before erroring on a later step
	// of the same call). Don't persist a row since there's
	// nothing to track.
	if len(committed) == 0 {
		_, _ = e.LAPI.DeleteDecisionsByOrigin(ctx, tagged)
		return nil, fmt.Errorf("all %d chunks failed: %w", failedChunks, lastErr)
	}

	// Persist the tracking row with the COMMITTED CIDR list (not
	// the requested set) so Revoke and reconcile see only what is
	// actually in LAPI. The cidr_count reflects what landed; the
	// API response surfaces failed_chunks separately so the
	// operator can decide to retry the country.
	cidrJSON, err := json.Marshal(committed)
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
	`, code, string(cidrJSON), len(committed), reason, durationGoString, createdBy, mmdbVersion)
	if err != nil {
		// Persist failure: roll back the whole LAPI side via the
		// origin tag so we don't leak decisions the panel can't
		// track via the table row.
		_, _ = e.LAPI.DeleteDecisionsByOrigin(ctx, tagged)
		return nil, fmt.Errorf("persist tracking row: %w", err)
	}
	id, _ := res.LastInsertId()

	out := &BanResult{
		CountryCode:    code,
		CIDRCount:      len(committed),
		RequestedCount: len(cidrs),
		FailedChunks:   failedChunks,
		MMDBVersion:    mmdbVersion,
		ExpansionID:    id,
		OriginTag:      tagged,
		ReplacedRows:   existing,
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
		       duration, created_at, created_by, mmdb_version_at_creation,
		       state
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
			&e.State,
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
