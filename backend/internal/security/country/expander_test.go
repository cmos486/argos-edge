package country

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/cmos486/argos-edge/backend/internal/crowdsec"
)

// fakeLAPI captures Add/Delete calls so tests can assert on the
// origin tag, CIDR shape, and idempotency without standing up a
// real LAPI.
//
// v1.3.22: AddRangeDecisions is the only Add-side surface; the
// fake records the number of batch calls separately from the
// flattened per-decision push list so tests can lock in
// "exactly one batch call" (the v1.3.22 latency fix). The
// failPushAtBatch field lets a test exercise the "batch fails,
// expander unwinds" path -- LAPI itself is atomic on /v1/alerts
// arrays, so a real partial failure cannot happen, but we still
// assert the unwind code path.
type fakeLAPI struct {
	pushed         []crowdsec.AddRangeDecisionInput
	batchCalls     int
	deletedOrigins []string
	failNextBatch  bool
}

func (f *fakeLAPI) AddRangeDecisions(_ context.Context, ins []crowdsec.AddRangeDecisionInput) error {
	f.batchCalls++
	if f.failNextBatch {
		f.failNextBatch = false
		return errors.New("simulated lapi batch failure")
	}
	f.pushed = append(f.pushed, ins...)
	return nil
}

func (f *fakeLAPI) DeleteDecisionsByOrigin(_ context.Context, origin string) (int, error) {
	f.deletedOrigins = append(f.deletedOrigins, origin)
	// Drop matching pushes too -- the next assertion can verify the
	// "no leftover decisions" invariant after Revoke or unwinding.
	kept := f.pushed[:0]
	removed := 0
	for _, p := range f.pushed {
		if p.Origin == origin {
			removed++
			continue
		}
		kept = append(kept, p)
	}
	f.pushed = kept
	return removed, nil
}

// fakeSource returns a fixed CIDR list for known codes; everything
// else returns empty so the expander surfaces ErrCountryNotFound.
type fakeSource struct {
	byCode  map[string][]string
	version string
}

func (f *fakeSource) ListCIDRs(code string) ([]string, string, error) {
	return f.byCode[code], f.version, nil
}

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if _, err := d.Exec(`
		CREATE TABLE country_ban_expansions (
			id                       INTEGER PRIMARY KEY AUTOINCREMENT,
			country_code             TEXT NOT NULL,
			decision_ids             TEXT NOT NULL,
			cidr_count               INTEGER NOT NULL,
			reason                   TEXT NOT NULL DEFAULT '',
			duration                 TEXT NOT NULL,
			created_at               TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			created_by               TEXT NOT NULL,
			mmdb_version_at_creation TEXT NOT NULL,
			UNIQUE(country_code)
		)
	`); err != nil {
		t.Fatal(err)
	}
	return d
}

func newExpander(t *testing.T) (*Expander, *fakeLAPI, *fakeSource, *sql.DB) {
	t.Helper()
	d := openTestDB(t)
	lapi := &fakeLAPI{}
	src := &fakeSource{
		byCode: map[string][]string{
			// Use placeholder codes (XX, YY, ZZ) so tests do not
			// imply real-country behaviour. Tiny CIDR sets keep
			// assertions deterministic.
			"XX": {"192.0.2.0/24", "198.51.100.0/24"},
			"YY": {"203.0.113.0/24", "2001:db8::/32"},
		},
		version: "2026-04",
	}
	e := &Expander{DB: d, LAPI: lapi, Source: src}
	return e, lapi, src, d
}

func TestBanHappyPath(t *testing.T) {
	e, lapi, _, d := newExpander(t)
	res, err := e.Ban(context.Background(), "XX", "4h", "test ban", "admin")
	if err != nil {
		t.Fatalf("ban: %v", err)
	}
	if res.CIDRCount != 2 {
		t.Fatalf("expected 2 cidrs, got %d", res.CIDRCount)
	}
	if res.OriginTag != "argos-country-XX" {
		t.Fatalf("origin tag: %q", res.OriginTag)
	}
	if res.MMDBVersion != "2026-04" {
		t.Fatalf("mmdb version: %q", res.MMDBVersion)
	}
	if len(lapi.pushed) != 2 {
		t.Fatalf("expected 2 lapi pushes, got %d", len(lapi.pushed))
	}
	for _, p := range lapi.pushed {
		if p.Origin != "argos-country-XX" {
			t.Fatalf("origin: %q", p.Origin)
		}
		if p.DurationHours != 4 {
			t.Fatalf("duration_hours: %d", p.DurationHours)
		}
	}
	// Tracking row persisted.
	var n int
	_ = d.QueryRow(`SELECT cidr_count FROM country_ban_expansions WHERE country_code='XX'`).Scan(&n)
	if n != 2 {
		t.Fatalf("tracking row cidr_count: %d", n)
	}
}

func TestBanRejectsInvalidCode(t *testing.T) {
	e, _, _, _ := newExpander(t)
	// "xx" is intentionally NOT in this list -- the expander
	// upper-cases ASCII before validation, so lowercase is treated
	// as an operator typo and accepted. See TestBanLowerCasesCode.
	for _, bad := range []string{"", "x", "XXX", "B1", "12"} {
		_, err := e.Ban(context.Background(), bad, "4h", "x", "admin")
		if err == nil {
			t.Fatalf("expected error for code %q", bad)
		}
		if !strings.Contains(err.Error(), "ISO 3166-1 alpha-2") {
			t.Fatalf("wrong error for %q: %v", bad, err)
		}
	}
}

func TestBanRejectsUnknownCountry(t *testing.T) {
	e, _, _, _ := newExpander(t)
	_, err := e.Ban(context.Background(), "ZZ", "4h", "x", "admin")
	if !errors.Is(err, ErrCountryNotFound) {
		t.Fatalf("expected ErrCountryNotFound, got %v", err)
	}
}

func TestBanReplacesExistingExpansion(t *testing.T) {
	e, lapi, _, d := newExpander(t)
	// First ban: 4h.
	if _, err := e.Ban(context.Background(), "XX", "4h", "first", "admin"); err != nil {
		t.Fatal(err)
	}
	// Second ban for the same country: should revoke the previous
	// LAPI decisions and replace the row, NOT stack a new row.
	res, err := e.Ban(context.Background(), "XX", "168h", "second", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if res.ReplacedRows != 1 {
		t.Fatalf("expected ReplacedRows=1, got %d", res.ReplacedRows)
	}
	// Exactly one row in the table.
	var rows int
	_ = d.QueryRow(`SELECT COUNT(*) FROM country_ban_expansions`).Scan(&rows)
	if rows != 1 {
		t.Fatalf("expected 1 row, got %d", rows)
	}
	// LAPI saw a delete for the origin between the two bans.
	if len(lapi.deletedOrigins) == 0 {
		t.Fatalf("expected DeleteDecisionsByOrigin call between bans")
	}
	// New duration recorded.
	var dur string
	_ = d.QueryRow(`SELECT duration FROM country_ban_expansions WHERE country_code='XX'`).Scan(&dur)
	if dur != "168h" {
		t.Fatalf("duration: %q", dur)
	}
}

func TestBanUnwindsOnLAPIFailure(t *testing.T) {
	e, lapi, _, d := newExpander(t)
	lapi.failNextBatch = true
	_, err := e.Ban(context.Background(), "XX", "4h", "x", "admin")
	if err == nil {
		t.Fatalf("expected ban to fail")
	}
	// The expander must have called DeleteDecisionsByOrigin even
	// though the LAPI batch call returned an error -- LAPI is
	// atomic, so the safety-net delete is a no-op in production
	// but the call itself protects against any future LAPI build
	// that processes partials.
	if len(lapi.deletedOrigins) == 0 {
		t.Fatalf("expected DeleteDecisionsByOrigin call after batch failure")
	}
	// And no row was persisted.
	var rows int
	_ = d.QueryRow(`SELECT COUNT(*) FROM country_ban_expansions`).Scan(&rows)
	if rows != 0 {
		t.Fatalf("expected 0 rows after unwind, got %d", rows)
	}
}

// TestBanCallsLAPIInExactlyOneBatch is the v1.3.22 regression lock:
// the Ban path MUST emit exactly one AddRangeDecisions call carrying
// the full CIDR list, not N sequential calls. The pre-v1.3.22
// implementation looped one call per CIDR and made BR (~250 CIDRs)
// take ~60s, freezing the Settings UI. If a future refactor goes back
// to per-CIDR loops, this test fails.
func TestBanCallsLAPIInExactlyOneBatch(t *testing.T) {
	e, lapi, _, _ := newExpander(t)
	if _, err := e.Ban(context.Background(), "XX", "4h", "batch test", "admin"); err != nil {
		t.Fatal(err)
	}
	if lapi.batchCalls != 1 {
		t.Fatalf("expected exactly 1 batch call, got %d (regression: per-CIDR loop is back)", lapi.batchCalls)
	}
	// The single batch call must carry every CIDR from the source.
	// fakeSource["XX"] has 2 entries; pushed len must equal 2 from
	// the one call.
	if len(lapi.pushed) != 2 {
		t.Fatalf("expected 2 pushed entries from the single batch, got %d", len(lapi.pushed))
	}
	// Every entry shares the same origin tag and has the right
	// CIDR / duration shape -- regression protection if the batch
	// builder drops fields.
	for i, p := range lapi.pushed {
		if p.Origin != "argos-country-XX" {
			t.Fatalf("entry %d origin: %q", i, p.Origin)
		}
		if p.DurationHours != 4 {
			t.Fatalf("entry %d duration_hours: %d", i, p.DurationHours)
		}
	}
}

func TestRevokeRemovesBothDecisionsAndRow(t *testing.T) {
	e, lapi, _, d := newExpander(t)
	if _, err := e.Ban(context.Background(), "YY", "4h", "x", "admin"); err != nil {
		t.Fatal(err)
	}
	pushedBefore := len(lapi.pushed)
	if pushedBefore == 0 {
		t.Fatalf("test setup: expected pushes")
	}
	removed, err := e.Revoke(context.Background(), "YY")
	if err != nil {
		t.Fatal(err)
	}
	if removed != pushedBefore {
		t.Fatalf("removed=%d, expected=%d", removed, pushedBefore)
	}
	if len(lapi.pushed) != 0 {
		t.Fatalf("lapi.pushed should be empty after revoke")
	}
	var rows int
	_ = d.QueryRow(`SELECT COUNT(*) FROM country_ban_expansions WHERE country_code='YY'`).Scan(&rows)
	if rows != 0 {
		t.Fatalf("tracking row still present after revoke")
	}
}

func TestRevokeMissingRowIsNoError(t *testing.T) {
	e, _, _, _ := newExpander(t)
	_, err := e.Revoke(context.Background(), "XX")
	if err != nil {
		t.Fatalf("revoke of missing expansion should not error: %v", err)
	}
}

func TestListReturnsActiveExpansions(t *testing.T) {
	e, _, _, _ := newExpander(t)
	if _, err := e.Ban(context.Background(), "XX", "4h", "first", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Ban(context.Background(), "YY", "168h", "second", "admin"); err != nil {
		t.Fatal(err)
	}
	expansions, err := e.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(expansions) != 2 {
		t.Fatalf("expected 2 expansions, got %d", len(expansions))
	}
	// Ordered by country_code ASC: XX before YY.
	if expansions[0].CountryCode != "XX" || expansions[1].CountryCode != "YY" {
		t.Fatalf("ordering: %v", expansions)
	}
	if len(expansions[1].CIDRs) != 2 {
		t.Fatalf("YY expected 2 cidrs, got %d", len(expansions[1].CIDRs))
	}
}

func TestBanLowerCasesCode(t *testing.T) {
	e, lapi, _, _ := newExpander(t)
	res, err := e.Ban(context.Background(), "xx", "4h", "x", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if res.CountryCode != "XX" {
		t.Fatalf("expected uppercased code, got %q", res.CountryCode)
	}
	if lapi.pushed[0].Origin != "argos-country-XX" {
		t.Fatalf("origin: %q", lapi.pushed[0].Origin)
	}
}
