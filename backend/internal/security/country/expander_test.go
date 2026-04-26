package country

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/cmos486/argos-edge/backend/internal/crowdsec"
)

// fakeLAPI captures Add/Delete calls so tests can assert on the
// origin tag, CIDR shape, and idempotency without standing up a
// real LAPI.
//
// v1.3.22: chunked batch semantics. Each AddRangeDecisions call is
// one chunk (one /v1/alerts POST). Tests use:
//   - failAllBatches: every chunk errors. Exercises the all-chunks-
//     fail unwind path.
//   - failChunkAt N: the Nth chunk (0-indexed) errors; everything
//     else succeeds. Exercises continue-on-error semantics.
//
// The pushed slice is the FLATTENED list of CIDRs that landed in
// successful chunks; batchCalls is the total number of chunks
// attempted (including failed ones).
type fakeLAPI struct {
	pushed         []crowdsec.AddRangeDecisionInput
	batchCalls     int
	deletedOrigins []string
	failAllBatches bool
	failChunkAt    int // -1 = no chunk-specific failure; 0/1/2/... = fail that chunk
	// v1.3.31: optional per-batch delay so the JobRunner mutex
	// serialisation test can observe two concurrent submissions
	// resolving in order. Zero is the default (no delay) and
	// existing tests are unaffected.
	addDelay time.Duration
}

func (f *fakeLAPI) AddRangeDecisions(_ context.Context, ins []crowdsec.AddRangeDecisionInput) error {
	idx := f.batchCalls
	f.batchCalls++
	if f.addDelay > 0 {
		time.Sleep(f.addDelay)
	}
	if f.failAllBatches {
		return errors.New("simulated lapi batch failure")
	}
	if f.failChunkAt > 0 && idx == f.failChunkAt {
		return errors.New("simulated lapi chunk failure")
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

// TestBanUnwindsWhenAllChunksFail: continue-on-error semantics
// say a single failed chunk is logged + skipped, but if EVERY
// chunk fails the expander must roll back any partial state and
// return an error rather than silently persisting an empty row.
func TestBanUnwindsWhenAllChunksFail(t *testing.T) {
	e, lapi, _, d := newExpander(t)
	// XX has 2 CIDRs -> 1 chunk at default size. failAllBatches
	// makes that chunk error.
	lapi.failAllBatches = true
	_, err := e.Ban(context.Background(), "XX", "4h", "x", "admin")
	if err == nil {
		t.Fatalf("expected ban to fail when all chunks fail")
	}
	// Origin-tagged delete called as the unwind safety net.
	if len(lapi.deletedOrigins) == 0 {
		t.Fatalf("expected DeleteDecisionsByOrigin call after all-chunks failure")
	}
	var rows int
	_ = d.QueryRow(`SELECT COUNT(*) FROM country_ban_expansions`).Scan(&rows)
	if rows != 0 {
		t.Fatalf("expected 0 rows after unwind, got %d", rows)
	}
}

// TestBanSmallInputUsesSingleBatch is the small-input regression
// lock: small countries (Andorra, Vatican, the test fixtures)
// must produce exactly 1 batch call. Catches a future refactor
// that re-introduces a per-CIDR loop "for safety".
func TestBanSmallInputUsesSingleBatch(t *testing.T) {
	e, lapi, _, _ := newExpander(t)
	if _, err := e.Ban(context.Background(), "XX", "4h", "batch test", "admin"); err != nil {
		t.Fatal(err)
	}
	if lapi.batchCalls != 1 {
		t.Fatalf("expected exactly 1 batch call for 2-CIDR input, got %d (regression: per-CIDR loop is back)", lapi.batchCalls)
	}
	if len(lapi.pushed) != 2 {
		t.Fatalf("expected 2 pushed entries from the single batch, got %d", len(lapi.pushed))
	}
	for i, p := range lapi.pushed {
		if p.Origin != "argos-country-XX" {
			t.Fatalf("entry %d origin: %q", i, p.Origin)
		}
		if p.DurationHours != 4 {
			t.Fatalf("entry %d duration_hours: %d", i, p.DurationHours)
		}
	}
}

// TestBanChunksLargeInput: input larger than chunk_size produces
// ceil(N/chunk_size) batch calls. Locks in the v1.3.22 chunking
// invariant. Without this, a future "optimization" that goes back
// to single-batch would cause the same 9-min BR latency observed
// in prod.
func TestBanChunksLargeInput(t *testing.T) {
	d := openTestDB(t)
	lapi := &fakeLAPI{}
	// 2500 CIDRs to test chunking. We don't bake them into the
	// shared fakeSource because the small-input tests would then
	// also hit chunking semantics; instead build a dedicated
	// source for this test.
	cidrs := make([]string, 2500)
	for i := range cidrs {
		cidrs[i] = fmt.Sprintf("198.51.100.%d/32", i%256)
	}
	src := &fakeSource{
		byCode:  map[string][]string{"AA": cidrs},
		version: "2026-04",
	}
	// Use a small ChunkSize so the test runs quickly and the math
	// is clear: 2500 / 500 = 5 chunks.
	e := &Expander{DB: d, LAPI: lapi, Source: src, ChunkSize: 500}

	res, err := e.Ban(context.Background(), "AA", "4h", "chunk test", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if lapi.batchCalls != 5 {
		t.Fatalf("expected 5 batch calls (2500/500), got %d", lapi.batchCalls)
	}
	if res.CIDRCount != 2500 {
		t.Fatalf("CIDRCount: %d, want 2500", res.CIDRCount)
	}
	if res.RequestedCount != 2500 {
		t.Fatalf("RequestedCount: %d, want 2500", res.RequestedCount)
	}
	if res.FailedChunks != 0 {
		t.Fatalf("FailedChunks: %d, want 0", res.FailedChunks)
	}
}

// TestBanContinuesOnChunkFailure: if a single chunk fails mid-
// loop, subsequent chunks still proceed. The persisted row
// reflects the COMMITTED CIDR set (excluding the failed chunk's
// entries), and FailedChunks counts the failure.
func TestBanContinuesOnChunkFailure(t *testing.T) {
	d := openTestDB(t)
	lapi := &fakeLAPI{failChunkAt: 1} // first chunk OK, second fails, third OK
	cidrs := make([]string, 1500)
	for i := range cidrs {
		cidrs[i] = fmt.Sprintf("203.0.113.%d/32", i%256)
	}
	src := &fakeSource{
		byCode:  map[string][]string{"AA": cidrs},
		version: "2026-04",
	}
	e := &Expander{DB: d, LAPI: lapi, Source: src, ChunkSize: 500}

	res, err := e.Ban(context.Background(), "AA", "4h", "partial test", "admin")
	if err != nil {
		t.Fatalf("expected partial-success Ban to return nil error, got %v", err)
	}
	if lapi.batchCalls != 3 {
		t.Fatalf("expected 3 batch calls attempted, got %d", lapi.batchCalls)
	}
	if res.FailedChunks != 1 {
		t.Fatalf("FailedChunks: %d, want 1", res.FailedChunks)
	}
	// 1500 requested, chunk 2 (500 entries) failed -> 1000 committed.
	if res.CIDRCount != 1000 {
		t.Fatalf("CIDRCount: %d, want 1000 (3 chunks - 1 failed * 500)", res.CIDRCount)
	}
	if res.RequestedCount != 1500 {
		t.Fatalf("RequestedCount: %d, want 1500", res.RequestedCount)
	}
	// Row exists with the committed count.
	var n int
	_ = d.QueryRow(`SELECT cidr_count FROM country_ban_expansions WHERE country_code='AA'`).Scan(&n)
	if n != 1000 {
		t.Fatalf("persisted cidr_count: %d, want 1000", n)
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
