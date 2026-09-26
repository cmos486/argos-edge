package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cmos486/argos-edge/backend/internal/db/dbtest"
	"github.com/cmos486/argos-edge/backend/internal/security/country"
)

// TestListCountryExpansionsOmitsCIDRs (v1.3.42.1): the list endpoint
// drops the CIDR arrays unless ?cidrs=1; cidr_count stays.
func TestListCountryExpansionsOmitsCIDRs(t *testing.T) {
	d := dbtest.Open(t)
	if _, err := d.Exec(`INSERT INTO country_ban_expansions
		(country_code, decision_ids, cidr_count, reason, duration, created_by, mmdb_version_at_creation)
		VALUES ('ZZ', '["203.0.113.0/24","198.51.100.0/24"]', 2, 'test', '24h', 'test', 'v1')`); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{DB: d, CountryExpander: &country.Expander{DB: d}}

	get := func(url string) []map[string]any {
		rec := httptest.NewRecorder()
		h.ListCountryExpansions(rec, httptest.NewRequest(http.MethodGet, url, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", url, rec.Code, rec.Body.String())
		}
		var out []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	slim := get("/api/security/countries")
	if len(slim) != 1 {
		t.Fatalf("rows = %d", len(slim))
	}
	if _, has := slim[0]["cidrs"]; has {
		t.Fatalf("cidrs present without ?cidrs=1: %v", slim[0]["cidrs"])
	}
	if slim[0]["cidr_count"] != float64(2) {
		t.Fatalf("cidr_count = %v", slim[0]["cidr_count"])
	}
	full := get("/api/security/countries?cidrs=1")
	cidrs, _ := full[0]["cidrs"].([]any)
	if len(cidrs) != 2 {
		t.Fatalf("cidrs with ?cidrs=1 = %v", full[0]["cidrs"])
	}
}
