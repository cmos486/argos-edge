package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/crowdsec"
	"github.com/cmos486/argos-edge/backend/internal/geoip"
)

func TestThreatsFilterMatches(t *testing.T) {
	ip := crowdsec.Decision{Origin: "CAPI", Type: "ban", Scope: "Ip", Value: "203.0.113.7", Scenario: "crowdsecurity/http-probing"}
	rng := crowdsec.Decision{Origin: "argos-country-BR", Type: "ban", Scope: "Range", Value: "198.51.100.0/24", Scenario: "argos/country-ban"}
	geo := func(v string) *crowdsec.GeoEnrichment {
		if v == "203.0.113.7" {
			return &crowdsec.GeoEnrichment{CountryCode: "ES"}
		}
		return nil
	}
	cases := []struct {
		name string
		f    threatsFilter
		d    crowdsec.Decision
		want bool
	}{
		{"no filter", threatsFilter{}, ip, true},
		{"origin case-insensitive", threatsFilter{Origin: "capi"}, ip, true},
		{"origin mismatch", threatsFilter{Origin: "cscli"}, ip, false},
		{"type", threatsFilter{Type: "BAN"}, ip, true},
		{"type mismatch", threatsFilter{Type: "captcha"}, ip, false},
		{"search on value", threatsFilter{Search: "113.7"}, ip, true},
		{"search on scenario, case-insensitive", threatsFilter{Search: "http-prob"}, ip, true},
		{"search miss", threatsFilter{Search: "sqli"}, ip, false},
		{"ip contains", threatsFilter{IP: "203.0.113"}, ip, true},
		{"ip miss", threatsFilter{IP: "10.0"}, ip, false},
		{"scenario contains", threatsFilter{Scenario: "probing"}, ip, true},
		{"scenario miss", threatsFilter{Scenario: "crawl"}, ip, false},
		{"country match on Ip scope", threatsFilter{Country: "ES"}, ip, true},
		{"country mismatch", threatsFilter{Country: "DE"}, ip, false},
		{"country never matches a Range", threatsFilter{Country: "BR"}, rng, false},
		{"range by ip fragment", threatsFilter{IP: "198.51.100"}, rng, true},
		{"combined", threatsFilter{Origin: "CAPI", Type: "ban", Search: "203", Country: "ES"}, ip, true},
		{"combined one miss", threatsFilter{Origin: "CAPI", Type: "captcha", Search: "203", Country: "ES"}, ip, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.f.matches(tc.d, geo); got != tc.want {
				t.Fatalf("matches(%+v) = %v, want %v", tc.f, got, tc.want)
			}
		})
	}
}

// threatsHandlers wires a Handlers to a fake LAPI serving n decisions
// (ids 1..n, origin CAPI except every 10th which is cscli).
func threatsHandlers(t *testing.T, n int) *Handlers {
	t.Helper()
	list := make([]crowdsec.Decision, 0, n)
	for i := 1; i <= n; i++ {
		origin := "CAPI"
		if i%10 == 0 {
			origin = "cscli"
		}
		list = append(list, crowdsec.Decision{
			ID: int64(i), Origin: origin, Type: "ban", Scope: "Ip",
			Value: fmt.Sprintf("203.0.%d.%d", i/256, i%256), Scenario: "crowdsecurity/http-probing",
			Duration: "4h0m0s", Until: time.Now().Add(4 * time.Hour),
		})
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/decisions" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(list)
	}))
	t.Cleanup(srv.Close)
	// crowdsec.New so the client carries its real 15 s list cache: the
	// cache-write test below relies on the second ListDecisions call
	// returning the cached slice.
	return &Handlers{CrowdSec: crowdsec.New(srv.URL, "test-key", "", "")}
}

func getThreats(t *testing.T, h *Handlers, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/threats/decisions"+query, nil)
	rec := httptest.NewRecorder()
	h.ThreatsDecisions(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status %d body %s", query, rec.Code, rec.Body.String())
	}
	return rec
}

func TestThreatsDecisionsWithoutPageKeepsFlatArray(t *testing.T) {
	h := threatsHandlers(t, 250)
	var got []crowdsec.Decision
	if err := json.Unmarshal(getThreats(t, h, "").Body.Bytes(), &got); err != nil {
		t.Fatalf("flat array expected without page=: %v", err)
	}
	if len(got) != 250 {
		t.Fatalf("flat array: want 250 rows, got %d", len(got))
	}
	if err := json.Unmarshal(getThreats(t, h, "?origin=cscli&search=203.0.0").Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	// ids 10..250 step 10 with value 203.0.0.x: ids 10..250 below 256 -> 25 rows
	if len(got) != 25 {
		t.Fatalf("filtered flat array: want 25 rows, got %d", len(got))
	}
}

func TestThreatsDecisionsPaged(t *testing.T) {
	h := threatsHandlers(t, 250)
	var p threatsDecisionsPage

	if err := json.Unmarshal(getThreats(t, h, "?page=2").Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Total != 250 || p.Page != 2 || p.PerPage != 100 || p.Pages != 3 || len(p.Decisions) != 100 {
		t.Fatalf("page 2: total=%d page=%d per_page=%d pages=%d rows=%d", p.Total, p.Page, p.PerPage, p.Pages, len(p.Decisions))
	}
	if p.Decisions[0].ID != 101 || p.Decisions[99].ID != 200 {
		t.Fatalf("page 2 rows: first id %d last id %d", p.Decisions[0].ID, p.Decisions[99].ID)
	}

	// Past the end clamps to the last page.
	if err := json.Unmarshal(getThreats(t, h, "?page=9").Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Page != 3 || len(p.Decisions) != 50 || p.Decisions[0].ID != 201 {
		t.Fatalf("page 9 clamp: page=%d rows=%d first=%d", p.Page, len(p.Decisions), p.Decisions[0].ID)
	}

	// per_page and a filter together; empty result is a valid page 1 of 1.
	if err := json.Unmarshal(getThreats(t, h, "?page=1&per_page=10&origin=cscli").Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Total != 25 || p.Pages != 3 || len(p.Decisions) != 10 || p.Decisions[0].ID != 10 {
		t.Fatalf("filtered page: total=%d pages=%d rows=%d first=%d", p.Total, p.Pages, len(p.Decisions), p.Decisions[0].ID)
	}
	if err := json.Unmarshal(getThreats(t, h, "?page=1&origin=manual").Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Total != 0 || p.Pages != 1 || p.Page != 1 || p.Decisions == nil || len(p.Decisions) != 0 {
		t.Fatalf("empty page: %+v", p)
	}

	// A paged response is a fraction of the flat one: the point of the release.
	flat := getThreats(t, h, "").Body.Len()
	paged := getThreats(t, h, "?page=1&per_page=100").Body.Len()
	if paged*2 > flat {
		t.Fatalf("paged body %d bytes is not well under the flat body %d bytes", paged, flat)
	}
}

func TestThreatsDecisionsDoesNotWriteIntoClientCache(t *testing.T) {
	h := threatsHandlers(t, 20)
	// A GeoDB with no readers still yields a non-nil Result ("Unknown"),
	// so every Ip-scoped row gets a Geo pointer when enriched.
	h.GeoDB = &geoip.DB{}
	for _, query := range []string{"?page=1", ""} {
		// The first call populates the client cache; the handler must
		// enrich its own copy so the cached list stays untouched.
		var probe struct {
			Decisions []crowdsec.Decision `json:"decisions"`
		}
		body := getThreats(t, h, query).Body.Bytes()
		if query == "" {
			_ = json.Unmarshal(body, &probe.Decisions)
		} else {
			_ = json.Unmarshal(body, &probe)
		}
		if len(probe.Decisions) == 0 || probe.Decisions[0].Geo == nil {
			t.Fatalf("%q: response rows should be geo-enriched", query)
		}
		cached, err := h.CrowdSec.ListDecisions(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range cached {
			if d.Geo != nil {
				t.Fatalf("%q: handler wrote Geo into the LAPI client's cached slice (id %d)", query, d.ID)
			}
		}
	}
}
