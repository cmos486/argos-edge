package crowdsec

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeLAPIServer stands up a tiny HTTP server that:
//   - answers POST /v1/watchers/login with a stub JWT (any string;
//     doMachineRequest does not validate it) so the machine-credential
//     path completes,
//   - records every other request URL into capturedURLs so tests can
//     assert query-string shape,
//   - lets a per-test handler hook produce the response for each
//     non-login request.
//
// Returned client is wired with a 1s HTTP timeout so a buggy test
// cannot hang CI.
func fakeLAPIServer(t *testing.T, handle func(w http.ResponseWriter, r *http.Request)) (*Client, *[]string, func()) {
	t.Helper()
	captured := &[]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/watchers/login" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			expire := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
			_, _ = w.Write([]byte(`{"code":200,"expire":"` + expire + `","token":"stub-jwt"}`))
			return
		}
		// Capture the FULL request URL (path + raw query) so tests can
		// assert on the exact filter the client constructed.
		full := r.URL.Path
		if r.URL.RawQuery != "" {
			full += "?" + r.URL.RawQuery
		}
		*captured = append(*captured, r.Method+" "+full)
		handle(w, r)
	}))
	c := &Client{
		HTTP:            &http.Client{Timeout: 1 * time.Second},
		URL:             srv.URL,
		MachineUser:     "stub",
		MachinePassword: "stub",
	}
	return c, captured, srv.Close
}

// TestDeleteDecisionsByOriginUsesSingularParam locks in the v1.3.22
// fix for the v1.3.21 LAPI filter naming bug. CrowdSec's
// pkg/database/decisions.go uses different filter maps for GET (where
// "origins" plural is the multi-value list filter) vs DELETE (where
// "origin" singular is the single-value EQ filter). v1.3.21 sent the
// plural name on the DELETE path; LAPI rejected it with
// `'origins' doesn't exist: invalid filter`.
//
// This test asserts the constructed URL carries `origin=` (singular)
// and explicitly NOT `origins=` (plural). If a future refactor goes
// back to the plural name -- which looks visually right because the
// GET endpoint accepts it -- this test fails.
func TestDeleteDecisionsByOriginUsesSingularParam(t *testing.T) {
	c, captured, stop := fakeLAPIServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"nbDeleted":"7"}`))
	})
	defer stop()

	n, err := c.DeleteDecisionsByOrigin(context.Background(), "argos-country-XX")
	if err != nil {
		t.Fatalf("DeleteDecisionsByOrigin: %v", err)
	}
	if n != 7 {
		t.Fatalf("nbDeleted parse: got %d, want 7", n)
	}

	if len(*captured) != 1 {
		t.Fatalf("expected 1 captured request, got %d: %v", len(*captured), *captured)
	}
	got := (*captured)[0]
	if !strings.HasPrefix(got, "DELETE ") {
		t.Fatalf("expected DELETE method, got %q", got)
	}
	// Must use singular name. The DELETE handler in LAPI's
	// pkg/database/decisions.go (case "origin", L471) only matches
	// the singular form.
	if !strings.Contains(got, "origin=argos-country-XX") {
		t.Fatalf("expected query to contain origin=argos-country-XX, got %q", got)
	}
	// Must NOT use the plural form. Real LAPI returns 500
	// "'origins' doesn't exist: invalid filter" if it sees this on
	// the DELETE endpoint -- the regression we are locking out.
	if strings.Contains(got, "origins=") {
		t.Fatalf("DELETE must use singular 'origin', not plural 'origins'; got %q", got)
	}
}

// TestAddRangeDecisionsBatchSendsSinglePOST asserts the v1.3.22
// latency fix + the v1.3.33 alert-shape restructure together:
// AddRangeDecisions emits ONE POST /v1/alerts with ONE alert
// envelope carrying all N decisions inside. The pre-v1.3.22
// per-CIDR loop made BR (~21,521 CIDRs) take many minutes and
// deadlocked the Settings UI's "expanding..." button. The pre-
// v1.3.33 N-alerts-with-1-decision-each shape collided with
// CrowdSec's flush.max_items: 5000 cap and silently flushed
// older argos-country-* alerts. If either regression returns
// (loop of POSTs, OR multi-alert envelope), this test fails.
func TestAddRangeDecisionsBatchSendsSinglePOST(t *testing.T) {
	var bodies [][]byte
	c, captured, stop := fakeLAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Capture the request body so we can count the array length
		// LAPI received.
		var buf [1 << 16]byte
		n, _ := r.Body.Read(buf[:])
		bodies = append(bodies, append([]byte{}, buf[:n]...))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`["1","2","3"]`))
	})
	defer stop()

	in := []AddRangeDecisionInput{
		{CIDR: "192.0.2.0/24", Reason: "test", Origin: "argos-country-XX", DurationHours: 4},
		{CIDR: "198.51.100.0/24", Reason: "test", Origin: "argos-country-XX", DurationHours: 4},
		{CIDR: "203.0.113.0/24", Reason: "test", Origin: "argos-country-XX", DurationHours: 4},
	}
	if err := c.AddRangeDecisions(context.Background(), in); err != nil {
		t.Fatalf("AddRangeDecisions: %v", err)
	}

	// Exactly one POST /v1/alerts (login does not count -- it's
	// matched out of capture by the helper).
	if len(*captured) != 1 {
		t.Fatalf("expected 1 captured POST, got %d: %v", len(*captured), *captured)
	}
	if !strings.HasPrefix((*captured)[0], "POST /v1/alerts") {
		t.Fatalf("expected POST /v1/alerts, got %q", (*captured)[0])
	}

	// v1.3.33 shape: the body carries ONE alert envelope with
	// 3 decisions inside (not 3 alerts each with 1 decision).
	if len(bodies) != 1 {
		t.Fatalf("expected 1 captured body, got %d", len(bodies))
	}
	var alerts []map[string]any
	if err := json.Unmarshal(bodies[0], &alerts); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("v1.3.33 shape: body must carry 1 alert envelope (CAPI-style); got %d alerts", len(alerts))
	}
	decisions, ok := alerts[0]["decisions"].([]any)
	if !ok {
		t.Fatalf("alert.decisions missing or not an array: %+v", alerts[0])
	}
	if len(decisions) != 3 {
		t.Fatalf("alert.decisions must carry all 3 input CIDRs as decisions; got %d", len(decisions))
	}
	// The alert's source.scope must mirror the origin tag (CAPI
	// pattern: source.scope='crowdsecurity/community-blocklist').
	src, _ := alerts[0]["source"].(map[string]any)
	if src["scope"] != "argos-country-XX" {
		t.Fatalf("alert.source.scope must equal the origin tag; got %v", src["scope"])
	}
}

// TestAddRangeDecisionsRejectsHeterogeneousOrigin: v1.3.33's
// homogeneity assumption. Mixed-origin batches don't fit one
// alert envelope; reject explicitly so the caller groups by
// origin client-side instead of silently miswriting.
func TestAddRangeDecisionsRejectsHeterogeneousOrigin(t *testing.T) {
	c, _, stop := fakeLAPIServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer stop()
	in := []AddRangeDecisionInput{
		{CIDR: "192.0.2.0/24", Origin: "argos-country-XX", DurationHours: 4},
		{CIDR: "198.51.100.0/24", Origin: "argos-country-YY", DurationHours: 4},
	}
	if err := c.AddRangeDecisions(context.Background(), in); err == nil {
		t.Fatal("mixed-origin batch must error")
	}
}

// TestAddRangeDecisionsEmptyInputIsNoop: zero-CIDR input must not
// fire any HTTP at all. The expander relies on this so a country
// returning zero ranges from the MMDB doesn't blow up at the LAPI
// layer (it's caught earlier as ErrCountryNotFound, but the
// defensive layer here protects against future callers).
func TestAddRangeDecisionsEmptyInputIsNoop(t *testing.T) {
	c, captured, stop := fakeLAPIServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer stop()

	if err := c.AddRangeDecisions(context.Background(), nil); err != nil {
		t.Fatalf("empty input must not error, got: %v", err)
	}
	if len(*captured) != 0 {
		t.Fatalf("empty input must not fire any HTTP request, got: %v", *captured)
	}
}

// TestQueryAlertsContract pins the /v1/alerts query the panel builds
// to what the LAPI (v1.7.7, pkg/database/alertfilter.go) accepts, as
// verified live on 2026-09-26: relative durations for since/until,
// exact kind, include_capi=false, with_decisions=false, an explicit
// limit, and nothing else. An unknown key is an HTTP 500 on prod
// ("filter parameter 'x' is unknown"), so a new parameter must be
// added to allowedAlertParams here, deliberately, after a pre-flight.
func TestQueryAlertsContract(t *testing.T) {
	allowedAlertParams := map[string]bool{
		"since": true, "until": true, "kind": true, "scope": true, "value": true,
		"scenario": true, "ip": true, "range": true, "has_active_decision": true,
		"decision_type": true, "origin": true, "include_capi": true,
		"with_decisions": true, "simulated": true, "limit": true, "sort": true,
		"created_before": true,
	}
	cases := []struct {
		name string
		q    AlertsQuery
		want string
	}{
		{"panel default 24h", AlertsQuery{Since: 24 * time.Hour},
			"include_capi=false&limit=5000&since=1440m&with_decisions=false"},
		{"kind + window", AlertsQuery{Since: 48 * time.Hour, Until: 24 * time.Hour, Kind: "waf"},
			"include_capi=false&kind=waf&limit=5000&since=2880m&until=1440m&with_decisions=false"},
		{"legacy ListAlerts shape", AlertsQuery{Since: 6 * time.Hour, Scope: "Ip", IncludeCAPI: true, WithDecisions: true, Limit: 500},
			"limit=500&scope=Ip&since=360m"},
		{"sub-minute since is 1m, never a timestamp", AlertsQuery{Since: 10 * time.Second},
			"include_capi=false&limit=5000&since=1m&with_decisions=false"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := tc.q.Values()
			for k := range v {
				if !allowedAlertParams[k] {
					t.Fatalf("query emits %q, which the LAPI does not accept (500 in prod)", k)
				}
			}
			if got := v.Encode(); got != tc.want {
				t.Fatalf("query: got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestQueryAlertsSendsContractAndReadsRemediation drives the fake LAPI:
// the wire query equals Values(), a "null" body is an empty list, and
// the remediation flag reaches WasBlocked without a decisions array.
func TestQueryAlertsSendsContractAndReadsRemediation(t *testing.T) {
	c, captured, stop := fakeLAPIServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":1,"kind":"waf","scenario":"crowdsecurity/vpatch-env-access","remediation":null},
			{"id":2,"kind":"crowdsec","scenario":"crowdsecurity/appsec-native","remediation":true}]`))
	})
	defer stop()
	list, err := c.QueryAlerts(context.Background(), AlertsQuery{Since: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if len(*captured) != 1 || (*captured)[0] != "GET /v1/alerts?include_capi=false&limit=5000&since=1440m&with_decisions=false" {
		t.Fatalf("wire query: %v", *captured)
	}
	if len(list) != 2 || list[0].WasBlocked() || !list[1].WasBlocked() {
		t.Fatalf("remediation not honoured: %+v", list)
	}
}
