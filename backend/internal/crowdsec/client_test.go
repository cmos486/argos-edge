package crowdsec

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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
	mu := atomic.Int32{} // throwaway, ensures the slice address stays stable
	_ = mu
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
// latency fix: AddRangeDecisions emits ONE POST /v1/alerts with the
// full N-element array, not N sequential POSTs. The pre-v1.3.22
// per-CIDR loop made BR (~21,521 CIDRs) take many minutes and
// deadlocked the Settings UI's "expanding..." button. If a future
// refactor goes back to a one-call-per-input loop, this test fails.
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

	// And the single body must carry all 3 alert envelopes.
	if len(bodies) != 1 {
		t.Fatalf("expected 1 captured body, got %d", len(bodies))
	}
	var alerts []map[string]any
	if err := json.Unmarshal(bodies[0], &alerts); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(alerts) != 3 {
		t.Fatalf("batch body must carry all 3 alerts in a single POST, got %d", len(alerts))
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
