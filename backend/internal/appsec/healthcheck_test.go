package appsec

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPingCounts405AsReachable(t *testing.T) {
	// CrowdSec AppSec replies 405 to GET requests -- that's the
	// "endpoint is up, wrong verb" signal and MUST count as healthy.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer srv.Close()
	h := &Health{Client: &http.Client{Timeout: 2 * time.Second}}
	if err := h.ping(context.Background(), srv.URL); err != nil {
		t.Fatalf("405 should be healthy, got err: %v", err)
	}
}

func TestPing404IsUnhealthy(t *testing.T) {
	// 404 means the crowdsec container is up but has no AppSec
	// collections installed -- the handler route literally does not
	// exist. That is the failure mode the v1.3.1 prod outage hit:
	// crowdsec:7423 accepted connections but returned 404. We need
	// to surface that as unhealthy, not "everything's fine".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	h := &Health{Client: &http.Client{Timeout: 2 * time.Second}}
	if err := h.ping(context.Background(), srv.URL); err == nil {
		t.Fatal("404 must be unhealthy")
	}
}

// v1.3.4: 500 on an authed probe is actually healthy. CrowdSec
// AppSec returns 500 to a GET-without-AppSec-headers even when the
// sidecar is perfectly up. Pre-v1.3.4 we treated that as a hard
// down signal and fired false `appsec_unavailable` events on
// healthy stacks.
func TestPing500IsHealthyForLiveness(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	h := &Health{Client: &http.Client{Timeout: 2 * time.Second}}
	if err := h.ping(context.Background(), srv.URL); err != nil {
		t.Fatalf("500 should be healthy for liveness (sidecar answered), got: %v", err)
	}
}

func TestPingConnectionRefusedIsUnhealthy(t *testing.T) {
	// Listener on localhost:0 grabs a port then closes it so the
	// subsequent connect attempt guarantees ECONNREFUSED.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	url := srv.URL
	srv.Close()
	h := &Health{Client: &http.Client{Timeout: 500 * time.Millisecond}}
	if err := h.ping(context.Background(), url); err == nil {
		t.Fatal("connection refused must be unhealthy")
	}
}

// v1.3.4: the probe now sends the bouncer API key via
// X-Crowdsec-Appsec-Api-Key, matching what the caddy-side plugin
// sends. Pre-v1.3.4 we sent no header and CrowdSec logged
// "missing API key" every five minutes.
func TestPingSendsBouncerAPIKeyHeader(t *testing.T) {
	t.Setenv("CROWDSEC_BOUNCER_API_KEY", "test-bouncer-key-abc123")

	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-Crowdsec-Appsec-Api-Key")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer srv.Close()

	h := &Health{Client: &http.Client{Timeout: 2 * time.Second}}
	if err := h.ping(context.Background(), srv.URL); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if gotKey != "test-bouncer-key-abc123" {
		t.Fatalf("probe should forward bouncer key on X-Crowdsec-Appsec-Api-Key; got %q", gotKey)
	}
}

// v1.3.4: 401 is now treated as "sidecar up" (it answered) for
// liveness-probe purposes. The key mismatch case is still visible
// because we no longer produce the `missing API key` log spam on
// CrowdSec (we send the key), so a 401 genuinely means key
// mismatch -- surfaced via CrowdSec's own auth log, not via this
// probe's notification. Keeping the probe simple (any response =
// up) avoids chasing the wrong layer.
func TestPing401IsHealthyForLiveness(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	h := &Health{Client: &http.Client{Timeout: 2 * time.Second}}
	if err := h.ping(context.Background(), srv.URL); err != nil {
		t.Fatalf("401 should be healthy for liveness probe, got: %v", err)
	}
}

func TestAppsecURLForMode(t *testing.T) {
	cases := []struct {
		mode, want string
	}{
		{"block", "http://crowdsec:7422"},
		{"detect", "http://crowdsec:7423"},
		{"disabled", ""},
		{"", ""},
		{"garbage", ""},
	}
	for _, tc := range cases {
		if got := appsecURLForMode(tc.mode); got != tc.want {
			t.Errorf("mode=%q want %q got %q", tc.mode, tc.want, got)
		}
	}
}
