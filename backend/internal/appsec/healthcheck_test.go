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

func TestPing5xxIsUnhealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	h := &Health{Client: &http.Client{Timeout: 2 * time.Second}}
	if err := h.ping(context.Background(), srv.URL); err == nil {
		t.Fatal("500 must be unhealthy")
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
