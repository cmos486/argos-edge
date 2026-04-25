package api

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/cmos486/argos-edge/backend/internal/caddy"
	"github.com/cmos486/argos-edge/backend/internal/models"
)

// --- parseHealthCheckerLine ---

func TestParseHealthCheckerLineUnexpectedStatus(t *testing.T) {
	line := `{"level":"info","ts":1777061302.3220565,"logger":"http.handlers.reverse_proxy.health_checker.active","msg":"unexpected status code","status_code":302,"host":"192.0.2.156:8000"}`
	evt, ok := parseHealthCheckerLine(line, time.Unix(0, 0))
	if !ok {
		t.Fatal("expected ok=true")
	}
	if evt.addr != "192.0.2.156:8000" {
		t.Errorf("addr=%q", evt.addr)
	}
	if !evt.statusCodePresent || evt.statusCode != 302 {
		t.Errorf("status=%d present=%v", evt.statusCode, evt.statusCodePresent)
	}
	if evt.msg != "unexpected status code" {
		t.Errorf("msg=%q", evt.msg)
	}
	// ts from raw should override the passed-in fallback
	if evt.at.IsZero() {
		t.Error("at not populated")
	}
}

func TestParseHealthCheckerLineHTTPFailure(t *testing.T) {
	line := `{"level":"info","ts":1777061305.3,"logger":"http.handlers.reverse_proxy.health_checker.active","msg":"HTTP request failed","host":"192.0.2.161:3001","error":"dial tcp: connection refused"}`
	evt, ok := parseHealthCheckerLine(line, time.Unix(0, 0))
	if !ok {
		t.Fatal("expected ok=true")
	}
	if evt.errMsg != "dial tcp: connection refused" {
		t.Errorf("errMsg=%q", evt.errMsg)
	}
	if evt.statusCodePresent {
		t.Error("expected no status code")
	}
}

func TestParseHealthCheckerLineRejectsOtherLoggers(t *testing.T) {
	line := `{"logger":"http.handlers.reverse_proxy","msg":"something","host":"10.0.0.1:80"}`
	if _, ok := parseHealthCheckerLine(line, time.Now()); ok {
		t.Error("expected ok=false for non-health-checker logger")
	}
}

func TestParseHealthCheckerLineRejectsMalformed(t *testing.T) {
	if _, ok := parseHealthCheckerLine("not json", time.Now()); ok {
		t.Error("expected ok=false for malformed JSON")
	}
}

// --- classifyTarget ---

func targetFixture(host string, port int) models.Target {
	return models.Target{
		ID:            99,
		TargetGroupID: 3,
		Host:          host,
		Port:          port,
		Enabled:       true,
	}
}

func TestClassifyTargetHealthyWhenInCaddyAndNoRecentFailure(t *testing.T) {
	up := map[string]caddy.Upstream{
		"10.0.0.5:8080": {Address: "10.0.0.5:8080", NumRequests: 0, Fails: 0},
	}
	out := classifyTarget(targetFixture("10.0.0.5", 8080), up, nil)
	if out.Status != "healthy" {
		t.Errorf("status=%q, want healthy", out.Status)
	}
	if out.LastStatusCode != nil || out.LastError != "" {
		t.Errorf("unexpected last_* fields populated")
	}
}

func TestClassifyTargetHealthyPassesThroughInFlightCounter(t *testing.T) {
	up := map[string]caddy.Upstream{
		"10.0.0.5:8080": {Address: "10.0.0.5:8080", NumRequests: 42, Fails: 0},
	}
	out := classifyTarget(targetFixture("10.0.0.5", 8080), up, nil)
	if out.NumRequests != 42 {
		t.Errorf("num_requests=%d, want 42", out.NumRequests)
	}
}

func TestClassifyTargetUnhealthyStatusCode(t *testing.T) {
	addr := "10.0.0.6:8080"
	at := time.Now().UTC().Add(-15 * time.Second)
	up := map[string]caddy.Upstream{addr: {Address: addr, NumRequests: 0, Fails: 2}}
	events := map[string]healthCheckerEvent{
		addr: {
			addr:              addr,
			at:                at,
			msg:               "unexpected status code",
			statusCode:        302,
			statusCodePresent: true,
		},
	}
	out := classifyTarget(targetFixture("10.0.0.6", 8080), up, events)
	if out.Status != "unhealthy" {
		t.Fatalf("status=%q want unhealthy", out.Status)
	}
	if out.LastStatusCode == nil || *out.LastStatusCode != 302 {
		t.Errorf("last_status_code=%v want 302", out.LastStatusCode)
	}
	if !strings.Contains(out.LastError, "302") {
		t.Errorf("last_error=%q should mention 302", out.LastError)
	}
	if out.LastCheckedAt == nil || !out.LastCheckedAt.Equal(at) {
		t.Errorf("last_checked_at=%v want %v", out.LastCheckedAt, at)
	}
	if out.NumFails != 2 {
		t.Errorf("num_fails=%d", out.NumFails)
	}
}

func TestClassifyTargetUnhealthyNetworkError(t *testing.T) {
	addr := "10.0.0.7:3001"
	events := map[string]healthCheckerEvent{
		addr: {
			addr:   addr,
			at:     time.Now().UTC(),
			msg:    "HTTP request failed",
			errMsg: "dial tcp: connection refused",
		},
	}
	out := classifyTarget(targetFixture("10.0.0.7", 3001), map[string]caddy.Upstream{addr: {Address: addr}}, events)
	if out.Status != "unhealthy" {
		t.Fatalf("status=%q want unhealthy", out.Status)
	}
	if out.LastError != "dial tcp: connection refused" {
		t.Errorf("last_error=%q", out.LastError)
	}
	if out.LastStatusCode != nil {
		t.Errorf("expected no status code for network error")
	}
}

func TestClassifyTargetUnknownNotInCaddy(t *testing.T) {
	out := classifyTarget(targetFixture("10.0.0.8", 80), nil, nil)
	if out.Status != "unknown" {
		t.Errorf("status=%q want unknown", out.Status)
	}
	if out.NumRequests != 0 || out.NumFails != 0 {
		t.Errorf("counters should be zero")
	}
}


// --- recentHealthCheckerEvents ---

// testDB stands up an in-memory SQLite with just the log_entries
// columns we actually touch. The full migration graph is overkill
// for this unit.
func testDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if _, err := d.Exec(`
		CREATE TABLE log_entries (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TIMESTAMP NOT NULL,
			source TEXT NOT NULL,
			raw TEXT NOT NULL DEFAULT ''
		)`); err != nil {
		t.Fatal(err)
	}
	return d
}

func insertLog(t *testing.T, d *sql.DB, ts time.Time, source, raw string) {
	t.Helper()
	_, err := d.Exec(`INSERT INTO log_entries (timestamp, source, raw) VALUES (?,?,?)`,
		ts.UTC(), source, raw)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRecentHealthCheckerEventsKeepsMostRecentPerAddr(t *testing.T) {
	d := testDB(t)
	now := time.Now().UTC()

	insertLog(t, d, now.Add(-60*time.Second), "caddy_error",
		`{"logger":"http.handlers.reverse_proxy.health_checker.active","msg":"unexpected status code","status_code":302,"host":"1.1.1.1:80","ts":`+fmt.Sprintf("%f", float64(now.Add(-60*time.Second).Unix()))+`}`)
	insertLog(t, d, now.Add(-10*time.Second), "caddy_error",
		`{"logger":"http.handlers.reverse_proxy.health_checker.active","msg":"unexpected status code","status_code":500,"host":"1.1.1.1:80","ts":`+fmt.Sprintf("%f", float64(now.Add(-10*time.Second).Unix()))+`}`)

	out, err := recentHealthCheckerEvents(context.Background(), d, now.Add(-90*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	evt, ok := out["1.1.1.1:80"]
	if !ok {
		t.Fatal("expected 1.1.1.1:80 key")
	}
	if evt.statusCode != 500 {
		t.Errorf("want most-recent 500, got %d", evt.statusCode)
	}
}

func TestRecentHealthCheckerEventsIgnoresOldEntries(t *testing.T) {
	d := testDB(t)
	now := time.Now().UTC()
	insertLog(t, d, now.Add(-200*time.Second), "caddy_error",
		`{"logger":"http.handlers.reverse_proxy.health_checker.active","msg":"unexpected status code","status_code":500,"host":"1.2.3.4:80"}`)
	out, err := recentHealthCheckerEvents(context.Background(), d, now.Add(-90*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Errorf("expected 0 events (all too old), got %d", len(out))
	}
}

func TestRecentHealthCheckerEventsIgnoresOtherLoggers(t *testing.T) {
	d := testDB(t)
	now := time.Now().UTC()
	insertLog(t, d, now.Add(-5*time.Second), "caddy_error",
		`{"logger":"tls.obtain","msg":"something","host":"a:1"}`)
	out, err := recentHealthCheckerEvents(context.Background(), d, now.Add(-90*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Errorf("expected 0 events (wrong logger), got %d", len(out))
	}
}

// --- cache behaviour ---

func TestTargetHealthCacheServesCachedBodyWithinTTL(t *testing.T) {
	c := &TargetHealthCache{TTL: 5 * time.Second}
	c.body = TargetsHealthResponse{
		Targets:   []TargetHealth{{TargetID: 1, Host: "cached", Port: 80, Status: "healthy"}},
		FetchedAt: time.Now(),
	}
	c.at = time.Now()

	h := &Handlers{TargetHealthCache: c}
	req := httptest.NewRequest(http.MethodGet, "/api/targets/health", nil)
	w := httptest.NewRecorder()
	h.TargetsHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"host":"cached"`) {
		t.Errorf("body does not contain cached target: %s", w.Body.String())
	}
}

func TestTargetHealthCacheInvalidateClearsAt(t *testing.T) {
	c := &TargetHealthCache{TTL: 5 * time.Second}
	c.at = time.Now()
	c.Invalidate()
	if !c.at.IsZero() {
		t.Error("Invalidate did not zero at")
	}
}
