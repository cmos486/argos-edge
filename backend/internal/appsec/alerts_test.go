package appsec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/crowdsec"
	"github.com/cmos486/argos-edge/backend/internal/notifications"
)

// fakeLAPI answers the machine login and GET /v1/alerts with the
// alerts the test installs, recording every alerts query string.
type fakeLAPI struct {
	mu      sync.Mutex
	queries []string
	alerts  []crowdsec.Alert
	srv     *httptest.Server
}

func newFakeLAPI(t *testing.T) (*fakeLAPI, *Provider) {
	t.Helper()
	f := &fakeLAPI{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost && r.URL.Path == "/v1/watchers/login" {
			_, _ = w.Write([]byte(`{"code":200,"expire":"2099-01-01T00:00:00Z","token":"stub"}`))
			return
		}
		f.mu.Lock()
		f.queries = append(f.queries, r.URL.RawQuery)
		list := f.alerts
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(list)
	}))
	t.Cleanup(f.srv.Close)
	p := NewProvider(crowdsec.New(f.srv.URL, "", "stub", "stub"))
	return f, p
}

func wafAlert(id int64, ip, fqdn string, at time.Time) crowdsec.Alert {
	return crowdsec.Alert{
		ID: id, Kind: "waf", Scenario: "crowdsecurity/vpatch-env-access",
		CreatedAtText: at.UTC().Format(time.RFC3339), StartAt: at.UTC().Format(time.RFC3339),
		Source: crowdsec.AlertSource{Scope: "Ip", Value: ip},
		Events: []crowdsec.AlertEvent{{Meta: []crowdsec.AlertEventMeta{
			{Key: "target_fqdn", Value: fqdn}, {Key: "uri", Value: "/.env"}, {Key: "message", Value: "env access"},
		}}},
	}
}

func banAlert(id int64, ip string, at time.Time) crowdsec.Alert {
	t := true
	return crowdsec.Alert{
		ID: id, Kind: "crowdsec", Scenario: "crowdsecurity/appsec-native", Remediation: &t,
		CreatedAtText: at.UTC().Format(time.RFC3339),
		Source:        crowdsec.AlertSource{Scope: "Ip", Value: ip},
	}
}

func TestAlertsOneFetchServesEveryShortWindow(t *testing.T) {
	f, p := newFakeLAPI(t)
	now := time.Now().UTC()
	f.alerts = []crowdsec.Alert{
		wafAlert(1, "203.0.113.1", "a.example.com", now.Add(-10*time.Minute)),
		wafAlert(2, "203.0.113.1", "a.example.com", now.Add(-3*time.Hour)),
		banAlert(3, "203.0.113.1", now.Add(-20*time.Hour)),
		{ID: 4, Kind: "crowdsec", Scenario: "crowdsecurity/http-probing", CreatedAtText: now.Format(time.RFC3339)}, // not AppSec
	}
	ctx := context.Background()
	all, at, err := p.Alerts(ctx, 24*time.Hour)
	if err != nil || len(all) != 3 || at.IsZero() {
		t.Fatalf("24h: n=%d at=%v err=%v", len(all), at, err)
	}
	h1, _, _ := p.Alerts(ctx, time.Hour)
	if len(h1) != 1 || h1[0].ID != 1 {
		t.Fatalf("1h window from the same fetch: %+v", h1)
	}
	if _, err := p.Metrics(ctx, 6*time.Hour, "block", "", ""); err != nil {
		t.Fatal(err)
	}
	if n := len(f.queries); n != 1 {
		t.Fatalf("one LAPI fetch expected for 24h + 1h + metrics(6h), got %d: %v", n, f.queries)
	}
	if q := f.queries[0]; q != "include_capi=false&limit=5000&since=1440m&with_decisions=false" {
		t.Fatalf("panel default query: %q", q)
	}
	// The dashboard's 24 h range arrives with its bucket snap (24 h 15 m):
	// still the short fetch, not a 7 d one.
	if _, _, err := p.Alerts(ctx, 24*time.Hour+15*time.Minute); err != nil {
		t.Fatal(err)
	}
	if n := len(f.queries); n != 1 {
		t.Fatalf("24h15m must reuse the 24 h fetch, got %d queries", n)
	}
	// A 7 d view is its own fetch; a second 7 d call inside the TTL is not.
	if _, _, err := p.Alerts(ctx, 7*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Alerts(ctx, 7*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if n := len(f.queries); n != 2 || !strings.Contains(f.queries[1], "since=10080m") {
		t.Fatalf("7d fetch: %v", f.queries)
	}
}

func TestAlertsSevenDayFallbackByWindows(t *testing.T) {
	f, p := newFakeLAPI(t)
	now := time.Now().UTC()
	full := make([]crowdsec.Alert, alertsFallbackAt)
	for i := range full {
		full[i] = wafAlert(int64(i+1), "203.0.113.9", "x.example.com", now.Add(-time.Duration(i)*time.Minute))
	}
	f.alerts = full
	if _, _, err := p.Alerts(context.Background(), 7*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	// 1 full fetch + 7 daily windows.
	if n := len(f.queries); n != 8 {
		t.Fatalf("expected 8 queries (1 + 7 windows), got %d: %v", n, f.queries)
	}
	if f.queries[1] != "include_capi=false&limit=5000&since=1440m&with_decisions=false" {
		t.Fatalf("day 0 window: %q", f.queries[1])
	}
	if f.queries[2] != "include_capi=false&limit=5000&since=2880m&until=1440m&with_decisions=false" {
		t.Fatalf("day 1 window: %q", f.queries[2])
	}
	if !strings.Contains(f.queries[7], "since=10080m&until=8640m") {
		t.Fatalf("day 6 window: %q", f.queries[7])
	}
}

func TestSummarizeHitsBansAndHosts(t *testing.T) {
	now := time.Now().UTC()
	alerts := []crowdsec.Alert{
		wafAlert(1, "203.0.113.1", "A.example.com", now.Add(-5*time.Minute)),
		wafAlert(2, "203.0.113.2", "a.example.com", now.Add(-6*time.Minute)),
		wafAlert(3, "203.0.113.2", "b.example.com", now.Add(-7*time.Minute)),
		banAlert(4, "203.0.113.2", now.Add(-8*time.Minute)),
		wafAlert(5, "203.0.113.3", "c.example.com", now.Add(-30*time.Hour)), // outside
	}
	s := Summarize(alerts, now.Add(-24*time.Hour), now, 15*time.Minute, "block", "detect", now.Add(-time.Hour).Format(time.RFC3339))
	if s.Hits != 3 || s.Bans != 1 {
		t.Fatalf("hits=%d bans=%d", s.Hits, s.Bans)
	}
	if s.HitsByHost["a.example.com"] != 2 || s.HitsByHost["b.example.com"] != 1 {
		t.Fatalf("hits by host: %v", s.HitsByHost)
	}
	if s.ByIP["203.0.113.2"] != 3 || len(s.HostsByIP["203.0.113.2"]) != 2 {
		t.Fatalf("by ip: %v hosts %v", s.ByIP, s.HostsByIP)
	}
	if s.Blocked != 4 || s.Logged != 0 {
		t.Fatalf("mode boundary attribution: blocked=%d logged=%d", s.Blocked, s.Logged)
	}
	var total int
	for _, o := range s.Buckets {
		total += o.Blocked + o.Detected
	}
	if total != 4 {
		t.Fatalf("buckets carry %d events, want 4", total)
	}
}

type captureNotifier struct {
	mu     sync.Mutex
	events []notifications.Event
}

func (c *captureNotifier) Emit(ev notifications.Event) {
	c.mu.Lock()
	c.events = append(c.events, ev)
	c.mu.Unlock()
}

func TestBurstDetectorEmitsOncePerBurst(t *testing.T) {
	f, p := newFakeLAPI(t)
	n := &captureNotifier{}
	p.SetNotifier(n)
	now := time.Now().UTC()
	var alerts []crowdsec.Alert
	// 12 hits from one IP inside 30 s, after SetNotifier: one burst.
	for i := 0; i < 12; i++ {
		alerts = append(alerts, wafAlert(int64(100+i), "198.51.100.7", "h.example.com", now.Add(time.Duration(i)*2*time.Second+time.Second)))
	}
	// 12 hits from another IP spread over 5 minutes: no burst.
	for i := 0; i < 12; i++ {
		alerts = append(alerts, wafAlert(int64(200+i), "198.51.100.8", "h.example.com", now.Add(time.Duration(i)*25*time.Second+time.Second)))
	}
	f.alerts = alerts
	if _, _, err := p.Alerts(context.Background(), 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if len(n.events) != 1 || n.events[0].Type != notifications.EvtWAFAttackBurst || n.events[0].Data["remote_ip"] != "198.51.100.7" || n.events[0].Data["engine"] != "appsec" {
		t.Fatalf("burst events: %+v", n.events)
	}
	if n.events[0].HostDomain != "h.example.com" || n.events[0].Data["count"].(int) < burstThresh {
		t.Fatalf("burst event shape: %+v", n.events[0])
	}
	// A refresh that sees the same alerts again must not re-emit.
	p.short.set.at = time.Time{}
	if _, _, err := p.Alerts(context.Background(), 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if len(n.events) != 1 {
		t.Fatalf("burst re-emitted on refresh: %d events", len(n.events))
	}
}

func TestBurstDetectorIgnoresHistoryBeforeNotifier(t *testing.T) {
	f, p := newFakeLAPI(t)
	now := time.Now().UTC()
	var alerts []crowdsec.Alert
	for i := 0; i < 12; i++ {
		alerts = append(alerts, wafAlert(int64(i+1), "198.51.100.9", "h.example.com", now.Add(-10*time.Minute+time.Duration(i)*time.Second)))
	}
	f.alerts = alerts
	n := &captureNotifier{}
	p.SetNotifier(n) // after the burst happened
	if _, _, err := p.Alerts(context.Background(), 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if len(n.events) != 0 {
		t.Fatalf("history before SetNotifier must not notify: %+v", n.events)
	}
	_ = fmt.Sprint
}

// TestWindowsUseStartedAt: the LAPI filters since/until on started_at;
// the panel windows on the same field so its counts match a LAPI
// query over the same window. An alert inserted now (created_at) for
// an event that started 26 h ago is outside a 24 h window.
func TestWindowsUseStartedAt(t *testing.T) {
	now := time.Now().UTC()
	old := wafAlert(1, "203.0.113.5", "a.example.com", now.Add(-26*time.Hour))
	old.CreatedAtText = now.Format(time.RFC3339)
	fresh := wafAlert(2, "203.0.113.5", "a.example.com", now.Add(-30*time.Minute))
	in := filterWindow([]crowdsec.Alert{old, fresh}, 24*time.Hour, now)
	if len(in) != 1 || in[0].ID != 2 {
		t.Fatalf("filterWindow by started_at: %+v", in)
	}
	s := Summarize([]crowdsec.Alert{old, fresh}, now.Add(-24*time.Hour), now, time.Hour, "block", "", "")
	if s.Hits != 1 {
		t.Fatalf("Summarize by started_at: hits=%d", s.Hits)
	}
}
