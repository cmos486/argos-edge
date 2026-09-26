package logs

import (
	"testing"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/models"
)

// TestAdmitObserverThenFilterThenWriter pins the per-entry order: the
// observer sees every entry, the ingest filter decides what reaches
// the writer, audit and waf_audit are never filtered.
func TestAdmitObserverThenFilterThenWriter(t *testing.T) {
	ing := &Ingestor{ch: make(chan models.LogEntry, 16)}
	var seen []models.LogEntry
	ing.SetObserver(func(e models.LogEntry) { seen = append(seen, e) })
	f := &IngestFilter{byRule: map[string]int64{}, day: utcDay(time.Now())}
	f.rules = ParseRules(DefaultDropLoggers, DefaultDropUserAgents, "")
	ing.SetFilter(f)
	now := time.Now().UTC()

	dropped := models.LogEntry{Source: models.LogCaddyAccess, Timestamp: now, UserAgent: "Uptime-Kuma/2.5.0", Path: "/"}
	kept := models.LogEntry{Source: models.LogCaddyAccess, Timestamp: now, UserAgent: "Mozilla/5.0", Path: "/x"}
	audit := models.LogEntry{Source: models.LogAudit, Timestamp: now, UserAgent: "Uptime-Kuma/2.5.0", Message: "login user"}
	waf := models.LogEntry{Source: models.LogWAFAudit, Timestamp: now, UserAgent: "Uptime-Kuma/2.5.0"}
	routine := models.LogEntry{Source: models.LogCaddyError, Timestamp: now, Message: "http.handlers.reverse_proxy.health_checker.active: HTTP request failed -- x"}

	if ing.admit(dropped) {
		t.Fatal("monitor row must not reach the writer")
	}
	for _, e := range []models.LogEntry{kept, audit, waf} {
		if !ing.admit(e) {
			t.Fatalf("%s must reach the writer", e.Source)
		}
	}
	if ing.admit(routine) {
		t.Fatal("routine health-checker line must not reach the writer")
	}
	if len(seen) != 5 {
		t.Fatalf("observer must see every entry, saw %d", len(seen))
	}
	if n := len(ing.ch); n != 3 {
		t.Fatalf("writer must receive 3 entries (kept, audit, waf), got %d", n)
	}
	for _, want := range []string{"/x", "", ""} {
		e := <-ing.ch
		if e.Source == models.LogCaddyAccess && e.Path != want {
			t.Fatalf("unexpected access entry in writer: %+v", e)
		}
		if e.UserAgent == "Uptime-Kuma/2.5.0" && e.Source == models.LogCaddyAccess {
			t.Fatalf("dropped entry reached the writer: %+v", e)
		}
	}
	if st := f.Stats(); st.Total != 2 {
		t.Fatalf("two drops must be counted, got %+v", st)
	}
	// No filter installed: everything reaches the writer.
	bare := &Ingestor{ch: make(chan models.LogEntry, 1)}
	if !bare.admit(dropped) {
		t.Fatal("without a filter every entry is stored")
	}
}
