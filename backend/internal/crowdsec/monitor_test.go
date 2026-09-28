package crowdsec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/cmos486/argos-edge/backend/internal/notifications"
)

func drainEvents(em *notifications.Emitter) []notifications.Event {
	var out []notifications.Event
	for {
		select {
		case ev := <-em.Events():
			out = append(out, ev)
		default:
			return out
		}
	}
}

// TestNotifyPerDecision pins the origins that keep a per-decision
// event (v1.3.42.2).
func TestNotifyPerDecision(t *testing.T) {
	cases := []struct {
		origin string
		want   bool
	}{
		{"CAPI", false}, {"capi", false}, {" CAPI ", false}, {"lists", false}, {"LISTS", false},
		{"crowdsec", true}, {"cscli", true}, {"manual", true}, {"argos-country-BR", true}, {"", true},
	}
	for _, c := range cases {
		if got := notifyPerDecision(c.origin); got != c.want {
			t.Errorf("notifyPerDecision(%q) = %v, want %v", c.origin, got, c.want)
		}
	}
}

// TestMonitorSkipsBlocklistPerDecisionEvents (v1.3.42.2): a simulated
// community-blocklist pull of 15,000 CAPI decisions plus 10 from a
// third-party list, with new IDs, produces no per-decision
// threat_ip_banned event; the one new local decision in the same poll
// does; the threat_intel_updated summary counts all of them; nothing
// is dropped from the queue.
func TestMonitorSkipsBlocklistPerDecisionEvents(t *testing.T) {
	var phase atomic.Int32
	c, _, closeFn := fakeLAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/decisions" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		list := []Decision{{ID: 1, Origin: "crowdsec", Type: "ban", Scope: "Ip", Value: "203.0.113.1", Scenario: "crowdsecurity/http-probing", Duration: "4h"}}
		if phase.Load() >= 1 {
			list = append(list, Decision{ID: 2, Origin: "crowdsec", Type: "ban", Scope: "Ip", Value: "203.0.113.2", Scenario: "crowdsecurity/ssh-bf", Duration: "4h"})
			for i := int64(0); i < 15000; i++ {
				list = append(list, Decision{ID: 1000 + i, Origin: "CAPI", Type: "ban", Scope: "Ip",
					Value: fmt.Sprintf("198.51.100.%d", i%256), Scenario: "crowdsecurity/community-blocklist", Duration: "24h"})
			}
			for i := int64(0); i < 10; i++ {
				list = append(list, Decision{ID: 20000 + i, Origin: "lists", Type: "ban", Scope: "Ip",
					Value: fmt.Sprintf("192.0.2.%d", i), Scenario: "lists:example", Duration: "24h"})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(list)
	})
	defer closeFn()
	c.BouncerKey = "stub-key"

	em := notifications.NewEmitter()
	m := NewMonitor(c, em)
	ctx := context.Background()

	m.tick(ctx) // first poll only primes the previous set
	if got := drainEvents(em); len(got) != 0 {
		t.Fatalf("first poll emitted %d events, want 0", len(got))
	}

	phase.Store(1)
	m.tick(ctx)
	events := drainEvents(em)
	var banned, summaries int
	for _, ev := range events {
		switch ev.Type {
		case notifications.EvtThreatIPBanned:
			banned++
			if ev.Data["ip"] != "203.0.113.2" {
				t.Errorf("per-decision event for %v, want only the local decision 203.0.113.2", ev.Data["ip"])
			}
		case notifications.EvtThreatIntelUpdated:
			summaries++
			if ev.Data["added_count"] != 15011 || ev.Data["removed_count"] != 0 || ev.Data["total"] != 15012 {
				t.Errorf("summary counts = %v, want added 15011 removed 0 total 15012", ev.Data)
			}
		default:
			t.Errorf("unexpected event type %s", ev.Type)
		}
	}
	if banned != 1 || summaries != 1 {
		t.Fatalf("got %d threat_ip_banned and %d threat_intel_updated events, want 1 and 1 (total %d)", banned, summaries, len(events))
	}
	if d := em.Dropped(); d != 0 {
		t.Fatalf("emitter dropped %d events, want 0", d)
	}
}
