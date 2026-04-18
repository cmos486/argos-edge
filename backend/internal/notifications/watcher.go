package notifications

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/models"
)

// LogWatcher is the Observer wired into logs.Ingestor. It maintains
// in-memory sliding windows to detect WAF attack bursts, rate-limit
// bursts, target up/down transitions, and cert renewal failures, and
// emits events via the provided Emitter.
//
// Everything is in-memory: on panel restart the windows reset. For
// homelab scale that's fine -- the events are "ongoing condition"
// signals, not "count every single occurrence ever".
type LogWatcher struct {
	em *Emitter

	mu sync.Mutex

	// wafAttack: remote_ip -> []timestamps (oldest evicted)
	wafAttack map[string][]time.Time
	// rateLimit: host_domain -> []timestamps
	rateLimit map[string][]time.Time
	// targetState: host:port -> last known state ("up" / "down")
	targetState map[string]string
}

// NewLogWatcher wires an observer against the emitter.
func NewLogWatcher(em *Emitter) *LogWatcher {
	return &LogWatcher{
		em:          em,
		wafAttack:   make(map[string][]time.Time),
		rateLimit:   make(map[string][]time.Time),
		targetState: make(map[string]string),
	}
}

// Observe is the Ingestor.Observer. Must not block.
func (w *LogWatcher) Observe(e models.LogEntry) {
	now := time.Now().UTC()
	switch e.Source {
	case models.LogWAFAudit:
		w.onWAFAudit(e, now)
	case models.LogCaddyError:
		w.onCaddyError(e, now)
	case models.LogCaddyAccess:
		w.onCaddyAccess(e, now)
	}
}

func (w *LogWatcher) onWAFAudit(e models.LogEntry, now time.Time) {
	// Only CRITICAL/ERROR severity counts as attack for the burst signal
	if e.WAFSeverity != "CRITICAL" && e.WAFSeverity != "ERROR" {
		return
	}
	if e.RemoteIP == "" {
		return
	}
	const (
		window = 60 * time.Second
		thresh = 10
	)
	w.mu.Lock()
	list := w.wafAttack[e.RemoteIP]
	// drop entries older than the window
	cutoff := now.Add(-window)
	i := 0
	for ; i < len(list); i++ {
		if list[i].After(cutoff) {
			break
		}
	}
	list = append(list[i:], now)
	w.wafAttack[e.RemoteIP] = list
	shouldFire := len(list) >= thresh
	var count int
	if shouldFire {
		count = len(list)
		// reset so we don't re-fire on every subsequent violation
		// within the same burst; next burst after a clean window re-arms
		w.wafAttack[e.RemoteIP] = nil
	}
	w.mu.Unlock()
	if shouldFire {
		w.em.Emit(Event{
			Type:       EvtWAFAttackBurst,
			Severity:   SeverityCritical,
			HostDomain: e.HostDomain,
			HostID:     derefInt64(e.HostID),
			Message:    "attack burst from " + e.RemoteIP,
			Data: map[string]any{
				"remote_ip":      e.RemoteIP,
				"count":          count,
				"window_seconds": int(window.Seconds()),
			},
		})
	}
}

func (w *LogWatcher) onCaddyError(e models.LogEntry, now time.Time) {
	msg := e.Message
	lower := strings.ToLower(msg)
	// cert renewal failures: caddy logs like
	//   "tls.issuance.acme: could not obtain certificate: ..."
	if strings.Contains(lower, "obtain certificate") || strings.Contains(lower, "obtaining certificate") {
		if strings.Contains(lower, "error") || e.Level == "error" {
			w.em.Emit(Event{
				Type:       EvtCertRenewalFailed,
				Severity:   SeverityError,
				HostDomain: e.HostDomain,
				Message:    "ACME renewal failed: " + truncate(msg, 200),
				Data:       map[string]any{"error": msg, "logger": "caddy_error"},
			})
			return
		}
	}
	// target health-checker transitions. Caddy's active health checker
	// logger is "http.reverse_proxy.health_checker.active" and emits
	// messages containing "host is up" / "host is down" with a
	// "host" field in the structured log. Our ingestor flattens the
	// message + logger into e.Message so we substring-match here.
	if strings.Contains(lower, "host is down") {
		hostPort := extractHostPort(msg)
		w.mu.Lock()
		prev := w.targetState[hostPort]
		w.targetState[hostPort] = "down"
		w.mu.Unlock()
		if prev != "down" {
			w.em.Emit(Event{
				Type:     EvtTargetUnhealthy,
				Severity: SeverityError,
				Message:  "target " + hostPort + " is down",
				Data:     map[string]any{"target": hostPort, "state": "down"},
			})
		}
		return
	}
	if strings.Contains(lower, "host is up") {
		hostPort := extractHostPort(msg)
		w.mu.Lock()
		prev := w.targetState[hostPort]
		w.targetState[hostPort] = "up"
		w.mu.Unlock()
		if prev == "down" {
			w.em.Emit(Event{
				Type:     EvtTargetRecovered,
				Severity: SeverityInfo,
				Message:  "target " + hostPort + " is up",
				Data:     map[string]any{"target": hostPort, "state": "up"},
			})
		}
		return
	}
}

func (w *LogWatcher) onCaddyAccess(e models.LogEntry, now time.Time) {
	if e.Status != 429 {
		return
	}
	if e.HostDomain == "" {
		return
	}
	const (
		window = 30 * time.Second
		thresh = 5
	)
	w.mu.Lock()
	list := w.rateLimit[e.HostDomain]
	cutoff := now.Add(-window)
	i := 0
	for ; i < len(list); i++ {
		if list[i].After(cutoff) {
			break
		}
	}
	list = append(list[i:], now)
	w.rateLimit[e.HostDomain] = list
	shouldFire := len(list) >= thresh
	var count int
	if shouldFire {
		count = len(list)
		w.rateLimit[e.HostDomain] = nil
	}
	w.mu.Unlock()
	if shouldFire {
		w.em.Emit(Event{
			Type:       EvtRateLimitTriggered,
			Severity:   SeverityWarning,
			HostDomain: e.HostDomain,
			HostID:     derefInt64(e.HostID),
			Message:    fmt.Sprintf("rate limit hit %d times in %ds on %s", count, int(window.Seconds()), e.HostDomain),
			Data: map[string]any{
				"count":          count,
				"window_seconds": int(window.Seconds()),
			},
		})
	}
}

func derefInt64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// extractHostPort pulls a "host:port" substring from a Caddy log
// message. Best-effort: if the format changes, emits the whole message
// as the target id. Caddy typically writes messages like:
//   "active health check: host is up" with structured fields host=... ,
// but our ingestor collapses that into a plain string, so we fall
// back to the last "host:port" looking token.
func extractHostPort(msg string) string {
	// look for host:port pattern
	fields := strings.Fields(msg)
	for _, f := range fields {
		f = strings.Trim(f, `"',`)
		if i := strings.LastIndexByte(f, ':'); i > 0 && i < len(f)-1 {
			tail := f[i+1:]
			if _, err := strconv.Atoi(tail); err == nil {
				return f
			}
		}
	}
	return msg
}
