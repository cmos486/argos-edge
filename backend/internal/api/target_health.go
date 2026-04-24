package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/caddy"
	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/models"
)

// TargetHealth is the per-target view the UI renders in the Target
// groups page. Status collapses three signals into one verdict:
//
//   - Caddy /reverse_proxy/upstreams counters (authoritative for
//     num_requests / fails)
//   - Recent (last 90s) caddy_error log lines whose logger prefix is
//     http.handlers.reverse_proxy.health_checker.active -- that is
//     Caddy's own active health probe reporting a bad response or a
//     network-level error
//   - Presence of the target in the upstreams list at all; a freshly
//     added target or one on a disabled host group returns "unknown"
type TargetHealth struct {
	TargetID       int64      `json:"target_id"`
	TargetGroupID  int64      `json:"target_group_id"`
	Host           string     `json:"host"`
	Port           int        `json:"port"`
	Enabled        bool       `json:"enabled"`
	Status         string     `json:"status"`
	LastStatusCode *int       `json:"last_status_code,omitempty"`
	LastError      string     `json:"last_error,omitempty"`
	LastCheckedAt  *time.Time `json:"last_checked_at,omitempty"`
	NumRequests    int        `json:"num_requests"`
	NumFails       int        `json:"num_fails"`
}

// TargetsHealthResponse is the body of GET /api/targets/health.
type TargetsHealthResponse struct {
	Targets   []TargetHealth `json:"targets"`
	FetchedAt time.Time      `json:"fetched_at"`
}

// TargetHealthCache memoises the full response for a short TTL so the
// UI polling loop does not DoS the caddy admin API or the log_entries
// scan. 30s matches the dashboard cache cadence.
type TargetHealthCache struct {
	TTL time.Duration

	mu   sync.Mutex
	at   time.Time
	body TargetsHealthResponse
}

// NewTargetHealthCache returns a cache with the standard 30s TTL.
func NewTargetHealthCache() *TargetHealthCache {
	return &TargetHealthCache{TTL: 30 * time.Second}
}

// Invalidate drops the cache; called when a reconcile is likely to
// change the upstream list.
func (c *TargetHealthCache) Invalidate() {
	c.mu.Lock()
	c.at = time.Time{}
	c.mu.Unlock()
}

// healthCheckerEvent is the parsed shape of one Caddy health_checker
// log line. addr is the upstream the probe targeted (host:port). The
// three outcome fields are sparse:
//   - statusCodePresent + statusCode: msg="unexpected status code"
//   - errMsg: msg="HTTP request failed" (network/TLS/timeout)
type healthCheckerEvent struct {
	addr              string
	at                time.Time
	msg               string
	statusCode        int
	statusCodePresent bool
	errMsg            string
}

// TargetsHealth handles GET /api/targets/health. Returns the cached
// body when fresh, otherwise builds a new one by joining the DB
// target list with live Caddy counters + recent health_checker log
// events.
func (h *Handlers) TargetsHealth(w http.ResponseWriter, r *http.Request) {
	if h.TargetHealthCache == nil {
		writeError(w, http.StatusServiceUnavailable, "target health cache not wired")
		return
	}

	c := h.TargetHealthCache
	c.mu.Lock()
	if !c.at.IsZero() && time.Since(c.at) < c.TTL {
		body := c.body
		c.mu.Unlock()
		writeJSON(w, http.StatusOK, body)
		return
	}
	c.mu.Unlock()

	body, err := h.buildTargetsHealth(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "build target health failed")
		return
	}

	c.mu.Lock()
	c.at = time.Now()
	c.body = body
	c.mu.Unlock()

	writeJSON(w, http.StatusOK, body)
}

// buildTargetsHealth is the uncached path. Shape:
//  1. list all targets (across all groups)
//  2. fetch live upstream counters from caddy admin
//  3. fetch last 90s of health_checker log events, keep the most
//     recent one per address
//  4. classify each target
func (h *Handlers) buildTargetsHealth(ctx context.Context) (TargetsHealthResponse, error) {
	out := TargetsHealthResponse{
		Targets:   []TargetHealth{},
		FetchedAt: time.Now().UTC(),
	}

	tgs, err := db.ListTargetGroups(ctx, h.DB, true)
	if err != nil {
		return out, fmt.Errorf("list target groups: %w", err)
	}

	var upstreams []caddy.Upstream
	if h.Caddy != nil {
		// Swallow the error: Caddy admin being temporarily unreachable
		// must not 500 the whole endpoint. Each target falls back to
		// "unknown" with zero counters.
		if ups, uerr := h.Caddy.Upstreams(ctx); uerr == nil {
			upstreams = ups
		}
	}
	upByAddr := make(map[string]caddy.Upstream, len(upstreams))
	for _, u := range upstreams {
		upByAddr[u.Address] = u
	}

	events, err := recentHealthCheckerEvents(ctx, h.DB, out.FetchedAt.Add(-90*time.Second))
	if err != nil {
		return out, fmt.Errorf("recent health events: %w", err)
	}

	for _, tg := range tgs {
		for _, t := range tg.Targets {
			out.Targets = append(out.Targets, classifyTarget(t, upByAddr, events))
		}
	}
	return out, nil
}

// classifyTarget turns the raw signals into a single TargetHealth.
//
// Rules:
//   - target not present in caddy upstreams -> unknown (target group
//     disabled, or caddy not reconciled yet).
//   - recent failure log for this address -> unhealthy (attach
//     status_code / error / timestamp).
//   - present in upstreams, no recent failure log -> healthy. Caddy
//     only logs health_checker events for failures, so the absence of
//     a log in the 90-second window means either a passing probe or
//     no active probe (passive health is still keeping the upstream
//     in the pool). Either way nothing has recently broken; "healthy"
//     is the right operator-facing verdict.
//
// Note: Caddy's num_requests in the admin API is the currently
// in-flight request count, not a cumulative total -- we still surface
// it because non-zero means "a request is actively being served right
// now" which is a useful signal in the tooltip, but it no longer
// gates the status verdict.
func classifyTarget(
	t models.Target,
	upByAddr map[string]caddy.Upstream,
	events map[string]healthCheckerEvent,
) TargetHealth {
	addr := fmt.Sprintf("%s:%d", t.Host, t.Port)
	out := TargetHealth{
		TargetID:      t.ID,
		TargetGroupID: t.TargetGroupID,
		Host:          t.Host,
		Port:          t.Port,
		Enabled:       t.Enabled,
		Status:        "unknown",
	}

	up, inCaddy := upByAddr[addr]
	if inCaddy {
		out.NumRequests = up.NumRequests
		out.NumFails = up.Fails
	}

	if evt, ok := events[addr]; ok {
		out.Status = "unhealthy"
		at := evt.at
		out.LastCheckedAt = &at
		if evt.statusCodePresent {
			sc := evt.statusCode
			out.LastStatusCode = &sc
			out.LastError = fmt.Sprintf("unexpected status code %d", evt.statusCode)
		} else if evt.errMsg != "" {
			out.LastError = evt.errMsg
		} else if evt.msg != "" {
			out.LastError = evt.msg
		}
		return out
	}

	if inCaddy {
		out.Status = "healthy"
	}
	return out
}

// recentHealthCheckerEvents scans log_entries for caddy_error lines
// whose raw JSON logger matches the active health_checker prefix,
// within [since, now). Returns a map keyed by upstream address
// (host:port) holding the MOST RECENT event seen for that address.
//
// The parse is raw-JSON based because the schema only extracts
// level/msg/error into columns; the status_code + host fields of
// caddy's health_checker output are specific to this logger and live
// in the raw field.
func recentHealthCheckerEvents(ctx context.Context, d *sql.DB, since time.Time) (map[string]healthCheckerEvent, error) {
	out := map[string]healthCheckerEvent{}
	rows, err := d.QueryContext(ctx, `
		SELECT timestamp, raw
		  FROM log_entries
		 WHERE source = 'caddy_error'
		   AND timestamp >= ?
		   AND raw LIKE '%health_checker.active%'
		 ORDER BY timestamp ASC`,
		since.UTC(),
	)
	if err != nil {
		return nil, fmt.Errorf("query log_entries: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var ts time.Time
		var raw string
		if err := rows.Scan(&ts, &raw); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		evt, ok := parseHealthCheckerLine(raw, ts)
		if !ok {
			continue
		}
		// Later iterations overwrite earlier ones because rows are
		// ASC-ordered; the final entry for each addr is the most
		// recent event.
		out[evt.addr] = evt
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows: %w", err)
	}
	return out, nil
}

// parseHealthCheckerLine decodes a single raw line and extracts only
// the health-checker fields we care about. Returns ok=false for lines
// that don't look like an active health_checker event (other logger,
// missing host, or malformed JSON).
func parseHealthCheckerLine(raw string, ts time.Time) (healthCheckerEvent, bool) {
	var r struct {
		Logger     string  `json:"logger"`
		Msg        string  `json:"msg"`
		Host       string  `json:"host"`
		Error      string  `json:"error"`
		StatusCode *int    `json:"status_code"`
		TS         float64 `json:"ts"`
	}
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return healthCheckerEvent{}, false
	}
	if !strings.HasPrefix(r.Logger, "http.handlers.reverse_proxy.health_checker.active") {
		return healthCheckerEvent{}, false
	}
	if r.Host == "" {
		return healthCheckerEvent{}, false
	}
	evt := healthCheckerEvent{
		addr:   r.Host,
		at:     ts.UTC(),
		msg:    r.Msg,
		errMsg: r.Error,
	}
	if r.TS > 0 {
		sec, frac := int64(r.TS), r.TS-float64(int64(r.TS))
		evt.at = time.Unix(sec, int64(frac*1e9)).UTC()
	}
	if r.StatusCode != nil {
		evt.statusCode = *r.StatusCode
		evt.statusCodePresent = true
	}
	return evt, true
}
