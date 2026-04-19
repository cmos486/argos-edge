package api

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/logs"
	"github.com/cmos486/argos-edge/backend/internal/models"
)

const (
	maxLogLimit     = 1000
	defaultLogLimit = 100
	maxCSVRows      = 100000
	maxSSEPerUser   = 3
	sseHeartbeat    = 30 * time.Second
	statsCacheTTL   = 10 * time.Second
	tsCacheTTL      = 30 * time.Second
)

// parseLogFilter decodes the shared query-string filter used by every
// /api/logs endpoint.
func parseLogFilter(r *http.Request) db.LogFilter {
	q := r.URL.Query()
	f := db.LogFilter{}

	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.From = t
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.To = t
		}
	}
	for _, s := range splitCSV(q.Get("source")) {
		f.Sources = append(f.Sources, models.LogSource(s))
	}
	for _, s := range splitCSV(q.Get("host_id")) {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			f.HostIDs = append(f.HostIDs, n)
		}
	}
	for _, s := range splitCSV(q.Get("rule_id")) {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			f.RuleIDs = append(f.RuleIDs, n)
		}
	}
	f.StatusExpr = q.Get("status")
	f.Methods = splitCSV(q.Get("method"))
	f.PathExpr = q.Get("path")
	f.RemoteIP = q.Get("remote_ip")
	f.Levels = splitCSV(q.Get("level"))
	f.Query = q.Get("q")
	for _, s := range splitCSV(q.Get("waf_rule_id")) {
		if n, err := strconv.Atoi(s); err == nil {
			f.WAFRuleIDs = append(f.WAFRuleIDs, n)
		}
	}
	f.WAFSeverity = splitCSV(q.Get("waf_severity"))
	return f
}

// resolveHostDomains expands LogFilter.HostIDs with the current domain
// of each requested host so queries cover caddy_error rows (and any
// future waf_audit / audit rows) that landed without a linked host_id.
// Unknown ids are silently dropped (the remaining HostIDs leg still
// matches on id for rows that DO have a link).
func (h *Handlers) resolveHostDomains(r *http.Request, f *db.LogFilter) {
	if len(f.HostIDs) == 0 {
		return
	}
	for _, id := range f.HostIDs {
		var domain string
		err := h.DB.QueryRowContext(r.Context(),
			`SELECT domain FROM hosts WHERE id = ?`, id,
		).Scan(&domain)
		if err == nil && domain != "" {
			f.HostDomainsOR = append(f.HostDomainsOR, domain)
		}
	}
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ListLogs is GET /api/logs.
func (h *Handlers) ListLogs(w http.ResponseWriter, r *http.Request) {
	f := parseLogFilter(r)
	h.resolveHostDomains(r, &f)
	limit := clamp(atoiDefault(r.URL.Query().Get("limit"), defaultLogLimit), 1, maxLogLimit)
	offset := max0(atoiDefault(r.URL.Query().Get("offset"), 0))
	order := r.URL.Query().Get("order")

	entries, err := db.ListLogEntries(r.Context(), h.DB, f, order, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list logs failed")
		return
	}
	total, err := db.CountLogEntries(r.Context(), h.DB, f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "count logs failed")
		return
	}
	if entries == nil {
		entries = []models.LogEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entries":     entries,
		"total_count": total,
		"has_more":    offset+len(entries) < total,
	})
}

// GetLog is GET /api/logs/{id}.
func (h *Handlers) GetLog(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r, "id")
	if !ok {
		return
	}
	e, err := db.GetLogEntry(r.Context(), h.DB, id)
	if err != nil {
		if errors.Is(err, db.ErrLogNotFound) {
			writeError(w, http.StatusNotFound, "log entry not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get log failed")
		return
	}
	// Enrich remote_ip with geo when we have one. Wrapping via
	// map[string]any keeps models.LogEntry dependency-free while
	// letting the frontend render the flag/country/ASN line under
	// the IP in the WAF detail drawer.
	if e.RemoteIP != "" {
		if geo := h.enrichIP(e.RemoteIP); geo != nil {
			out := map[string]any{
				"id":                e.ID,
				"timestamp":         e.Timestamp,
				"source":            e.Source,
				"level":             e.Level,
				"host_id":           e.HostID,
				"host_domain":       e.HostDomain,
				"rule_id":           e.RuleID,
				"remote_ip":         e.RemoteIP,
				"method":            e.Method,
				"path":              e.Path,
				"status":            e.Status,
				"duration_ms":       e.DurationMs,
				"size_bytes":        e.SizeBytes,
				"user_agent":        e.UserAgent,
				"upstream":          e.Upstream,
				"message":           e.Message,
				"raw":               e.Raw,
				"waf_rule_id":       e.WAFRuleID,
				"waf_rule_message":  e.WAFRuleMessage,
				"waf_severity":      e.WAFSeverity,
				"waf_anomaly_score": e.WAFAnomalyScore,
				"geo":               geo,
			}
			writeJSON(w, http.StatusOK, out)
			return
		}
	}
	writeJSON(w, http.StatusOK, e)
}

// --- SSE stream ---

var sseCounts sync.Map // userID -> int

func (h *Handlers) StreamLogs(w http.ResponseWriter, r *http.Request) {
	u, _ := userFromContext(r.Context())
	c := incrSSE(u.ID)
	if c > maxSSEPerUser {
		decrSSE(u.ID)
		writeError(w, http.StatusTooManyRequests, "too many concurrent log streams for this user")
		return
	}
	defer decrSSE(u.ID)

	// The server has a 30s WriteTimeout that otherwise buffers every
	// Flush() until it fires -- producing the "first byte arrives at
	// t+30s, then connection closes, EventSource auto-reconnects, cycle
	// forever" symptom on real (non-loopback) clients. Disable the
	// write deadline per-request via net/http's ResponseController so
	// the rest of the server keeps its global write timeout.
	rc := http.NewResponseController(w)
	if err := rc.SetWriteDeadline(time.Time{}); err != nil {
		// Non-fatal: if a middleware wrapped the writer with a type
		// that does not expose the deadline setter, fall through.
		// Worst case we are back to the pre-fix behaviour.
		slog.Warn("sse: could not disable write deadline", "err", err)
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // kill proxy buffering
	w.WriteHeader(http.StatusOK)
	// Emit an initial SSE comment + flush so the client's EventSource
	// fires onopen immediately. Without this the browser may hold the
	// connection in an "opening" state until the first real event
	// arrives (which can be a full poll tick away).
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	filter := parseLogFilter(r)
	h.resolveHostDomains(r, &filter)
	filter.From = time.Time{} // stream is "from now" only
	filter.To = time.Time{}

	// Start from the current max id so existing rows are not replayed.
	var lastID int64
	_ = h.DB.QueryRowContext(r.Context(),
		`SELECT COALESCE(MAX(id), 0) FROM log_entries`).Scan(&lastID)

	poll := time.NewTicker(1 * time.Second)
	defer poll.Stop()
	heartbeat := time.NewTicker(sseHeartbeat)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			fmt.Fprint(w, ": heartbeat\n\n")
			flusher.Flush()
		case <-poll.C:
			rows, err := db.StreamLogEntries(r.Context(), h.DB, filter, lastID, 100)
			if err != nil {
				fmt.Fprintf(w, "event: error\ndata: %s\n\n", err.Error())
				flusher.Flush()
				continue
			}
			for _, e := range rows {
				if e.ID > lastID {
					lastID = e.ID
				}
				b, err := encodeJSONLine(e)
				if err != nil {
					continue
				}
				// Also emit a default `message` event so clients that
				// did not attach a named 'entry' listener still see
				// new rows. Both frames point at the same payload.
				fmt.Fprintf(w, "event: entry\ndata: %s\n\n", b)
				fmt.Fprintf(w, "data: %s\n\n", b)
			}
			if len(rows) > 0 {
				flusher.Flush()
			}
		}
	}
}

func incrSSE(uid int64) int {
	v, _ := sseCounts.LoadOrStore(uid, new(int))
	p := v.(*int)
	*p++
	return *p
}

func decrSSE(uid int64) {
	if v, ok := sseCounts.Load(uid); ok {
		p := v.(*int)
		if *p > 0 {
			*p--
		}
	}
}

// --- Export CSV ---

func (h *Handlers) ExportLogsCSV(w http.ResponseWriter, r *http.Request) {
	filter := parseLogFilter(r)
	h.resolveHostDomains(r, &filter)
	total, err := db.CountLogEntries(r.Context(), h.DB, filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "count logs failed")
		return
	}
	if total > maxCSVRows {
		writeError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("export would be %d rows (cap %d); refine filters", total, maxCSVRows))
		return
	}

	filename := "argos-logs-" + time.Now().UTC().Format("20060102T150405Z") + ".csv"
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{
		"timestamp", "source", "level", "host_id", "host_domain", "rule_id",
		"remote_ip", "method", "path", "status", "duration_ms", "size_bytes",
		"user_agent", "upstream", "message",
	})

	// Paginate through the match set to avoid loading everything at once.
	const page = 2000
	written := 0
	for offset := 0; ; offset += page {
		rows, err := db.ListLogEntries(r.Context(), h.DB, filter, "asc", page, offset)
		if err != nil || len(rows) == 0 {
			break
		}
		for _, e := range rows {
			hostID := ""
			if e.HostID != nil {
				hostID = strconv.FormatInt(*e.HostID, 10)
			}
			ruleID := ""
			if e.RuleID != nil {
				ruleID = strconv.FormatInt(*e.RuleID, 10)
			}
			_ = cw.Write([]string{
				e.Timestamp.UTC().Format(time.RFC3339Nano),
				string(e.Source), e.Level, hostID, e.HostDomain, ruleID,
				e.RemoteIP, e.Method, e.Path,
				strconv.Itoa(e.Status),
				strconv.Itoa(e.DurationMs), strconv.Itoa(e.SizeBytes),
				e.UserAgent, e.Upstream, e.Message,
			})
			written++
		}
		if len(rows) < page {
			break
		}
	}
	cw.Flush()
}

// --- Stats + Timeseries with small TTL caches ---

type statsCache struct {
	mu      sync.Mutex
	entries map[string]*cacheEntry
}

type cacheEntry struct {
	stored time.Time
	value  any
}

var logCache = &statsCache{entries: map[string]*cacheEntry{}}

func (c *statsCache) get(key string, ttl time.Duration) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || time.Since(e.stored) > ttl {
		return nil, false
	}
	return e.value, true
}

func (c *statsCache) put(key string, v any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = &cacheEntry{stored: time.Now(), value: v}
	if len(c.entries) > 256 {
		// Evict any 10 stale entries when the map grows unbounded.
		n := 0
		for k, e := range c.entries {
			if time.Since(e.stored) > statsCacheTTL {
				delete(c.entries, k)
				n++
				if n > 10 {
					break
				}
			}
		}
	}
}

func cacheKey(prefix string, f db.LogFilter, extra string) string {
	return fmt.Sprintf("%s|%s|%s|%v|%v|%v|%v|%s|%v|%s|%s|%v|%s|%s",
		prefix,
		f.From.UTC().Format(time.RFC3339Nano),
		f.To.UTC().Format(time.RFC3339Nano),
		f.Sources, f.HostIDs, f.HostDomainsOR, f.RuleIDs,
		f.StatusExpr, f.Methods,
		f.PathExpr, f.RemoteIP, f.Levels, f.Query, extra)
}

func (h *Handlers) LogStats(w http.ResponseWriter, r *http.Request) {
	f := parseLogFilter(r)
	h.resolveHostDomains(r, &f)
	key := cacheKey("stats", f, "")
	if v, ok := logCache.get(key, statsCacheTTL); ok {
		writeJSON(w, http.StatusOK, v)
		return
	}
	s, err := db.ComputeStats(r.Context(), h.DB, f)
	if err != nil {
		slog.Error("log stats compute", "error", err)
		writeError(w, http.StatusInternalServerError, "stats failed")
		return
	}
	logCache.put(key, s)
	writeJSON(w, http.StatusOK, s)
}

func (h *Handlers) LogTimeseries(w http.ResponseWriter, r *http.Request) {
	f := parseLogFilter(r)
	h.resolveHostDomains(r, &f)
	bucket := atoiDefault(r.URL.Query().Get("bucket_seconds"), 0)
	if bucket <= 0 {
		bucket = autoBucketSeconds(f)
	}
	key := cacheKey("ts", f, strconv.Itoa(bucket))
	if v, ok := logCache.get(key, tsCacheTTL); ok {
		writeJSON(w, http.StatusOK, v)
		return
	}
	pts, err := db.ComputeTimeseries(r.Context(), h.DB, f, bucket)
	if err != nil {
		slog.Error("log timeseries compute", "error", err)
		writeError(w, http.StatusInternalServerError, "timeseries failed")
		return
	}
	resp := map[string]any{"bucket_seconds": bucket, "points": pts}
	logCache.put(key, resp)
	writeJSON(w, http.StatusOK, resp)
}

// autoBucketSeconds picks 1min/5min/1h based on the filter's time span.
func autoBucketSeconds(f db.LogFilter) int {
	if f.From.IsZero() || f.To.IsZero() {
		return 60
	}
	span := f.To.Sub(f.From)
	switch {
	case span <= time.Hour:
		return 60
	case span <= 6*time.Hour:
		return 300
	case span <= 48*time.Hour:
		return 3600
	default:
		return 3600
	}
}

// --- Purge ---

func (h *Handlers) PurgeLogs(w http.ResponseWriter, r *http.Request) {
	n, err := logs.RunPurgeOnce(r.Context(), h.DB)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "purge failed")
		return
	}
	h.audit(r, "purge", "logs", 0, map[string]any{"removed": n})
	writeJSON(w, http.StatusOK, map[string]any{"removed": n})
}

// --- Presets ---

type logPreset struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Filters     map[string]any `json:"filters"`
}

func (h *Handlers) ListLogPresets(w http.ResponseWriter, r *http.Request) {
	presets := []logPreset{
		{"all_errors", "All errors", "Any 4xx or 5xx response",
			map[string]any{"status": "4xx,5xx"}},
		{"5xx_last_hour", "5xx (last hour)", "Server errors in the last 60 minutes",
			map[string]any{"status": "5xx", "from_relative_minutes": 60}},
		{"slow_requests", "Slow requests", "Access entries with duration over 1s",
			map[string]any{"source": "caddy_access", "q_hint": "filter UI by duration>1000 client-side"}},
		{"cert_events", "Certificate events", "ACME / certificate messages from Caddy errors",
			map[string]any{"source": "caddy_error", "q": "acme"}},
		{"auth_events", "Auth events", "Login, logout and failed logins",
			map[string]any{"source": "audit", "q": "login"}},
		{"config_changes", "Config changes", "Mutations on hosts, target groups and rules",
			map[string]any{"source": "audit", "q": "create update delete"}},
		{"blocked", "Blocked requests", "Access entries that returned 403",
			map[string]any{"source": "caddy_access", "status": "403"}},
		{"waf_blocks", "WAF blocks", "Coraza audit rows at ERROR or CRITICAL severity",
			map[string]any{"source": "waf_audit", "waf_severity": "CRITICAL,ERROR"}},
		{"waf_alerts_24h", "WAF alerts (24h)", "Any Coraza audit entry in the last 24 hours",
			map[string]any{"source": "waf_audit", "from_relative_minutes": 1440}},
	}
	writeJSON(w, http.StatusOK, presets)
}

// --- helpers ---

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func max0(v int) int {
	if v < 0 {
		return 0
	}
	return v
}

// encodeJSONLine marshals an entry compactly for SSE framing.
func encodeJSONLine(e models.LogEntry) (string, error) {
	b, err := jsonMarshalCompact(e)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// RouteLogsMux is a convenience for server.go to attach all /api/logs
// routes in one shot; kept as a method so it can access h.
func (h *Handlers) RouteLogsMux(r chi.Router) {
	r.Get("/logs", h.ListLogs)
	r.Get("/logs/presets", h.ListLogPresets)
	r.Get("/logs/stats", h.LogStats)
	r.Get("/logs/timeseries", h.LogTimeseries)
	r.Get("/logs/stream", h.StreamLogs)
	r.Get("/logs/export.csv", h.ExportLogsCSV)
	r.Post("/logs/purge", h.PurgeLogs)
	r.Get("/logs/{id}", h.GetLog)
}

// unused helper to silence potential lint on context.Background use
var _ = context.Background
