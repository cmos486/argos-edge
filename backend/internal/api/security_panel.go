package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cmos486/argos-edge/backend/internal/crowdsec"
	"github.com/cmos486/argos-edge/backend/internal/security"
)

// v1.3.23 read/write endpoints supporting the SelfBlockBanner v2
// and the v1.3.24 /security UI tabs (Banned IPs, Whitelist,
// Activity, dashboard widget). Wired under /api/security/* by the
// router; all behind the same session middleware.
//
//   GET    /api/security/decisions             list + filter + paginate
//   DELETE /api/security/decisions/{id}        unban single
//   GET    /api/security/whitelist             list rows
//   DELETE /api/security/whitelist/{id}        delete single
//   GET    /api/security/audit-log             paginated query of log_entries
//   GET    /api/security/dashboard-stats       aggregate counts
//   GET    /api/security/public-ip-self        Detector status snapshot

// ListDecisions handles GET /api/security/decisions.
//
// Query params:
//
//	scope     filter by scope (Ip, Range, Country, AS) - exact match
//	origin    filter by origin (cscli, argos-country-XX, etc.) - exact match
//	q         substring match against value/scenario (case-insensitive)
//	limit     max rows returned (default 100, max 1000)
//	offset    skip first N rows
//
// LAPI itself is the source of truth; the panel does not maintain
// a parallel decisions table. We hit the cached ListDecisions and
// filter / paginate client-side -- that keeps the implementation
// simple at small scale (the bouncer cache handles hot-path
// lookups).
func (h *Handlers) ListDecisions(w http.ResponseWriter, r *http.Request) {
	if h.CrowdSec == nil {
		writeJSON(w, http.StatusOK, struct {
			Decisions []crowdsec.Decision `json:"decisions"`
			Total     int                 `json:"total"`
		}{Decisions: []crowdsec.Decision{}, Total: 0})
		return
	}
	all, err := h.CrowdSec.ListDecisions(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "lapi: "+err.Error())
		return
	}

	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	scope := strings.TrimSpace(r.URL.Query().Get("scope"))
	origin := strings.TrimSpace(r.URL.Query().Get("origin"))

	filtered := make([]crowdsec.Decision, 0, len(all))
	for _, d := range all {
		if scope != "" && !strings.EqualFold(d.Scope, scope) {
			continue
		}
		if origin != "" && d.Origin != origin {
			continue
		}
		if q != "" {
			if !strings.Contains(strings.ToLower(d.Value), q) &&
				!strings.Contains(strings.ToLower(d.Scenario), q) {
				continue
			}
		}
		filtered = append(filtered, d)
	}

	limit := atoiClamp(r.URL.Query().Get("limit"), 100, 1, 1000)
	offset := atoiClamp(r.URL.Query().Get("offset"), 0, 0, 1<<30)
	total := len(filtered)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	page := filtered[offset:end]

	writeJSON(w, http.StatusOK, struct {
		Decisions []crowdsec.Decision `json:"decisions"`
		Total     int                 `json:"total"`
		Limit     int                 `json:"limit"`
		Offset    int                 `json:"offset"`
	}{Decisions: page, Total: total, Limit: limit, Offset: offset})
}

// DeleteDecisionByID handles DELETE /api/security/decisions/{id}.
// The Banned IPs UI tab calls this for the per-row "unban" button.
func (h *Handlers) DeleteDecisionByID(w http.ResponseWriter, r *http.Request) {
	if h.CrowdSec == nil {
		writeError(w, http.StatusServiceUnavailable, "crowdsec client not wired")
		return
	}
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid decision id")
		return
	}
	n, err := h.CrowdSec.DeleteDecisionByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, crowdsec.ErrNotConfigured) {
			writeError(w, http.StatusServiceUnavailable, "crowdsec machine credentials missing")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete: "+err.Error())
		return
	}
	h.audit(r, "security_unban_by_id", "decision", id, map[string]any{
		"id":      id,
		"deleted": n,
	})
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "deleted": n})
}

// ListWhitelist handles GET /api/security/whitelist. Returns rows
// ordered newest-first so the UI tab renders recent operator
// adds at the top.
func (h *Handlers) ListWhitelist(w http.ResponseWriter, r *http.Request) {
	entries, err := security.ListWhitelist(r.Context(), h.DB)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list: "+err.Error())
		return
	}
	if entries == nil {
		entries = []security.WhitelistEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

// DeleteWhitelist handles DELETE /api/security/whitelist/{id}.
// Idempotent: missing id returns 200 with deleted=false. The
// shared sentinel rewrite happens automatically; the operator
// still needs to re-run setup-appsec.sh to drop the YAML entry
// from CrowdSec.
func (h *Handlers) DeleteWhitelist(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid whitelist id")
		return
	}
	deleted, err := security.DeleteWhitelistByID(r.Context(), h.DB, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "delete: "+err.Error())
		return
	}
	h.audit(r, "security_whitelist_delete", "whitelist", id, map[string]any{
		"id":      id,
		"deleted": deleted,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"id":             id,
		"deleted":        deleted,
		"reload_needed":  deleted,
		"reload_command": "docker compose exec crowdsec /setup-appsec.sh",
	})
}

// AuditLogEntry is one row returned by /api/security/audit-log.
// Mirrors what the v1.3.24 Activity tab will render: when, who,
// what, from where.
type AuditLogEntry struct {
	ID         int64  `json:"id"`
	Timestamp  string `json:"timestamp"`
	Action     string `json:"action"`
	Resource   string `json:"resource_type"`
	ResourceID int64  `json:"resource_id"`
	UserID     int64  `json:"user_id"`
	SourceIP   string `json:"source_ip"`
	XFFChain   string `json:"xff_chain,omitempty"`
	Diff       any    `json:"diff,omitempty"`
}

// AuditLog handles GET /api/security/audit-log. Reads from
// log_entries WHERE source='audit', parses the JSON raw column to
// surface user_id / source_ip / xff_chain / diff cleanly.
//
// Query params:
//
//	q          substring match against action / resource / source_ip
//	limit      default 100, max 500
//	offset     skip first N rows
func (h *Handlers) AuditLog(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	limit := atoiClamp(r.URL.Query().Get("limit"), 100, 1, 500)
	offset := atoiClamp(r.URL.Query().Get("offset"), 0, 0, 1<<30)

	// Total first so the UI can render pagination cleanly.
	var total int
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM log_entries WHERE source = 'audit'`,
	).Scan(&total); err != nil {
		writeError(w, http.StatusInternalServerError, "count: "+err.Error())
		return
	}

	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT id, timestamp, message, raw
		  FROM log_entries
		 WHERE source = 'audit'
		 ORDER BY id DESC
		 LIMIT ? OFFSET ?
	`, limit*5, offset) // fetch wider, filter in memory
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query: "+err.Error())
		return
	}
	defer rows.Close()

	out := make([]AuditLogEntry, 0, limit)
	for rows.Next() && len(out) < limit {
		var (
			id        int64
			timestamp string
			message   string
			raw       string
		)
		if err := rows.Scan(&id, &timestamp, &message, &raw); err != nil {
			continue
		}
		entry := AuditLogEntry{ID: id, Timestamp: timestamp}
		// raw is the marshalled enrichAuditDiff payload. Parse
		// best-effort; an entry from before v1.3.23 may lack
		// _source_ip, in which case we leave it blank.
		var payload map[string]any
		if err := json.Unmarshal([]byte(raw), &payload); err == nil {
			if v, ok := payload["action"].(string); ok {
				entry.Action = v
			}
			if v, ok := payload["resource_type"].(string); ok {
				entry.Resource = v
			}
			if v, ok := payload["resource_id"].(float64); ok {
				entry.ResourceID = int64(v)
			}
			if v, ok := payload["user_id"].(float64); ok {
				entry.UserID = int64(v)
			}
			if v, ok := payload["_source_ip"].(string); ok {
				entry.SourceIP = v
			}
			if v, ok := payload["_xff_chain"].(string); ok {
				entry.XFFChain = v
			}
			// Drop the internal keys before forwarding the diff.
			delete(payload, "_source_ip")
			delete(payload, "_xff_chain")
			delete(payload, "user_id")
			delete(payload, "action")
			delete(payload, "resource_type")
			delete(payload, "resource_id")
			if len(payload) > 0 {
				entry.Diff = payload
			}
		}
		// q substring filter (action / resource / source IP).
		if q != "" {
			hay := strings.ToLower(entry.Action + " " + entry.Resource + " " + entry.SourceIP)
			if !strings.Contains(hay, q) {
				continue
			}
		}
		out = append(out, entry)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"entries": out,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

// DashboardStats is the rollup the v1.3.24 dashboard widget will
// render: bans count by scope + top countries (from active
// argos-country-* origin tags). Cheap enough to compute per-call;
// no caching layer.
type DashboardStats struct {
	BansTotal        int               `json:"bans_total"`
	BansByScope      map[string]int    `json:"bans_by_scope"`
	BansByOrigin     map[string]int    `json:"bans_by_origin"`
	TopCountries     []CountryStat     `json:"top_countries"`
	WhitelistEntries int               `json:"whitelist_entries"`
	AuditLast24h     int               `json:"audit_last_24h"`
	GeneratedAt      string            `json:"generated_at"`
}

// CountryStat is one row in DashboardStats.TopCountries, ordered
// by decision count desc.
type CountryStat struct {
	CountryCode  string `json:"country_code"`
	CIDRCount    int    `json:"cidr_count"`
	DecisionsActive int `json:"decisions_active"`
}

// DashboardStats handles GET /api/security/dashboard-stats.
func (h *Handlers) DashboardStats(w http.ResponseWriter, r *http.Request) {
	stats := DashboardStats{
		BansByScope:  map[string]int{},
		BansByOrigin: map[string]int{},
		TopCountries: []CountryStat{},
	}

	if h.CrowdSec != nil {
		all, err := h.CrowdSec.ListDecisions(r.Context())
		if err == nil {
			stats.BansTotal = len(all)
			for _, d := range all {
				stats.BansByScope[d.Scope]++
				stats.BansByOrigin[d.Origin]++
			}
		}
	}

	// Whitelist count.
	_ = h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM security_whitelist`).Scan(&stats.WhitelistEntries)

	// Audit events in the last 24h.
	_ = h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM log_entries WHERE source='audit' AND timestamp >= datetime('now', '-1 day')`).
		Scan(&stats.AuditLast24h)

	// Country expansions: use the panel-managed table for the
	// authoritative CIDR count per country, then enrich with
	// LAPI decision counts grouped by argos-country-XX origin.
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT country_code, cidr_count FROM country_ban_expansions ORDER BY cidr_count DESC LIMIT 20`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var s CountryStat
			if err := rows.Scan(&s.CountryCode, &s.CIDRCount); err == nil {
				origin := "argos-country-" + s.CountryCode
				if c, ok := stats.BansByOrigin[origin]; ok {
					s.DecisionsActive = c
				}
				stats.TopCountries = append(stats.TopCountries, s)
			}
		}
	}

	stats.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	writeJSON(w, http.StatusOK, stats)
}

// PublicIPSelf handles GET /api/security/public-ip-self. Returns
// the cached public IP detection state (last-detected IP, last
// poll time, last error if any). Banner v2 reads check-self for
// the in-context probe; this endpoint exists for the v1.3.24
// "diagnostics" panel that surfaces detection health.
func (h *Handlers) PublicIPSelf(w http.ResponseWriter, r *http.Request) {
	if h.PublicIP == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ip": "", "disabled": true,
		})
		return
	}
	writeJSON(w, http.StatusOK, h.PublicIP.Status(r.Context()))
}

// atoiClamp parses an integer query param into [min, max], with a
// default if the parse fails or the param is absent.
func atoiClamp(raw string, def, min, max int) int {
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

