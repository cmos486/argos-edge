package api

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/crowdsec"
	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/notifications"
)

func (h *Handlers) requireThreats(w http.ResponseWriter) bool {
	if h.CrowdSec == nil {
		writeError(w, http.StatusServiceUnavailable, "crowdsec client not wired")
		return false
	}
	return true
}

// ThreatsStatus GET /api/threats/status
func (h *Handlers) ThreatsStatus(w http.ResponseWriter, r *http.Request) {
	if !h.requireThreats(w) {
		return
	}
	st := &crowdsec.Status{
		LAPIURL:   h.CrowdSec.URL,
		BouncerOK: h.CrowdSec.BouncerKey != "",
		MachineOK: h.CrowdSec.MachineUser != "" && h.CrowdSec.MachinePassword != "",
	}
	if h.CrowdSecMonitor != nil {
		if t := h.CrowdSecMonitor.LastHeartbeat(); !t.IsZero() {
			st.LastHeartbeat = &t
		}
	}
	switch {
	case !st.BouncerOK:
		st.State = "not_configured"
	default:
		ver, err := h.CrowdSec.Heartbeat(r.Context())
		if err != nil {
			st.State = "disconnected"
			st.Error = err.Error()
		} else {
			st.State = "connected"
			st.LAPIVersion = ver
		}
	}
	writeJSON(w, http.StatusOK, st)
}

// threatsFilter is the server-side filter of GET /api/threats/decisions.
// Every text match is case-insensitive substring; Country compares the
// two-letter code of Ip-scoped decisions (Range / Country / Username
// values have no single IP to resolve, so they never match a country).
type threatsFilter struct {
	Origin   string // exact, case-insensitive
	Type     string // exact, case-insensitive
	Search   string // value OR scenario contains
	IP       string // value contains
	Country  string // geo country code of Ip-scoped values, exact
	Scenario string // scenario contains
}

func parseThreatsFilter(q url.Values) threatsFilter {
	return threatsFilter{
		Origin:   strings.TrimSpace(q.Get("origin")),
		Type:     strings.TrimSpace(q.Get("type")),
		Search:   strings.ToLower(strings.TrimSpace(q.Get("search"))),
		IP:       strings.ToLower(strings.TrimSpace(q.Get("ip"))),
		Country:  strings.ToUpper(strings.TrimSpace(q.Get("country"))),
		Scenario: strings.ToLower(strings.TrimSpace(q.Get("scenario"))),
	}
}

// matches reports whether d passes f. geo resolves an Ip-scoped value
// to its enrichment and is only called when Country is set.
func (f threatsFilter) matches(d crowdsec.Decision, geo func(ip string) *crowdsec.GeoEnrichment) bool {
	if f.Origin != "" && !strings.EqualFold(d.Origin, f.Origin) {
		return false
	}
	if f.Type != "" && !strings.EqualFold(d.Type, f.Type) {
		return false
	}
	var value, scenario string
	if f.Search != "" || f.IP != "" || f.Scenario != "" {
		value = strings.ToLower(d.Value)
		scenario = strings.ToLower(d.Scenario)
	}
	if f.Search != "" && !strings.Contains(value, f.Search) && !strings.Contains(scenario, f.Search) {
		return false
	}
	if f.IP != "" && !strings.Contains(value, f.IP) {
		return false
	}
	if f.Scenario != "" && !strings.Contains(scenario, f.Scenario) {
		return false
	}
	if f.Country != "" {
		if !strings.EqualFold(d.Scope, "Ip") {
			return false
		}
		g := geo(d.Value)
		if g == nil || !strings.EqualFold(g.CountryCode, f.Country) {
			return false
		}
	}
	return true
}

// threatsDecisionsPage is the paged envelope of GET /api/threats/decisions
// (v1.3.38.5, only when the request carries page=).
type threatsDecisionsPage struct {
	Decisions []crowdsec.Decision `json:"decisions"`
	Total     int                 `json:"total"`
	Page      int                 `json:"page"`
	PerPage   int                 `json:"per_page"`
	Pages     int                 `json:"pages"`
}

// ThreatsDecisions GET /api/threats/decisions
//
// Filters (all optional, applied server-side over the LAPI list the
// client caches for 15 s): origin, type, search (value or scenario),
// ip (value contains), country (two-letter code, Ip scope only),
// scenario. Without page= the response is the flat array it always
// was (every matching decision, geo-enriched). With page= (1-based)
// and per_page (default 100, max 1000) the response is the
// threatsDecisionsPage envelope, and only the rows of that page are
// geo-enriched: a CAPI-enrolled stack carries 20-50k decisions, and
// the flat shape was 7 MB per refresh for a table that shows 100.
func (h *Handlers) ThreatsDecisions(w http.ResponseWriter, r *http.Request) {
	if !h.requireThreats(w) {
		return
	}
	q := r.URL.Query()
	paged := q.Has("page")
	list, err := h.CrowdSec.ListDecisions(r.Context())
	if err != nil {
		if errors.Is(err, crowdsec.ErrNotConfigured) {
			if paged {
				writeJSON(w, http.StatusOK, threatsDecisionsPage{Decisions: []crowdsec.Decision{}, Page: 1, PerPage: 100, Pages: 1})
				return
			}
			writeJSON(w, http.StatusOK, []crowdsec.Decision{})
			return
		}
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	f := parseThreatsFilter(q)
	geo := func(ip string) *crowdsec.GeoEnrichment { return toThreatsGeo(h.enrichIP(ip)) }
	// Always a copy: ListDecisions hands out its cached slice and the
	// geo enrichment below writes into the rows.
	filtered := make([]crowdsec.Decision, 0, len(list))
	for _, d := range list {
		if f.matches(d, geo) {
			filtered = append(filtered, d)
		}
	}
	if !paged {
		writeJSON(w, http.StatusOK, enrichThreatsGeo(filtered, geo))
		return
	}
	perPage := atoiClamp(q.Get("per_page"), 100, 1, 1000)
	total := len(filtered)
	pages := (total + perPage - 1) / perPage
	if pages == 0 {
		pages = 1
	}
	page := atoiClamp(q.Get("page"), 1, 1, 1<<30)
	if page > pages {
		page = pages
	}
	start := (page - 1) * perPage
	end := start + perPage
	if end > total {
		end = total
	}
	writeJSON(w, http.StatusOK, threatsDecisionsPage{
		Decisions: enrichThreatsGeo(filtered[start:end], geo),
		Total:     total,
		Page:      page,
		PerPage:   perPage,
		Pages:     pages,
	})
}

// enrichThreatsGeo fills Geo on the Ip-scoped rows in place and
// returns rows. Range / Country / Username scopes would not parse as
// a single IP. rows must be the handler's own copy, never the LAPI
// client's cached list.
func enrichThreatsGeo(rows []crowdsec.Decision, geo func(ip string) *crowdsec.GeoEnrichment) []crowdsec.Decision {
	for i := range rows {
		if strings.EqualFold(rows[i].Scope, "Ip") {
			rows[i].Geo = geo(rows[i].Value)
		}
	}
	return rows
}

// AddThreatDecision POST /api/threats/decisions
func (h *Handlers) AddThreatDecision(w http.ResponseWriter, r *http.Request) {
	if !h.requireThreats(w) {
		return
	}
	var p crowdsec.AddDecisionInput
	if err := decodeJSON(r, &p); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if p.IP == "" {
		writeError(w, http.StatusBadRequest, "ip required")
		return
	}
	if p.DurationHours <= 0 {
		p.DurationHours = 1
	}
	if p.DurationHours > 8760 {
		writeError(w, http.StatusBadRequest, "duration_hours must be <= 8760 (1 year)")
		return
	}
	if err := h.CrowdSec.AddDecision(r.Context(), p); err != nil {
		if errors.Is(err, crowdsec.ErrNotConfigured) {
			writeError(w, http.StatusServiceUnavailable,
				"machine credentials not configured; run `cscli machines add argos-panel`")
			return
		}
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	h.audit(r, "create", "crowdsec_decision", 0, map[string]any{
		"ip": p.IP, "duration_hours": p.DurationHours, "reason": p.Reason,
	})
	writeJSON(w, http.StatusCreated, map[string]any{
		"ip":             p.IP,
		"duration_hours": p.DurationHours,
		"reason":         p.Reason,
		"applied_at":     time.Now().UTC(),
	})
}

// DeleteThreatDecision DELETE /api/threats/decisions?ip=x.x.x.x
func (h *Handlers) DeleteThreatDecision(w http.ResponseWriter, r *http.Request) {
	if !h.requireThreats(w) {
		return
	}
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		writeError(w, http.StatusBadRequest, "ip query parameter required")
		return
	}
	n, err := h.CrowdSec.DeleteDecision(r.Context(), ip)
	if err != nil {
		if errors.Is(err, crowdsec.ErrNotConfigured) {
			writeError(w, http.StatusServiceUnavailable,
				"machine credentials not configured; run `cscli machines add argos-panel`")
			return
		}
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	h.audit(r, "delete", "crowdsec_decision", 0, map[string]any{"ip": ip, "removed": n})
	writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "removed": n})
}

// ThreatsStats GET /api/threats/stats
func (h *Handlers) ThreatsStats(w http.ResponseWriter, r *http.Request) {
	if !h.requireThreats(w) {
		return
	}
	list, err := h.CrowdSec.ListDecisions(r.Context())
	if err != nil {
		if errors.Is(err, crowdsec.ErrNotConfigured) {
			writeJSON(w, http.StatusOK, crowdsec.Stats{
				Range:      "current",
				ByOrigin:   map[string]int{},
				ByScenario: map[string]int{},
				ByScope:    map[string]int{},
			})
			return
		}
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	s := crowdsec.Stats{
		Range:           "current",
		ActiveDecisions: len(list),
		ByOrigin:        map[string]int{},
		ByScenario:      map[string]int{},
		ByScope:         map[string]int{},
		LastUpdated:     time.Now().UTC(),
	}
	for _, d := range list {
		if d.Origin != "" {
			s.ByOrigin[d.Origin]++
		}
		if d.Scenario != "" {
			s.ByScenario[d.Scenario]++
		}
		if d.Scope != "" {
			s.ByScope[d.Scope]++
		}
	}
	writeJSON(w, http.StatusOK, s)
}

// ThreatsScenarios GET /api/threats/scenarios -- phase 7 returns the
// hardcoded list of collections we install at compose up. A future
// phase can introspect /v1/watchers/self for the live list. The
// UI uses this for the "Collections installed" read-only card.
func (h *Handlers) ThreatsScenarios(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, []crowdsec.Collection{
		{
			Name:    "crowdsecurity/base-http-scenarios",
			Version: "installed-via-COLLECTIONS",
			Parsers: []string{"crowdsecurity/caddy-logs"},
			Scenarios: []string{
				"crowdsecurity/http-crawl-non_statics",
				"crowdsecurity/http-probing",
				"crowdsecurity/http-bad-user-agent",
				"crowdsecurity/http-sensitive-files",
				"crowdsecurity/http-path-traversal-probing",
			},
		},
		{
			Name:    "crowdsecurity/http-cve",
			Version: "installed-via-COLLECTIONS",
			Scenarios: []string{
				"crowdsecurity/CVE-2022-26134",
				"crowdsecurity/CVE-2022-37042",
				"crowdsecurity/CVE-2022-44877",
				"crowdsecurity/CVE-2023-22515",
				"crowdsecurity/CVE-2023-49103",
			},
		},
	})
}

// RegenerateCrowdSecCredentials POST /api/crowdsec/regenerate-credentials
//
// v1.3.6 — operator-triggered path to force a credentials reset
// without waiting for the next boot. Typical use:
//
//  1. Operator deletes the argos-panel machine out-of-band
//     (`cscli machines delete argos-panel` inside the crowdsec
//     container).
//  2. Panel still has the old user+password in DB. Until this
//     endpoint (or a restart) runs, LAPI calls keep 401'ing.
//  3. Operator clicks "Regenerate credentials" in the AppSec
//     page banner -> hits this endpoint -> panel verifies via
//     LAPI login -> on 401, purges DB + emits event.
//  4. Response tells the operator to run the init sidecar:
//     `docker compose up crowdsec-init`.
//
// Does NOT invoke docker compose from the panel: no docker
// socket privilege, intentionally (that would be a big security
// regression). The operator runs the init container; the panel
// imports the fresh creds on the next reconcile.
func (h *Handlers) RegenerateCrowdSecCredentials(w http.ResponseWriter, r *http.Request) {
	if h.CrowdSec == nil {
		writeError(w, http.StatusServiceUnavailable, "crowdsec client not wired")
		return
	}
	ctx := r.Context()

	// Resolve current state via the same helpers the bootstrap
	// module uses so we don't double-decrypt / disagree with
	// main.go.
	currentUser := db.GetSettingValue(ctx, h.DB, crowdsec.SettingMachineUser, "")
	var currentPass string
	if h.Cipher != nil {
		currentPass = crowdsec.ResolveMachinePassword(ctx, h.DB, h.Cipher)
	}
	lapiURL := db.GetSettingValue(ctx, h.DB, "crowdsec.lapi_url", "http://crowdsec:8081")

	// No creds configured at all -> nothing to regenerate.
	// Operator just needs to run `docker compose up crowdsec-init`;
	// respond with that instruction and a 200 (not a 400 -- the
	// endpoint's job is to return instructions, not to complain).
	if currentUser == "" || currentPass == "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":      "no_credentials",
			"message":     "No machine credentials are configured. Run `docker compose up crowdsec-init` to generate them.",
			"next_action": "docker compose up crowdsec-init",
		})
		return
	}

	verr := crowdsec.VerifyMachineCredentials(ctx, lapiURL, currentUser, currentPass)
	if verr == nil {
		// Credentials are still valid; nothing to do.
		writeJSON(w, http.StatusOK, map[string]any{
			"status":       "valid",
			"message":      "Stored credentials are valid. No action needed.",
			"machine_user": currentUser,
		})
		return
	}
	if !errors.Is(verr, crowdsec.ErrStaleCredentials) {
		// Transient -- don't purge working creds on a flake.
		writeError(w, http.StatusBadGateway,
			"could not verify credentials (LAPI reachable?): "+verr.Error())
		return
	}

	// Stale -- purge.
	if perr := crowdsec.PurgeMachineCredentials(ctx, h.DB); perr != nil {
		writeError(w, http.StatusInternalServerError,
			"credentials detected as stale, but purge failed: "+perr.Error())
		return
	}
	// Audit + event so the stale-creds story shows up in the
	// Notifications page too.
	h.audit(r, "crowdsec_credentials_purged", "crowdsec", 0, map[string]any{
		"machine_user": currentUser,
	})
	if h.NotifEmitter != nil {
		h.NotifEmitter.Emit(notifications.Event{
			Type:     notifications.EvtCrowdSecCredsStale,
			Severity: notifications.SeverityWarning,
			Message:  "crowdsec machine credentials stale; purged by operator-triggered regenerate. Run `docker compose up crowdsec-init` to regenerate.",
			Data: map[string]any{
				"machine_user": currentUser,
				"source":       "regenerate_endpoint",
			},
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "purged",
		"message":     "Credentials were stale (LAPI returned 401) and have been cleared. Run `docker compose up crowdsec-init` to register a fresh machine; the panel will import on its next reconcile.",
		"next_action": "docker compose up crowdsec-init",
	})
}
