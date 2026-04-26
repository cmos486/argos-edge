package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/cmos486/argos-edge/backend/internal/security/country"
)

// v1.3.21: three /api/security/countries/* endpoints. They sit
// behind the same session middleware as the rest of /api/* (chi
// router applies it to the whole subtree).
//
//   POST   /api/security/countries/expand
//          body: {country_code, duration, reason}
//          Expands one country into N scope=Range LAPI decisions.
//
//   GET    /api/security/countries
//          Lists active expansions for the UI.
//
//   DELETE /api/security/countries/{cc}
//          Revokes the named country: drops every LAPI decision
//          tagged origin=argos-country-CC, removes the tracking
//          row.
//
// All three audit-log via h.audit so post-incident review can
// reconstruct who banned what country and when.

type expandCountryBody struct {
	Duration string `json:"duration"`
	Reason   string `json:"reason,omitempty"`
}

// ExpandCountry handles POST /api/security/countries/{cc}/expand.
//
// v1.3.31: replaced the synchronous v1.3.21 handler with an
// async submit-then-poll shape. Returns 202 + the new job_id;
// the goroutine spawned by JobRunner.Submit drives the LAPI
// chunked POST and updates progress in country_expansion_jobs.
// The frontend polls GET /api/security/jobs/{id} for status.
//
// Single-worker mutex inside JobRunner means concurrent submits
// queue (state=pending) until the in-flight expansion finishes;
// avoids the v1.3.22 LAPI WAL contention that motivated the
// chunked-batch design.
func (h *Handlers) ExpandCountry(w http.ResponseWriter, r *http.Request) {
	if h.CountryJobs == nil {
		writeError(w, http.StatusServiceUnavailable, "country job runner not wired (geoip db missing or crowdsec not configured)")
		return
	}
	cc := strings.TrimSpace(chi.URLParam(r, "cc"))
	if cc == "" {
		writeError(w, http.StatusBadRequest, "country code required in path")
		return
	}
	var body expandCountryBody
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	body.Duration = strings.TrimSpace(body.Duration)
	if body.Duration == "" {
		writeError(w, http.StatusBadRequest, `duration required (e.g. "4h", "168h", "8760h")`)
		return
	}

	actor := "unknown"
	if u, ok := userFromContext(r.Context()); ok {
		actor = u.Username
	}

	jobID, err := h.CountryJobs.Submit(r.Context(), cc, body.Duration, body.Reason, actor)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "submit: "+err.Error())
		return
	}
	job, err := h.CountryJobs.Get(r.Context(), jobID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read submitted job: "+err.Error())
		return
	}
	h.audit(r, "security_country_expand_submit", "country", jobID, map[string]any{
		"country_code": job.CountryCode,
		"duration":     body.Duration,
	})
	writeJSON(w, http.StatusAccepted, job)
}

// GetCountryJob handles GET /api/security/jobs/{id}.
func (h *Handlers) GetCountryJob(w http.ResponseWriter, r *http.Request) {
	if h.CountryJobs == nil {
		writeError(w, http.StatusServiceUnavailable, "country job runner not wired")
		return
	}
	idStr := chi.URLParam(r, "id")
	id, perr := strconv.ParseInt(idStr, 10, 64)
	if perr != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid job id")
		return
	}
	job, err := h.CountryJobs.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, country.ErrJobNotFound) {
			writeError(w, http.StatusNotFound, "job not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get job: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, job)
}

// ListCountryJobs handles GET /api/security/jobs?country=XX&limit=N.
// Empty country returns the most recent jobs across all countries.
func (h *Handlers) ListCountryJobs(w http.ResponseWriter, r *http.Request) {
	if h.CountryJobs == nil {
		writeJSON(w, http.StatusOK, []*country.Job{})
		return
	}
	cc := strings.TrimSpace(r.URL.Query().Get("country"))
	limit := 20
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}
	jobs, err := h.CountryJobs.ListByCountry(r.Context(), cc, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list jobs: "+err.Error())
		return
	}
	if jobs == nil {
		jobs = []*country.Job{}
	}
	writeJSON(w, http.StatusOK, jobs)
}

// ListCountryExpansions handles GET /api/security/countries.
func (h *Handlers) ListCountryExpansions(w http.ResponseWriter, r *http.Request) {
	if h.CountryExpander == nil {
		writeJSON(w, http.StatusOK, []country.Expansion{})
		return
	}
	expansions, err := h.CountryExpander.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list: "+err.Error())
		return
	}
	if expansions == nil {
		expansions = []country.Expansion{}
	}
	writeJSON(w, http.StatusOK, expansions)
}

// RevokeCountryBan handles DELETE /api/security/countries/{cc}.
func (h *Handlers) RevokeCountryBan(w http.ResponseWriter, r *http.Request) {
	if h.CountryExpander == nil {
		writeError(w, http.StatusServiceUnavailable, "country expander not wired")
		return
	}
	cc := chi.URLParam(r, "cc")
	if cc == "" {
		writeError(w, http.StatusBadRequest, "country code required in path")
		return
	}
	removed, err := h.CountryExpander.Revoke(r.Context(), cc)
	if err != nil {
		if strings.Contains(err.Error(), "ISO 3166-1") {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "revoke: "+err.Error())
		return
	}
	h.audit(r, "security_country_revoke", "country", 0, map[string]any{
		"country_code":            strings.ToUpper(cc),
		"removed_decision_count": removed,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"country_code":            strings.ToUpper(cc),
		"removed_decision_count": removed,
	})
}
