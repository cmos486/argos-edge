package api

import (
	"errors"
	"net/http"
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

type expandCountryRequest struct {
	CountryCode string `json:"country_code"`
	Duration    string `json:"duration"`
	Reason      string `json:"reason,omitempty"`
}

// ExpandCountry handles POST /api/security/countries/expand.
func (h *Handlers) ExpandCountry(w http.ResponseWriter, r *http.Request) {
	if h.CountryExpander == nil {
		writeError(w, http.StatusServiceUnavailable, "country expander not wired (geoip db missing or crowdsec not configured)")
		return
	}
	var req expandCountryRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	req.CountryCode = strings.TrimSpace(req.CountryCode)
	req.Duration = strings.TrimSpace(req.Duration)
	if req.CountryCode == "" {
		writeError(w, http.StatusBadRequest, "country_code required")
		return
	}
	if req.Duration == "" {
		writeError(w, http.StatusBadRequest, "duration required (e.g. \"4h\", \"168h\", \"8760h\")")
		return
	}

	actor := "unknown"
	if u, ok := userFromContext(r.Context()); ok {
		actor = u.Username
	}

	res, err := h.CountryExpander.Ban(r.Context(), req.CountryCode, req.Duration, req.Reason, actor)
	if err != nil {
		switch {
		case errors.Is(err, country.ErrCountryNotFound):
			writeError(w, http.StatusNotFound, "country not in geoip database")
		case strings.Contains(err.Error(), "ISO 3166-1") || strings.Contains(err.Error(), "duration"):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "expand: "+err.Error())
		}
		return
	}

	h.audit(r, "security_country_expand", "country", res.ExpansionID, map[string]any{
		"country_code":  res.CountryCode,
		"cidr_count":    res.CIDRCount,
		"mmdb_version":  res.MMDBVersion,
		"replaced_rows": res.ReplacedRows,
	})
	writeJSON(w, http.StatusCreated, res)
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
