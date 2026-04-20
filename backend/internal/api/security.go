package api

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/models"
	"github.com/cmos486/argos-edge/backend/internal/waf"
)

// --- requests ---

type hostSecurityRequest struct {
	WAFEnabled             *bool  `json:"waf_enabled,omitempty"`
	WAFMode                string `json:"waf_mode"`
	WAFParanoia            int    `json:"waf_paranoia"`
	WAFBlockStatus         int    `json:"waf_block_status"`
	WAFBlockBody           string `json:"waf_block_body"`
	RateLimitEnabled       *bool  `json:"rate_limit_enabled,omitempty"`
	RateLimitRequests      int    `json:"rate_limit_requests"`
	RateLimitWindowSeconds int    `json:"rate_limit_window_seconds"`
	RateLimitKey           string `json:"rate_limit_key"`
	RateLimitHeaderName    string `json:"rate_limit_header_name"`
	RateLimitStatus        int    `json:"rate_limit_status"`
}

type exclusionRequest struct {
	CRSRuleID   int    `json:"crs_rule_id"`
	PathPattern string `json:"path_pattern"`
	Reason      string `json:"reason"`
	Enabled     *bool  `json:"enabled,omitempty"`
}

type customRuleRequest struct {
	Name    string `json:"name"`
	SecRule string `json:"secrule"`
	Enabled *bool  `json:"enabled,omitempty"`
}

// --- GET bundle ---

func (h *Handlers) GetHostSecurity(w http.ResponseWriter, r *http.Request) {
	hostID, ok := h.requireHost(w, r)
	if !ok {
		return
	}
	bundle, err := db.LoadHostSecurityBundle(r.Context(), h.DB, hostID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load security failed")
		return
	}
	if bundle.Exclusions == nil {
		bundle.Exclusions = []models.WAFExclusion{}
	}
	if bundle.CustomRules == nil {
		bundle.CustomRules = []models.WAFCustomRule{}
	}
	writeJSON(w, http.StatusOK, bundle)
}

// --- PUT core ---

func (h *Handlers) UpdateHostSecurity(w http.ResponseWriter, r *http.Request) {
	hostID, ok := h.requireHost(w, r)
	if !ok {
		return
	}
	var req hostSecurityRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	sec, msg := req.toHostSecurity(hostID)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	updated, err := db.UpdateHostSecurity(r.Context(), h.DB, sec)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "update security failed")
		return
	}
	h.audit(r, "update", "host_security", hostID, updated)
	h.reconcile(r.Context())
	writeJSON(w, http.StatusOK, updated)
}

// --- exclusions ---

func (h *Handlers) CreateExclusion(w http.ResponseWriter, r *http.Request) {
	hostID, ok := h.requireHost(w, r)
	if !ok {
		return
	}
	var req exclusionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	e, msg := req.toExclusion(hostID, 0)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if req.Enabled != nil {
		e.Enabled = *req.Enabled
	} else {
		e.Enabled = true
	}
	created, err := db.CreateExclusion(r.Context(), h.DB, e)
	if err != nil {
		if errors.Is(err, db.ErrExclusionDuplicate) {
			writeError(w, http.StatusConflict, "exclusion already exists for this rule + path")
			return
		}
		writeError(w, http.StatusInternalServerError, "create exclusion failed")
		return
	}
	h.audit(r, "create", "waf_exclusion", created.ID, created)
	h.reconcile(r.Context())
	writeJSON(w, http.StatusCreated, created)
}

func (h *Handlers) UpdateExclusion(w http.ResponseWriter, r *http.Request) {
	hostID, ok := h.requireHost(w, r)
	if !ok {
		return
	}
	exID, ok := parseIDParam(w, r, "id")
	if !ok {
		return
	}
	var req exclusionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	e, msg := req.toExclusion(hostID, exID)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if req.Enabled == nil {
		writeError(w, http.StatusBadRequest, "enabled required on update")
		return
	}
	e.Enabled = *req.Enabled
	updated, err := db.UpdateExclusion(r.Context(), h.DB, e)
	if err != nil {
		if errors.Is(err, db.ErrExclusionNotFound) {
			writeError(w, http.StatusNotFound, "exclusion not found")
			return
		}
		if errors.Is(err, db.ErrExclusionDuplicate) {
			writeError(w, http.StatusConflict, "exclusion already exists for this rule + path")
			return
		}
		writeError(w, http.StatusInternalServerError, "update exclusion failed")
		return
	}
	h.audit(r, "update", "waf_exclusion", updated.ID, updated)
	h.reconcile(r.Context())
	writeJSON(w, http.StatusOK, updated)
}

func (h *Handlers) DeleteExclusion(w http.ResponseWriter, r *http.Request) {
	hostID, ok := h.requireHost(w, r)
	if !ok {
		return
	}
	exID, ok := parseIDParam(w, r, "id")
	if !ok {
		return
	}
	if err := db.DeleteExclusion(r.Context(), h.DB, hostID, exID); err != nil {
		if errors.Is(err, db.ErrExclusionNotFound) {
			writeError(w, http.StatusNotFound, "exclusion not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete exclusion failed")
		return
	}
	h.audit(r, "delete", "waf_exclusion", exID, nil)
	h.reconcile(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) ToggleExclusion(w http.ResponseWriter, r *http.Request) {
	hostID, ok := h.requireHost(w, r)
	if !ok {
		return
	}
	exID, ok := parseIDParam(w, r, "id")
	if !ok {
		return
	}
	e, err := db.ToggleExclusion(r.Context(), h.DB, hostID, exID)
	if err != nil {
		if errors.Is(err, db.ErrExclusionNotFound) {
			writeError(w, http.StatusNotFound, "exclusion not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "toggle exclusion failed")
		return
	}
	h.audit(r, "toggle", "waf_exclusion", e.ID, map[string]any{"enabled": e.Enabled})
	h.reconcile(r.Context())
	writeJSON(w, http.StatusOK, e)
}

// --- custom rules ---

func (h *Handlers) CreateCustomRule(w http.ResponseWriter, r *http.Request) {
	hostID, ok := h.requireHost(w, r)
	if !ok {
		return
	}
	var req customRuleRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	rule, msg := req.toCustomRule(hostID, 0)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	} else {
		rule.Enabled = true
	}
	created, err := db.CreateCustomRule(r.Context(), h.DB, rule)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "create custom rule failed")
		return
	}
	h.audit(r, "create", "waf_custom_rule", created.ID, created)
	h.reconcile(r.Context())
	writeJSON(w, http.StatusCreated, created)
}

func (h *Handlers) UpdateCustomRule(w http.ResponseWriter, r *http.Request) {
	hostID, ok := h.requireHost(w, r)
	if !ok {
		return
	}
	cID, ok := parseIDParam(w, r, "id")
	if !ok {
		return
	}
	var req customRuleRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	rule, msg := req.toCustomRule(hostID, cID)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if req.Enabled == nil {
		writeError(w, http.StatusBadRequest, "enabled required on update")
		return
	}
	rule.Enabled = *req.Enabled
	updated, err := db.UpdateCustomRule(r.Context(), h.DB, rule)
	if err != nil {
		if errors.Is(err, db.ErrCustomRuleNotFound) {
			writeError(w, http.StatusNotFound, "custom rule not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "update custom rule failed")
		return
	}
	h.audit(r, "update", "waf_custom_rule", updated.ID, updated)
	h.reconcile(r.Context())
	writeJSON(w, http.StatusOK, updated)
}

func (h *Handlers) DeleteCustomRule(w http.ResponseWriter, r *http.Request) {
	hostID, ok := h.requireHost(w, r)
	if !ok {
		return
	}
	cID, ok := parseIDParam(w, r, "id")
	if !ok {
		return
	}
	if err := db.DeleteCustomRule(r.Context(), h.DB, hostID, cID); err != nil {
		if errors.Is(err, db.ErrCustomRuleNotFound) {
			writeError(w, http.StatusNotFound, "custom rule not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete custom rule failed")
		return
	}
	h.audit(r, "delete", "waf_custom_rule", cID, nil)
	h.reconcile(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) ToggleCustomRule(w http.ResponseWriter, r *http.Request) {
	hostID, ok := h.requireHost(w, r)
	if !ok {
		return
	}
	cID, ok := parseIDParam(w, r, "id")
	if !ok {
		return
	}
	rule, err := db.ToggleCustomRule(r.Context(), h.DB, hostID, cID)
	if err != nil {
		if errors.Is(err, db.ErrCustomRuleNotFound) {
			writeError(w, http.StatusNotFound, "custom rule not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "toggle custom rule failed")
		return
	}
	h.audit(r, "toggle", "waf_custom_rule", rule.ID, map[string]any{"enabled": rule.Enabled})
	h.reconcile(r.Context())
	writeJSON(w, http.StatusOK, rule)
}

// --- request validation ---

func (req *hostSecurityRequest) toHostSecurity(hostID int64) (models.HostSecurity, string) {
	mode := models.WAFMode(req.WAFMode)
	if mode == "" {
		mode = models.WAFModeDetect
	}
	if mode != models.WAFModeDetect && mode != models.WAFModeBlock {
		return models.HostSecurity{}, `waf_mode must be "detect" or "block"`
	}
	paranoia := req.WAFParanoia
	if paranoia == 0 {
		paranoia = 1
	}
	if paranoia < 1 || paranoia > 4 {
		return models.HostSecurity{}, "waf_paranoia must be between 1 and 4"
	}
	status := req.WAFBlockStatus
	if status == 0 {
		status = 403
	}
	if status < 100 || status > 599 {
		return models.HostSecurity{}, "waf_block_status must be between 100 and 599"
	}

	rlKey := models.RateLimitKey(req.RateLimitKey)
	if rlKey == "" {
		rlKey = models.RateLimitKeyIP
	}
	switch rlKey {
	case models.RateLimitKeyIP, models.RateLimitKeyHeader, models.RateLimitKeyGlobal:
	default:
		return models.HostSecurity{}, `rate_limit_key must be "ip", "header" or "global"`
	}

	rlEnabled := false
	if req.RateLimitEnabled != nil {
		rlEnabled = *req.RateLimitEnabled
	}
	if rlEnabled {
		if req.RateLimitRequests < 1 {
			return models.HostSecurity{}, "rate_limit_requests must be >= 1"
		}
		if req.RateLimitWindowSeconds < 1 || req.RateLimitWindowSeconds > 3600 {
			return models.HostSecurity{}, "rate_limit_window_seconds must be between 1 and 3600"
		}
		if rlKey == models.RateLimitKeyHeader && req.RateLimitHeaderName == "" {
			return models.HostSecurity{}, `rate_limit_header_name required when rate_limit_key is "header"`
		}
	}
	rlStatus := req.RateLimitStatus
	if rlStatus == 0 {
		rlStatus = 429
	}

	wafEnabled := false
	if req.WAFEnabled != nil {
		wafEnabled = *req.WAFEnabled
	}

	return models.HostSecurity{
		HostID:                 hostID,
		WAFEnabled:             wafEnabled,
		WAFMode:                mode,
		WAFParanoia:            paranoia,
		WAFBlockStatus:         status,
		WAFBlockBody:           req.WAFBlockBody,
		RateLimitEnabled:       rlEnabled,
		RateLimitRequests:      req.RateLimitRequests,
		RateLimitWindowSeconds: req.RateLimitWindowSeconds,
		RateLimitKey:           rlKey,
		RateLimitHeaderName:    req.RateLimitHeaderName,
		RateLimitStatus:        rlStatus,
	}, ""
}

func (req *exclusionRequest) toExclusion(hostID, id int64) (models.WAFExclusion, string) {
	if req.CRSRuleID <= 0 {
		return models.WAFExclusion{}, "crs_rule_id must be > 0"
	}
	if req.PathPattern != "" {
		if req.PathPattern[0] != '/' {
			return models.WAFExclusion{}, "path_pattern must start with /"
		}
	}
	return models.WAFExclusion{
		ID:          id,
		HostID:      hostID,
		CRSRuleID:   req.CRSRuleID,
		PathPattern: req.PathPattern,
		Reason:      req.Reason,
	}, ""
}

func (req *customRuleRequest) toCustomRule(hostID, id int64) (models.WAFCustomRule, string) {
	if _, err := waf.ValidateSecRule(req.SecRule); err != nil {
		return models.WAFCustomRule{}, fmt.Sprintf("secrule invalid: %v", err)
	}
	return models.WAFCustomRule{
		ID:      id,
		HostID:  hostID,
		Name:    req.Name,
		SecRule: req.SecRule,
	}, ""
}
