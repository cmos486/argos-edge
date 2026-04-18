package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/models"
)

type ruleRequest struct {
	Priority int                 `json:"priority"`
	Name     string              `json:"name"`
	Enabled  *bool               `json:"enabled,omitempty"`
	Action   models.ActionEnv    `json:"action"`
	Matchers []models.MatcherEnv `json:"matchers"`
}

type reorderRequest struct {
	RuleIDs []int64 `json:"rule_ids"`
}

// ListRules returns every rule for a host.
func (h *Handlers) ListRules(w http.ResponseWriter, r *http.Request) {
	hostID, ok := h.requireHost(w, r)
	if !ok {
		return
	}
	rules, err := db.ListRulesByHost(r.Context(), h.DB, hostID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list rules failed")
		return
	}
	if rules == nil {
		rules = []models.Rule{}
	}
	writeJSON(w, http.StatusOK, rules)
}

// GetRule returns one rule scoped to the host.
func (h *Handlers) GetRule(w http.ResponseWriter, r *http.Request) {
	hostID, ok := h.requireHost(w, r)
	if !ok {
		return
	}
	ruleID, ok := parseIDParam(w, r, "rule_id")
	if !ok {
		return
	}
	rule, err := db.GetRule(r.Context(), h.DB, hostID, ruleID)
	if err != nil {
		if errors.Is(err, db.ErrRuleNotFound) || errors.Is(err, db.ErrRuleHostMismatch) {
			writeError(w, http.StatusNotFound, "rule not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get rule failed")
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

// CreateRule inserts a new rule for the host. Priority defaults to
// max(priority)+10 when absent.
func (h *Handlers) CreateRule(w http.ResponseWriter, r *http.Request) {
	hostID, ok := h.requireHost(w, r)
	if !ok {
		return
	}
	var req ruleRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	rule := req.toRule(hostID, 0)
	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	} else {
		rule.Enabled = true
	}

	// Priority is validated only when the caller supplied one; zero
	// means "auto assign", which the repo handles.
	if rule.Priority != 0 {
		if err := rule.Validate(h.tgExistsFn(r.Context())); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		// Validate everything except priority.
		rule.Priority = 1
		if err := rule.Validate(h.tgExistsFn(r.Context())); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		rule.Priority = 0
	}

	created, err := db.CreateRule(r.Context(), h.DB, rule)
	if err != nil {
		if errors.Is(err, db.ErrRulePriorityTaken) {
			writeError(w, http.StatusConflict, "priority already taken for this host")
			return
		}
		writeError(w, http.StatusInternalServerError, "create rule failed")
		return
	}
	h.audit(r, "create", "rule", created.ID, created)
	h.reconcile(r.Context())
	writeJSON(w, http.StatusCreated, created)
}

// UpdateRule overwrites a rule.
func (h *Handlers) UpdateRule(w http.ResponseWriter, r *http.Request) {
	hostID, ok := h.requireHost(w, r)
	if !ok {
		return
	}
	ruleID, ok := parseIDParam(w, r, "rule_id")
	if !ok {
		return
	}
	var req ruleRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.Enabled == nil {
		writeError(w, http.StatusBadRequest, "enabled required on update")
		return
	}
	rule := req.toRule(hostID, ruleID)
	rule.Enabled = *req.Enabled
	if err := rule.Validate(h.tgExistsFn(r.Context())); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	updated, err := db.UpdateRule(r.Context(), h.DB, rule)
	if err != nil {
		if errors.Is(err, db.ErrRuleNotFound) {
			writeError(w, http.StatusNotFound, "rule not found")
			return
		}
		if errors.Is(err, db.ErrRulePriorityTaken) {
			writeError(w, http.StatusConflict, "priority already taken for this host")
			return
		}
		writeError(w, http.StatusInternalServerError, "update rule failed")
		return
	}
	h.audit(r, "update", "rule", updated.ID, updated)
	h.reconcile(r.Context())
	writeJSON(w, http.StatusOK, updated)
}

// DeleteRule removes a rule.
func (h *Handlers) DeleteRule(w http.ResponseWriter, r *http.Request) {
	hostID, ok := h.requireHost(w, r)
	if !ok {
		return
	}
	ruleID, ok := parseIDParam(w, r, "rule_id")
	if !ok {
		return
	}
	if err := db.DeleteRule(r.Context(), h.DB, hostID, ruleID); err != nil {
		if errors.Is(err, db.ErrRuleNotFound) {
			writeError(w, http.StatusNotFound, "rule not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete rule failed")
		return
	}
	h.audit(r, "delete", "rule", ruleID, nil)
	h.reconcile(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

// ToggleRule flips enabled.
func (h *Handlers) ToggleRule(w http.ResponseWriter, r *http.Request) {
	hostID, ok := h.requireHost(w, r)
	if !ok {
		return
	}
	ruleID, ok := parseIDParam(w, r, "rule_id")
	if !ok {
		return
	}
	rule, err := db.ToggleRule(r.Context(), h.DB, hostID, ruleID)
	if err != nil {
		if errors.Is(err, db.ErrRuleNotFound) {
			writeError(w, http.StatusNotFound, "rule not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "toggle rule failed")
		return
	}
	h.audit(r, "toggle", "rule", rule.ID, map[string]any{"enabled": rule.Enabled})
	h.reconcile(r.Context())
	writeJSON(w, http.StatusOK, rule)
}

// ReorderRules reassigns priorities based on the ordered rule_ids.
func (h *Handlers) ReorderRules(w http.ResponseWriter, r *http.Request) {
	hostID, ok := h.requireHost(w, r)
	if !ok {
		return
	}
	var req reorderRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if err := db.ReorderRules(r.Context(), h.DB, hostID, req.RuleIDs); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "reorder", "rule", hostID, map[string]any{"rule_ids": req.RuleIDs})
	h.reconcile(r.Context())
	// Return the freshly ordered list so the UI does not have to re-fetch.
	rules, err := db.ListRulesByHost(r.Context(), h.DB, hostID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list rules after reorder failed")
		return
	}
	if rules == nil {
		rules = []models.Rule{}
	}
	writeJSON(w, http.StatusOK, rules)
}

// --- helpers ---

// requireHost verifies the {host_id} URL param resolves to an existing
// host. Returns the id and true on success; writes 4xx on failure.
func (h *Handlers) requireHost(w http.ResponseWriter, r *http.Request) (int64, bool) {
	hostID, ok := parseIDParam(w, r, "host_id")
	if !ok {
		return 0, false
	}
	if _, err := db.GetHost(r.Context(), h.DB, hostID); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "host not found")
			return 0, false
		}
		writeError(w, http.StatusInternalServerError, "get host failed")
		return 0, false
	}
	return hostID, true
}

// tgExistsFn wraps the db existence check so rule validators can verify
// forward action target_group_id without importing db themselves.
func (h *Handlers) tgExistsFn(ctx context.Context) models.TargetGroupExistsFn {
	return func(id int64) (bool, error) {
		_, err := db.GetTargetGroup(ctx, h.DB, id)
		if err == nil {
			return true, nil
		}
		if errors.Is(err, db.ErrTargetGroupNotFound) {
			return false, nil
		}
		return false, err
	}
}

// toRule packs the wire shape into a models.Rule. Enabled is left as
// zero here; the caller decides based on POST (default true) vs PUT
// (required from client).
func (req *ruleRequest) toRule(hostID, id int64) models.Rule {
	return models.Rule{
		ID:       id,
		HostID:   hostID,
		Priority: req.Priority,
		Name:     req.Name,
		Action:   req.Action,
		Matchers: req.Matchers,
	}
}
