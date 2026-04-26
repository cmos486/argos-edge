package api

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/security"
	"github.com/cmos486/argos-edge/backend/internal/security/scenarios"
)

// v1.3.25 settings keys backing the scenarios + appsec-tuning UI.
const (
	settingScenariosDisabled        = "appsec.disabled_scenarios"
	settingScenariosLastModifiedAt  = "appsec.scenarios.last_modified_at"
	settingScenariosLastAppliedAt   = "appsec.scenarios.last_applied_at"
	settingTuningInbound            = "appsec.inbound_threshold"
	settingTuningOutbound           = "appsec.outbound_threshold"
	settingTuningLastModifiedAt     = "appsec.tuning.last_modified_at"
	settingTuningLastAppliedAt      = "appsec.tuning.last_applied_at"
)

// ScenariosResponse is the body of GET /api/security/scenarios.
// reload_needed is true when the panel-managed disabled set has
// been modified more recently than the operator's last "Mark as
// applied" click. The UI surfaces a persistent badge in that
// state.
type ScenariosResponse struct {
	Scenarios       []scenarios.Scenario `json:"scenarios"`
	IsAvailable     bool                 `json:"is_available"`
	MountPath       string               `json:"mount_path"`
	DisabledCount   int                  `json:"disabled_count"`
	LastModifiedAt  string               `json:"last_modified_at,omitempty"`
	LastAppliedAt   string               `json:"last_applied_at,omitempty"`
	ReloadNeeded    bool                 `json:"reload_needed"`
}

// ListScenarios handles GET /api/security/scenarios.
func (h *Handlers) ListScenarios(w http.ResponseWriter, r *http.Request) {
	disabledCSV := db.GetSettingValue(r.Context(), h.DB, settingScenariosDisabled, "")
	res := h.scenariosReader().Read(disabledCSV)

	disabledCount := 0
	for _, s := range res.Scenarios {
		if s.Disabled {
			disabledCount++
		}
	}
	lm := db.GetSettingValue(r.Context(), h.DB, settingScenariosLastModifiedAt, "")
	la := db.GetSettingValue(r.Context(), h.DB, settingScenariosLastAppliedAt, "")
	resp := ScenariosResponse{
		Scenarios:      res.Scenarios,
		IsAvailable:    res.IsAvailable,
		MountPath:      res.MountPath,
		DisabledCount:  disabledCount,
		LastModifiedAt: lm,
		LastAppliedAt:  la,
		ReloadNeeded:   reloadNeeded(lm, la),
	}
	writeJSON(w, http.StatusOK, resp)
}

type patchScenarioRequest struct {
	Disabled *bool `json:"disabled"`
}

// PatchScenario handles PATCH /api/security/scenarios/{name}.
// Idempotent: setting to current state is a no-op.
//
// {name} must arrive as the canonical "<owner>/<short>" form OR
// the bare short-name; the reader's parseDisabledSet tolerates
// both. Canonical names contain a slash, which the client must
// URL-encode (encodeURIComponent in JS produces %2F). chi v5
// captures the encoded segment as-is -- url.PathUnescape decodes
// it back to "owner/short" so the sentinel + setting CSV both
// see the unencoded form. cscli on the reload side requires the
// unencoded form too.
func (h *Handlers) PatchScenario(w http.ResponseWriter, r *http.Request) {
	raw := chi.URLParam(r, "name")
	name, err := url.PathUnescape(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid scenario name encoding")
		return
	}
	name = strings.TrimSpace(name)
	if name == "" {
		writeError(w, http.StatusBadRequest, "scenario name required")
		return
	}
	var req patchScenarioRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.Disabled == nil {
		writeError(w, http.StatusBadRequest, "disabled field required")
		return
	}

	csv := db.GetSettingValue(r.Context(), h.DB, settingScenariosDisabled, "")
	current := splitDisabledCSV(csv)
	target := *req.Disabled
	changed := false
	if target {
		// Add to disabled set if not already present.
		if !containsString(current, name) {
			current = append(current, name)
			changed = true
		}
	} else {
		// Remove from disabled set. Tolerate either the
		// passed name OR the canonical / short variant being
		// present. Keep it simple: only remove exact-match.
		filtered := current[:0]
		for _, s := range current {
			if s == name {
				changed = true
				continue
			}
			filtered = append(filtered, s)
		}
		current = filtered
	}

	newCSV := scenarios.FormatDisabledCSV(current)
	if changed {
		if err := db.UpsertSetting(r.Context(), h.DB, settingScenariosDisabled, newCSV); err != nil {
			writeError(w, http.StatusInternalServerError, "persist: "+err.Error())
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)
		_ = db.UpsertSetting(r.Context(), h.DB, settingScenariosLastModifiedAt, now)
		// Materialise the sentinel file. Failure here surfaces
		// to the operator -- the DB write succeeded but the
		// next setup-appsec.sh run won't see the change.
		if err := security.WriteDisabledScenarios(newCSV); err != nil {
			writeError(w, http.StatusInternalServerError, "sentinel: "+err.Error())
			return
		}
		h.audit(r, "scenarios_patch", "scenario", 0, map[string]any{
			"name":     name,
			"disabled": target,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":     name,
		"disabled": target,
		"changed":  changed,
	})
}

// MarkScenariosApplied handles POST /api/security/scenarios/mark-applied.
// Updates last_applied_at = now so the UI's "Pending reload"
// badge clears. The operator is asserting that they've run
// setup-appsec.sh; v1.3.25 trusts that assertion (drift
// detection is v1.3.26+ work).
func (h *Handlers) MarkScenariosApplied(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC().Format(time.RFC3339)
	if err := db.UpsertSetting(r.Context(), h.DB, settingScenariosLastAppliedAt, now); err != nil {
		writeError(w, http.StatusInternalServerError, "persist: "+err.Error())
		return
	}
	h.audit(r, "scenarios_mark_applied", "scenario", 0, map[string]any{
		"applied_at": now,
	})
	writeJSON(w, http.StatusOK, map[string]any{"last_applied_at": now})
}

// AppSecTuningResponse is the body of GET /api/security/appsec-tuning.
type AppSecTuningResponse struct {
	InboundThreshold  int    `json:"inbound_threshold"`
	OutboundThreshold int    `json:"outbound_threshold"`
	LastModifiedAt    string `json:"last_modified_at,omitempty"`
	LastAppliedAt     string `json:"last_applied_at,omitempty"`
	ReloadNeeded      bool   `json:"reload_needed"`
}

// GetAppSecTuning handles GET /api/security/appsec-tuning.
func (h *Handlers) GetAppSecTuning(w http.ResponseWriter, r *http.Request) {
	in := atoiSettingValue(r, h, settingTuningInbound, 15)
	out := atoiSettingValue(r, h, settingTuningOutbound, 4)
	lm := db.GetSettingValue(r.Context(), h.DB, settingTuningLastModifiedAt, "")
	la := db.GetSettingValue(r.Context(), h.DB, settingTuningLastAppliedAt, "")
	writeJSON(w, http.StatusOK, AppSecTuningResponse{
		InboundThreshold:  in,
		OutboundThreshold: out,
		LastModifiedAt:    lm,
		LastAppliedAt:     la,
		ReloadNeeded:      reloadNeeded(lm, la),
	})
}

type patchAppSecTuningRequest struct {
	InboundThreshold  *int `json:"inbound_threshold"`
	OutboundThreshold *int `json:"outbound_threshold"`
}

// PatchAppSecTuning handles PATCH /api/security/appsec-tuning.
// Partial update; either or both fields. Validates 1..100 range.
func (h *Handlers) PatchAppSecTuning(w http.ResponseWriter, r *http.Request) {
	var req patchAppSecTuningRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	in := atoiSettingValue(r, h, settingTuningInbound, 15)
	out := atoiSettingValue(r, h, settingTuningOutbound, 4)
	changed := false
	if req.InboundThreshold != nil {
		v := *req.InboundThreshold
		if v < 1 || v > 100 {
			writeError(w, http.StatusBadRequest, "inbound_threshold must be 1..100")
			return
		}
		if v != in {
			in = v
			_ = db.UpsertSetting(r.Context(), h.DB, settingTuningInbound, strconv.Itoa(v))
			changed = true
		}
	}
	if req.OutboundThreshold != nil {
		v := *req.OutboundThreshold
		if v < 1 || v > 100 {
			writeError(w, http.StatusBadRequest, "outbound_threshold must be 1..100")
			return
		}
		if v != out {
			out = v
			_ = db.UpsertSetting(r.Context(), h.DB, settingTuningOutbound, strconv.Itoa(v))
			changed = true
		}
	}
	if changed {
		now := time.Now().UTC().Format(time.RFC3339)
		_ = db.UpsertSetting(r.Context(), h.DB, settingTuningLastModifiedAt, now)
		if err := security.WriteAppSecTuning(security.AppSecTuning{
			InboundThreshold:  in,
			OutboundThreshold: out,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "sentinel: "+err.Error())
			return
		}
		h.audit(r, "appsec_tuning_patch", "appsec_tuning", 0, map[string]any{
			"inbound":  in,
			"outbound": out,
		})
	}
	writeJSON(w, http.StatusOK, AppSecTuningResponse{
		InboundThreshold:  in,
		OutboundThreshold: out,
		ReloadNeeded:      changed,
	})
}

// MarkAppSecTuningApplied handles POST /api/security/appsec-tuning/mark-applied.
func (h *Handlers) MarkAppSecTuningApplied(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC().Format(time.RFC3339)
	if err := db.UpsertSetting(r.Context(), h.DB, settingTuningLastAppliedAt, now); err != nil {
		writeError(w, http.StatusInternalServerError, "persist: "+err.Error())
		return
	}
	h.audit(r, "appsec_tuning_mark_applied", "appsec_tuning", 0, map[string]any{
		"applied_at": now,
	})
	writeJSON(w, http.StatusOK, map[string]any{"last_applied_at": now})
}

// scenariosReader returns the panel-bound reader. h.ScenariosReader
// allows tests to override the mount path; production wires the
// default which points at /crowdsec-state via the read-only
// volume mount.
func (h *Handlers) scenariosReader() *scenarios.Reader {
	if h.ScenariosReader != nil {
		return h.ScenariosReader
	}
	return scenarios.New()
}

// reloadNeeded returns true when the panel has written the
// sentinel more recently than the operator clicked "Mark as
// applied". Both timestamps are RFC3339; missing applied means
// it's been modified at least once but never marked -- still
// pending.
func reloadNeeded(modifiedAt, appliedAt string) bool {
	if modifiedAt == "" {
		return false
	}
	if appliedAt == "" {
		return true
	}
	tm, err := time.Parse(time.RFC3339, modifiedAt)
	if err != nil {
		return true
	}
	ta, err := time.Parse(time.RFC3339, appliedAt)
	if err != nil {
		return true
	}
	return tm.After(ta)
}

// splitDisabledCSV tolerates whitespace + empty entries. Renamed
// from splitCSV to avoid colliding with logs.go's splitCSV (used
// by the log filter parser).
func splitDisabledCSV(s string) []string {
	out := []string{}
	for _, raw := range strings.Split(s, ",") {
		t := strings.TrimSpace(raw)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// atoiSettingValue reads a setting as int with a default fallback.
// Used for the appsec.inbound/outbound thresholds which are stored
// as TEXT but represent integers.
func atoiSettingValue(r *http.Request, h *Handlers, key string, def int) int {
	raw := db.GetSettingValue(r.Context(), h.DB, key, "")
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return n
}
