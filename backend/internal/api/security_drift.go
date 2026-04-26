package api

import (
	"net/http"

	"github.com/cmos486/argos-edge/backend/internal/security/drift"
)

// DriftResponse is the body of GET /api/security/drift.
//
// v1.3.27 replaces the v1.3.25 operator-trust mark-applied
// signal. The drift detector runs on a 60s ticker comparing
// panel intent (sentinel files + settings) against actual
// CrowdSec runtime state (read-only /crowdsec-state mount); the
// API just reads the persisted snapshot from the settings table.
type DriftResponse struct {
	Scenarios    drift.ScenarioDrift `json:"scenarios"`
	AppSecTuning drift.TuningDrift   `json:"appsec_tuning"`
	LastCheckAt  string              `json:"last_check_at,omitempty"`
}

// GetDrift handles GET /api/security/drift.
func (h *Handlers) GetDrift(w http.ResponseWriter, r *http.Request) {
	scn, tn := drift.LoadState(r.Context(), h.DB)
	writeJSON(w, http.StatusOK, DriftResponse{
		Scenarios:    scn,
		AppSecTuning: tn,
		LastCheckAt:  drift.LastCheckAt(scn, tn),
	})
}
