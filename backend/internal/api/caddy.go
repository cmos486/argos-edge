package api

import (
	"context"
	"net/http"
	"time"
)

// CaddyStatus probes the Caddy Admin API and returns the result verbatim.
// Used by the panel dashboard to render an OK/KO card.
func (h *Handlers) CaddyStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	st := h.Caddy.Status(ctx)
	writeJSON(w, http.StatusOK, st)
}
