package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/models"
)

// domainRE matches an FQDN with at least one dot, lowercase-normalised by
// the handler before validation. Intentionally permissive on the label set
// (IDNs punycoded upstream, hyphens allowed, numeric labels tolerated);
// Caddy will reject truly unusable domains when it tries to issue a cert.
var domainRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

type hostRequest struct {
	Domain      string `json:"domain"`
	UpstreamURL string `json:"upstream_url"`
	TLSMode     string `json:"tls_mode"`
	TLSEmail    string `json:"tls_email"`
	Enabled     *bool  `json:"enabled,omitempty"`
}

// ListHosts returns every host.
func (h *Handlers) ListHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := db.ListHosts(r.Context(), h.DB)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list hosts failed")
		return
	}
	if hosts == nil {
		hosts = []models.Host{}
	}
	writeJSON(w, http.StatusOK, hosts)
}

// GetHost returns a single host by id.
func (h *Handlers) GetHost(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r)
	if !ok {
		return
	}
	host, err := db.GetHost(r.Context(), h.DB, id)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "host not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get host failed")
		return
	}
	writeJSON(w, http.StatusOK, host)
}

// CreateHost inserts a new host and triggers a reconcile.
func (h *Handlers) CreateHost(w http.ResponseWriter, r *http.Request) {
	var req hostRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	host, msg := req.toHost(0)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	// New hosts default to enabled unless the caller explicitly disables them.
	if req.Enabled != nil {
		host.Enabled = *req.Enabled
	} else {
		host.Enabled = true
	}

	created, err := db.CreateHost(r.Context(), h.DB, host)
	if err != nil {
		if errors.Is(err, db.ErrDomainTaken) {
			writeError(w, http.StatusConflict, "domain already registered")
			return
		}
		writeError(w, http.StatusInternalServerError, "create host failed")
		return
	}
	h.reconcile(r.Context())
	writeJSON(w, http.StatusCreated, created)
}

// UpdateHost replaces the mutable fields of an existing host.
func (h *Handlers) UpdateHost(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r)
	if !ok {
		return
	}
	var req hostRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	host, msg := req.toHost(id)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	// PUT carries the full resource; require an explicit enabled flag so
	// the client has to decide rather than inherit an implicit default.
	if req.Enabled == nil {
		writeError(w, http.StatusBadRequest, "enabled required on update")
		return
	}
	host.Enabled = *req.Enabled

	updated, err := db.UpdateHost(r.Context(), h.DB, host)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "host not found")
			return
		}
		if errors.Is(err, db.ErrDomainTaken) {
			writeError(w, http.StatusConflict, "domain already registered")
			return
		}
		writeError(w, http.StatusInternalServerError, "update host failed")
		return
	}
	h.reconcile(r.Context())
	writeJSON(w, http.StatusOK, updated)
}

// DeleteHost removes a host and triggers a reconcile.
func (h *Handlers) DeleteHost(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r)
	if !ok {
		return
	}
	if err := db.DeleteHost(r.Context(), h.DB, id); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "host not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete host failed")
		return
	}
	h.reconcile(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

// ToggleHost flips the enabled flag.
func (h *Handlers) ToggleHost(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r)
	if !ok {
		return
	}
	host, err := db.ToggleHost(r.Context(), h.DB, id)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "host not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "toggle host failed")
		return
	}
	h.reconcile(r.Context())
	writeJSON(w, http.StatusOK, host)
}

// reconcile kicks the reconciler; failures are logged, not surfaced,
// because the DB change already succeeded and the operator can retry via
// an edit or a restart.
func (h *Handlers) reconcile(ctx context.Context) {
	if h.Reconciler == nil {
		return
	}
	if err := h.Reconciler.ApplyFromDB(ctx); err != nil {
		slog.Error("reconcile after mutation failed", "error", err)
	}
}

// toHost validates the request and produces a models.Host without the
// Enabled flag (handler decides that). Returns "" on success, an error
// message on rejection.
func (req *hostRequest) toHost(id int64) (models.Host, string) {
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if !domainRE.MatchString(domain) {
		return models.Host{}, "domain must be a valid fqdn"
	}

	u, err := url.Parse(strings.TrimSpace(req.UpstreamURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return models.Host{}, "upstream_url must be a valid http or https url"
	}

	mode := models.TLSMode(strings.ToLower(strings.TrimSpace(req.TLSMode)))
	if mode == "" {
		mode = models.TLSModeAuto
	}
	if mode != models.TLSModeAuto && mode != models.TLSModeNone {
		return models.Host{}, `tls_mode must be "auto" or "none"`
	}

	email := strings.TrimSpace(req.TLSEmail)
	if mode == models.TLSModeAuto && email == "" {
		return models.Host{}, "tls_email required when tls_mode is auto"
	}

	return models.Host{
		ID:          id,
		Domain:      domain,
		UpstreamURL: u.String(),
		TLSMode:     mode,
		TLSEmail:    email,
	}, ""
}

func parseIDParam(w http.ResponseWriter, r *http.Request) (int64, bool) {
	raw := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "invalid id")
		return 0, false
	}
	return id, true
}
