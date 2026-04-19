package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/models"
)

// domainRE matches an FQDN with at least one dot, lowercase-normalised by
// the handler before validation. Intentionally permissive on the label set
// (IDNs punycoded upstream, hyphens allowed, numeric labels tolerated);
// Caddy will reject truly unusable domains when it tries to issue a cert.
var domainRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// hostRequest is the shape POST/PUT /api/hosts accepts. Exactly one of
// TargetGroupID or TargetGroup (inline) must be provided on create; PUT
// keeps the existing target_group_id unless TargetGroupID is sent.
type hostRequest struct {
	Domain        string              `json:"domain"`
	TargetGroupID *int64              `json:"target_group_id,omitempty"`
	TargetGroup   *targetGroupRequest `json:"target_group,omitempty"`
	TLSMode       string              `json:"tls_mode"`
	TLSEmail      string              `json:"tls_email"`
	Enabled       *bool               `json:"enabled,omitempty"`
	// AuthRequired is the Phase-C ForwardAuth toggle. Optional on
	// create (default 0 = public); optional on update (omit = keep
	// current). Pointer so "not sent" is distinguishable from
	// "explicitly false".
	AuthRequired *bool `json:"auth_required,omitempty"`
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
	id, ok := parseIDParam(w, r, "id")
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

// CreateHost inserts a new host. Callers supply either a reference to
// an existing target group via target_group_id or an inline target_group
// object (which is created alongside the host in one transaction).
// Exactly one path must be populated.
func (h *Handlers) CreateHost(w http.ResponseWriter, r *http.Request) {
	var req hostRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}

	host, msg := req.toHostCore(0)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if req.Enabled != nil {
		host.Enabled = *req.Enabled
	} else {
		host.Enabled = true
	}
	if req.AuthRequired != nil {
		host.AuthRequired = *req.AuthRequired
	}

	hasID := req.TargetGroupID != nil
	hasInline := req.TargetGroup != nil
	if hasID == hasInline {
		writeError(w, http.StatusBadRequest,
			"exactly one of target_group_id or target_group (inline) must be provided")
		return
	}

	if hasID {
		tgID := *req.TargetGroupID
		if tgID <= 0 {
			writeError(w, http.StatusBadRequest, "target_group_id must be positive")
			return
		}
		if _, err := db.GetTargetGroup(r.Context(), h.DB, tgID); err != nil {
			if errors.Is(err, db.ErrTargetGroupNotFound) {
				writeError(w, http.StatusBadRequest, "target_group_id does not exist")
				return
			}
			writeError(w, http.StatusInternalServerError, "check target group failed")
			return
		}
		host.TargetGroupID = tgID
		created, err := db.CreateHost(r.Context(), h.DB, host)
		if err != nil {
			if errors.Is(err, db.ErrDomainTaken) {
				writeError(w, http.StatusConflict, "domain already registered")
				return
			}
			writeError(w, http.StatusInternalServerError, "create host failed")
			return
		}
		h.audit(r, "create", "host", created.ID, created)
		h.reconcile(r.Context())
		writeJSON(w, http.StatusCreated, created)
		return
	}

	// Inline path: TG + targets + host in one transaction.
	tg, initial, tgMsg := req.TargetGroup.toTargetGroup(0)
	if tgMsg != "" {
		writeError(w, http.StatusBadRequest, "target_group: "+tgMsg)
		return
	}
	if len(initial) == 0 {
		writeError(w, http.StatusBadRequest,
			"target_group inline must include at least one target")
		return
	}
	created, err := db.CreateHostWithTargetGroup(r.Context(), h.DB, tg, initial, host)
	if err != nil {
		if errors.Is(err, db.ErrTargetGroupNameTaken) {
			writeError(w, http.StatusConflict, "target group name already taken")
			return
		}
		if errors.Is(err, db.ErrDomainTaken) {
			writeError(w, http.StatusConflict, "domain already registered")
			return
		}
		if errors.Is(err, db.ErrTargetDuplicate) {
			writeError(w, http.StatusConflict, "duplicate target in inline target group")
			return
		}
		writeError(w, http.StatusInternalServerError, "create host with target group failed")
		return
	}
	h.audit(r, "create", "host", created.ID, created)
	h.reconcile(r.Context())
	writeJSON(w, http.StatusCreated, created)
}

// UpdateHost replaces the mutable fields of an existing host. Inline
// target_group creation is not supported on update; callers must pick
// an existing target_group_id if they want to switch groups.
func (h *Handlers) UpdateHost(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r, "id")
	if !ok {
		return
	}
	var req hostRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.TargetGroup != nil {
		writeError(w, http.StatusBadRequest,
			"inline target_group not supported on update; pick an existing target_group_id")
		return
	}

	host, msg := req.toHostCore(id)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if req.Enabled == nil {
		writeError(w, http.StatusBadRequest, "enabled required on update")
		return
	}
	host.Enabled = *req.Enabled

	// Load current row once; needed both for preserving an unchanged
	// target_group_id AND for keeping auth_required when the caller
	// did not send it (partial update).
	current, cerr := db.GetHost(r.Context(), h.DB, id)
	if cerr != nil {
		if errors.Is(cerr, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "host not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "get host failed")
		return
	}
	if req.AuthRequired != nil {
		host.AuthRequired = *req.AuthRequired
	} else {
		host.AuthRequired = current.AuthRequired
	}

	if req.TargetGroupID == nil {
		host.TargetGroupID = current.TargetGroupID
	} else {
		if *req.TargetGroupID <= 0 {
			writeError(w, http.StatusBadRequest, "target_group_id must be positive")
			return
		}
		if _, err := db.GetTargetGroup(r.Context(), h.DB, *req.TargetGroupID); err != nil {
			if errors.Is(err, db.ErrTargetGroupNotFound) {
				writeError(w, http.StatusBadRequest, "target_group_id does not exist")
				return
			}
			writeError(w, http.StatusInternalServerError, "check target group failed")
			return
		}
		host.TargetGroupID = *req.TargetGroupID
	}

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
	h.audit(r, "update", "host", updated.ID, updated)
	// Additionally emit the dedicated audit event when the
	// ForwardAuth flag toggled, so the security log has a cleanly
	// filterable signal beyond "generic host update".
	if current.AuthRequired != updated.AuthRequired {
		h.audit(r, "host_auth_required_changed", "host", updated.ID, map[string]any{
			"domain": updated.Domain,
			"from":   current.AuthRequired,
			"to":     updated.AuthRequired,
		})
	}
	h.reconcile(r.Context())
	writeJSON(w, http.StatusOK, updated)
}

// DeleteHost removes a host and triggers a reconcile.
func (h *Handlers) DeleteHost(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r, "id")
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
	h.audit(r, "delete", "host", id, nil)
	h.reconcile(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

// ToggleHost flips the enabled flag.
func (h *Handlers) ToggleHost(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r, "id")
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
	h.audit(r, "toggle", "host", host.ID, map[string]any{"enabled": host.Enabled})
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

// toHostCore validates the generic host fields (domain, tls_mode,
// tls_email) and returns a models.Host with those fields populated.
// Target group resolution is the caller's responsibility.
func (req *hostRequest) toHostCore(id int64) (models.Host, string) {
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if !domainRE.MatchString(domain) {
		return models.Host{}, "domain must be a valid fqdn"
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
		ID:       id,
		Domain:   domain,
		TLSMode:  mode,
		TLSEmail: email,
	}, ""
}
