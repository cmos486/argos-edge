package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/cmos486/argos-edge/backend/internal/caddycfg"
	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/dnsproviders"
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
	// TLSACMECAURL (optional) overrides the acme.ca_url global
	// setting for this host only. Empty string clears the override.
	// Useful for debugging a single host on LE staging without
	// affecting the rest of the panel.
	TLSACMECAURL *string `json:"tls_acme_ca_url,omitempty"`
	// TLSChallenge selects the ACME challenge: dns / http / tls-alpn.
	// Optional; omit on update to preserve current value.
	TLSChallenge *string `json:"tls_challenge,omitempty"`
	// TLSDNSProvider (v1.3+) names the dns_providers row this host
	// pulls credentials from when tls_challenge='dns'. Optional; on
	// create defaults to "cloudflare", on update preserves current.
	// Ignored when tls_challenge != 'dns'.
	TLSDNSProvider *string `json:"tls_dns_provider,omitempty"`
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
	// Creating a host with tls_mode=manual would land it in a
	// pending-cert state (Caddy serves 503 until a cert is uploaded).
	// Reject here and point the operator at the supported flow; the
	// upload handler atomically flips tls_mode=manual as a side effect.
	if host.TLSMode == models.TLSModeManual {
		writeError(w, http.StatusBadRequest,
			"to use tls_mode=manual, create the host with auto/none first and then upload a certificate via Certificates -> Imported -> Import")
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
	if req.TLSACMECAURL != nil {
		host.TLSACMECAURL = strings.TrimSpace(*req.TLSACMECAURL)
	}
	if req.TLSChallenge != nil {
		host.TLSChallenge = models.TLSChallenge(strings.TrimSpace(*req.TLSChallenge))
	} else {
		host.TLSChallenge = models.TLSChallengeDNS
	}
	if req.TLSDNSProvider != nil {
		host.TLSDNSProvider = strings.TrimSpace(*req.TLSDNSProvider)
	}
	if host.TLSDNSProvider == "" {
		host.TLSDNSProvider = "cloudflare"
	}
	if msg := h.validateDNSProvider(r.Context(), host); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
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
	if req.TLSACMECAURL != nil {
		host.TLSACMECAURL = strings.TrimSpace(*req.TLSACMECAURL)
	} else {
		host.TLSACMECAURL = current.TLSACMECAURL
	}
	if req.TLSChallenge != nil {
		host.TLSChallenge = models.TLSChallenge(strings.TrimSpace(*req.TLSChallenge))
	} else {
		host.TLSChallenge = current.TLSChallenge
	}
	if req.TLSDNSProvider != nil {
		host.TLSDNSProvider = strings.TrimSpace(*req.TLSDNSProvider)
	} else {
		host.TLSDNSProvider = current.TLSDNSProvider
	}
	if host.TLSDNSProvider == "" {
		host.TLSDNSProvider = "cloudflare"
	}
	if msg := h.validateDNSProvider(r.Context(), host); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}

	// Transition guard. Going INTO manual must happen through the
	// upload endpoint (which atomically flips tls_mode after persisting
	// the cert row + files). A direct auto/none -> manual here would
	// strand the host in "manual without a cert" which Caddy serves
	// as 503. Going OUT of manual is allowed and cascades the cleanup
	// of the manual cert row + files so the operator does not have
	// to visit two tabs to undo.
	if current.TLSMode != models.TLSModeManual && host.TLSMode == models.TLSModeManual {
		writeError(w, http.StatusBadRequest,
			"to set tls_mode=manual, upload a certificate via Certificates -> Imported -> Import")
		return
	}
	cascadeDropManual := current.TLSMode == models.TLSModeManual && host.TLSMode != models.TLSModeManual

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
	// Cascade the manual-cert cleanup AFTER the host row is persisted:
	// if UpdateHost failed we don't want to have wiped the cert.
	// Deletes are best-effort -- a missing row or file is acceptable,
	// the host mode flip is the source of truth.
	if cascadeDropManual {
		if err := db.DeleteManualCert(r.Context(), h.DB, updated.ID); err != nil && !errors.Is(err, db.ErrManualCertNotFound) {
			slog.Warn("cascade: delete manual cert row", "host", updated.Domain, "error", err)
		}
		if h.ManualCertStore != nil {
			if err := h.ManualCertStore.Remove(updated.ID); err != nil {
				slog.Warn("cascade: remove manual cert files", "host", updated.Domain, "error", err)
			}
		}
		h.audit(r, "delete", "manual_cert", updated.ID, map[string]any{
			"domain":      updated.Domain,
			"reason":      "tls_mode changed to " + string(updated.TLSMode),
			"cascade":     true,
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
	if mode != models.TLSModeAuto && mode != models.TLSModeNone && mode != models.TLSModeManual {
		return models.Host{}, `tls_mode must be "auto", "none" or "manual"`
	}

	email := strings.TrimSpace(req.TLSEmail)
	if mode == models.TLSModeAuto && email == "" {
		return models.Host{}, "tls_email required when tls_mode is auto"
	}

	// Validate tls_acme_ca_url when the caller sent one; the caller
	// decides whether to keep or preserve the existing value.
	if req.TLSACMECAURL != nil {
		if err := caddycfg.ValidateACMECAURL(*req.TLSACMECAURL); err != nil {
			return models.Host{}, "tls_acme_ca_url: " + err.Error()
		}
	}

	// Validate tls_challenge only when it is actually going to be
	// used. mode=auto issues via the selected challenge; mode=none
	// (plain HTTP) and mode=manual (operator-uploaded cert) ignore
	// the challenge value entirely -- round-tripping a manual-mode
	// host that still carries its old tls_challenge=dns column would
	// otherwise fail here on every save.
	//
	// v1.3 change: the "CLOUDFLARE_API_TOKEN env required" check is
	// gone. Credentials now live in dns_providers (DB + encrypted);
	// the "is a provider ready?" gate runs as validateDNSProvider
	// after toHostCore has resolved the tls_dns_provider value.
	if req.TLSChallenge != nil && mode == models.TLSModeAuto {
		chall := models.TLSChallenge(strings.TrimSpace(*req.TLSChallenge))
		switch chall {
		case models.TLSChallengeDNS,
			models.TLSChallengeHTTP, models.TLSChallengeTLSALPN:
			// ok; DNS credentials checked separately
		default:
			return models.Host{}, `tls_challenge must be one of "dns", "http", "tls-alpn"`
		}
	}

	return models.Host{
		ID:       id,
		Domain:   domain,
		TLSMode:  mode,
		TLSEmail: email,
	}, ""
}

// validateDNSProvider gates a DNS-01 host on the dns_providers row
// for host.TLSDNSProvider existing, being enabled, and having
// credentials set. Returns an empty string on success or a short
// user-facing message suitable for a 400 body. Callers pass the
// already-validated host (tls_mode, tls_challenge filled in) so this
// function only runs its check when the DNS-01 path is actually in
// play.
//
// Legacy compat: if the provider is cloudflare AND the panel sees
// the pre-v1.3 env var CLOUDFLARE_API_TOKEN, the call succeeds even
// without a DB row -- the reconciler's DNSOpts.LegacyCFEnvSet path
// then emits the env placeholder so issuance still works. This
// covers the window between a v1.2 -> v1.3 upgrade and the operator
// either removing the env var or running the boot-time import.
func (h *Handlers) validateDNSProvider(ctx context.Context, host models.Host) string {
	if host.TLSMode != models.TLSModeAuto {
		return ""
	}
	if host.TLSChallenge != models.TLSChallengeDNS {
		return ""
	}
	name := host.TLSDNSProvider
	if name == "" {
		name = "cloudflare"
	}
	if _, err := dnsproviders.Get(name); err != nil {
		return "tls_dns_provider: " + err.Error()
	}
	row, err := db.GetDNSProvider(ctx, h.DB, name)
	if err != nil {
		// Unknown name AFTER the catalogue check => DB out of sync.
		// Also covers a seed row missing on older installs.
		if errors.Is(err, db.ErrDNSProviderNotFound) {
			return "tls_dns_provider: provider " + name + " not present in catalogue"
		}
		return "tls_dns_provider: lookup failed"
	}
	if row.Enabled && len(row.CredentialsEncrypted) > 0 {
		return ""
	}
	if name == "cloudflare" && os.Getenv("CLOUDFLARE_API_TOKEN") != "" {
		return ""
	}
	return "tls_dns_provider: " + name +
		" is not enabled in Settings -> DNS providers"
}
