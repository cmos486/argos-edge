package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cmos486/argos-edge/backend/internal/crypto"
	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/dnsproviders"
)

// dnsProviderFieldDTO mirrors dnsproviders.ProviderField for UI
// consumption. Kept distinct so the API response shape does not
// leak unexported catalogue internals if they ever change.
type dnsProviderFieldDTO struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Required    bool   `json:"required"`
	Placeholder string `json:"placeholder,omitempty"`
	Secret      bool   `json:"secret,omitempty"`
}

// dnsProviderDTO is the shape GET returns for a single provider.
// Credentials are NEVER included (not even masked); the UI signals
// "has credentials" via Configured=true and renders inputs with the
// __UNCHANGED__ sentinel pre-filled when the user edits.
type dnsProviderDTO struct {
	Name        string                `json:"name"`
	DisplayName string                `json:"display_name"`
	Enabled     bool                  `json:"enabled"`
	Configured  bool                  `json:"configured"`
	Fields      []dnsProviderFieldDTO `json:"fields"`
	CaddyModule string                `json:"caddy_module"`
	DocsURL     string                `json:"docs_url,omitempty"`
	UpdatedAt   *time.Time            `json:"updated_at,omitempty"`
}

func (h *Handlers) dnsProviderDTO(name string) (dnsProviderDTO, error) {
	cat, err := dnsproviders.Get(name)
	if err != nil {
		return dnsProviderDTO{}, err
	}
	out := dnsProviderDTO{
		Name:        cat.Name,
		DisplayName: cat.DisplayName,
		CaddyModule: cat.CaddyModule,
		DocsURL:     cat.DocsURL,
	}
	for _, f := range cat.Fields {
		out.Fields = append(out.Fields, dnsProviderFieldDTO{
			Key:         f.Key,
			Label:       f.Label,
			Required:    f.Required,
			Placeholder: f.Placeholder,
			Secret:      f.Secret,
		})
	}
	return out, nil
}

// ListDNSProviders GET /api/dns-providers
//
// Returns the catalogue joined with the DB rows (enabled flag,
// configured flag, updated_at). Credentials are never returned.
func (h *Handlers) ListDNSProviders(w http.ResponseWriter, r *http.Request) {
	rows, err := db.ListDNSProviders(r.Context(), h.DB)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list dns providers failed")
		return
	}
	byName := make(map[string]struct {
		enabled    bool
		configured bool
		updatedAt  time.Time
	}, len(rows))
	for _, row := range rows {
		byName[row.Name] = struct {
			enabled    bool
			configured bool
			updatedAt  time.Time
		}{
			enabled:    row.Enabled,
			configured: len(row.CredentialsEncrypted) > 0,
			updatedAt:  row.UpdatedAt,
		}
	}
	out := make([]dnsProviderDTO, 0, len(dnsproviders.List()))
	for _, p := range dnsproviders.List() {
		d, err := h.dnsProviderDTO(p.Name)
		if err != nil {
			continue
		}
		if meta, ok := byName[p.Name]; ok {
			d.Enabled = meta.enabled
			d.Configured = meta.configured
			u := meta.updatedAt
			d.UpdatedAt = &u
		}
		out = append(out, d)
	}
	writeJSON(w, http.StatusOK, out)
}

// GetDNSProvider GET /api/dns-providers/{name}
//
// Same shape as the list element, minus the credentials.
func (h *Handlers) GetDNSProvider(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(chi.URLParam(r, "name"))
	d, err := h.dnsProviderDTO(name)
	if err != nil {
		var uerr dnsproviders.ErrUnknownProvider
		if errors.As(err, &uerr) {
			writeError(w, http.StatusNotFound, "unknown dns provider")
			return
		}
		writeError(w, http.StatusInternalServerError, "get dns provider failed")
		return
	}
	row, err := db.GetDNSProvider(r.Context(), h.DB, name)
	if err == nil {
		d.Enabled = row.Enabled
		d.Configured = len(row.CredentialsEncrypted) > 0
		u := row.UpdatedAt
		d.UpdatedAt = &u
	} else if !errors.Is(err, db.ErrDNSProviderNotFound) {
		writeError(w, http.StatusInternalServerError, "get dns provider failed")
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// dnsProviderPutRequest is the wire shape PUT accepts. Credentials
// is a nested map[string]string so new providers (with different
// field shapes) work without client-side schema changes.
//
// Sentinel: a credential value of crypto.Unchanged ("__UNCHANGED__")
// tells the server to keep the previously-stored value for that
// single field. A caller sending the full credentials map without
// the sentinel replaces everything. Omitting Credentials entirely is
// the "toggle enabled only" path.
type dnsProviderPutRequest struct {
	Enabled     *bool             `json:"enabled,omitempty"`
	Credentials map[string]string `json:"credentials,omitempty"`
}

// UpdateDNSProvider PUT /api/dns-providers/{name}
//
// Validates credentials against the catalogue + applies the
// __UNCHANGED__ sentinel. Triggers a reconcile on success so the
// new credentials take effect on the next Caddy /load.
func (h *Handlers) UpdateDNSProvider(w http.ResponseWriter, r *http.Request) {
	if h.Cipher == nil {
		writeError(w, http.StatusServiceUnavailable, "cipher not wired")
		return
	}
	name := strings.TrimSpace(chi.URLParam(r, "name"))
	cat, err := dnsproviders.Get(name)
	if err != nil {
		var uerr dnsproviders.ErrUnknownProvider
		if errors.As(err, &uerr) {
			writeError(w, http.StatusNotFound, "unknown dns provider")
			return
		}
		writeError(w, http.StatusInternalServerError, "get dns provider failed")
		return
	}

	var req dnsProviderPutRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}

	current, err := db.GetDNSProvider(r.Context(), h.DB, name)
	if err != nil && !errors.Is(err, db.ErrDNSProviderNotFound) {
		writeError(w, http.StatusInternalServerError, "load dns provider failed")
		return
	}

	// Resolve desired enabled value.
	enabled := current.Enabled
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	// Resolve credentials. Three shapes:
	//   a) req.Credentials == nil  -> preserve (toggle-enabled path)
	//   b) req.Credentials = {...} -> replace, applying sentinels
	//   c) enabled=true && no creds on DB && creds map is empty -> error
	var finalCreds map[string]string
	if req.Credentials == nil {
		// preserve: pass nil through to the repo
		finalCreds = nil
	} else {
		// Start from current (if any) so sentinels can reach back
		// to the previous value per field.
		existing, derr := db.GetDecryptedDNSCredentials(r.Context(), h.DB, h.Cipher, name)
		if derr != nil && !errors.Is(derr, db.ErrDNSProviderNotFound) {
			writeError(w, http.StatusInternalServerError,
				"decrypt current credentials failed: "+derr.Error())
			return
		}
		merged := make(map[string]string, len(cat.Fields))
		for k, v := range existing {
			merged[k] = v
		}
		for k, v := range dnsproviders.FilterKnownFields(name, req.Credentials) {
			if v == crypto.Unchanged {
				// keep whatever was in merged (possibly missing -> stays missing)
				continue
			}
			merged[k] = v
		}
		if err := dnsproviders.ValidateCredentials(name, merged); err != nil {
			// Only enforce required-field validation when the caller
			// sent credentials. A toggle-enabled-only PUT skips this
			// block entirely.
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		finalCreds = merged
	}

	// If the operator is trying to enable a provider without any
	// credentials (neither DB nor payload), reject. Allowing this
	// creates a Caddy config that mentions the provider by name but
	// has no auth, which fails cert issuance for every host using it.
	if enabled && finalCreds == nil && len(current.CredentialsEncrypted) == 0 {
		writeError(w, http.StatusBadRequest,
			"enabling a provider requires credentials")
		return
	}

	if err := db.UpsertDNSProviderCredentials(r.Context(), h.DB, h.Cipher, name, enabled, finalCreds); err != nil {
		writeError(w, http.StatusInternalServerError, "persist dns provider failed")
		return
	}

	h.audit(r, "update", "dns_provider", 0, map[string]any{
		"name":          name,
		"enabled":       enabled,
		"credentials_updated": req.Credentials != nil,
	})

	// Reconcile so Caddy picks up the new credentials immediately.
	// Failures here do NOT roll back the DB write; the operator's
	// intent (change credentials) is persisted and the reconciler
	// retries on next mutation.
	if h.Reconciler != nil {
		if rerr := h.Reconciler.ApplyFromDB(r.Context()); rerr != nil {
			// Report so the operator sees "saved but not applied";
			// 500 is wrong here because the DB is consistent.
			writeJSON(w, http.StatusOK, map[string]any{
				"saved":            true,
				"reconcile_error":  rerr.Error(),
			})
			return
		}
	}

	// Return the fresh DTO (sans credentials).
	refreshed, _ := h.dnsProviderDTO(name)
	row, err := db.GetDNSProvider(r.Context(), h.DB, name)
	if err == nil {
		refreshed.Enabled = row.Enabled
		refreshed.Configured = len(row.CredentialsEncrypted) > 0
		u := row.UpdatedAt
		refreshed.UpdatedAt = &u
	}
	writeJSON(w, http.StatusOK, refreshed)
}

