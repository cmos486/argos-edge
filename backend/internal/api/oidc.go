package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/oidc"
	"github.com/cmos486/argos-edge/backend/internal/session"
)

// OIDCProviderCache memoises the *oidc.Provider (which performs a
// network discovery in its constructor) keyed by a fingerprint of
// the current settings. A PUT /config that changes any of
// issuer/client_id/client_secret/scopes flips the fingerprint and
// forces a rebuild on the next /login or /callback. Zero value is
// usable; no New() needed.
type OIDCProviderCache struct {
	mu          sync.Mutex
	fingerprint string
	provider    *oidc.Provider
}

// get returns a Provider matching cfg, rebuilding if the cached one
// was against a different config. RedirectURI is part of the
// fingerprint too so a fleet-wide rename of the panel host triggers
// a refresh.
func (pc *OIDCProviderCache) get(ctx context.Context, cfg oidc.Config, redirectURI string) (*oidc.Provider, error) {
	fp := fingerprintConfig(cfg, redirectURI)
	pc.mu.Lock()
	if pc.fingerprint == fp && pc.provider != nil {
		p := pc.provider
		pc.mu.Unlock()
		return p, nil
	}
	pc.mu.Unlock()

	p, err := oidc.LoadProvider(ctx, cfg, redirectURI)
	if err != nil {
		return nil, err
	}
	pc.mu.Lock()
	pc.fingerprint = fp
	pc.provider = p
	pc.mu.Unlock()
	return p, nil
}

// Invalidate drops the cached provider. Called by PUT /config so
// the next login rebuilds against the new settings.
func (pc *OIDCProviderCache) Invalidate() {
	pc.mu.Lock()
	pc.fingerprint = ""
	pc.provider = nil
	pc.mu.Unlock()
}

func fingerprintConfig(cfg oidc.Config, redirectURI string) string {
	h := sha256.New()
	h.Write([]byte(cfg.IssuerURL))
	h.Write([]byte{0})
	h.Write([]byte(cfg.ClientID))
	h.Write([]byte{0})
	h.Write([]byte(cfg.ClientSecret))
	h.Write([]byte{0})
	h.Write([]byte(strings.Join(cfg.Scopes, " ")))
	h.Write([]byte{0})
	h.Write([]byte(redirectURI))
	return hex.EncodeToString(h.Sum(nil))
}

// redirectURI reconstructs the absolute callback URL from the
// request. Trusts X-Forwarded-Proto from Caddy (it always sets the
// header when TLS-terminating). Leaving it dynamic means operators
// do not duplicate the panel's public URL into a separate setting.
func (h *Handlers) oidcRedirectURI(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if xfp := r.Header.Get("X-Forwarded-Proto"); xfp != "" {
		scheme = xfp
	}
	host := r.Host
	if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
		host = xfh
	}
	return scheme + "://" + host + "/api/auth/oidc/callback"
}

// OIDCAvailable GET /api/auth/oidc/available
//
// Auth: public. Returns {enabled: bool} so the Login page can
// decide whether to render the "Sign in with SSO" button WITHOUT
// leaking any config details. Always 200 -- 404-ing on disabled
// would force the client to catch-and-ignore, which is noisy.
func (h *Handlers) OIDCAvailable(w http.ResponseWriter, r *http.Request) {
	cfg, err := oidc.Load(r.Context(), h.DB, h.Cipher)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]bool{"enabled": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": cfg.Ready()})
}

// OIDCLogin GET /api/auth/oidc/login?rd=<returnTo>
//
// Auth: public. When oidc.enabled=false → 404 (route invisible).
// Success: 302 to the IdP's authZ URL with PKCE parameters. The
// server-side state is stashed in h.OIDCStore for the callback to
// consume.
func (h *Handlers) OIDCLogin(w http.ResponseWriter, r *http.Request) {
	cfg := h.loadOIDCConfigOrError(w, r, false)
	if cfg == nil {
		return
	}
	if !cfg.Ready() {
		writeError(w, http.StatusServiceUnavailable, "oidc not fully configured")
		return
	}
	prov, err := h.OIDCProviderCache.get(r.Context(), *cfg, h.oidcRedirectURI(r))
	if err != nil {
		writeError(w, http.StatusBadGateway, "oidc discovery: "+err.Error())
		return
	}
	rd := r.URL.Query().Get("rd")
	authURL, err := h.OIDCStore.StartAuth(prov, rd)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "start oidc flow: "+err.Error())
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// OIDCCallback GET /api/auth/oidc/callback?code=&state=
//
// Auth: public. Validates state+code, exchanges, verifies ID token,
// upserts user, mints argos session, sets the session cookie (with
// Domain = cookie_parent_domain when set) and redirects to the
// return-to URL if safe (same parent domain) or "/" otherwise.
func (h *Handlers) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	cfg := h.loadOIDCConfigOrError(w, r, false)
	if cfg == nil {
		return
	}
	// IdP error → surface to /login with ?error=...
	if e := r.URL.Query().Get("error"); e != "" {
		h.audit(r, "oidc_login_failed", "user", 0, map[string]any{
			"stage":      "idp_error",
			"error":      e,
			"desc":       r.URL.Query().Get("error_description"),
			"remote_ip":  h.clientIP(r),
			"user_agent": userAgent(r),
		})
		redirectToLoginError(w, r, e)
		return
	}
	prov, err := h.OIDCProviderCache.get(r.Context(), *cfg, h.oidcRedirectURI(r))
	if err != nil {
		writeError(w, http.StatusBadGateway, "oidc discovery: "+err.Error())
		return
	}
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	claims, returnTo, err := h.OIDCStore.HandleCallback(r.Context(), prov, code, state)
	if err != nil {
		reason := "callback"
		if errors.Is(err, oidc.ErrStateNotFound) {
			reason = "state_not_found"
		}
		h.audit(r, "oidc_login_failed", "user", 0, map[string]any{
			"stage":      reason,
			"error":      err.Error(),
			"remote_ip":  h.clientIP(r),
			"user_agent": userAgent(r),
		})
		redirectToLoginError(w, r, reason)
		return
	}

	user, err := oidc.UpsertUserFromClaims(r.Context(), h.DB, *cfg, claims)
	if err != nil {
		reason := "upsert"
		if errors.Is(err, oidc.ErrNotAllowed) {
			reason = "not_allowed"
		} else if errors.Is(err, oidc.ErrNoAutoProvision) {
			reason = "no_auto_provision"
		} else if errors.Is(err, oidc.ErrEmailUnverified) {
			reason = "email_unverified"
		}
		h.audit(r, "oidc_login_failed", "user", 0, map[string]any{
			"stage":      reason,
			"email":      claims.Email,
			"sub":        claims.Subject,
			"error":      err.Error(),
			"remote_ip":  h.clientIP(r),
			"user_agent": userAgent(r),
		})
		redirectToLoginError(w, r, reason)
		return
	}

	// Issue argos session. Same absolute TTL as password login.
	absTTL := session.DefaultAbsoluteTTL
	if h.Timeouts != nil {
		abs, _ := h.Timeouts.Get(r.Context())
		if abs > 0 {
			absTTL = abs
		}
	}
	s, err := session.Create(r.Context(), h.DB, user.ID, absTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create session")
		return
	}
	setSessionCookie(w, s, h.CookieSecure, h.cookieDomain(r.Context()))

	if h.Audit != nil {
		h.Audit.Record(r.Context(), user.ID, "oidc_login_success", "user", user.ID,
			map[string]any{
				"email":      user.Email,
				"provider":   user.Provider,
				"sub":        claims.Subject,
				"remote_ip":  h.clientIP(r),
				"user_agent": userAgent(r),
			})
	}

	safe := h.safeReturnTo(r.Context(), returnTo)
	http.Redirect(w, r, safe, http.StatusFound)
}

// OIDCStatus GET /api/auth/oidc/status
//
// Auth: the caller must already be signed in. Returns a scrubbed
// view of the config -- never leaks the decrypted client_secret.
// Also includes the canonical redirect_uri the operator must
// register in their IdP config.
func (h *Handlers) OIDCStatus(w http.ResponseWriter, r *http.Request) {
	cfg, err := oidc.Load(r.Context(), h.DB, h.Cipher)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := map[string]any{
		"enabled":                cfg.Enabled,
		"issuer_url":             cfg.IssuerURL,
		"client_id":              cfg.ClientID,
		"client_secret_set":      cfg.ClientSecret != "",
		"scopes":                 strings.Join(cfg.Scopes, " "),
		"cookie_parent_domain":   cfg.CookieParentDomain,
		"auto_provision":         cfg.AutoProvision,
		"require_email_verified": cfg.RequireEmailVerified,
		// Always emit arrays, never null. Go's json encoder renders a
		// nil slice as null which then crashes SSOSection's toForm()
		// (expects .join()). A zero-length []string marshals as [].
		"allowed_emails":  nonNilList(cfg.AllowedEmails),
		"allowed_domains": nonNilList(cfg.AllowedDomains),
		"redirect_uri":    h.oidcRedirectURI(r),
	}
	writeJSON(w, http.StatusOK, resp)
}

// nonNilList returns a guaranteed-non-nil []string copy of s so JSON
// marshalling emits [] rather than null for empty lists. Cheap (one
// append) and isolates the defensiveness to one place.
func nonNilList(s []string) []string {
	if s == nil {
		return []string{}
	}
	return append([]string{}, s...)
}

type oidcConfigRequest struct {
	Enabled              *bool    `json:"enabled,omitempty"`
	IssuerURL            *string  `json:"issuer_url,omitempty"`
	ClientID             *string  `json:"client_id,omitempty"`
	ClientSecret         *string  `json:"client_secret,omitempty"`
	Scopes               *string  `json:"scopes,omitempty"`
	CookieParentDomain   *string  `json:"cookie_parent_domain,omitempty"`
	AutoProvision        *bool    `json:"auto_provision,omitempty"`
	RequireEmailVerified *bool    `json:"require_email_verified,omitempty"`
	AllowedEmails        []string `json:"allowed_emails,omitempty"`
	AllowedDomains       []string `json:"allowed_domains,omitempty"`
}

// OIDCConfigPut PUT /api/auth/oidc/config
//
// Fields are all optional (pointer-valued booleans + strings, slice
// pointers). Omitted fields keep their current value. An explicit
// empty client_secret is interpreted as "keep the previous one" per
// the spec so a typical admin flow (tweak scopes only) does not
// require re-entering the secret. An explicit null → "clear" would
// be an ambiguity the spec explicitly rules out.
func (h *Handlers) OIDCConfigPut(w http.ResponseWriter, r *http.Request) {
	if h.Cipher == nil {
		writeError(w, http.StatusServiceUnavailable, "cipher not wired")
		return
	}
	var req oidcConfigRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}

	current, err := oidc.Load(r.Context(), h.DB, h.Cipher)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Merge incoming fields on top of current.
	next := current
	if req.Enabled != nil {
		next.Enabled = *req.Enabled
	}
	if req.IssuerURL != nil {
		next.IssuerURL = strings.TrimSpace(*req.IssuerURL)
	}
	if req.ClientID != nil {
		next.ClientID = strings.TrimSpace(*req.ClientID)
	}
	if req.ClientSecret != nil && *req.ClientSecret != "" {
		next.ClientSecret = *req.ClientSecret
	}
	if req.Scopes != nil {
		s := strings.TrimSpace(*req.Scopes)
		if s != "" {
			next.Scopes = strings.Fields(s)
		}
	}
	if req.CookieParentDomain != nil {
		v := strings.TrimSpace(*req.CookieParentDomain)
		for len(v) > 0 && v[0] == '.' {
			v = v[1:]
		}
		next.CookieParentDomain = v
	}
	if req.AutoProvision != nil {
		next.AutoProvision = *req.AutoProvision
	}
	if req.RequireEmailVerified != nil {
		next.RequireEmailVerified = *req.RequireEmailVerified
	}
	if req.AllowedEmails != nil {
		next.AllowedEmails = normaliseList(req.AllowedEmails)
	}
	if req.AllowedDomains != nil {
		next.AllowedDomains = normaliseList(req.AllowedDomains)
	}

	// Validate: if enabled, issuer must be reachable. When disabling
	// or the issuer is unchanged + empty, skip the probe so toggling
	// the feature off does not require a live IdP.
	if next.Enabled {
		if next.IssuerURL == "" {
			writeError(w, http.StatusBadRequest, "issuer_url required when enabled=true")
			return
		}
		if _, derr := oidc.DiscoverOnly(r.Context(), next.IssuerURL); derr != nil {
			writeError(w, http.StatusBadRequest, "issuer not reachable: "+derr.Error())
			return
		}
	}

	// Persist settings. client_secret is re-encrypted even if
	// unchanged so the ciphertext rotates its AES-GCM nonce (harmless
	// churn, defensive).
	encSecret := ""
	if next.ClientSecret != "" {
		ct, eerr := h.Cipher.Encrypt(next.ClientSecret)
		if eerr != nil {
			writeError(w, http.StatusInternalServerError, "encrypt secret: "+eerr.Error())
			return
		}
		encSecret = ct
	}
	updates := map[string]string{
		"oidc.enabled":                 boolStr(next.Enabled),
		"oidc.issuer_url":              next.IssuerURL,
		"oidc.client_id":               next.ClientID,
		"oidc.client_secret_encrypted": encSecret,
		"oidc.scopes":                  strings.Join(next.Scopes, " "),
		"oidc.cookie_parent_domain":    next.CookieParentDomain,
		"oidc.auto_provision":          boolStr(next.AutoProvision),
		"oidc.require_email_verified":  boolStr(next.RequireEmailVerified),
		"oidc.allowed_emails":          strings.Join(next.AllowedEmails, ","),
		"oidc.allowed_domains":         strings.Join(next.AllowedDomains, ","),
	}
	for k, v := range updates {
		if err := db.UpsertSetting(r.Context(), h.DB, k, v); err != nil {
			writeError(w, http.StatusInternalServerError, "persist "+k+": "+err.Error())
			return
		}
	}
	h.OIDCProviderCache.Invalidate()

	// Audit. diff keys only -- never log the secret.
	h.audit(r, "oidc_config_changed", "oidc", 0, map[string]any{
		"enabled":                next.Enabled,
		"issuer_url":             next.IssuerURL,
		"client_id_set":          next.ClientID != "",
		"client_secret_set":      next.ClientSecret != "",
		"scopes":                 strings.Join(next.Scopes, " "),
		"cookie_parent_domain":   next.CookieParentDomain,
		"auto_provision":         next.AutoProvision,
		"require_email_verified": next.RequireEmailVerified,
	})

	// Return the scrubbed shape /status would.
	h.OIDCStatus(w, r)
}

// OIDCTest POST /api/auth/oidc/test
//
// Body (optional): {issuer_url: "..."}  -- overrides the saved
// setting so the operator can probe a new IdP before saving.
// Returns the discovery endpoints so the UI can show a "connected
// to https://keycloak.../realms/argos" confirmation.
func (h *Handlers) OIDCTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IssuerURL string `json:"issuer_url,omitempty"`
	}
	// body is optional; decodeJSON.DisallowUnknownFields is fine
	// with an empty body becoming a zero-valued struct.
	_ = decodeJSON(r, &req)
	issuer := strings.TrimSpace(req.IssuerURL)
	if issuer == "" {
		issuer = strings.TrimSpace(db.GetSettingValue(r.Context(), h.DB, "oidc.issuer_url", ""))
	}
	if issuer == "" {
		writeError(w, http.StatusBadRequest, "issuer_url required (no saved value)")
		return
	}
	res, err := oidc.DiscoverOnly(r.Context(), issuer)
	if err != nil {
		writeError(w, http.StatusBadGateway, "discovery: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// --- helpers ---

// loadOIDCConfigOrError is the "is the feature turned on at all"
// gate every public oidc endpoint uses. Returns nil AFTER writing an
// HTTP response so the caller can just `return`.
//
// requireReady=true demands the full config (issuer + client + secret);
// false only checks "enabled". The split lets /status (admin-only)
// render partial config so the operator sees what's missing.
func (h *Handlers) loadOIDCConfigOrError(w http.ResponseWriter, r *http.Request, requireReady bool) *oidc.Config {
	cfg, err := oidc.Load(r.Context(), h.DB, h.Cipher)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return nil
	}
	if !cfg.Enabled {
		// Spec: disabled → 404, route should feel invisible.
		http.NotFound(w, r)
		return nil
	}
	if requireReady && !cfg.Ready() {
		writeError(w, http.StatusServiceUnavailable, "oidc not fully configured")
		return nil
	}
	return &cfg
}

// safeReturnTo prevents open-redirect abuse. Accepted targets:
//  1. Relative paths ("/", "/dashboard").
//  2. Absolute URLs whose host equals the panel host OR is a
//     subdomain of oidc.cookie_parent_domain.
//
// Anything else falls back to "/".
//
// The relative-path branch rejects a few extras that would otherwise
// fool downstream consumers:
//   - Backslash (literal or %5c / %5C): Chrome, Firefox and Safari all
//     normalise "\" to "/" before issuing the network request, so
//     "/\evil.com" in a Location header becomes "//evil.com" and
//     crosses the origin. HasPrefix("//") doesn't catch that because
//     the literal bytes still begin with "/\".
//   - ASCII control bytes (0x00-0x1f, 0x7f): header injection and
//     terminal-escape smuggling. No legitimate return-to needs them.
func (h *Handlers) safeReturnTo(ctx context.Context, raw string) string {
	if raw == "" {
		return "/"
	}
	if containsUnsafeRelativeChars(raw) {
		return "/"
	}
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "/"
	}
	host := strings.ToLower(u.Host)
	parent := strings.ToLower(db.GetSettingValue(ctx, h.DB, "oidc.cookie_parent_domain", ""))
	for len(parent) > 0 && parent[0] == '.' {
		parent = parent[1:]
	}
	panelDomain := strings.ToLower(h.PanelDomain)
	if host == panelDomain {
		return raw
	}
	if parent != "" && (host == parent || strings.HasSuffix(host, "."+parent)) {
		return raw
	}
	return "/"
}

// SafeRedirect GET /api/auth/safe-redirect?rd=<url>
//
// Public helper the frontend calls after password or TOTP login to
// resolve the post-auth destination through the same allowlist the
// OIDC callback uses. Centralising the check means one validator,
// one set of unit tests, one place to fix if the rules evolve.
// Always 200; the body is {"url": "<safe>"} where <safe> is "/"
// when the requested rd is missing / unparseable / off-domain.
func (h *Handlers) SafeRedirect(w http.ResponseWriter, r *http.Request) {
	rd := r.URL.Query().Get("rd")
	safe := h.safeReturnTo(r.Context(), rd)
	writeJSON(w, http.StatusOK, map[string]string{"url": safe})
}

// redirectToLoginError sends the browser back to the client-side
// /login route with a short reason code so Login.tsx can surface it.
// The route is NOT the API; we use the SPA path because that is
// what the browser can render.
func redirectToLoginError(w http.ResponseWriter, r *http.Request, reason string) {
	q := url.Values{}
	q.Set("oidc_error", reason)
	http.Redirect(w, r, "/login?"+q.Encode(), http.StatusFound)
}

// containsUnsafeRelativeChars reports whether raw contains characters
// that a browser or log line would mishandle when the value is treated
// as a relative path. Scans once; bails on the first hit.
//
// Detected:
//   - "\": browsers normalise to "/" before navigation.
//   - "%5c" / "%5C": URL-encoded backslash, same normalisation.
//   - bytes 0x00-0x1f and 0x7f: control characters including NUL, CR,
//     LF. Useful as header-injection or log-smuggling payloads; no
//     legitimate return-to path contains them.
func containsUnsafeRelativeChars(raw string) bool {
	for i := 0; i < len(raw); i++ {
		b := raw[i]
		if b < 0x20 || b == 0x7f || b == '\\' {
			return true
		}
		if b == '%' && i+2 < len(raw) {
			h1 := raw[i+1]
			h2 := raw[i+2]
			if h1 == '5' && (h2 == 'c' || h2 == 'C') {
				return true
			}
		}
	}
	return false
}

func normaliseList(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		v := strings.ToLower(strings.TrimSpace(s))
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
