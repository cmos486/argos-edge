// Package oidc is argos' OpenID Connect SSO layer. It owns the
// runtime config, the Authorization-Code-with-PKCE flow, and the
// user provisioning path that binds an OIDC "sub" claim to a row
// in users.
//
// The local password + TOTP path is NOT touched by this package --
// both remain fully functional as the break-glass entry when the
// IdP is unavailable. An OIDC-provisioned user has NULL
// password_hash and bypasses local TOTP (the provider is
// authoritative for MFA); a local user keeps the bcrypt+TOTP
// challenge they had before.
//
// The design is deliberately agnostic: any OIDC-compliant provider
// (Authentik, Authelia, Keycloak, Google, Okta, ...) works as long
// as it serves the /.well-known/openid-configuration discovery
// document and speaks Authorization Code + PKCE. UI settings and
// this package never name a specific vendor.
package oidc

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/cmos486/argos-edge/backend/internal/crypto"
	"github.com/cmos486/argos-edge/backend/internal/db"
)

// Config bundles the persisted settings into one struct the rest of
// the package consumes. The Cipher is NOT stored (it is a runtime
// dependency of the api layer); it is only threaded through Load so
// the client_secret ciphertext can be decrypted once at load.
type Config struct {
	Enabled            bool
	IssuerURL          string
	ClientID           string
	ClientSecret       string   // plaintext in memory, never persisted
	Scopes             []string // at minimum "openid"
	CookieParentDomain string   // e.g. ".cmos486.es" or "" for panel-only
	AutoProvision      bool
	AllowedEmails      []string // lowercased, exact match
	AllowedDomains     []string // lowercased, matches email domain
}

// DefaultScopes is what argos requests when the operator leaves
// oidc.scopes empty. "openid" is mandatory per the spec; email /
// profile give us email + name claims for provisioning.
var DefaultScopes = []string{"openid", "email", "profile"}

// Sentinel errors.
var (
	// ErrDisabled means the feature is off in settings. Callers (the
	// /api/auth/oidc/{login,callback} handlers) return 404 so the
	// route is invisible when unconfigured.
	ErrDisabled = errors.New("oidc: disabled in settings")

	// ErrNotAllowed is returned by CheckAllowlist when the user's
	// email is not on either allowlist (and at least one is set).
	ErrNotAllowed = errors.New("oidc: email not on allowlist")

	// ErrNotConfigured means the settings are enabled but issuer_url
	// or client_id/secret are empty. Surfaced as 503 by the handler
	// so the UI can prompt the operator to finish System > SSO.
	ErrNotConfigured = errors.New("oidc: missing issuer_url / client_id / client_secret")
)

// Load reads the 9 oidc.* settings, decrypts the client_secret, and
// returns a Config. Does NOT touch the network; call provider.Load
// to confirm the issuer responds.
func Load(ctx context.Context, d *sql.DB, cipher *crypto.Cipher) (Config, error) {
	cfg := Config{
		Enabled:            db.GetSettingValue(ctx, d, "oidc.enabled", "false") == "true",
		IssuerURL:          strings.TrimSpace(db.GetSettingValue(ctx, d, "oidc.issuer_url", "")),
		ClientID:           strings.TrimSpace(db.GetSettingValue(ctx, d, "oidc.client_id", "")),
		CookieParentDomain: strings.TrimSpace(db.GetSettingValue(ctx, d, "oidc.cookie_parent_domain", "")),
		AutoProvision:      db.GetSettingValue(ctx, d, "oidc.auto_provision", "true") == "true",
	}

	secretEnc := db.GetSettingValue(ctx, d, "oidc.client_secret_encrypted", "")
	if secretEnc != "" {
		if cipher == nil {
			return cfg, fmt.Errorf("oidc: cipher not wired; cannot decrypt client_secret")
		}
		pt, err := cipher.Decrypt(secretEnc)
		if err != nil {
			return cfg, fmt.Errorf("oidc: decrypt client_secret: %w", err)
		}
		cfg.ClientSecret = pt
	}

	scopesRaw := strings.TrimSpace(db.GetSettingValue(ctx, d, "oidc.scopes", ""))
	cfg.Scopes = parseSpaceList(scopesRaw, DefaultScopes)
	if !containsStr(cfg.Scopes, "openid") {
		// openid is mandatory -- prepend if the operator removed it.
		cfg.Scopes = append([]string{"openid"}, cfg.Scopes...)
	}

	cfg.AllowedEmails = parseCSVLower(db.GetSettingValue(ctx, d, "oidc.allowed_emails", ""))
	cfg.AllowedDomains = parseCSVLower(db.GetSettingValue(ctx, d, "oidc.allowed_domains", ""))

	return cfg, nil
}

// Ready reports whether the config has the minimum fields to run a
// flow. Enabled=false or empty issuer/client returns false; the
// handler tiers its response between 404 (disabled) and 503 (enabled
// but incomplete) based on this split.
func (c Config) Ready() bool {
	return c.Enabled && c.IssuerURL != "" && c.ClientID != "" && c.ClientSecret != ""
}

// CheckAllowlist returns nil when email is permitted by either the
// email or domain allowlist. When BOTH lists are empty, every
// authenticated identity is allowed in.
//
// Match semantics:
//   - AllowedEmails: exact (case-insensitive) match against the full
//     address.
//   - AllowedDomains: exact match on the domain part, also
//     case-insensitive. "example.com" matches foo@example.com but
//     NOT foo@bar.example.com (operators must list subdomains
//     explicitly -- safer default than wildcard suffix).
func (c Config) CheckAllowlist(email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if len(c.AllowedEmails) == 0 && len(c.AllowedDomains) == 0 {
		return nil
	}
	if containsStr(c.AllowedEmails, email) {
		return nil
	}
	at := strings.LastIndexByte(email, '@')
	if at > 0 {
		domain := email[at+1:]
		if containsStr(c.AllowedDomains, domain) {
			return nil
		}
	}
	return ErrNotAllowed
}

// --- helpers ---

func containsStr(xs []string, needle string) bool {
	for _, x := range xs {
		if x == needle {
			return true
		}
	}
	return false
}

func parseSpaceList(s string, fallback []string) []string {
	if s == "" {
		return append([]string(nil), fallback...)
	}
	parts := strings.Fields(s)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return append([]string(nil), fallback...)
	}
	return out
}

func parseCSVLower(s string) []string {
	if s == "" {
		return nil
	}
	raw := strings.Split(s, ",")
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		v := strings.ToLower(strings.TrimSpace(r))
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
