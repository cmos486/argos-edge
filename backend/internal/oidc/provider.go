package oidc

import (
	"context"
	"fmt"
	"net/http"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// DiscoveryTimeout caps every call to the issuer's
// .well-known/openid-configuration endpoint. Short enough to fail
// fast on misconfiguration; long enough that a slow LAN IdP
// (Authentik behind a cold Traefik) does not spurious-fail.
const DiscoveryTimeout = 5 * time.Second

// Provider wraps the raw *coreoidc.Provider plus a pre-built
// oauth2.Config so the flow layer can ask "give me the authZ URL"
// without re-wiring scopes + redirect URI on every request.
type Provider struct {
	Raw         *coreoidc.Provider
	OAuth       *oauth2.Config
	Verifier    *coreoidc.IDTokenVerifier
	IssuerURL   string
	RedirectURI string
}

// TestResult is the shape POST /api/auth/oidc/test returns. Gives
// the operator a fingerprint of what discovery resolved to so they
// can sanity-check against their provider's docs.
type TestResult struct {
	Issuer      string   `json:"issuer"`
	AuthURL     string   `json:"authorization_endpoint"`
	TokenURL    string   `json:"token_endpoint"`
	UserInfoURL string   `json:"userinfo_endpoint,omitempty"`
	JWKSURL     string   `json:"jwks_uri,omitempty"`
	IDTokenAlgs []string `json:"id_token_signing_alg_values_supported,omitempty"`
}

// DiscoverOnly fetches the discovery doc and returns its salient
// endpoints WITHOUT building a Provider. Used by PUT /config + POST
// /test to validate a new issuer before persisting.
func DiscoverOnly(ctx context.Context, issuerURL string) (TestResult, error) {
	ctx, cancel := context.WithTimeout(ctx, DiscoveryTimeout)
	defer cancel()
	p, err := coreoidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return TestResult{}, fmt.Errorf("discovery: %w", err)
	}
	var meta struct {
		Issuer      string   `json:"issuer"`
		AuthURL     string   `json:"authorization_endpoint"`
		TokenURL    string   `json:"token_endpoint"`
		UserInfoURL string   `json:"userinfo_endpoint"`
		JWKSURL     string   `json:"jwks_uri"`
		IDTokenAlgs []string `json:"id_token_signing_alg_values_supported"`
	}
	if err := p.Claims(&meta); err != nil {
		return TestResult{}, fmt.Errorf("parse discovery claims: %w", err)
	}
	return TestResult{
		Issuer:      meta.Issuer,
		AuthURL:     meta.AuthURL,
		TokenURL:    meta.TokenURL,
		UserInfoURL: meta.UserInfoURL,
		JWKSURL:     meta.JWKSURL,
		IDTokenAlgs: meta.IDTokenAlgs,
	}, nil
}

// LoadProvider runs discovery and builds a ready-to-flow Provider.
// RedirectURI must be the exact URL the IdP has registered (argos
// does NOT try to infer; it's surfaced in the /status endpoint for
// the operator to copy verbatim into their provider config).
func LoadProvider(ctx context.Context, cfg Config, redirectURI string) (*Provider, error) {
	if !cfg.Ready() {
		return nil, ErrNotConfigured
	}
	ctx2, cancel := context.WithTimeout(ctx, DiscoveryTimeout)
	defer cancel()
	raw, err := coreoidc.NewProvider(ctx2, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery %s: %w", cfg.IssuerURL, err)
	}
	oauth := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     raw.Endpoint(),
		Scopes:       cfg.Scopes,
	}
	verifier := raw.Verifier(&coreoidc.Config{ClientID: cfg.ClientID})
	return &Provider{
		Raw:         raw,
		OAuth:       oauth,
		Verifier:    verifier,
		IssuerURL:   cfg.IssuerURL,
		RedirectURI: redirectURI,
	}, nil
}

// HTTPClient is the dialer used by LoadProvider + the token exchange.
// Exposed so tests can inject a mock transport that serves the
// discovery + token endpoints in-process.
var HTTPClient = &http.Client{Timeout: 10 * time.Second}
