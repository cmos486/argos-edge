package caddycfg

import (
	"fmt"
	"net/url"
	"strings"
)

// Let's Encrypt ACME v2 directory URLs. Exposed so the UI can render
// the two presets by value without hard-coding strings in the frontend.
const (
	// LEProductionCAURL is the real Let's Encrypt directory. Certs
	// issued here chain to a trusted root every browser ships.
	LEProductionCAURL = "https://acme-v02.api.letsencrypt.org/directory"

	// LEStagingCAURL is the Let's Encrypt staging environment. Same
	// ACME protocol, massively higher rate limits, and the certs
	// chain to an untrusted root -- browsers will show a warning.
	// Used for panel development and for debugging a host without
	// burning production quota.
	LEStagingCAURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// ResolveACMECAURL picks the effective ACME directory URL for one host,
// in this precedence: env var > per-host override > global setting >
// "". An empty return string means "leave caddy at its built-in default"
// (which today is LE production). This function never errors -- the
// write-path validator below is where malformed URLs get rejected.
//
// The env-var argument is threaded through by the reconciler so this
// package stays pure (no os.Getenv here) and easy to unit-test.
func ResolveACMECAURL(envURL, perHostURL, globalURL string) string {
	if s := strings.TrimSpace(envURL); s != "" {
		return s
	}
	if s := strings.TrimSpace(perHostURL); s != "" {
		return s
	}
	return strings.TrimSpace(globalURL)
}

// ValidateACMECAURL accepts an empty string (clear / use default) or a
// well-formed https URL with a non-empty host. http:// is rejected --
// ACME v2 directories are https-only in the wild, and accepting http://
// here would just hide bugs further down the stack.
func ValidateACMECAURL(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("invalid url: %v", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("must use https scheme")
	}
	if u.Host == "" {
		return fmt.Errorf("missing host")
	}
	return nil
}
