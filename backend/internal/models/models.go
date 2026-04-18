// Package models holds the plain data types the panel persists or
// serialises. Keep these dependency-free so any layer can depend on
// them without pulling in SQL, HTTP, or Caddy concerns.
package models

import "time"

// TLSMode controls whether Caddy should automate certificates for a host.
type TLSMode string

const (
	TLSModeAuto TLSMode = "auto" // Let's Encrypt via DNS-01 (cloudflare)
	TLSModeNone TLSMode = "none" // plain HTTP, no TLS
)

// Host is a domain managed by the panel plus the upstream Caddy proxies to.
type Host struct {
	ID                int64     `json:"id"`
	Domain            string    `json:"domain"`
	UpstreamURL       string    `json:"upstream_url"`
	UpstreamVerifyTLS bool      `json:"upstream_verify_tls"`
	TLSMode           TLSMode   `json:"tls_mode"`
	TLSEmail          string    `json:"tls_email"`
	Enabled           bool      `json:"enabled"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// CertStatus mirrors one entry from Caddy's certificate storage.
type CertStatus struct {
	Domain         string    `json:"domain"`
	Issuer         string    `json:"issuer"`
	NotAfter       time.Time `json:"not_after"`
	LastCheckedAt  time.Time `json:"last_checked_at"`
}
