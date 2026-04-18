package waf

import (
	"fmt"

	"github.com/cmos486/argos-edge/backend/internal/models"
)

// RateLimitZone is the slice of JSON config that goes inside the
// caddy-ratelimit handler's `rate_limits` map. We keep it as a tiny
// struct so the caddycfg package can marshal it alongside its own
// route+handler types.
type RateLimitZone struct {
	ZoneName  string
	Key       string // Caddy placeholder or literal
	Window    string // e.g. "60s"
	MaxEvents int
}

// BuildRateLimitZone produces the per-host zone. Nil return means
// "rate limit disabled" or invalid configuration.
func BuildRateLimitZone(hostID int64, cfg models.HostSecurity) *RateLimitZone {
	if !cfg.RateLimitEnabled {
		return nil
	}
	if cfg.RateLimitRequests <= 0 || cfg.RateLimitWindowSeconds <= 0 {
		return nil
	}
	key, ok := keyPlaceholder(cfg)
	if !ok {
		return nil
	}
	return &RateLimitZone{
		ZoneName:  fmt.Sprintf("rl_host_%d", hostID),
		Key:       key,
		Window:    fmt.Sprintf("%ds", cfg.RateLimitWindowSeconds),
		MaxEvents: cfg.RateLimitRequests,
	}
}

// keyPlaceholder returns the Caddy placeholder that caddy-ratelimit
// uses to bucket events. "global" collapses every request into the
// same counter (useful for "no more than N req/s site-wide").
func keyPlaceholder(cfg models.HostSecurity) (string, bool) {
	switch cfg.RateLimitKey {
	case models.RateLimitKeyIP:
		return "{http.request.remote.host}", true
	case models.RateLimitKeyHeader:
		if cfg.RateLimitHeaderName == "" {
			return "", false
		}
		// Caddy lowercases header names in the placeholder path.
		return "{http.request.header." + cfg.RateLimitHeaderName + "}", true
	case models.RateLimitKeyGlobal:
		return "global", true
	default:
		return "", false
	}
}
