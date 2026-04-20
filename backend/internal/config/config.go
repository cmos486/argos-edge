// Package config loads panel configuration from environment variables.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// PanelMode enumerates the two supported deployment shapes. In lan
// mode the panel binds to 0.0.0.0:8080 and cookies stay non-secure so
// plain HTTP works. In behind_caddy mode the panel binds loopback-
// only (127.0.0.1:8080 inside the container; Caddy reaches it via
// the docker internal bridge by service name), cookies get Secure +
// SameSite=Strict, HSTS + CSP get added, and the bootstrap adds the
// panel itself as a host in argos.db the first time it starts.
type PanelMode string

const (
	ModeLAN         PanelMode = "lan"
	ModeBehindCaddy PanelMode = "behind_caddy"
)

type Config struct {
	Listen               string
	DBPath               string
	CaddyAdmin           string
	CaddyTLSDial         string
	CaddyAccessLog       string
	CaddyErrorsLog       string
	CaddyWAFAuditLog     string
	CRSRulesDir          string
	LogLevel             slog.Level
	SessionSecret        string
	InitialAdminUser     string
	InitialAdminPassword string
	MasterKeyHex         string

	// Phase 9b panel-mode wiring.
	PanelMode     PanelMode
	PanelDomain   string // only used when PanelMode == ModeBehindCaddy
	SecureCookies bool   // derived from PanelMode
}

// Load reads configuration from env vars. Returns an error if required
// values are missing.
func Load() (*Config, error) {
	c := &Config{
		Listen:               getenv("ARGOS_LISTEN", ":8080"),
		DBPath:               getenv("ARGOS_DB_PATH", "./argos.db"),
		CaddyAdmin:           getenv("ARGOS_CADDY_ADMIN", "http://localhost:2019"),
		CaddyTLSDial:         getenv("ARGOS_CADDY_TLS_DIAL", "caddy:443"),
		CaddyAccessLog:       getenv("ARGOS_CADDY_ACCESS_LOG", "/var/log/caddy/access.log"),
		CaddyErrorsLog:       getenv("ARGOS_CADDY_ERRORS_LOG", "/var/log/caddy/errors.log"),
		CaddyWAFAuditLog:     getenv("ARGOS_CADDY_WAF_AUDIT_LOG", "/var/log/caddy/waf-audit.log"),
		CRSRulesDir:          getenv("ARGOS_CRS_RULES_DIR", "/etc/coraza/crs/rules"),
		SessionSecret:        os.Getenv("ARGOS_SESSION_SECRET"),
		InitialAdminUser:     getenv("ARGOS_INITIAL_ADMIN_USER", "admin"),
		InitialAdminPassword: os.Getenv("ARGOS_INITIAL_ADMIN_PASSWORD"),
		MasterKeyHex:         os.Getenv("ARGOS_MASTER_KEY"),
	}

	// Phase 9b: panel mode drives cookie security + bind + bootstrap.
	// ARGOS_COOKIE_SECURE (phase 0) is retired; its value is now
	// derived from ARGOS_PANEL_MODE. Breaking change: operators who
	// set ARGOS_COOKIE_SECURE=true by hand must switch to
	// ARGOS_PANEL_MODE=behind_caddy to recover the same behaviour.
	modeStr := getenv("ARGOS_PANEL_MODE", "lan")
	switch PanelMode(modeStr) {
	case ModeLAN:
		c.PanelMode = ModeLAN
		c.SecureCookies = false
		if c.Listen == ":8080" {
			// keep the existing default; operators can override via
			// ARGOS_LISTEN if they want a different bind.
		}
	case ModeBehindCaddy:
		c.PanelMode = ModeBehindCaddy
		c.PanelDomain = os.Getenv("ARGOS_PANEL_DOMAIN")
		if c.PanelDomain == "" {
			return nil, fmt.Errorf("ARGOS_PANEL_MODE=behind_caddy requires ARGOS_PANEL_DOMAIN")
		}
		c.SecureCookies = true
	default:
		return nil, fmt.Errorf("ARGOS_PANEL_MODE %q is not one of lan, behind_caddy", modeStr)
	}

	lvl, err := parseLevel(getenv("ARGOS_LOG_LEVEL", "info"))
	if err != nil {
		return nil, fmt.Errorf("ARGOS_LOG_LEVEL: %w", err)
	}
	c.LogLevel = lvl

	if c.SessionSecret == "" {
		return nil, fmt.Errorf("ARGOS_SESSION_SECRET is required")
	}
	if c.MasterKeyHex == "" {
		return nil, fmt.Errorf("ARGOS_MASTER_KEY is required (generate with: openssl rand -hex 32)")
	}

	return c, nil
}

func getenv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func parseBool(s string) bool {
	switch strings.ToLower(s) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown level %q", s)
	}
}
