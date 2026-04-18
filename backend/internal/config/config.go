// Package config loads panel configuration from environment variables.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

type Config struct {
	Listen               string
	DBPath               string
	CaddyAdmin           string
	LogLevel             slog.Level
	SessionSecret        string
	InitialAdminUser     string
	InitialAdminPassword string
}

// Load reads configuration from env vars. Returns an error if required
// values are missing.
func Load() (*Config, error) {
	c := &Config{
		Listen:               getenv("ARGOS_LISTEN", ":8080"),
		DBPath:               getenv("ARGOS_DB_PATH", "./argos.db"),
		CaddyAdmin:           getenv("ARGOS_CADDY_ADMIN", "http://localhost:2019"),
		SessionSecret:        os.Getenv("ARGOS_SESSION_SECRET"),
		InitialAdminUser:     getenv("ARGOS_INITIAL_ADMIN_USER", "admin"),
		InitialAdminPassword: os.Getenv("ARGOS_INITIAL_ADMIN_PASSWORD"),
	}

	lvl, err := parseLevel(getenv("ARGOS_LOG_LEVEL", "info"))
	if err != nil {
		return nil, fmt.Errorf("ARGOS_LOG_LEVEL: %w", err)
	}
	c.LogLevel = lvl

	if c.SessionSecret == "" {
		return nil, fmt.Errorf("ARGOS_SESSION_SECRET is required")
	}

	return c, nil
}

func getenv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
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
