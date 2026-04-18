// Command argos runs the argos-edge panel backend.
package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/cmos486/argos-edge/backend/internal/config"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "argos: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(logger)

	logger.Info("argos starting",
		"listen", cfg.Listen,
		"db", cfg.DBPath,
		"caddy_admin", cfg.CaddyAdmin,
	)

	// TODO: wire db, caddy client, admin bootstrap, http server.
	return nil
}
