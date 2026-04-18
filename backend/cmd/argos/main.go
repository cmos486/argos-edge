// Command argos runs the argos-edge panel backend.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/api"
	"github.com/cmos486/argos-edge/backend/internal/auth"
	"github.com/cmos486/argos-edge/backend/internal/caddy"
	"github.com/cmos486/argos-edge/backend/internal/config"
	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/logs"
	"github.com/cmos486/argos-edge/backend/internal/reconciler"
	"github.com/cmos486/argos-edge/backend/internal/server"
	"github.com/cmos486/argos-edge/backend/migrations"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		if err := runMigrateCommand(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "argos migrate: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "argos: %v\n", err)
		os.Exit(1)
	}
}

// runMigrateCommand implements the `argos migrate rollback` subcommand
// used by the phase-2 sandboxed down-migration test.
func runMigrateCommand(args []string) error {
	if len(args) == 0 || args[0] != "rollback" {
		return fmt.Errorf("usage: argos migrate rollback")
	}
	path := os.Getenv("ARGOS_DB_PATH")
	if path == "" {
		return fmt.Errorf("ARGOS_DB_PATH required")
	}
	d, err := db.Open(path)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()

	downHooks := map[string]db.Hook{}
	for v, h := range migrations.DownHooks {
		downHooks[v] = db.Hook(h)
	}
	return db.Rollback(context.Background(), d, migrations.FS, downHooks)
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	d, err := db.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()

	upHooks := map[string]db.Hook{}
	for v, h := range migrations.UpHooks {
		upHooks[v] = db.Hook(h)
	}
	if err := db.Migrate(ctx, d, migrations.FS, upHooks); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	if err := auth.Bootstrap(ctx, d, cfg.InitialAdminUser, cfg.InitialAdminPassword); err != nil {
		return fmt.Errorf("bootstrap admin: %w", err)
	}

	caddyClient := caddy.NewClient(cfg.CaddyAdmin)
	probeCaddy(ctx, caddyClient, logger)

	api.LoadCRSCatalogOnce(cfg.CRSRulesDir)

	ingestor := logs.NewIngestor(d, cfg.CaddyAccessLog, cfg.CaddyErrorsLog, cfg.CaddyWAFAuditLog)
	if err := ingestor.Start(ctx); err != nil {
		logger.Warn("log ingestor start failed", "error", err)
	} else {
		logger.Info("log ingestor started",
			"access", cfg.CaddyAccessLog, "errors", cfg.CaddyErrorsLog)
	}
	defer ingestor.Close()
	auditRec := logs.NewRecorder(ingestor)

	retentionCancel := logs.StartRetention(ctx, d)
	defer retentionCancel()

	rec := reconciler.New(d, cfg.CaddyAdmin)
	if err := rec.ApplyFromDBWithBackoff(ctx); err != nil {
		// Not fatal: the operator can still reach the panel, add a host,
		// and trigger a reconcile from the UI once caddy recovers.
		logger.Error("initial caddy reconcile failed", "error", err)
	} else {
		logger.Info("caddy reconcile ok")
	}

	srv := server.New(server.Config{
		Addr:         cfg.Listen,
		DB:           d,
		Caddy:        caddyClient,
		Reconciler:   rec,
		Audit:        auditRec,
		CaddyTLSDial: cfg.CaddyTLSDial,
		CookieSecure: cfg.CookieSecure,
	})

	errCh := make(chan error, 1)
	go func() {
		logger.Info("http listening", "addr", cfg.Listen)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err, ok := <-errCh:
		if ok && err != nil {
			return fmt.Errorf("http server: %w", err)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}

// probeCaddy logs a one-shot status at startup so the operator sees whether
// the admin API is reachable. Not fatal: Caddy may come up slightly later
// than the panel depending on healthcheck timing.
func probeCaddy(ctx context.Context, c *caddy.Client, logger *slog.Logger) {
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	st := c.Status(probeCtx)
	if !st.OK {
		logger.Warn("caddy admin probe failed", "address", st.Address, "error", st.Error)
		return
	}
	logger.Info("caddy admin probe ok", "address", st.Address, "has_http", st.HasHTTP)
}
