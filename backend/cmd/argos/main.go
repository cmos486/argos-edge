// Command argos runs the argos-edge panel backend.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/api"
	"github.com/cmos486/argos-edge/backend/internal/auth"
	"github.com/cmos486/argos-edge/backend/internal/backup"
	"github.com/cmos486/argos-edge/backend/internal/caddy"
	"github.com/cmos486/argos-edge/backend/internal/config"
	"github.com/cmos486/argos-edge/backend/internal/crypto"
	"github.com/cmos486/argos-edge/backend/internal/dashboard"
	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/logs"
	"github.com/cmos486/argos-edge/backend/internal/notifications"
	"github.com/cmos486/argos-edge/backend/internal/notifications/senders"
	"github.com/cmos486/argos-edge/backend/internal/reconciler"
	"github.com/cmos486/argos-edge/backend/internal/server"
	"github.com/cmos486/argos-edge/backend/migrations"
)

// argosVersion is baked in at build time via -ldflags "-X main.argosVersion=...".
// Falls back to "dev" when run outside the Docker build.
var argosVersion = "dev"

// argosCommit is baked in at build time via -ldflags "-X main.argosCommit=...".
var argosCommit = ""

// backupDir is the in-container mount point of the argos_backups volume.
const backupDir = "/data/backups"

// caddyDataDir is the in-container RO mount of argos_caddy_data (phase 9a).
const caddyDataDir = "/data/caddy"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		if err := runMigrateCommand(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "argos migrate: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "restore" {
		if err := runRestoreCommand(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "argos restore: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "argos: %v\n", err)
		os.Exit(1)
	}
}

// runRestoreCommand stages a backup for restore and exits 0 without
// starting the HTTP server. Operator then runs
// `docker compose restart argos` to apply. Usage:
//   /argos restore --file /data/backups/<name>.tar.gz [--yes]
func runRestoreCommand(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	file := fs.String("file", "", "path to the backup .tar.gz")
	yes := fs.Bool("yes", false, "skip confirmation prompt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *file == "" {
		return fmt.Errorf("usage: argos restore --file <path> --yes")
	}
	if !*yes {
		fmt.Fprintf(os.Stderr, "Restore requires --yes. This overwrites the live DB on the next restart.\n")
		return fmt.Errorf("aborted (missing --yes)")
	}
	dbPath := os.Getenv("ARGOS_DB_PATH")
	if dbPath == "" {
		return fmt.Errorf("ARGOS_DB_PATH required")
	}
	d, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer d.Close()

	mgr := &backup.Manager{
		DB:           d,
		DBPath:       dbPath,
		BackupDir:    backupDir,
		CaddyDir:     caddyDataDir,
		ArgosVersion: argosVersion,
		Commit:       argosCommit,
	}
	plan, err := mgr.Prepare(context.Background(), *file, 0)
	if err != nil {
		return fmt.Errorf("prepare: %w", err)
	}
	if err := mgr.Apply(plan); err != nil {
		return fmt.Errorf("apply: %w", err)
	}
	fmt.Printf("restore scheduled: %s\nrestart the container to apply: docker compose restart argos\n",
		plan.Filename)
	return nil
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
	startedAt := time.Now().UTC()
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

	// Phase 9a: if a prior /api/backups/.../restore left a flag, apply
	// it BEFORE opening the DB so the running pool never sees the old
	// file.
	restoredFrom, rerr := backup.ApplyPending(cfg.DBPath)
	if rerr != nil {
		logger.Error("restore pending failed", "error", rerr)
		// continue anyway; the flag is already cleared and the live DB
		// will be used as-is
	} else if restoredFrom != "" {
		logger.Warn("restored from backup on boot", "from", restoredFrom)
	}

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

	// Phase 5: crypto master key -> cipher, used for encrypting channel
	// secrets and the VAPID private key in the settings table.
	cipher, err := crypto.New(cfg.MasterKeyHex)
	if err != nil {
		return fmt.Errorf("crypto: %w", err)
	}

	// Phase 5: notification emitter is wired BEFORE the ingestor so
	// its observer can push events into the same queue. Worker starts
	// after we have the repo + sender registry.
	notifEmitter := notifications.NewEmitter()
	defer notifEmitter.Close()
	notifWatcher := notifications.NewLogWatcher(notifEmitter)

	ingestor := logs.NewIngestor(d, cfg.CaddyAccessLog, cfg.CaddyErrorsLog, cfg.CaddyWAFAuditLog)
	ingestor.SetObserver(notifWatcher.Observe)
	if err := ingestor.Start(ctx); err != nil {
		logger.Warn("log ingestor start failed", "error", err)
	} else {
		logger.Info("log ingestor started",
			"access", cfg.CaddyAccessLog, "errors", cfg.CaddyErrorsLog)
	}
	defer ingestor.Close()
	auditRec := logs.NewRecorder(ingestor)
	auditRec.SetNotifier(notifEmitter)

	retentionCancel := logs.StartRetention(ctx, d)
	defer retentionCancel()

	// Phase 5: notification repo, VAPID keys, sender registry, worker.
	notifRepo := &notifications.NotifRepo{DB: d, Cipher: cipher}
	vapid, err := notifications.EnsureVAPID(ctx, d, cipher)
	if err != nil {
		return fmt.Errorf("vapid: %w", err)
	}
	senderRegistry := notifications.SenderRegistry{
		notifications.TypeWebhook:     senders.NewWebhook(),
		notifications.TypeEmail:       senders.NewEmail(),
		notifications.TypeTelegram:    senders.NewTelegram(),
		notifications.TypeBrowserPush: senders.NewBrowserPush(notifRepo, vapid),
	}
	notifWorker := notifications.NewWorker(notifEmitter, notifRepo, senderRegistry)
	notifWorkerCancel := notifWorker.Start(ctx)
	defer notifWorkerCancel()

	notifRetention := &notifications.RetentionPurger{DB: d, Repo: notifRepo}
	notifRetentionCancel := notifRetention.Start(ctx)
	defer notifRetentionCancel()

	certDetectCron := &notifications.CertAndDetectCron{
		DB:           d,
		Emitter:      notifEmitter,
		CaddyTLSDial: cfg.CaddyTLSDial,
	}
	certDetectCancel := certDetectCron.Start(ctx)
	defer certDetectCancel()

	healthCron := &notifications.HealthCron{
		Emitter:    notifEmitter,
		PanelURL:   "http://localhost" + cfg.Listen,
		CaddyAdmin: cfg.CaddyAdmin,
	}
	healthCronCancel := healthCron.Start(ctx)
	defer healthCronCancel()

	// Phase 9a: backup manager + scheduler. CaddyDir is RO; empty
	// string tells the manager to skip caddy tree (useful for tests).
	caddyDir := caddyDataDir
	if _, err := os.Stat(caddyDir); err != nil {
		caddyDir = "" // mount not present
	}
	backupMgr := &backup.Manager{
		DB:           d,
		DBPath:       cfg.DBPath,
		BackupDir:    backupDir,
		CaddyDir:     caddyDir,
		ArgosVersion: argosVersion,
		Commit:       argosCommit,
	}
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		logger.Warn("mkdir backup dir", "error", err)
	}
	// Phase 9a polish: bring the backups table and the /data/backups/
	// directory back into sync on every boot. Tolerates the first
	// boot (dir empty, table empty) and a prior restore that rewound
	// the table (files on disk remain, rows are re-added as orphans).
	if err := backupMgr.Reconcile(ctx); err != nil {
		logger.Warn("backup reconcile failed", "error", err)
	}
	backupSched := &backup.Scheduler{
		Manager: backupMgr,
		DB:      d,
		Emitter: notifEmitter,
	}
	backupSchedCancel := backupSched.Start(ctx)
	defer backupSchedCancel()

	// If we restored from a backup on this boot, emit the event now
	// that the emitter + worker are both up.
	if restoredFrom != "" {
		notifEmitter.Emit(notifications.Event{
			Type:     notifications.EvtConfigRestored,
			Severity: notifications.SeverityWarning,
			Message:  "restored " + restoredFrom,
			Data:     map[string]any{"from_backup": restoredFrom},
		})
		// also write an audit row so the history tab shows it
		auditRec.Record(ctx, 0, "restore", "backup", 0, map[string]any{"from": restoredFrom})
	}

	rec := reconciler.New(d, cfg.CaddyAdmin)
	if err := rec.ApplyFromDBWithBackoff(ctx); err != nil {
		// Not fatal: the operator can still reach the panel, add a host,
		// and trigger a reconcile from the UI once caddy recovers.
		logger.Error("initial caddy reconcile failed", "error", err)
	} else {
		logger.Info("caddy reconcile ok")
	}

	// Phase 6: dashboard query engine + response cache.
	dashQ := &dashboard.Queries{DB: d}
	dashCache := dashboard.NewCache(30 * time.Second)

	srv := server.New(server.Config{
		Addr:         cfg.Listen,
		DB:           d,
		Caddy:        caddyClient,
		Reconciler:   rec,
		Audit:        auditRec,
		CaddyTLSDial: cfg.CaddyTLSDial,
		CookieSecure: cfg.CookieSecure,
		NotifRepo:    notifRepo,
		NotifWorker:  notifWorker,
		NotifEmitter: notifEmitter,
		VAPIDKeys:    vapid,
		BackupMgr:    backupMgr,
		ArgosVersion: argosVersion,
		DashQueries:  dashQ,
		DashCache:    dashCache,
		StartedAt:    startedAt,
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
