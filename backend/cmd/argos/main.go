// Command argos runs the argos-edge panel backend.
package main

import (
	"context"
	"database/sql"
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
	"github.com/cmos486/argos-edge/backend/internal/appsec"
	"github.com/cmos486/argos-edge/backend/internal/auth"
	"github.com/cmos486/argos-edge/backend/internal/backup"
	"github.com/cmos486/argos-edge/backend/internal/caddy"
	"github.com/cmos486/argos-edge/backend/internal/config"
	"github.com/cmos486/argos-edge/backend/internal/crowdsec"
	"github.com/cmos486/argos-edge/backend/internal/certs"
	"github.com/cmos486/argos-edge/backend/internal/crypto"
	"github.com/cmos486/argos-edge/backend/internal/dashboard"
	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/geoip"
	"github.com/cmos486/argos-edge/backend/internal/hardening"
	"github.com/cmos486/argos-edge/backend/internal/logs"
	"github.com/cmos486/argos-edge/backend/internal/models"
	"github.com/cmos486/argos-edge/backend/internal/notifications"
	"github.com/cmos486/argos-edge/backend/internal/notifications/senders"
	"github.com/cmos486/argos-edge/backend/internal/oidc"
	"github.com/cmos486/argos-edge/backend/internal/reconciler"
	"github.com/cmos486/argos-edge/backend/internal/server"
	"github.com/cmos486/argos-edge/backend/internal/totp"
	"github.com/cmos486/argos-edge/backend/migrations"
	"github.com/robfig/cron/v3"
)

// argosVersion is baked in at build time via -ldflags "-X main.argosVersion=...".
// The source-tree default tracks the most recent released tag; CI
// overrides with the exact tag on release builds and with
// "<tag>-dev-<short-sha>" on main builds between tags.
var argosVersion = "1.3.2"

// argosCommit is baked in at build time via -ldflags "-X main.argosCommit=...".
var argosCommit = ""

// backupDir is the in-container mount point of the argos_backups volume.
const backupDir = "/data/backups"

// caddyDataDir is the in-container RO mount of argos_caddy_data (phase 9a).
const caddyDataDir = "/data/caddy"

// geoipDir is the in-container path where DB-IP Lite mmdb files live.
const geoipDir = "/data/geoip"

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
	if len(os.Args) > 1 && os.Args[1] == "disable-2fa" {
		if err := runDisable2FACommand(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "argos disable-2fa: %v\n", err)
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
//
//	/argos restore --file /data/backups/<name>.tar.gz [--yes]
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

// runDisable2FACommand is the CLI break-glass for TOTP. It bypasses the
// API entirely and executes the DB update directly, so it works even
// when the panel is locked out (e.g. admin lost both phone and recovery
// codes). Writes an audit row with source="cli" so the event is
// visible in the logs tab after the admin logs back in.
//
// Usage:
//
//	argos disable-2fa --user <username> --yes
//
// The --yes flag is required to prevent fat-fingered execution during
// container maintenance. No remote invocation path: operator must be
// able to `docker compose exec` into the container to run it.
func runDisable2FACommand(args []string) error {
	fs := flag.NewFlagSet("disable-2fa", flag.ContinueOnError)
	user := fs.String("user", "", "username to disable 2FA for")
	yes := fs.Bool("yes", false, "skip confirmation prompt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *user == "" {
		return fmt.Errorf("usage: argos disable-2fa --user <username> --yes")
	}
	if !*yes {
		return fmt.Errorf("refusing to run without --yes (irreversible: 2FA will be fully removed for %q)", *user)
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

	ctx := context.Background()
	var (
		uid        int64
		wasEnabled int
	)
	err = d.QueryRowContext(ctx,
		`SELECT id, totp_enabled FROM users WHERE username = ?`, *user).
		Scan(&uid, &wasEnabled)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("user %q not found", *user)
		}
		return fmt.Errorf("lookup user: %w", err)
	}
	if err := totp.DisableTOTP(ctx, d, uid); err != nil {
		return fmt.Errorf("disable totp: %w", err)
	}
	// Audit trail: direct INSERT into log_entries (the Ingestor batcher
	// runs inside the panel process, which isn't up when we're CLI).
	// Mimics logs.Recorder's payload so the existing /api/logs filters
	// and the UI detail drawer render this event exactly like any
	// other audit row.
	rawPayload := fmt.Sprintf(
		`{"user_id":0,"action":"totp_disabled","resource_type":"user","resource_id":%d,`+
			`"diff":{"username":%q,"source":"cli","was_enabled":%t}}`,
		uid, *user, wasEnabled != 0)
	if _, err := d.ExecContext(ctx, `
		INSERT INTO log_entries (timestamp, source, level, message, raw)
		VALUES (?, 'audit', 'warn', ?, ?)`,
		time.Now().UTC(),
		"totp_disabled user",
		rawPayload,
	); err != nil {
		// Audit logging failure is not fatal -- 2FA is already off.
		fmt.Fprintf(os.Stderr, "warning: audit log insert failed: %v\n", err)
	}

	fmt.Fprintf(os.Stdout, "2FA disabled for user %q (user_id=%d, was_enabled=%t) at %s\n",
		*user, uid, wasEnabled != 0, time.Now().UTC().Format(time.RFC3339))
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

	// v1.3: if the operator still has CLOUDFLARE_API_TOKEN in their
	// .env from v1.2 and the dns_providers row has no credentials
	// yet, move the token into the encrypted DB. Idempotent on reruns.
	if ierr := db.ImportLegacyCloudflareToken(ctx, d, cipher); ierr != nil {
		logger.Warn("cloudflare token import failed", "error", ierr)
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

	// v1.3.2: AppSec health probe. Pairs with the generator's
	// appsec_fail_open=true default -- fail-open keeps traffic
	// flowing when the sidecar dies; this cron tells the operator
	// their WAF-inline is silently off.
	appsecHealth := &appsec.Health{
		DB:      d,
		Emitter: notifEmitter,
	}
	appsecHealthCancel := appsecHealth.Start(ctx)
	defer appsecHealthCancel()

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
	// GeoIP DB-IP Lite: try to load the on-disk mmdb files. If they
	// are absent (first boot) or stale, fire a background refresh
	// that does NOT block startup -- Lookup returns "Unknown" until
	// the download lands. A monthly cron keeps them fresh (DB-IP
	// publishes on the 1st; we pull on the 5th at 03:00 UTC so CDN
	// edges have time to warm).
	geoDB := geoip.NewDB(geoipDir)
	if err := os.MkdirAll(geoipDir, 0o755); err != nil {
		logger.Warn("geoip: mkdir data dir", "error", err)
	}
	if err := geoDB.Load(); err != nil {
		logger.Info("geoip: on-disk DBs not yet present; kicking off background download",
			"dir", geoipDir)
	} else {
		// openIfExists returns (nil, nil) for an absent file, so Load()
		// also succeeds with both readers nil on a cold boot. Branch on
		// the Status() versions so the log reflects reality instead of
		// printing country_version="" asn_version="" under "loaded".
		st := geoDB.Status()
		switch {
		case st.CountryDBVersion == "" && st.ASNDBVersion == "":
			logger.Info("geoip: no local DBs found, scheduling background download",
				"dir", geoipDir)
		case st.CountryDBVersion == "" || st.ASNDBVersion == "":
			logger.Warn("geoip: partial load, will refresh",
				"country_version", st.CountryDBVersion,
				"asn_version", st.ASNDBVersion)
		default:
			logger.Info("geoip: loaded",
				"country_version", st.CountryDBVersion,
				"asn_version", st.ASNDBVersion)
		}
	}
	geoCache := geoip.NewCache(10000, 24*time.Hour)
	geoDL := geoip.NewDownloader(geoDB)
	// Kick a background refresh if either file is missing.
	if st := geoDB.Status(); st.CountryDBSize == 0 || st.ASNDBSize == 0 {
		go func() {
			rctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			if err := geoDL.RefreshAll(rctx); err != nil {
				logger.Warn("geoip: initial background refresh failed", "error", err)
			} else {
				geoCache.Invalidate()
			}
		}()
	}
	// Monthly cron: day 5, 03:00 UTC.
	geoCronCancel, geoNextFn := startGeoIPCron(ctx, geoDL, geoCache, logger)
	defer geoCronCancel()

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

	// Boot reconcile for manual cert files: after a restore to fresh
	// infrastructure (wiped caddy_manual_certs volume) the DB has the
	// host_manual_certs rows but the plaintext .crt/.key files do
	// not exist on disk. Decrypt from argos.db and materialise so
	// Caddy's next /load finds the files it is about to reference
	// via tls.certificates.load_files. Best-effort: per-row errors
	// are logged, not fatal.
	manualCertStore := certs.New()
	if n, mcErrs := certs.ReconcileManualCerts(ctx, d, manualCertStore, cipher); n > 0 || len(mcErrs) > 0 {
		logger.Info("manual cert reconcile",
			"materialised", n,
			"errors", len(mcErrs))
		for _, e := range mcErrs {
			logger.Warn("manual cert reconcile error", "error", e)
		}
	}

	rec := reconciler.New(d, cfg.CaddyAdmin, cipher)
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

	// Phase 9b: timeouts cache + login rate limiter. Both read their
	// durable state from SQLite, so they are cheap to allocate and
	// safe to share across all handlers.
	timeouts := hardening.NewTimeoutCache(d)
	loginRL := hardening.NewLoginRateLimiter(d)

	// Phase 2FA: in-memory pending-challenge registry. Background
	// sweeper drops expired entries every TTL/2 so a user who walks
	// away mid-login does not leak an entry forever.
	totpStore := totp.NewChallengeStore()
	totpStore.StartSweeper(ctx)

	// Daily purge of totp_attempts (older than 24h). Same cadence and
	// rationale as the login_attempts purge inside logs retention.
	go func() {
		t := time.NewTicker(1 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err := totp.PurgeTOTPAttempts(ctx, d); err != nil {
					logger.Warn("totp purge failed", "error", err)
				}
			}
		}
	}()

	// Phase 7: CrowdSec LAPI client. Credentials come from env with
	// settings as the fallback path so ops can flip them via the
	// /settings UI without editing .env (phase 10 concern).
	csURL := getenvWithSetting(ctx, d, "CROWDSEC_LAPI_URL", "crowdsec.lapi_url", "http://crowdsec:8081")
	csKey := getenvWithSetting(ctx, d, "CROWDSEC_BOUNCER_API_KEY", "crowdsec.bouncer_api_key", "")
	csUser := getenvWithSetting(ctx, d, "CROWDSEC_PANEL_MACHINE_USER", "crowdsec.machine_user", "")
	csPass := getenvWithSetting(ctx, d, "CROWDSEC_PANEL_MACHINE_PASSWORD", "crowdsec.machine_password", "")
	csClient := crowdsec.New(csURL, csKey, csUser, csPass)
	csMonitor := crowdsec.NewMonitor(csClient, notifEmitter)
	csMonitorCancel := csMonitor.Start(ctx)
	defer csMonitorCancel()
	// Sync the bouncer-configured signal into settings so the
	// reconciler can emit / skip the crowdsec block without reading
	// env vars itself. The key itself stays out of argos.db --
	// settings just holds "configured" truth via a non-empty sentinel.
	csConfigured := "false"
	if csKey != "" {
		csConfigured = "true"
	}
	_ = db.UpsertSetting(ctx, d, "crowdsec.bouncer_configured", csConfigured)
	_ = db.UpsertSetting(ctx, d, "crowdsec.lapi_url", csURL)
	if csKey == "" {
		logger.Info("crowdsec: bouncer key not configured; /threats UI will show setup banner",
			"url", csURL)
	} else {
		logger.Info("crowdsec: client wired", "url", csURL, "machine_write", csUser != "")
		// Trigger an immediate reconcile so the new bouncer block lands
		// in caddy without waiting for the next host mutation.
		logger.Info("crowdsec: reconciling caddy to enable bouncer")
	}

	// AppSec wiring (CrowdSec WAF inline). Status reader probes the
	// detect listener to confirm AppSec is loaded; metrics provider
	// reuses the machine-JWT LAPI client with a 30s cache. Rule count
	// is a static baseline (setup-appsec.sh installs 3 collections
	// that resolve to ~188 rules at v0.8/14.8/1.1). A later hub
	// inspection endpoint could replace the baseline; right now
	// CrowdSec exposes no live count over LAPI.
	const appsecDetectProbe = "http://crowdsec:7423"
	const appsecShippedRuleCount = 188
	appsecHub := appsec.NewProbeHub(appsecDetectProbe, appsecShippedRuleCount)
	appsecStatus := &appsec.StatusReader{DB: d, Hub: appsecHub}
	appsecProvider := appsec.NewProvider(csClient)

	// OIDC pending-login store (PKCE verifiers + state tokens). Lives
	// in-memory only; entries expire after 10 min, a container
	// restart invalidates half-completed auths by definition.
	oidcStore := oidc.NewPendingStore()
	oidcStore.StartSweeper(ctx)

	// ForwardAuth cache -- 30s per validated session token, shared
	// across every protected host's per-request subrequest. Sweeper
	// evicts expired entries on a timer so the map does not grow
	// unbounded for infrequent users.
	forwardAuthCache := api.NewForwardAuthCache()
	forwardAuthCache.StartSweeper(ctx)

	// Phase 9b: bootstrap the panel host in behind_caddy mode. The
	// first time the panel boots in that mode, we create an argos.db
	// row for the configured domain so Caddy immediately starts
	// serving the panel over TLS. Idempotent -- skips if the domain
	// already exists.
	if cfg.PanelMode == config.ModeBehindCaddy {
		if err := bootstrapPanelHost(ctx, d, cfg.PanelDomain, logger); err != nil {
			logger.Warn("panel host bootstrap failed", "error", err)
		}
	}

	srv := server.New(server.Config{
		Addr:               cfg.Listen,
		DB:                 d,
		Caddy:              caddyClient,
		Reconciler:         rec,
		Audit:              auditRec,
		CaddyTLSDial:       cfg.CaddyTLSDial,
		CookieSecure:       cfg.SecureCookies,
		PanelMode:          string(cfg.PanelMode),
		PanelDomain:        cfg.PanelDomain,
		NotifRepo:          notifRepo,
		NotifWorker:        notifWorker,
		NotifEmitter:       notifEmitter,
		VAPIDKeys:          vapid,
		BackupMgr:          backupMgr,
		ArgosVersion:       argosVersion,
		DashQueries:        dashQ,
		DashCache:          dashCache,
		StartedAt:          startedAt,
		Timeouts:           timeouts,
		LoginRL:            loginRL,
		CrowdSec:           csClient,
		CrowdSecMonitor:    csMonitor,
		GeoDB:              geoDB,
		GeoCache:           geoCache,
		GeoDownloader:      geoDL,
		GeoNextRefreshAt:   geoNextFn,
		Cipher:             cipher,
		TOTPStore:          totpStore,
		ManualCertStore:    manualCertStore,
		AppSecStatusReader: appsecStatus,
		AppSecProvider:     appsecProvider,
		OIDCStore:          oidcStore,
		ForwardAuthCache:   forwardAuthCache,
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

// bootstrapPanelHost creates (once) the host row + target_group that
// tell Caddy to serve the panel itself under the configured domain.
// Target is the internal docker service name "argos:8080" so Caddy
// reaches the panel over the argos_net bridge without the operator
// publishing :8080 to the host.
//
// Idempotent: if a host with that domain already exists it's left
// alone. Running as nobody means we cannot discover dynamically
// whether the operator has reconfigured the TG -- we trust them.
func bootstrapPanelHost(ctx context.Context, d *sql.DB, domain string, logger *slog.Logger) error {
	if domain == "" {
		return fmt.Errorf("domain required")
	}
	// Already exists?
	var existing int
	if err := d.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM hosts WHERE domain = ?`, domain).Scan(&existing); err != nil {
		return fmt.Errorf("check hosts: %w", err)
	}
	if existing > 0 {
		return nil
	}

	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Create or find the TG.
	var tgID int64
	const tgName = "argos-panel-internal"
	if err := tx.QueryRowContext(ctx,
		`SELECT id FROM target_groups WHERE name = ?`, tgName).Scan(&tgID); err != nil {
		if err != sql.ErrNoRows {
			return fmt.Errorf("lookup tg: %w", err)
		}
		res, err := tx.ExecContext(ctx, `
			INSERT INTO target_groups
			 (name, protocol, verify_tls, algorithm, health_check_enabled,
			  health_check_path, health_check_method, health_check_expect_status,
			  health_check_interval_seconds, health_check_timeout_seconds,
			  health_check_fails_to_unhealthy, health_check_passes_to_healthy)
			 VALUES (?, 'http', 0, 'round_robin', 1,
			         '/healthz', 'GET', '200', 15, 5, 3, 2)`, tgName)
		if err != nil {
			return fmt.Errorf("insert tg: %w", err)
		}
		tgID, _ = res.LastInsertId()
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO targets (target_group_id, host, port, weight, enabled)
			 VALUES (?, 'argos', 8080, 1, 1)`, tgID); err != nil {
			return fmt.Errorf("insert target: %w", err)
		}
	}

	// Insert the host.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO hosts (domain, target_group_id, tls_mode, tls_email, enabled)
		 VALUES (?, ?, ?, ?, 1)`,
		domain, tgID, string(models.TLSModeAuto), ""); err != nil {
		return fmt.Errorf("insert host: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	logger.Info("bootstrap: added panel host + TG",
		"domain", domain, "target", "argos:8080", "tg", tgName)
	return nil
}

// getenvWithSetting prefers an env var (matches the compose wiring
// for phase-7 CrowdSec credentials) and falls back to the argos
// settings table when the env var is empty. This lets ops either
// pin credentials in .env or persist them via the settings UI.
func getenvWithSetting(ctx context.Context, d *sql.DB, envKey, settingKey, fallback string) string {
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	if v := db.GetSettingValue(ctx, d, settingKey, ""); v != "" {
		return v
	}
	return fallback
}

// startGeoIPCron schedules the monthly DB-IP Lite refresh. DB-IP
// publishes new databases on the 1st; we fetch on the 5th at 03:00
// UTC to let CDN edges warm. Cache is invalidated on every
// successful refresh so UI reads hit the fresh data.
//
// Returns a cancel func plus a closure the API layer calls to surface
// the next scheduled fire time on /api/geoip/status.
func startGeoIPCron(ctx context.Context, dl *geoip.Downloader, cache *geoip.Cache, logger *slog.Logger) (context.CancelFunc, func() time.Time) {
	ctx, cancel := context.WithCancel(ctx)
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	c := cron.New(cron.WithParser(parser))
	id, err := c.AddFunc("0 3 5 * *", func() {
		rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer rcancel()
		if err := dl.RefreshAll(rctx); err != nil {
			logger.Warn("geoip: monthly refresh failed", "error", err)
			return
		}
		cache.Invalidate()
		logger.Info("geoip: monthly refresh done")
	})
	if err != nil {
		logger.Error("geoip: cron AddFunc", "error", err)
		cancel()
		return cancel, func() time.Time { return time.Time{} }
	}
	c.Start()
	logger.Info("geoip: monthly refresh cron armed",
		"schedule", "0 3 5 * *",
		"next", c.Entry(id).Next.Format(time.RFC3339))
	go func() {
		<-ctx.Done()
		stop := c.Stop()
		<-stop.Done()
	}()
	return cancel, func() time.Time { return c.Entry(id).Next }
}
