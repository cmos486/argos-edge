// Package server wires the HTTP router.
package server

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/cmos486/argos-edge/backend/internal/api"
	"github.com/cmos486/argos-edge/backend/internal/appsec"
	"github.com/cmos486/argos-edge/backend/internal/backup"
	"github.com/cmos486/argos-edge/backend/internal/caddy"
	"github.com/cmos486/argos-edge/backend/internal/crowdsec"
	"github.com/cmos486/argos-edge/backend/internal/certs"
	"github.com/cmos486/argos-edge/backend/internal/crypto"
	"github.com/cmos486/argos-edge/backend/internal/dashboard"
	"github.com/cmos486/argos-edge/backend/internal/geoip"
	"github.com/cmos486/argos-edge/backend/internal/hardening"
	"github.com/cmos486/argos-edge/backend/internal/logs"
	"github.com/cmos486/argos-edge/backend/internal/notifications"
	"github.com/cmos486/argos-edge/backend/internal/oidc"
	"github.com/cmos486/argos-edge/backend/internal/reconciler"
	"github.com/cmos486/argos-edge/backend/internal/security/country"
	"github.com/cmos486/argos-edge/backend/internal/security/publicip"
	"github.com/cmos486/argos-edge/backend/internal/totp"
	"github.com/cmos486/argos-edge/backend/static"
)

// Config bundles runtime dependencies needed by the HTTP layer.
type Config struct {
	Addr            string
	DB              *sql.DB
	Caddy           *caddy.Client
	Reconciler      *reconciler.Reconciler
	Audit           *logs.Recorder
	CaddyTLSDial    string
	CookieSecure    bool
	PanelMode       string
	PanelDomain     string
	Timeouts        *hardening.TimeoutCache
	LoginRL         *hardening.LoginRateLimiter
	NotifRepo       *notifications.NotifRepo
	NotifWorker     *notifications.Worker
	NotifEmitter    *notifications.Emitter
	VAPIDKeys       *notifications.VAPIDKeys
	BackupMgr       *backup.Manager
	ArgosVersion    string
	DashQueries     *dashboard.Queries
	DashCache       *dashboard.Cache
	StartedAt       time.Time
	CrowdSec        *crowdsec.Client
	CrowdSecMonitor *crowdsec.Monitor
	GeoDB            *geoip.DB
	GeoCache         *geoip.Cache
	GeoDownloader    *geoip.Downloader
	GeoNextRefreshAt func() time.Time
	Cipher          *crypto.Cipher
	TOTPStore       *totp.ChallengeStore
	ManualCertStore *certs.Store

	AppSecStatusReader *appsec.StatusReader
	AppSecProvider     *appsec.Provider

	OIDCStore         *oidc.PendingStore
	ForwardAuthCache  *api.ForwardAuthCache
	TargetHealthCache *api.TargetHealthCache

	// v1.3.21 country-ban expander. Optional: nil-safe, the
	// /api/security/countries/* handlers return 503 when unwired.
	CountryExpander *country.Expander

	// v1.3.31 async country-ban job runner. Wraps Expander in a
	// single-worker goroutine + country_expansion_jobs row.
	// Optional: nil-safe.
	CountryJobs *country.JobRunner

	// v1.3.23 public-IP detector. Optional: nil-safe; the
	// SelfBlockBanner v2 multi-IP path degrades to "no public IP
	// detected" when unwired.
	PublicIP *publicip.Detector
}

// New builds the argos HTTP server. The returned *http.Server is not yet
// listening; the caller runs ListenAndServe and Shutdown.
//
// Layout:
//   - /healthz         unauthenticated liveness probe for compose/LXC
//   - /api/auth/login  public, issues session cookie
//   - /api/*           everything else requires a valid session
func New(cfg Config) *http.Server {
	h := &api.Handlers{
		DB:                 cfg.DB,
		Caddy:              cfg.Caddy,
		Reconciler:         cfg.Reconciler,
		Audit:              cfg.Audit,
		CaddyTLSDial:       cfg.CaddyTLSDial,
		CookieSecure:       cfg.CookieSecure,
		PanelMode:          cfg.PanelMode,
		PanelDomain:        cfg.PanelDomain,
		NotifRepo:          cfg.NotifRepo,
		NotifWorker:        cfg.NotifWorker,
		NotifEmitter:       cfg.NotifEmitter,
		VAPIDKeys:          cfg.VAPIDKeys,
		BackupMgr:          cfg.BackupMgr,
		ArgosVersion:       cfg.ArgosVersion,
		DashQueries:        cfg.DashQueries,
		DashCache:          cfg.DashCache,
		StartedAt:          cfg.StartedAt,
		Timeouts:           cfg.Timeouts,
		LoginRL:            cfg.LoginRL,
		CrowdSec:           cfg.CrowdSec,
		CrowdSecMonitor:    cfg.CrowdSecMonitor,
		GeoDB:              cfg.GeoDB,
		GeoCache:           cfg.GeoCache,
		GeoDownloader:      cfg.GeoDownloader,
		GeoNextRefreshAt:   cfg.GeoNextRefreshAt,
		Cipher:             cfg.Cipher,
		TOTPStore:          cfg.TOTPStore,
		ManualCertStore:    cfg.ManualCertStore,
		AppSecStatusReader: cfg.AppSecStatusReader,
		AppSecProvider:     cfg.AppSecProvider,
		OIDCStore:          cfg.OIDCStore,
		OIDCProviderCache:  &api.OIDCProviderCache{},
		ForwardAuthCache:   cfg.ForwardAuthCache,
		TargetHealthCache:  cfg.TargetHealthCache,
		CountryExpander:    cfg.CountryExpander,
		CountryJobs:        cfg.CountryJobs,
		PublicIP:           cfg.PublicIP,
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	// middleware.RealIP rewrites r.RemoteAddr from X-Forwarded-For /
	// X-Real-IP / True-Client-IP without validating who set them. That
	// is only safe behind a trusted proxy. In behind_caddy mode Caddy
	// is the sole front door and scrubs those headers before
	// forwarding; in LAN mode the panel is reachable directly and the
	// headers are attacker-controlled -- a client would cycle the
	// value per request to defeat the IP-keyed login rate limiter.
	// Gate the middleware on PanelMode and let h.clientIP() fall back
	// to r.RemoteAddr (the actual socket peer) in LAN mode.
	if cfg.PanelMode == "behind_caddy" {
		r.Use(middleware.RealIP)
	}
	r.Use(middleware.Recoverer)
	r.Use(h.SecurityHeaders)

	r.Get("/healthz", api.Healthz)

	r.Route("/api", func(r chi.Router) {
		r.Post("/auth/login", h.Login)
		r.Get("/healthz", api.Healthz)

		// Phase 2FA: public endpoints that complete a password-verified
		// login by consuming a pending challenge. They never issue a
		// session without a valid challenge_id, so they're safe outside
		// the Authenticate middleware.
		r.Post("/auth/totp/verify", h.TOTPVerify)
		r.Post("/auth/totp/recovery", h.TOTPRecovery)

		// OIDC SSO public endpoints. /available is the cheap
		// {enabled: bool} probe the Login page uses to decide
		// whether to render the SSO button. /login 404s when the
		// feature is disabled so the route is invisible by
		// default; /callback validates the IdP-issued state before
		// trusting anything and only mints a session after a
		// verified ID token.
		r.Get("/auth/oidc/available", h.OIDCAvailable)
		r.Get("/auth/oidc/login", h.OIDCLogin)
		r.Get("/auth/oidc/callback", h.OIDCCallback)

		// ForwardAuth sub-request from Caddy. Public on purpose: the
		// handler exists precisely to tell Caddy whether the
		// incoming cookie is valid. Responds 200 + X-Auth-* on
		// success, 302 to /login on failure.
		r.Get("/auth/forward", h.ForwardAuth)

		// SafeRedirect canonicalises a post-login ?rd=<url> through
		// the same allowlist the OIDC callback uses. Public so the
		// Login page can call it right after password/TOTP login.
		r.Get("/auth/safe-redirect", h.SafeRedirect)

		r.Group(func(r chi.Router) {
			r.Use(h.Authenticate)

			r.Post("/auth/logout", h.Logout)
			r.Get("/auth/me", h.Me)

			// Phase 2FA: enrollment + lifecycle management endpoints.
			r.Post("/auth/totp/setup", h.TOTPSetup)
			r.Post("/auth/totp/activate", h.TOTPActivate)
			r.Post("/auth/totp/disable", h.TOTPDisable)
			r.Get("/auth/totp/status", h.TOTPStatus)
			r.Post("/auth/totp/recovery/regenerate", h.TOTPRegenerateRecovery)

			// OIDC admin plane: status + config + connectivity test.
			// Distinct from the public /oidc/{login,callback} pair
			// (those stay outside the authed group).
			r.Get("/auth/oidc/status", h.OIDCStatus)
			r.Put("/auth/oidc/config", h.OIDCConfigPut)
			r.Post("/auth/oidc/test", h.OIDCTest)
			r.Get("/caddy/status", h.CaddyStatus)

			r.Get("/hosts", h.ListHosts)
			r.Post("/hosts", h.CreateHost)
			r.Get("/hosts/{id}", h.GetHost)
			r.Put("/hosts/{id}", h.UpdateHost)
			r.Delete("/hosts/{id}", h.DeleteHost)
			r.Post("/hosts/{id}/toggle", h.ToggleHost)

			r.Get("/hosts/{host_id}/rules", h.ListRules)
			r.Post("/hosts/{host_id}/rules", h.CreateRule)
			r.Post("/hosts/{host_id}/rules/reorder", h.ReorderRules)
			r.Get("/hosts/{host_id}/rules/{rule_id}", h.GetRule)
			r.Put("/hosts/{host_id}/rules/{rule_id}", h.UpdateRule)
			r.Delete("/hosts/{host_id}/rules/{rule_id}", h.DeleteRule)
			r.Post("/hosts/{host_id}/rules/{rule_id}/toggle", h.ToggleRule)

			r.Get("/hosts/{host_id}/security", h.GetHostSecurity)
			r.Put("/hosts/{host_id}/security", h.UpdateHostSecurity)
			r.Post("/hosts/{host_id}/security/exclusions", h.CreateExclusion)
			r.Put("/hosts/{host_id}/security/exclusions/{id}", h.UpdateExclusion)
			r.Delete("/hosts/{host_id}/security/exclusions/{id}", h.DeleteExclusion)
			r.Post("/hosts/{host_id}/security/exclusions/{id}/toggle", h.ToggleExclusion)
			r.Post("/hosts/{host_id}/security/custom-rules", h.CreateCustomRule)
			r.Put("/hosts/{host_id}/security/custom-rules/{id}", h.UpdateCustomRule)
			r.Delete("/hosts/{host_id}/security/custom-rules/{id}", h.DeleteCustomRule)
			r.Post("/hosts/{host_id}/security/custom-rules/{id}/toggle", h.ToggleCustomRule)

			r.Get("/security/overview", h.SecurityOverviewHandler)

			// v1.3.19: minimal security endpoints behind the
			// self-block banner. Full /security panel ships in
			// v1.3.20+ (decisions list, scenarios, country
			// blocking, audit log).
			r.Get("/security/check-self", h.CheckSelf)
			r.Post("/security/decisions/unban-ip", h.UnbanIP)
			r.Post("/security/whitelist", h.AddWhitelist)
			// v1.3.21 country-ban expansion: real enforcement of
			// scope=Country bans via panel-side expansion to
			// scope=Range decisions, which the upstream
			// caddy-crowdsec-bouncer plugin actually handles.
			// v1.3.31 made the expand endpoint async + path-based.
			r.Post("/security/countries/{cc}/expand", h.ExpandCountry)
			r.Get("/security/countries", h.ListCountryExpansions)
			r.Delete("/security/countries/{cc}", h.RevokeCountryBan)
			// v1.3.31 async-job polling endpoints. /jobs is
			// top-level to leave room for future job types
			// (audit retention, scenario re-installs, etc.).
			r.Get("/security/jobs", h.ListCountryJobs)
			r.Get("/security/jobs/{id}", h.GetCountryJob)
			// v1.3.23 read/write surface for SelfBlockBanner v2
			// + the v1.3.24 /security UI tabs.
			r.Get("/security/decisions", h.ListDecisions)
			r.Delete("/security/decisions/{id}", h.DeleteDecisionByID)
			r.Get("/security/whitelist", h.ListWhitelist)
			r.Delete("/security/whitelist/{id}", h.DeleteWhitelist)
			r.Get("/security/audit-log", h.AuditLog)
			r.Get("/security/dashboard-stats", h.DashboardStats)
			r.Get("/security/public-ip-self", h.PublicIPSelf)
			// v1.3.25 scenarios + AppSec tuning UI surface.
			// Read state from the /crowdsec-state mount (panel-
			// side) and the panel-managed sentinels.
			r.Get("/security/scenarios", h.ListScenarios)
			r.Patch("/security/scenarios/{name}", h.PatchScenario)
			r.Get("/security/appsec-tuning", h.GetAppSecTuning)
			r.Patch("/security/appsec-tuning", h.PatchAppSecTuning)
			// v1.3.27 drift detection: replaces the operator-trust
			// mark-applied model. Detector runs on a 60s ticker;
			// this endpoint serves the cached snapshot.
			r.Get("/security/drift", h.GetDrift)
			r.Get("/crs/rules", h.ListCRSRules)

			r.Get("/target-groups", h.ListTargetGroups)
			r.Post("/target-groups", h.CreateTargetGroup)
			r.Get("/target-groups/{id}", h.GetTargetGroup)
			r.Put("/target-groups/{id}", h.UpdateTargetGroup)
			r.Delete("/target-groups/{id}", h.DeleteTargetGroup)
			r.Post("/target-groups/{id}/targets", h.AddTarget)
			r.Put("/target-groups/{id}/targets/{target_id}", h.UpdateTarget)
			r.Delete("/target-groups/{id}/targets/{target_id}", h.DeleteTarget)
			r.Post("/target-groups/{id}/targets/{target_id}/toggle", h.ToggleTarget)
			r.Get("/targets/health", h.TargetsHealth)

			r.Get("/certs", h.ListCerts)
			r.Post("/certs/{id}/renew", h.RenewCert)

			// v1.1 Fase 2: manual cert uploads. {id} is host_id.
			r.Get("/manual-certs", h.ListManualCerts)
			r.Get("/manual-certs/{id}", h.GetManualCert)
			r.Post("/manual-certs/{id}", h.UploadManualCert)
			r.Delete("/manual-certs/{id}", h.DeleteManualCert)
			r.Get("/manual-certs/{id}/download", h.DownloadManualCert)

			// Logs + settings live under the same authed group.
			h.RouteLogsMux(r)
			r.Get("/settings", h.ListSettings)
			r.Put("/settings/{key}", h.UpdateSetting)

			// v1.3: DNS provider catalogue + encrypted credentials.
			// Credentials never leave the server; the GET endpoints
			// return only metadata + {enabled, configured} flags.
			r.Get("/dns-providers", h.ListDNSProviders)
			r.Get("/dns-providers/{name}", h.GetDNSProvider)
			r.Put("/dns-providers/{name}", h.UpdateDNSProvider)

			// Phase 5: notifications
			r.Get("/notifications/event-types", h.ListNotificationEventTypes)
			r.Get("/notifications/channels", h.ListNotificationChannels)
			r.Post("/notifications/channels", h.CreateNotificationChannel)
			r.Get("/notifications/channels/{id}", h.GetNotificationChannel)
			r.Put("/notifications/channels/{id}", h.UpdateNotificationChannel)
			r.Delete("/notifications/channels/{id}", h.DeleteNotificationChannel)
			r.Post("/notifications/channels/{id}/toggle", h.ToggleNotificationChannel)
			r.Post("/notifications/channels/{id}/test", h.TestNotificationChannel)

			r.Get("/notifications/rules", h.ListNotificationRules)
			r.Post("/notifications/rules", h.CreateNotificationRule)
			r.Get("/notifications/rules/{id}", h.GetNotificationRule)
			r.Put("/notifications/rules/{id}", h.UpdateNotificationRule)
			r.Delete("/notifications/rules/{id}", h.DeleteNotificationRule)
			r.Post("/notifications/rules/{id}/toggle", h.ToggleNotificationRule)

			r.Get("/notifications/deliveries", h.ListNotificationDeliveries)
			r.Get("/notifications/deliveries/{id}", h.GetNotificationDelivery)
			r.Post("/notifications/deliveries/{id}/retry", h.RetryNotificationDelivery)

			r.Get("/notifications/recent-alerts", h.RecentAlerts)

			// Phase 5: Web Push
			r.Get("/push/vapid-public-key", h.GetVAPIDPublicKey)
			r.Post("/push/subscribe", h.SubscribePush)
			r.Delete("/push/subscribe", h.UnsubscribePush)
			r.Get("/push/subscriptions", h.ListPushSubscriptions)

			// Phase 9a: backups + config export/import
			r.Get("/backups", h.ListBackups)
			r.Post("/backups", h.CreateBackup)
			r.Get("/backups/{id}", h.GetBackup)
			r.Delete("/backups/{id}", h.DeleteBackup)
			r.Get("/backups/{id}/download", h.DownloadBackup)
			r.Post("/backups/{id}/restore", h.RestoreBackup)
			r.Post("/backups/upload-and-restore", h.UploadAndRestore)

			r.Get("/config/export.yaml", h.ExportConfig)
			r.Post("/config/import/validate", h.ValidateImport)
			r.Post("/config/import/apply", h.ApplyImport)

			// Phase 6: dashboard
			r.Get("/dashboard/overview", h.DashboardOverview)
			r.Get("/dashboard/traffic", h.DashboardTraffic)
			r.Get("/dashboard/security", h.DashboardSecurity)
			r.Get("/dashboard/health", h.DashboardHealth)

			// Phase 9b: panel system diagnostics
			r.Get("/system/health", h.SystemHealth)

			// Phase 7: CrowdSec threat intel
			r.Get("/threats/status", h.ThreatsStatus)
			r.Get("/threats/decisions", h.ThreatsDecisions)
			r.Post("/threats/decisions", h.AddThreatDecision)
			r.Delete("/threats/decisions", h.DeleteThreatDecision)
			r.Get("/threats/stats", h.ThreatsStats)
			r.Get("/threats/scenarios", h.ThreatsScenarios)

			// v1.3.6: operator-triggered stale-creds reset. Verifies
			// stored machine creds against LAPI; purges on 401,
			// returns next-action instructions on success. Scoped
			// under /crowdsec/ (not /threats/) because it operates
			// on CrowdSec credentials, not threat decisions.
			r.Post("/crowdsec/regenerate-credentials", h.RegenerateCrowdSecCredentials)

			// GeoIP enrichment (DB-IP Lite, CC-BY)
			r.Get("/geoip/lookup", h.GeoLookup)
			r.Get("/geoip/status", h.GeoStatus)
			r.Post("/geoip/refresh", h.GeoRefresh)

			// AppSec (WAF inline): status + metrics + runtime mode flip.
			r.Get("/appsec/status", h.AppSecStatus)
			r.Get("/appsec/metrics", h.AppSecMetrics)
			r.Patch("/appsec/mode", h.AppSecPatchMode)
		})
	})

	r.Handle("/*", api.SPAHandler(static.FS()))

	return &http.Server{
		Addr:              cfg.Addr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// WriteTimeout: 20 minutes to give the country-expansion
		// path room. v1.3.22 chunks expansions of large countries
		// (BR has ~21k CIDRs in DB-IP Lite) into 500-alert batches;
		// at the empirical LAPI throughput of ~40 alerts/sec, a
		// full BR run takes ~9 minutes wall-clock. The previous
		// 30s ceiling cut the panel's response off mid-loop and
		// left the operator with no signal whether it succeeded.
		// 20 minutes is generous; v1.3.23 will revisit with an
		// async background-job path that returns 202 immediately.
		WriteTimeout: 20 * time.Minute,
		IdleTimeout:  120 * time.Second,
	}
}
