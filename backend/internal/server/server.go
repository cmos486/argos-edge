// Package server wires the HTTP router.
package server

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/cmos486/argos-edge/backend/internal/api"
	"github.com/cmos486/argos-edge/backend/internal/backup"
	"github.com/cmos486/argos-edge/backend/internal/caddy"
	"github.com/cmos486/argos-edge/backend/internal/dashboard"
	"github.com/cmos486/argos-edge/backend/internal/logs"
	"github.com/cmos486/argos-edge/backend/internal/notifications"
	"github.com/cmos486/argos-edge/backend/internal/reconciler"
	"github.com/cmos486/argos-edge/backend/static"
)

// Config bundles runtime dependencies needed by the HTTP layer.
type Config struct {
	Addr         string
	DB           *sql.DB
	Caddy        *caddy.Client
	Reconciler   *reconciler.Reconciler
	Audit        *logs.Recorder
	CaddyTLSDial string
	CookieSecure bool
	NotifRepo    *notifications.NotifRepo
	NotifWorker  *notifications.Worker
	NotifEmitter *notifications.Emitter
	VAPIDKeys    *notifications.VAPIDKeys
	BackupMgr    *backup.Manager
	ArgosVersion string
	DashQueries  *dashboard.Queries
	DashCache    *dashboard.Cache
	StartedAt    time.Time
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
		DB:           cfg.DB,
		Caddy:        cfg.Caddy,
		Reconciler:   cfg.Reconciler,
		Audit:        cfg.Audit,
		CaddyTLSDial: cfg.CaddyTLSDial,
		CookieSecure: cfg.CookieSecure,
		NotifRepo:    cfg.NotifRepo,
		NotifWorker:  cfg.NotifWorker,
		NotifEmitter: cfg.NotifEmitter,
		VAPIDKeys:    cfg.VAPIDKeys,
		BackupMgr:    cfg.BackupMgr,
		ArgosVersion: cfg.ArgosVersion,
		DashQueries:  cfg.DashQueries,
		DashCache:    cfg.DashCache,
		StartedAt:    cfg.StartedAt,
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)

	r.Get("/healthz", api.Healthz)

	r.Route("/api", func(r chi.Router) {
		r.Post("/auth/login", h.Login)
		r.Get("/healthz", api.Healthz)

		r.Group(func(r chi.Router) {
			r.Use(h.Authenticate)

			r.Post("/auth/logout", h.Logout)
			r.Get("/auth/me", h.Me)
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

			r.Get("/certs", h.ListCerts)

			// Logs + settings live under the same authed group.
			h.RouteLogsMux(r)
			r.Get("/settings", h.ListSettings)
			r.Put("/settings/{key}", h.UpdateSetting)

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
		})
	})

	r.Handle("/*", api.SPAHandler(static.FS()))

	return &http.Server{
		Addr:              cfg.Addr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}
