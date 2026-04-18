// Package server wires the HTTP router.
package server

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/cmos486/argos-edge/backend/internal/api"
	"github.com/cmos486/argos-edge/backend/internal/caddy"
	"github.com/cmos486/argos-edge/backend/internal/reconciler"
	"github.com/cmos486/argos-edge/backend/static"
)

// Config bundles runtime dependencies needed by the HTTP layer.
type Config struct {
	Addr         string
	DB           *sql.DB
	Caddy        *caddy.Client
	Reconciler   *reconciler.Reconciler
	CookieSecure bool
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
		CookieSecure: cfg.CookieSecure,
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
