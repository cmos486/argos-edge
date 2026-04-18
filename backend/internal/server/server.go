// Package server wires the HTTP router.
package server

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/cmos486/argos-edge/backend/internal/api"
)

// New builds the argos HTTP server. The returned *http.Server is not yet
// listening; the caller runs ListenAndServe and Shutdown.
//
// Phase 0 only serves /healthz. Login, session, and Caddy-status endpoints
// will be added as their backing pieces land.
func New(addr string) *http.Server {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)

	r.Get("/healthz", api.Healthz)

	return &http.Server{
		Addr:              addr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}
