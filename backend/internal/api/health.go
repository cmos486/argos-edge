// Package api contains HTTP handlers for the panel.
package api

import "net/http"

// Healthz is a liveness probe. It deliberately does not touch the database
// or Caddy so that a degraded dependency does not mark the panel itself
// unhealthy; compose/Kubernetes readiness belongs to a separate endpoint
// added later.
func Healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
