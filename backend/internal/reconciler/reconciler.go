// Package reconciler pushes the panel's desired Caddy config to the Admin
// API's /load endpoint. Every host mutation calls Apply; startup calls
// ApplyFromDBWithBackoff so a cold caddy container is tolerated.
package reconciler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/caddycfg"
	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/models"
)

// Reconciler talks to Caddy's Admin API.
type Reconciler struct {
	db        *sql.DB
	adminBase string
	client    *http.Client
}

// New returns a Reconciler wired to the given DB handle and Caddy admin
// base URL, e.g. http://caddy:2019.
func New(d *sql.DB, adminBase string) *Reconciler {
	return &Reconciler{
		db:        d,
		adminBase: adminBase,
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

// ApplyFromDB reads the current enabled host set from the DB and pushes
// the derived config to Caddy.
func (r *Reconciler) ApplyFromDB(ctx context.Context) error {
	hosts, err := db.ListEnabledHosts(ctx, r.db)
	if err != nil {
		return fmt.Errorf("list enabled hosts: %w", err)
	}
	return r.Apply(ctx, hosts)
}

// Apply pushes the config derived from the explicit host set. Mutation
// handlers use this variant with the just-written state to avoid a
// read-after-write race.
func (r *Reconciler) Apply(ctx context.Context, hosts []models.Host) error {
	cfg, err := caddycfg.HostsToCaddyConfig(hosts)
	if err != nil {
		return fmt.Errorf("build caddy config: %w", err)
	}
	return r.load(ctx, cfg)
}

// ApplyFromDBWithBackoff retries ApplyFromDB up to 30 seconds with
// exponential backoff (500ms, 1s, 2s, 4s, 8s, 8s...). Used at startup
// where caddy may be a few seconds behind the panel.
func (r *Reconciler) ApplyFromDBWithBackoff(ctx context.Context) error {
	delay := 500 * time.Millisecond
	deadline := time.Now().Add(30 * time.Second)

	var lastErr error
	for attempt := 0; ; attempt++ {
		if err := r.ApplyFromDB(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if time.Now().Add(delay).After(deadline) {
			break
		}
		slog.Warn("reconcile failed, retrying",
			"attempt", attempt, "error", lastErr, "delay", delay)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay *= 2
		if delay > 8*time.Second {
			delay = 8 * time.Second
		}
	}
	return fmt.Errorf("reconcile exhausted 30s backoff: %w", lastErr)
}

func (r *Reconciler) load(ctx context.Context, cfg json.RawMessage) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		r.adminBase+"/load", bytes.NewReader(cfg))
	if err != nil {
		return fmt.Errorf("build /load request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("POST /load: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("caddy /load returned %d: %s", resp.StatusCode, string(body))
	}
	return nil
}
