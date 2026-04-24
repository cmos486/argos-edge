package appsec

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/notifications"
)

// Health probes the CrowdSec AppSec endpoint periodically so the
// panel can surface "your WAF-inline layer went dark" as a first
// class notification rather than having the operator discover it
// from Caddy's error log. Paired with the generator's default
// appsec_fail_open=true in v1.3.2: fail-open keeps traffic flowing,
// this cron tells the operator their WAF protection is gone.
//
// Transition model: a simple up/down memory flag. Fires an
// EvtAppSecUnavailable notification on the reachable -> unreachable
// edge only. Subsequent consecutive failures are silent (no spam);
// a successful probe resets the edge so the NEXT outage fires again.
// No "recovered" event: the intended UX is "operator gets paged
// when something broke", not a stream of status updates.
//
// Probe semantics: an HTTP GET against appsec_url with a short
// timeout. AppSec expects POST for real traffic and replies 405 to
// GET, which we count as "reachable" (the sidecar is up, we're
// just asking the wrong verb). Connection refused / timeout / 5xx
// all count as unreachable.
type Health struct {
	DB       *sql.DB
	Emitter  *notifications.Emitter
	Interval time.Duration // default 5m when zero
	Client   *http.Client  // default 5s timeout when nil

	mu       sync.Mutex
	lastUp   bool // last probe result; seeds from true so the first
	// outage triggers on the first failed probe
	lastEmit time.Time // for suppressing edge-flutter (< 1 min)
}

// Start launches the health cron. Returns a cancel func. The first
// probe runs 30 seconds after start -- enough for Caddy to reconcile
// but short enough that a bad configuration surfaces during the same
// operator session, not tomorrow.
func (h *Health) Start(ctx context.Context) context.CancelFunc {
	if h.Interval <= 0 {
		h.Interval = 5 * time.Minute
	}
	if h.Client == nil {
		h.Client = &http.Client{Timeout: 5 * time.Second}
	}
	h.lastUp = true // optimistic seed; avoids firing on panel boot when probe races with caddy

	ctx, cancel := context.WithCancel(ctx)
	go h.loop(ctx)
	return cancel
}

func (h *Health) loop(ctx context.Context) {
	first := time.NewTimer(30 * time.Second)
	defer first.Stop()
	select {
	case <-ctx.Done():
		return
	case <-first.C:
		h.probe(ctx)
	}
	t := time.NewTicker(h.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.probe(ctx)
		}
	}
}

// probe reads the current appsec.mode + derives the URL, then hits
// it. When mode=disabled the appsec layer is intentionally off and
// we skip the probe entirely -- otherwise we'd alert on an
// intentionally-quiet endpoint every 5 minutes.
func (h *Health) probe(ctx context.Context) {
	mode := db.GetSettingValue(ctx, h.DB, "appsec.mode", "detect")
	if mode == "disabled" || mode == "" {
		return
	}
	url := appsecURLForMode(mode)
	if url == "" {
		return
	}

	probeErr := h.ping(ctx, url)

	h.mu.Lock()
	prevUp := h.lastUp
	now := time.Now().UTC()
	// Edge detection: only fire on reachable -> unreachable. Rapid
	// flaps (up/down/up within a minute) get suppressed via lastEmit.
	if probeErr != nil {
		if prevUp && now.Sub(h.lastEmit) > 60*time.Second {
			h.lastEmit = now
			h.lastUp = false
			h.mu.Unlock()
			h.emit(url, probeErr)
			return
		}
		h.lastUp = false
	} else {
		h.lastUp = true
	}
	h.mu.Unlock()
}

// ping is the actual HTTP probe. v1.3.4 fix: we now send the
// CrowdSec bouncer API key on the `X-Crowdsec-Appsec-Api-Key`
// header. Pre-v1.3.4 we sent no auth, which was visible in
// CrowdSec's logs as a stream of `missing API key` errors every
// five minutes from the panel's IP -- alarming but harmless, since
// the bouncer plugin's own AppSec calls (from the caddy container)
// do authenticate correctly.
//
// Status interpretation:
//
//   - 200 or 2xx / 3xx / 4xx OTHER than 404/401  -> healthy.
//   - 404  -> unhealthy (no AppSec collections installed).
//   - 401  -> the sidecar IS up (auth ran, rejected us), but our
//     probe's key is wrong. We report this as an operator-config
//     warning, not an outage: it suggests CROWDSEC_BOUNCER_API_KEY
//     drifted between the caddy and panel containers, or setup-
//     appsec.sh was re-run without syncing the key back. Returns
//     a distinct error so emit() can surface the nuance.
//   - 5xx  -> unhealthy.
//   - dial / timeout -> unhealthy (network level).
func (h *Health) ping(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if key := bouncerAPIKey(); key != "" {
		req.Header.Set("X-Crowdsec-Appsec-Api-Key", key)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("appsec endpoint returned 404: no collections configured on crowdsec")
	case resp.StatusCode == http.StatusUnauthorized:
		return fmt.Errorf("appsec endpoint returned 401: bouncer API key mismatch between panel and crowdsec (sidecar itself is up)")
	case resp.StatusCode >= 500:
		return fmt.Errorf("appsec endpoint returned %d", resp.StatusCode)
	}
	return nil
}

// bouncerAPIKey reads the same env var Caddy reads. Settings-based
// override (crowdsec.bouncer_api_key) is handled at the API layer
// and copied into the env var at boot; the env var is the canonical
// source for both caddy and panel auth. Empty means "no key set" --
// the probe then sends no header and CrowdSec will 401 us (the
// healthcheck is honest about that being a config issue).
func bouncerAPIKey() string {
	return os.Getenv("CROWDSEC_BOUNCER_API_KEY")
}

// emit sends the notification. Separated from probe so probe stays
// pure (no side-effects on the nil-emitter path that tests use).
func (h *Health) emit(url string, cause error) {
	if h.Emitter == nil {
		slog.Warn("appsec unavailable", "url", url, "error", cause.Error())
		return
	}
	failOpen := db.GetSettingValue(context.Background(), h.DB, "appsec.fail_open", "true") == "true"
	msg := fmt.Sprintf("appsec unreachable at %s", url)
	if failOpen {
		msg += "; requests pass through (fail-open)"
	} else {
		msg += "; requests will 500 (fail-closed)"
	}
	h.Emitter.Emit(notifications.Event{
		Type:     notifications.EvtAppSecUnavailable,
		Severity: notifications.SeverityWarning,
		Message:  msg,
		Data: map[string]any{
			"appsec_url": url,
			"error":      cause.Error(),
			"fail_open":  failOpen,
		},
	})
	slog.Warn("appsec unavailable: fired notification",
		"url", url, "fail_open", failOpen, "error", cause.Error())
}

// appsecURLForMode mirrors reconciler.AppSecURLForMode without the
// import cycle. Kept local to this package; if a third call site
// ever wants it, move to a shared package. The two URLs match the
// docker-compose contract: port 7422 for block, 7423 for detect.
func appsecURLForMode(mode string) string {
	switch mode {
	case "block":
		return "http://crowdsec:7422"
	case "detect":
		return "http://crowdsec:7423"
	}
	return ""
}
