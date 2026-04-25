package api

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/appsec"
	"github.com/cmos486/argos-edge/backend/internal/crowdsec"
	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/reconciler"
)

// AppSecStatus GET /api/appsec/status
//
// Auth: inherits the authed group (same as every /api/* endpoint
// except login/totp). Safe to poll -- reads only the argos settings
// table and does one quick TCP probe of the AppSec listener.
func (h *Handlers) AppSecStatus(w http.ResponseWriter, r *http.Request) {
	if h.AppSecStatusReader == nil {
		// Degrade gracefully: return just what we can read from
		// settings. The UI already tolerates empty collections and
		// zero rules (Phase C spec: "mostrar error state en vez de
		// gráficos vacíos" applies to metrics, not status).
		st := appsec.Status{
			Mode: db.GetSettingValue(r.Context(), h.DB, "appsec.mode", "detect"),
		}
		writeJSON(w, http.StatusOK, st)
		return
	}
	writeJSON(w, http.StatusOK, h.AppSecStatusReader.Read(r.Context()))
}

// AppSecMetrics GET /api/appsec/metrics?window=24h
//
// Windows accepted: 1h, 6h, 12h, 24h (default). Anything else is
// clamped to 24h so the chart's bucket math stays sane.
func (h *Handlers) AppSecMetrics(w http.ResponseWriter, r *http.Request) {
	if h.AppSecProvider == nil {
		writeError(w, http.StatusServiceUnavailable, "appsec provider not wired")
		return
	}
	window := parseAppSecWindow(r.URL.Query().Get("window"))
	mode := db.GetSettingValue(r.Context(), h.DB, "appsec.mode", "detect")
	// v1.3.12: provide the metrics provider with the prior mode +
	// the timestamp of the last swap so historical alerts get
	// attributed to the mode that was actually active when they
	// fired -- not the mode the operator happens to have set right
	// now.
	prevMode := db.GetSettingValue(r.Context(), h.DB, "appsec.previous_mode", "")
	lastChangeAt := db.GetSettingValue(r.Context(), h.DB, "appsec.last_mode_change_at", "")
	m, err := h.AppSecProvider.Metrics(r.Context(), window, mode, prevMode, lastChangeAt)
	if err != nil {
		// v1.3.4: partial response instead of 502 when the problem
		// is "metrics require machine credentials and we only have
		// bouncer creds". The AppSec endpoint can be perfectly
		// reachable in that configuration; we just can't pull the
		// alert history. UI switches on `degraded.code` to render
		// an inline banner instead of failing the whole page.
		if errors.Is(err, crowdsec.ErrNotConfigured) {
			writeJSON(w, http.StatusOK, appsec.Metrics{
				Window: window.String(),
				Mode:   mode,
				Degraded: &appsec.DegradedReason{
					Code:    "machine_credentials_missing",
					Message: "AppSec metrics require CrowdSec machine credentials (the bouncer key alone is read-only, metrics need /v1/alerts which requires a machine JWT). Configure them in Settings → CrowdSec → Machine credentials; the AppSec endpoint itself remains reachable.",
				},
			})
			return
		}
		writeError(w, http.StatusBadGateway, "metrics from lapi: "+err.Error())
		return
	}
	// Enrich top_ips with GeoIP (when the subsystem is wired). Same
	// helper the dashboard / threats endpoints use. Private IPs
	// short-circuit inside enrichIP.
	for i := range m.TopIPs {
		ip := m.TopIPs[i].IP
		if net.ParseIP(ip) == nil {
			continue
		}
		if res := h.enrichIP(ip); res != nil {
			m.TopIPs[i].Geo = &appsec.GeoEnrichment{
				CountryCode: res.CountryCode,
				CountryName: res.CountryName,
				ASN:         res.ASN,
				ASNOrg:      res.ASNOrg,
				IsPrivate:   res.IsPrivate,
			}
		}
	}
	writeJSON(w, http.StatusOK, m)
}

type appsecPatchRequest struct {
	Mode string `json:"mode"`
}

// AppSecPatchMode PATCH /api/appsec/mode {mode}
//
// Pipeline (fail-fast):
//  1. Parse + validate the mode string.
//  2. Stash the previous mode for the audit diff + rollback path.
//  3. Call reconciler.SetAppSecMode which handles the DB write +
//     Caddy /load push + automatic rollback on reconcile failure.
//  4. On success: update last_mode_change_{at,by}, invalidate the
//     metrics cache, emit audit, return new mode.
func (h *Handlers) AppSecPatchMode(w http.ResponseWriter, r *http.Request) {
	if h.Reconciler == nil {
		writeError(w, http.StatusServiceUnavailable, "reconciler not wired")
		return
	}
	var req appsecPatchRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}
	req.Mode = strings.TrimSpace(strings.ToLower(req.Mode))
	if !reconciler.ValidAppSecMode(req.Mode) {
		writeError(w, http.StatusBadRequest, "mode must be one of: detect, block, disabled")
		return
	}

	prev, err := h.Reconciler.SetAppSecMode(r.Context(), req.Mode)
	if err != nil {
		// SetAppSecMode already rolled back the DB to prev on a
		// reconcile failure. We surface a 500 with the underlying
		// error so the operator sees WHY Caddy rejected the config.
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Record who + when. Both are best-effort -- a failure here
	// should not mask the successful mode flip.
	now := time.Now().UTC().Format(time.RFC3339)
	var username string
	if u, ok := userFromContext(r.Context()); ok {
		username = u.Username
	}
	_ = db.UpsertSetting(r.Context(), h.DB, "appsec.last_mode_change_at", now)
	_ = db.UpsertSetting(r.Context(), h.DB, "appsec.last_mode_change_by", username)
	// v1.3.12: persist the prior mode so the metrics provider can
	// attribute alerts that fired BEFORE the swap to the right
	// outcome. Without this, flipping detect -> block would
	// reclassify every alert in the 24h window as blocked even
	// though those requests actually flowed through detect-mode.
	_ = db.UpsertSetting(r.Context(), h.DB, "appsec.previous_mode", prev)

	// A mode flip changes how recent alerts should be attributed
	// (blocked vs logged). Drop the 30s cache so the next metrics
	// fetch reflects reality.
	if h.AppSecProvider != nil {
		h.AppSecProvider.Invalidate()
	}

	h.audit(r, "appsec_mode_changed", "appsec", 0, map[string]any{
		"from":      prev,
		"to":        req.Mode,
		"username":  username,
		"remote_ip": h.clientIP(r),
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"mode":          req.Mode,
		"previous":      prev,
		"reconciled_at": now,
	})
}

// parseAppSecWindow clamps the ?window= parameter to the small set
// the metrics bucketer understands. Unknown / empty values fall back
// to 24h so the dashboard never crashes on a malformed link.
func parseAppSecWindow(raw string) time.Duration {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1h":
		return 1 * time.Hour
	case "6h":
		return 6 * time.Hour
	case "12h":
		return 12 * time.Hour
	default:
		return 24 * time.Hour
	}
}
