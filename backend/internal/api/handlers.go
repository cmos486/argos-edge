package api

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/appsec"
	"github.com/cmos486/argos-edge/backend/internal/backup"
	"github.com/cmos486/argos-edge/backend/internal/caddy"
	"github.com/cmos486/argos-edge/backend/internal/certs"
	"github.com/cmos486/argos-edge/backend/internal/crowdsec"
	"github.com/cmos486/argos-edge/backend/internal/crypto"
	"github.com/cmos486/argos-edge/backend/internal/dashboard"
	"github.com/cmos486/argos-edge/backend/internal/geoip"
	"github.com/cmos486/argos-edge/backend/internal/hardening"
	"github.com/cmos486/argos-edge/backend/internal/logs"
	"github.com/cmos486/argos-edge/backend/internal/notifications"
	"github.com/cmos486/argos-edge/backend/internal/oidc"
	"github.com/cmos486/argos-edge/backend/internal/reconciler"
	"github.com/cmos486/argos-edge/backend/internal/security/country"
	"github.com/cmos486/argos-edge/backend/internal/totp"
)

// Handlers groups dependency-bearing handlers. Standalone handlers that
// touch nothing (e.g. Healthz) stay as package-level functions.
type Handlers struct {
	DB           *sql.DB
	Caddy        *caddy.Client
	Reconciler   *reconciler.Reconciler
	Audit        *logs.Recorder
	CaddyTLSDial string
	CookieSecure bool
	PanelMode    string
	PanelDomain  string

	// Phase 5 notifications wiring. All optional; nil -> 503s.
	NotifRepo    *notifications.NotifRepo
	NotifWorker  *notifications.Worker
	NotifEmitter *notifications.Emitter
	VAPIDKeys    *notifications.VAPIDKeys

	// Phase 9a backup + config IO wiring. Optional.
	BackupMgr    *backup.Manager
	ArgosVersion string

	// Phase 6 dashboard wiring.
	DashQueries *dashboard.Queries
	DashCache   *dashboard.Cache
	StartedAt   time.Time

	// Phase 9b hardening wiring.
	Timeouts *hardening.TimeoutCache
	LoginRL  *hardening.LoginRateLimiter

	// Phase 7 crowdsec wiring.
	CrowdSec        *crowdsec.Client
	CrowdSecMonitor *crowdsec.Monitor

	// GeoIP enrichment wiring.
	GeoDB            *geoip.DB
	GeoCache         *geoip.Cache
	GeoDownloader    *geoip.Downloader
	GeoNextRefreshAt func() time.Time

	// Phase 2FA: cipher (reused master key) + pending-challenge store.
	// Both nil-safe; the /totp endpoints 503 when unwired.
	Cipher    *crypto.Cipher
	TOTPStore *totp.ChallengeStore

	// v1.1 Fase 2: manual cert file-system store. Writes operator-
	// uploaded certs to the caddy_manual_certs shared volume.
	ManualCertStore *certs.Store

	// AppSec feature wiring. Nil-safe; /status degrades to mode-only
	// and /metrics 503s when the provider is unwired (e.g. tests).
	AppSecStatusReader *appsec.StatusReader
	AppSecProvider     *appsec.Provider

	// OIDC SSO wiring. Store is the in-memory pending-login state;
	// ProviderCache memoises discovery across requests. Both must
	// be non-nil for the public /oidc/* endpoints to work -- if the
	// operator leaves oidc.enabled=false the routes 404 regardless.
	OIDCStore         *oidc.PendingStore
	OIDCProviderCache *OIDCProviderCache

	// ForwardAuth per-host session cache. 30s TTL; Logout evicts
	// eagerly so protected hosts bounce immediately on sign-out.
	ForwardAuthCache *ForwardAuthCache

	// v1.3.7 target health cache. 30s TTL; Invalidate() is called
	// after every reconcile so a freshly-added target appears with
	// "unknown" on the next poll instead of stale data.
	TargetHealthCache *TargetHealthCache

	// v1.3.21 country-ban expander. Wraps the country MMDB +
	// crowdsec.Client to translate operator-issued country bans
	// into scope=Range LAPI decisions (the upstream
	// caddy-crowdsec-bouncer plugin does not handle scope=Country
	// in either stream or live mode).
	CountryExpander *country.Expander
}

// errorBody is the shape returned for any 4xx/5xx response from /api/*.
type errorBody struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("encode json response", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorBody{Error: msg})
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// jsonMarshalCompact is a tiny shim the SSE handler uses to frame
// entries without needing a bytes.Buffer round-trip.
func jsonMarshalCompact(v any) ([]byte, error) { return json.Marshal(v) }

// audit is the sugar every mutation handler uses to stamp an audit
// event. The user id is looked up from the session context when
// available (login records its own with explicit user id). Nil-safe
// when no recorder is wired.
func (h *Handlers) audit(r *http.Request, action, resourceType string, resourceID int64, diff any) {
	if h.Audit == nil {
		return
	}
	var uid int64
	if u, ok := userFromContext(r.Context()); ok {
		uid = u.ID
	}
	h.Audit.Record(r.Context(), uid, action, resourceType, resourceID, diff)
}
