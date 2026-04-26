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
	"github.com/cmos486/argos-edge/backend/internal/security/publicip"
	"github.com/cmos486/argos-edge/backend/internal/security/scenarios"
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

	// v1.3.31 async country expansion. Wraps the same Expander
	// in a single-worker goroutine + DB-backed progress shadow
	// so the panel UI can submit + poll instead of blocking on
	// the HTTP request for tens of seconds.
	CountryJobs *country.JobRunner

	// v1.3.23 public-IP detector. SelfBlockBanner v2 reads from
	// here so an operator hitting the panel via LAN can still see
	// when their public WAN IP is banned in CrowdSec. Nil-safe.
	PublicIP *publicip.Detector

	// v1.3.25 scenarios reader. Reads installed-scenario state
	// from the read-only /crowdsec-state mount. Nil-safe: the
	// handler default-constructs scenarios.New() at the default
	// mount path when this is unset; tests inject a fixture path.
	ScenariosReader *scenarios.Reader
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
//
// v1.3.23: source_ip + xff_chain are folded into the diff payload
// so the audit log surface (Activity tab in v1.3.24) can render
// "admin did X from Y at Z" without joining a parallel table. The
// diff arg keeps the existing call-site shape (additive). Internal
// keys "_source_ip" / "_xff_chain" are reserved -- callers should
// not collide.
func (h *Handlers) audit(r *http.Request, action, resourceType string, resourceID int64, diff any) {
	if h.Audit == nil {
		return
	}
	var uid int64
	if u, ok := userFromContext(r.Context()); ok {
		uid = u.ID
	}

	enriched := enrichAuditDiff(diff, h.clientIP(r), r.Header.Get("X-Forwarded-For"))
	h.Audit.Record(r.Context(), uid, action, resourceType, resourceID, enriched)
}

// enrichAuditDiff merges the request-level IP context into the
// caller's diff. When diff is a map[string]any we merge in place;
// otherwise we wrap into a new map under "diff" so non-map shapes
// don't get silently dropped. Empty IP / XFF values are omitted to
// keep the JSON small for tests / dev panels with no proxy chain.
func enrichAuditDiff(diff any, sourceIP, xff string) map[string]any {
	out := map[string]any{}
	if m, ok := diff.(map[string]any); ok {
		for k, v := range m {
			out[k] = v
		}
	} else if diff != nil {
		out["diff"] = diff
	}
	if sourceIP != "" {
		out["_source_ip"] = sourceIP
	}
	if xff != "" {
		out["_xff_chain"] = xff
	}
	return out
}
