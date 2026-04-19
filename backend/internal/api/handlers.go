package api

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/backup"
	"github.com/cmos486/argos-edge/backend/internal/caddy"
	"github.com/cmos486/argos-edge/backend/internal/crowdsec"
	"github.com/cmos486/argos-edge/backend/internal/dashboard"
	"github.com/cmos486/argos-edge/backend/internal/hardening"
	"github.com/cmos486/argos-edge/backend/internal/logs"
	"github.com/cmos486/argos-edge/backend/internal/notifications"
	"github.com/cmos486/argos-edge/backend/internal/reconciler"
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
	Timeouts  *hardening.TimeoutCache
	LoginRL   *hardening.LoginRateLimiter

	// Phase 7 crowdsec wiring.
	CrowdSec        *crowdsec.Client
	CrowdSecMonitor *crowdsec.Monitor
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

// jsonBytes and jsonMarshalCompact are tiny shims the SSE handler uses
// to frame entries without needing a bytes.Buffer round-trip.
func jsonBytes(v any) ([]byte, error)         { return json.Marshal(v) }
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
