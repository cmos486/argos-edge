package logs

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/models"
)

// NotifEmitter is the minimal interface the Recorder needs to publish
// notification events. Satisfied by *notifications.Emitter, defined
// here so logs does not import notifications (avoids a cycle: the
// notifications package already imports logs indirectly via its
// watcher's use of models).
type NotifEmitter interface {
	EmitAudit(userID int64, action, resourceType string, resourceID int64, diff any)
}

// Recorder captures audit events through the same batching writer the
// file tailers use. nil-safe: Record methods no-op when the recorder
// was not wired, so unit tests and phase-0 callers keep working.
type Recorder struct {
	ing    *Ingestor
	notify NotifEmitter
}

// NewRecorder returns a recorder that enqueues entries on ing.
func NewRecorder(ing *Ingestor) *Recorder {
	return &Recorder{ing: ing}
}

// SetNotifier wires an optional notification emitter. When set,
// Record also publishes a config_change / login_failed event per
// the phase-5 rules.
func (r *Recorder) SetNotifier(n NotifEmitter) {
	r.notify = n
}

// Record writes an audit entry. userID=0 is allowed for anonymous
// actions (e.g. failed login attempts before a session exists).
//
// diff is optional; when non-nil it is JSON-serialised into the raw
// column so the detail drawer can render the before/after payload.
func (r *Recorder) Record(
	ctx context.Context,
	userID int64,
	action string,
	resourceType string,
	resourceID int64,
	diff any,
) {
	if r == nil || r.ing == nil {
		return
	}
	var raw string
	payload := map[string]any{
		"user_id":       userID,
		"action":        action,
		"resource_type": resourceType,
		"resource_id":   resourceID,
	}
	if diff != nil {
		payload["diff"] = diff
	}
	if b, err := json.Marshal(payload); err == nil {
		raw = string(b)
	} else {
		slog.Warn("audit marshal failed", "error", err)
	}
	msg := action
	if resourceType != "" {
		msg = action + " " + resourceType
	}
	r.ing.Enqueue(models.LogEntry{
		Timestamp: time.Now().UTC(),
		Source:    models.LogAudit,
		Level:     "info",
		Message:   msg,
		Raw:       raw,
	})
	// Phase 5: publish notification events. login / logout are filtered
	// out of config_change to avoid saturation; failed_login maps to
	// its own event type so operators can alert on it distinctly.
	if r.notify != nil {
		r.notify.EmitAudit(userID, action, resourceType, resourceID, diff)
	}
}
