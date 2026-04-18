package logs

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/models"
)

// Recorder captures audit events through the same batching writer the
// file tailers use. nil-safe: Record methods no-op when the recorder
// was not wired, so unit tests and phase-0 callers keep working.
type Recorder struct {
	ing *Ingestor
}

// NewRecorder returns a recorder that enqueues entries on ing.
func NewRecorder(ing *Ingestor) *Recorder {
	return &Recorder{ing: ing}
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
}
