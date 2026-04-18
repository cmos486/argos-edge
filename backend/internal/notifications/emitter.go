package notifications

import (
	"log/slog"
	"sync/atomic"
	"time"
)

// QueueCapacity bounds the event queue. At capacity, Emit drops the
// event (with WARN log) so a runaway producer cannot block the caller.
const QueueCapacity = 1000

// Emitter is the publish side of the in-process event bus. It is safe
// for concurrent use by any number of goroutines. The worker owns the
// read side.
type Emitter struct {
	ch      chan Event
	dropped uint64
}

// NewEmitter returns an emitter with a buffered queue. Callers should
// pass this to subsystems (audit recorder, ingestor, cron jobs) that
// need to publish notifications.
func NewEmitter() *Emitter {
	return &Emitter{ch: make(chan Event, QueueCapacity)}
}

// Emit publishes an event without blocking. Drops + logs if the queue
// is full; the worker is expected to drain faster than real-world
// event rates on a homelab.
func (e *Emitter) Emit(ev Event) {
	if e == nil {
		return
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	select {
	case e.ch <- ev:
	default:
		n := atomic.AddUint64(&e.dropped, 1)
		slog.Warn("notifications: event queue full, dropping",
			"type", ev.Type, "dropped_total", n)
	}
}

// Events returns the receive side. Used by the worker.
func (e *Emitter) Events() <-chan Event {
	return e.ch
}

// Dropped returns the count of events lost to backpressure since
// startup. Exposed for /api diagnostics or a future dashboard widget.
func (e *Emitter) Dropped() uint64 {
	return atomic.LoadUint64(&e.dropped)
}

// Close drains and closes the channel. Called at shutdown after the
// worker has stopped so pending events are not lost mid-send.
func (e *Emitter) Close() {
	close(e.ch)
}

// EmitAudit is the adapter logs.Recorder calls. Maps audit actions to
// EvtConfigChange / EvtLoginFailed / (dropped for login+logout).
func (e *Emitter) EmitAudit(userID int64, action, resourceType string, resourceID int64, diff any) {
	if e == nil {
		return
	}
	switch action {
	case "login", "logout":
		return // noisy; not a config change
	case "failed_login":
		e.Emit(Event{
			Type:     EvtLoginFailed,
			Severity: SeverityWarning,
			Message:  "failed login attempt",
			Data: map[string]any{
				"user_id": userID,
				"diff":    diff,
			},
		})
		return
	}
	// Keep create/update/delete/toggle/reorder as config_change. Other
	// verbs would be silently ignored; audited actions stay audited
	// even if no notification fires.
	switch action {
	case "create", "update", "delete", "toggle", "reorder":
		e.Emit(Event{
			Type:     EvtConfigChange,
			Severity: SeverityInfo,
			Message:  action + " " + resourceType,
			Data: map[string]any{
				"user_id":       userID,
				"action":        action,
				"resource_type": resourceType,
				"resource_id":   resourceID,
				"diff":          diff,
			},
		})
	}
}
