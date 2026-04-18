package notifications

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"time"
)

// RepoIface abstracts the DB side the worker needs, so tests can stub
// without pulling in database/sql.
type RepoIface interface {
	ActiveRulesFor(ctx context.Context, et EventType) ([]Rule, error)
	GetChannel(ctx context.Context, id int64, redact bool) (*Channel, error)
	InsertDelivery(ctx context.Context, d *Delivery) (int64, error)
	UpdateDelivery(ctx context.Context, d *Delivery) error
}

// Worker drains the emitter queue, matches rules, renders templates
// and dispatches to senders. Retries are sync (within the same
// goroutine) so one runaway channel cannot block another by itself --
// if a future operator defines many slow channels, consider spawning
// per-channel goroutines.
type Worker struct {
	Emitter   *Emitter
	Repo      RepoIface
	Senders   SenderRegistry
	Throttle  *Throttle
	RateLimit *RateLimiter

	MaxAttempts int
	BaseBackoff time.Duration
}

// NewWorker returns a worker with sensible retry defaults.
func NewWorker(em *Emitter, repo RepoIface, senders SenderRegistry) *Worker {
	return &Worker{
		Emitter:     em,
		Repo:        repo,
		Senders:     senders,
		Throttle:    NewThrottle(),
		RateLimit:   NewRateLimiter(),
		MaxAttempts: 3,
		BaseBackoff: 2 * time.Second,
	}
}

// Start returns a cancel function. The worker runs until the context is
// cancelled or the emitter channel is closed.
func (w *Worker) Start(ctx context.Context) context.CancelFunc {
	ctx, cancel := context.WithCancel(ctx)
	go w.loop(ctx)
	// also spawn a throttle sweeper so old keys are GC'd
	go w.throttleSweeper(ctx)
	return cancel
}

func (w *Worker) loop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.Emitter.Events():
			if !ok {
				return
			}
			w.dispatch(ctx, ev)
		}
	}
}

func (w *Worker) throttleSweeper(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			w.Throttle.Sweep(now.Add(-24 * time.Hour))
		}
	}
}

// dispatch matches the event against every enabled rule and creates one
// delivery per match. Rule/channel CRUD runs on the DB thread; if a
// rule was deleted between Emit and dispatch we simply skip it.
func (w *Worker) dispatch(ctx context.Context, ev Event) {
	rules, err := w.Repo.ActiveRulesFor(ctx, ev.Type)
	if err != nil {
		slog.Warn("notifications: list rules failed", "type", ev.Type, "error", err)
		return
	}
	evJSON, _ := json.Marshal(ev)
	now := time.Now().UTC()
	for _, ru := range rules {
		if !matchesFilters(ru, ev) {
			continue
		}
		if !w.Throttle.Allow(ru.ID, ev.Type, ev.HostID, ru.ThrottleWindowSeconds, now) {
			w.recordTerminal(ctx, ru, nil, ev, string(evJSON), "", StatusThrottled, "throttled by rule", 0)
			continue
		}
		ch, err := w.Repo.GetChannel(ctx, ru.ChannelID, false)
		if err != nil {
			slog.Warn("notifications: channel not found", "channel_id", ru.ChannelID, "error", err)
			continue
		}
		if !ch.Enabled {
			continue
		}
		rendered, rErr := Render(ch.Template, ch.Type, &ev)
		if rErr != nil {
			w.recordTerminal(ctx, ru, ch, ev, string(evJSON), rendered, StatusFailed, "template: "+rErr.Error(), 0)
			continue
		}
		if !w.RateLimit.Allow(ch.ID, ch.RateLimitPerMinute, now) {
			w.recordTerminal(ctx, ru, ch, ev, string(evJSON), rendered, StatusRateLimited, "channel rate limit", 0)
			continue
		}
		sender, ok := w.Senders[ch.Type]
		if !ok {
			w.recordTerminal(ctx, ru, ch, ev, string(evJSON), rendered, StatusFailed, "no sender registered for type "+string(ch.Type), 0)
			continue
		}
		// insert pending delivery, then attempt with retries
		d := &Delivery{
			RuleID:          &ru.ID,
			ChannelID:       &ch.ID,
			EventType:       ev.Type,
			EventPayload:    string(evJSON),
			RenderedPayload: rendered,
			Status:          StatusPending,
		}
		id, err := w.Repo.InsertDelivery(ctx, d)
		if err != nil {
			slog.Warn("notifications: insert delivery", "error", err)
			continue
		}
		d.ID = id
		w.attempt(ctx, sender, ch, &ev, d)
	}
}

// attempt runs up to MaxAttempts tries with exponential backoff. On
// success updates the delivery to sent; on terminal failure to failed.
func (w *Worker) attempt(ctx context.Context, sender Sender, ch *Channel, ev *Event, d *Delivery) {
	var lastErr error
	for d.Attempts < w.MaxAttempts {
		d.Attempts++
		err := sender.Send(ctx, ch, ev, d.RenderedPayload)
		if err == nil {
			now := time.Now().UTC()
			d.SentAt = &now
			d.Status = StatusSent
			d.ErrorMessage = ""
			if err := w.Repo.UpdateDelivery(ctx, d); err != nil {
				slog.Warn("notifications: update delivery (sent)", "id", d.ID, "error", err)
			}
			return
		}
		lastErr = err
		// last attempt? bail
		if d.Attempts >= w.MaxAttempts {
			break
		}
		// backoff = BaseBackoff * 2^(attempts-1) + jitter
		sleep := w.BaseBackoff * (1 << (d.Attempts - 1))
		jitter := time.Duration(rand.Int63n(int64(w.BaseBackoff)))
		select {
		case <-ctx.Done():
			return
		case <-time.After(sleep + jitter):
		}
	}
	d.Status = StatusFailed
	if lastErr != nil {
		d.ErrorMessage = lastErr.Error()
	}
	if err := w.Repo.UpdateDelivery(ctx, d); err != nil {
		slog.Warn("notifications: update delivery (failed)", "id", d.ID, "error", err)
	}
}

// recordTerminal inserts a delivery that skipped the sender path
// (throttled, rate-limited, or template error).
func (w *Worker) recordTerminal(ctx context.Context, ru Rule, ch *Channel, ev Event, evJSON, rendered string,
	status DeliveryStatus, reason string, attempts int) {
	d := &Delivery{
		RuleID:          &ru.ID,
		EventType:       ev.Type,
		EventPayload:    evJSON,
		RenderedPayload: rendered,
		Status:          status,
		ErrorMessage:    reason,
		Attempts:        attempts,
	}
	if ch != nil {
		d.ChannelID = &ch.ID
	}
	if _, err := w.Repo.InsertDelivery(ctx, d); err != nil {
		slog.Warn("notifications: insert terminal delivery", "error", err)
	}
}

// matchesFilters evaluates the per-rule host/severity filters in Go.
// Empty filter = wildcard.
func matchesFilters(ru Rule, ev Event) bool {
	if len(ru.FilterHostIDs) > 0 {
		ok := false
		for _, id := range ru.FilterHostIDs {
			if id == ev.HostID {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(ru.FilterSeverities) > 0 {
		ok := false
		for _, s := range ru.FilterSeverities {
			if s == ev.Severity {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// RetryDelivery re-sends one failed delivery synchronously, bypassing
// throttle + rate limit. Returns the updated delivery.
func (w *Worker) RetryDelivery(ctx context.Context, d *Delivery) (*Delivery, error) {
	if d.ChannelID == nil {
		return nil, fmt.Errorf("delivery has no channel (channel was deleted)")
	}
	ch, err := w.Repo.GetChannel(ctx, *d.ChannelID, false)
	if err != nil {
		return nil, fmt.Errorf("lookup channel: %w", err)
	}
	sender, ok := w.Senders[ch.Type]
	if !ok {
		return nil, fmt.Errorf("no sender registered for %s", ch.Type)
	}
	// Reconstruct event from event_payload so the sender has access to
	// the original data.
	var ev Event
	if d.EventPayload != "" {
		_ = json.Unmarshal([]byte(d.EventPayload), &ev)
	}
	// reset attempt counter for manual retry
	d.Attempts = 0
	d.Status = StatusPending
	d.ErrorMessage = ""
	if err := w.Repo.UpdateDelivery(ctx, d); err != nil {
		return nil, fmt.Errorf("update delivery: %w", err)
	}
	w.attempt(ctx, sender, ch, &ev, d)
	return d, nil
}

// SendTest fires a one-off synthetic event through a channel without
// touching any rule. Used by the "Test" button.
func (w *Worker) SendTest(ctx context.Context, ch *Channel) (rendered string, err error) {
	ev := Event{
		Type:       EvtConfigChange,
		Severity:   SeverityInfo,
		HostDomain: "test.example",
		Timestamp:  time.Now().UTC(),
		Message:    "test event from argos notifications",
		Data:       map[string]any{"test": true, "channel": ch.Name},
	}
	rendered, rErr := Render(ch.Template, ch.Type, &ev)
	if rErr != nil {
		return "", fmt.Errorf("render: %w", rErr)
	}
	sender, ok := w.Senders[ch.Type]
	if !ok {
		return rendered, fmt.Errorf("no sender registered for %s", ch.Type)
	}
	return rendered, sender.Send(ctx, ch, &ev, rendered)
}

// Compile-time guards.
var _ = sql.ErrNoRows
