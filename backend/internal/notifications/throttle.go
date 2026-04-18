package notifications

import (
	"sync"
	"time"
)

// Throttle dedups repeated events per-rule within a time window. Keyed
// by (rule_id, event_type, host_id). Pure in-memory: restarts reset
// the window, which is fine for the intended "avoid alert storm"
// semantic.
type Throttle struct {
	mu   sync.Mutex
	seen map[throttleKey]time.Time
}

type throttleKey struct {
	RuleID    int64
	EventType EventType
	HostID    int64
}

// NewThrottle returns an empty throttle tracker.
func NewThrottle() *Throttle {
	return &Throttle{seen: make(map[throttleKey]time.Time)}
}

// Allow reports whether a new delivery for (rule, event, host) should
// proceed given the rule's throttle window. Updates the last-seen time
// only when allowing (so a throttled event does not reset the window).
//
// windowSeconds <= 0 disables throttling; Allow always returns true.
func (t *Throttle) Allow(ruleID int64, et EventType, hostID int64, windowSeconds int, now time.Time) bool {
	if windowSeconds <= 0 {
		return true
	}
	key := throttleKey{RuleID: ruleID, EventType: et, HostID: hostID}
	t.mu.Lock()
	defer t.mu.Unlock()
	last, ok := t.seen[key]
	if ok && now.Sub(last) < time.Duration(windowSeconds)*time.Second {
		return false
	}
	t.seen[key] = now
	return true
}

// Sweep removes entries older than cutoff. Called periodically so the
// map does not grow unbounded with host_id churn.
func (t *Throttle) Sweep(cutoff time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, v := range t.seen {
		if v.Before(cutoff) {
			delete(t.seen, k)
		}
	}
}
