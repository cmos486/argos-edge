package crowdsec

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/notifications"
)

// Monitor polls the LAPI on a tick. It emits three event types:
//   - threat_ip_banned: a new decision appeared since the last poll
//   - threat_intel_updated: summary of per-poll diff (added / removed)
//   - crowdsec_down: >=3 consecutive heartbeat failures
//
// The panel UI also reads ListDecisions directly; Monitor is the
// notifications side. Running both paths means the user sees ban
// notifications regardless of whether they have /threats open.
type Monitor struct {
	Client   *Client
	Emitter  *notifications.Emitter
	Interval time.Duration // defaults to 15s

	mu            sync.Mutex
	prevIDs       map[int64]Decision
	downStreak    int
	reportedDown  bool
	lastHeartbeat time.Time
}

// NewMonitor returns a ready-to-start monitor.
func NewMonitor(c *Client, em *notifications.Emitter) *Monitor {
	return &Monitor{
		Client:   c,
		Emitter:  em,
		Interval: 15 * time.Second,
		prevIDs:  make(map[int64]Decision),
	}
}

// Start launches the poll loop; returns a cancel func.
func (m *Monitor) Start(ctx context.Context) context.CancelFunc {
	ctx, cancel := context.WithCancel(ctx)
	go m.loop(ctx)
	return cancel
}

// LastHeartbeat is exposed for /api/threats/status.
func (m *Monitor) LastHeartbeat() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastHeartbeat
}

func (m *Monitor) loop(ctx context.Context) {
	if m.Interval <= 0 {
		m.Interval = 15 * time.Second
	}
	t := time.NewTicker(m.Interval)
	defer t.Stop()
	// initial tick immediately so the first render has fresh data
	m.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.tick(ctx)
		}
	}
}

func (m *Monitor) tick(ctx context.Context) {
	// 1. heartbeat
	_, hbErr := m.Client.Heartbeat(ctx)
	if hbErr != nil {
		m.mu.Lock()
		m.downStreak++
		streak := m.downStreak
		reported := m.reportedDown
		m.mu.Unlock()
		if streak >= 3 && !reported && m.Emitter != nil {
			m.Emitter.Emit(notifications.Event{
				Type:     notifications.EvtCrowdSecDown,
				Severity: notifications.SeverityError,
				Message:  "crowdsec LAPI unreachable",
				Data: map[string]any{
					"consecutive_failures": streak,
					"error":                hbErr.Error(),
				},
			})
			m.mu.Lock()
			m.reportedDown = true
			m.mu.Unlock()
		}
		return
	}
	// heartbeat ok -> clear streak, clear reported flag for next outage
	m.mu.Lock()
	m.downStreak = 0
	m.reportedDown = false
	m.lastHeartbeat = time.Now().UTC()
	m.mu.Unlock()

	// 2. decisions diff
	if m.Client.BouncerKey == "" {
		return // not configured; skip the diff path
	}
	list, err := m.Client.ListDecisions(ctx)
	if err != nil {
		slog.Debug("crowdsec monitor: list decisions", "error", err)
		return
	}
	curr := make(map[int64]Decision, len(list))
	for _, d := range list {
		curr[d.ID] = d
	}
	m.mu.Lock()
	prev := m.prevIDs
	m.prevIDs = curr
	m.mu.Unlock()

	if len(prev) == 0 {
		// first poll: don't fire "new ban" for every pre-existing row
		return
	}

	added := 0
	removed := 0
	for id, d := range curr {
		if _, ok := prev[id]; ok {
			continue
		}
		added++
		if m.Emitter != nil {
			m.Emitter.Emit(notifications.Event{
				Type:     notifications.EvtThreatIPBanned,
				Severity: notifications.SeverityInfo,
				Message:  "crowdsec banned " + d.Value,
				Data: map[string]any{
					"ip":       d.Value,
					"scope":    d.Scope,
					"scenario": d.Scenario,
					"duration": d.Duration,
					"origin":   d.Origin,
				},
			})
		}
	}
	for id := range prev {
		if _, ok := curr[id]; !ok {
			removed++
		}
	}
	if (added > 0 || removed > 0) && m.Emitter != nil {
		m.Emitter.Emit(notifications.Event{
			Type:     notifications.EvtThreatIntelUpdated,
			Severity: notifications.SeverityInfo,
			Message:  "threat intel updated",
			Data: map[string]any{
				"added_count":   added,
				"removed_count": removed,
				"total":         len(curr),
			},
		})
	}
}
