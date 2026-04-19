// Package hardening hosts the phase-9b runtime knobs: cached session
// timeouts read from the settings table, and the login rate-limiter.
// Kept separate from internal/session to avoid a cycle between
// session (stateless) and db/settings (which the api package uses).
package hardening

import (
	"context"
	"database/sql"
	"strconv"
	"sync"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db"
	"github.com/cmos486/argos-edge/backend/internal/session"
)

// TimeoutCache fetches session.absolute_timeout_hours +
// session.idle_timeout_hours from settings, caches them for one
// minute, and returns the parsed time.Duration pair. Cache staleness
// is acceptable: a max one-minute lag on a timeout change is fine.
type TimeoutCache struct {
	DB  *sql.DB
	mu  sync.Mutex
	at  time.Time
	abs time.Duration
	idle time.Duration
}

// NewTimeoutCache returns an empty cache. First call populates.
func NewTimeoutCache(d *sql.DB) *TimeoutCache {
	return &TimeoutCache{DB: d}
}

// Get returns (absolute, idle). Safe for concurrent use.
func (t *TimeoutCache) Get(ctx context.Context) (time.Duration, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if time.Since(t.at) < time.Minute && t.abs > 0 {
		return t.abs, t.idle
	}
	abs := readHours(ctx, t.DB, "session.absolute_timeout_hours", int(session.DefaultAbsoluteTTL/time.Hour))
	idle := readHours(ctx, t.DB, "session.idle_timeout_hours", int(session.DefaultIdleTTL/time.Hour))
	if idle > abs {
		// defensive: idle can never exceed absolute
		idle = abs
	}
	t.abs = time.Duration(abs) * time.Hour
	t.idle = time.Duration(idle) * time.Hour
	t.at = time.Now()
	return t.abs, t.idle
}

func readHours(ctx context.Context, d *sql.DB, key string, fallback int) int {
	s := db.GetSettingValue(ctx, d, key, "")
	if s == "" {
		return fallback
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}
