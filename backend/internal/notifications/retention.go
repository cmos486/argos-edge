package notifications

import (
	"context"
	"database/sql"
	"log/slog"
	"strconv"
	"time"

	"github.com/cmos486/argos-edge/backend/internal/db"
)

// RetentionPurger runs once an hour and drops deliveries older than
// notifications.retention_days plus any rows above
// notifications.max_entries. Mirrors logs.StartRetention's shape.
type RetentionPurger struct {
	DB   *sql.DB
	Repo *NotifRepo
}

// Start launches the cron. Returns a cancel func.
func (p *RetentionPurger) Start(ctx context.Context) context.CancelFunc {
	ctx, cancel := context.WithCancel(ctx)
	go p.loop(ctx)
	return cancel
}

func (p *RetentionPurger) loop(ctx context.Context) {
	// initial sweep 1 min after boot, then hourly
	first := time.NewTimer(1 * time.Minute)
	defer first.Stop()
	select {
	case <-ctx.Done():
		return
	case <-first.C:
		p.sweep(ctx)
	}
	t := time.NewTicker(1 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.sweep(ctx)
		}
	}
}

func (p *RetentionPurger) sweep(ctx context.Context) {
	days := intSetting(ctx, p.DB, "notifications.retention_days", 30)
	maxEntries := intSetting(ctx, p.DB, "notifications.max_entries", 100000)
	cutoff := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)
	n, err := p.Repo.PurgeDeliveries(ctx, cutoff, maxEntries)
	if err != nil {
		slog.Warn("notifications: purge failed", "error", err)
		return
	}
	if n > 0 {
		slog.Info("notifications: purged deliveries", "deleted", n,
			"retention_days", days, "max_entries", maxEntries)
	}
}

func intSetting(ctx context.Context, d *sql.DB, key string, fallback int) int {
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
